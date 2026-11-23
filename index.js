import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import 'dotenv/config';
import { MongoClient, ObjectId } from 'mongodb';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import Stripe from 'stripe';

const REQUIRED_ENV = ['DB_URL', 'STRIPE_SECRET_KEY', 'STRIPE_WEBHOOK_SECRET', 'CLIENT_URL'];
const missingEnv = REQUIRED_ENV.filter((key) => !process.env[key]);
if (missingEnv.length > 0) {
    console.error(`Missing required environment variables: ${missingEnv.join(', ')}`);
    process.exit(1);
}

const app = express();
const port = process.env.PORT || 5000;

app.disable('x-powered-by');
if (process.env.NODE_ENV === 'production') {
    app.set('trust proxy', 1);
}

app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginResourcePolicy: { policy: 'cross-origin' },
}));

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

const allowedOrigins = [
    process.env.CLIENT_URL,
    ...(process.env.CLIENT_URLS || '')
        .split(',')
        .map((origin) => origin.trim())
        .filter(Boolean),
];
if (process.env.NODE_ENV !== 'production') {
    allowedOrigins.push('http://localhost:3000');
}

const corsOptions = {
    origin(origin, callback) {
        if (!origin || allowedOrigins.includes(origin)) {
            return callback(null, true);
        }
        return callback(new Error('Not allowed by CORS'));
    },
    credentials: true,
};
app.use(cors(corsOptions));

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 600,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    message: { message: 'Too many requests, please try again later' },
});

const authLimiter = rateLimit({
    windowMs: 60 * 1000,
    limit: 30,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    message: { message: 'Too many attempts, please try again later' },
});

const writeLimiter = rateLimit({
    windowMs: 60 * 1000,
    limit: 60,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    message: { message: 'Too many requests, please slow down' },
});

app.use('/auth', authLimiter);
app.use((req, res, next) => {
    if (req.path.startsWith('/webhooks')) return next();
    return apiLimiter(req, res, next);
});
app.use((req, res, next) => {
    if (req.path.startsWith('/webhooks')) return next();
    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
        return writeLimiter(req, res, next);
    }
    next();
});

const client = new MongoClient(process.env.DB_URL);

export async function connectToMongoDB() {
    try {
        await client.connect();
        console.log("You successfully connected to DB!");
        return client;
    } catch (err) {
        console.error('Failed to connect to MongoDB:', err.message);
        process.exit(1);
    }
}

const connectedClient = await connectToMongoDB();
const database = connectedClient.db("fix-mate");
const services = database.collection("services");
const bookings = database.collection("bookings");
const users = database.collection("user");
const payments = database.collection("payments");

try {
    await payments.createIndex({ stripeSessionId: 1 }, { unique: true });
    await payments.createIndex({ paidAt: -1 });
} catch (err) {
    console.warn('payments index creation failed:', err.message);
}

const SERVICE_CATEGORIES = [
    'Smartphone', 'Laptop', 'Air conditioner', 'Refrigerator',
    'Television', 'Washing machine', 'Electrical',
];
const SERVICE_MODES = ['Home Visit', 'Shop Drop-off'];

// Cleans and validates a service body. Returns { data } or { error }.
function getServiceInput(body = {}) {
    const data = {
        title: String(body.title || '').trim(),
        category: body.category,
        description: String(body.description || '').trim(),
        image: String(body.image || '').trim(),
        basePrice: Number(body.basePrice),
        estimatedDuration: String(body.estimatedDuration || '').trim(),
        serviceMode: body.serviceMode,
        serviceArea: String(body.serviceArea || '').trim(),
    };

    if (data.title.length < 3 || data.title.length > 100) {
        return { error: 'Title must be 3 to 100 characters' };
    }
    if (!SERVICE_CATEGORIES.includes(data.category)) return { error: 'Select a valid category' };
    if (!Number.isFinite(data.basePrice) || data.basePrice <= 0 || data.basePrice > 1000000) {
        return { error: 'Price must be a number above 0' };
    }
    if (!data.estimatedDuration || data.estimatedDuration.length > 50) {
        return { error: 'Estimated time is required' };
    }
    if (!SERVICE_MODES.includes(data.serviceMode)) return { error: 'Select a valid service mode' };
    if (!data.serviceArea || data.serviceArea.length > 100) {
        return { error: 'Service area is required' };
    }
    if (data.description.length < 20 || data.description.length > 2000) {
        return { error: 'Description must be 20 to 2000 characters' };
    }
    if (data.image.length > 2048) {
        return { error: 'Image link is too long' };
    }
    if (data.image && !/^https?:\/\/\S+$/i.test(data.image)) {
        return { error: 'Image must be a valid link' };
    }

    return { data };
}

async function markBookingPaid(bookingId, session) {
  if (!ObjectId.isValid(bookingId)) return;

  const booking = await bookings.findOne({ _id: new ObjectId(bookingId) });
  if (!booking) return;

  // Already paid through a different checkout session — ignore this one
  if (booking.paymentStatus === 'paid' && booking.stripeSessionId !== session.id) {
    return;
  }

  const paidAt = new Date();
  const transactionId =
    typeof session.payment_intent === 'string'
      ? session.payment_intent
      : session.payment_intent?.id;

  // Only unpaid → paid transitions; webhook retries / verify calls become no-ops
  const result = await bookings.updateOne(
    { _id: new ObjectId(bookingId), paymentStatus: { $ne: 'paid' } },
    {
      $set: {
        paymentStatus: 'paid',
        paidAt,
        stripeSessionId: session.id,
        stripePaymentIntent: transactionId,
        updatedAt: paidAt,
      },
    }
  );

  if (result.matchedCount === 0) {
    const current = await bookings.findOne({ _id: new ObjectId(bookingId) });
    if (!current || current.stripeSessionId !== session.id) return;
  }

  await payments.updateOne(
    { stripeSessionId: session.id },
    {
      $set: {
        bookingId: String(booking._id),
        serviceTitle: booking.serviceTitle,
        customerName: booking.customerName,
        customerEmail: booking.customerEmail,
        technicianName: booking.technicianName,
        technicianEmail: booking.technicianEmail,
        amount:
          session.amount_total != null
            ? session.amount_total / 100
            : Number(booking.finalAmount),
        currency: (session.currency || 'usd').toUpperCase(),
        transactionId,
        stripeSessionId: session.id,
        paymentStatus: session.payment_status,
        paidAt,
        updatedAt: paidAt,
      },
    },
    { upsert: true }
  );
}

// Stripe needs the raw request body to verify the signature, so this route
// must be registered before express.json().
app.post('/webhooks/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
  const signature = req.headers['stripe-signature'];
  const secret = process.env.STRIPE_WEBHOOK_SECRET;

  if (!secret) {
    console.error('STRIPE_WEBHOOK_SECRET is not set');
    return res.status(500).send('Webhook secret is not configured');
  }

  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, signature, secret);
  } catch (error) {
    console.error('Stripe webhook signature verification failed:', error.message);
    return res.status(400).send(`Webhook Error: ${error.message}`);
  }

  if (
    event.type === 'checkout.session.completed' ||
    event.type === 'checkout.session.async_payment_succeeded'
  ) {
    const session = event.data.object;
    if (session.payment_status === 'paid' && session.metadata?.bookingId) {
      try {
        await markBookingPaid(session.metadata.bookingId, session);
      } catch (error) {
        console.error('Failed to mark booking as paid:', error);
        return res.status(500).send('Failed to update booking');
      }
    }
  }

  res.send({ received: true });
});

app.use(express.json({ limit: '100kb' }));

app.get('/', (req, res) => {
    res.send('fix-mate is running')
})

const JWKS = createRemoteJWKSet(
    new URL(`${process.env.CLIENT_URL}/api/auth/jwks`)
);

// auth related api
app.post('/auth/login', async (req, res) => {
    const { token } = req.body || {};
    if (!token || typeof token !== 'string') {
        return res.status(400).send({ message: 'Token is required' });
    }

    try {
        await jwtVerify(token, JWKS);
    } catch {
        return res.status(401).send({ message: 'Invalid token' });
    }

    res.cookie('token', token, {
        httpOnly: true,
        sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
        secure: process.env.NODE_ENV === 'production',
        maxAge: 7 * 24 * 60 * 60 * 1000,
    });
    res.send({ ok: true });
})


const verifyToken = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        res.status(401).send({ message: 'Unauthorized' });
        return;
    }
    const match = /^Bearer\s+(.+)$/i.exec(authHeader);
    if (!match) {
        res.status(401).send({ message: 'Unauthorized' });
        return;
    }
    const token = match[1];

    let payload;
    try {
        const result = await jwtVerify(token, JWKS);
        payload = result.payload;
    } catch (err) {
        console.error('JWT verification failed:', err.code || err.message);
        res.status(401).send({ message: 'Unauthorized' });
        return;
    }

    if (!ObjectId.isValid(payload.sub)) {
        res.status(401).send({ message: 'Unauthorized' });
        return;
    }

    const userQuery = { _id: new ObjectId(payload.sub) };
    const user = await users.findOne(userQuery);
    if (!user) {
        res.status(401).send({ message: 'Unauthorized' });
        return;
    }
    if (user.banned) {
        res.status(403).send({ message: 'Your account has been suspended' });
        return;
    }

    req.user = user;
    next();
}

const verifyTechnician = (req, res, next) => {
  // req.user already comes from the database in verifyToken
  if (req.user?.role !== 'technician') {
    return res.status(403).send({ message: 'Only technicians can do this' });
  }
  next();
};

// Customer-only guard (req.user comes from the database in verifyToken)
const verifyCustomer = (req, res, next) => {
  if (req.user?.role !== 'customer') {
    return res.status(403).send({ message: 'Only customers can do this' });
  }
  next();
};

const verifyAdmin = async (req, res, next) => {
  try {
    // req.user already comes from the database in verifyToken (and ban-checked there)
    if (req.user?.role !== 'admin') {
      return res.status(403).send({ message: 'Admins only' });
    }
    next();
  } catch (error) {
    console.error(error);
    res.status(500).send({ message: 'Something went wrong' });
  }
};

// Deleting a service is allowed for its owner (technician) or an admin.
const verifyTechnicianOrAdmin = (req, res, next) => {
  if (req.user?.role !== 'technician' && req.user?.role !== 'admin') {
    return res.status(403).send({ message: 'Technicians or admins only' });
  }
  next();
};

// services related apis
function escapeRegex(str) {
    return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

app.get('/services', async (req, res) => {
    const asString = (value) => (typeof value === 'string' ? value.trim() : '');
    const search = asString(req.query.search).slice(0, 100);
    const category = asString(req.query.category);
    const serviceMode = asString(req.query.serviceMode);
    const sort = asString(req.query.sort);
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const limit = Math.min(50, Math.max(1, parseInt(req.query.limit, 10) || 8));

    const query = { approvalStatus: 'approved', isAvailable: { $ne: false } };
    if (category) {
        query.category = category;
    }
    if (serviceMode) {
        query.serviceMode = serviceMode;
    }
    if (search) {
        const rx = { $regex: escapeRegex(search), $options: 'i' };
        query.$or = [
            { title: rx },
            { category: rx },
            { technicianName: rx }
        ];
    }

    let sortOption = { _id: -1 }; // newest first
    if (sort === 'price-asc') sortOption = { basePrice: 1 };
    else if (sort === 'price-desc') sortOption = { basePrice: -1 };

    const total = await services.countDocuments(query);
    const result = await services
        .find(query)
        .sort(sortOption)
        .skip((page - 1) * limit)
        .limit(limit)
        .toArray();

    res.send({
        services: result,
        total,
        page,
        totalPages: Math.ceil(total / limit)
    });
})

// Home page "Featured services": the 6 newest approved + available services.
// Registered before /services/:id so "featured" is not treated as an id.
app.get('/services/featured', async (req, res) => {
    try {
        const result = await services
            .find({ approvalStatus: 'approved', isAvailable: true })
            .sort({ createdAt: -1 })
            .limit(6)
            .toArray();
        res.send(result);
    } catch (error) {
        console.error(error);
        res.status(500).send({ message: 'Failed to fetch featured services' });
    }
});

// Registered before /services/:id so "my" is not treated as an id
app.get('/services/my', verifyToken, verifyTechnician, async (req, res) => {
  try {
    const myServices = await services
      .find({ technicianEmail: req.user.email })
      .sort({ createdAt: -1 })
      .toArray();
    res.send(myServices);
  } catch (error) {
    console.error(error);
    res.status(500).send({ message: 'Failed to fetch services' });
  }
});

app.get('/services/my/:id', verifyToken, verifyTechnician, async (req, res) => {
  try {
    if (!ObjectId.isValid(req.params.id)) {
      return res.status(404).send({ message: 'Service not found' });
    }
    const service = await services.findOne({
      _id: new ObjectId(req.params.id),
      technicianEmail: req.user.email,
    });
    if (!service) return res.status(404).send({ message: 'Service not found' });
    res.send(service);
  } catch (error) {
    console.error(error);
    res.status(500).send({ message: 'Failed to fetch service' });
  }
});

app.get('/services/:id', async (req, res) => {
    try {
        if (!ObjectId.isValid(req.params.id)) {
            return res.status(404).send({ message: 'Service not found' });
        }
        // Public detail: only approved + available services (matches the list endpoint)
        const result = await services.findOne({
            _id: new ObjectId(req.params.id),
            approvalStatus: 'approved',
            isAvailable: { $ne: false },
        });
        if (!result) {
            return res.status(404).send({ message: 'Service not found' });
        }

        // Attach the technician's public profile so the details page can show
        // their avatar, bio and area (services only store name + email).
        const technician = result.technicianEmail
            ? await users.findOne(
                { email: result.technicianEmail },
                { projection: { name: 1, email: 1, image: 1, bio: 1, area: 1, _id: 0 } }
            )
            : null;

        res.send({
            ...result,
            technician: technician
                ? {
                    name: technician.name || result.technicianName || '',
                    email: technician.email || result.technicianEmail || '',
                    image: technician.image || '',
                    bio: technician.bio || '',
                    area: technician.area || '',
                }
                : null,
        });
    } catch (error) {
        console.error(error);
        res.status(500).send({ message: 'Failed to fetch service' });
    }
})

app.put('/services/:id', verifyToken, verifyTechnician, async (req, res) => {
  try {
    if (!ObjectId.isValid(req.params.id)) {
      return res.status(404).send({ message: 'Service not found' });
    }
    const { data, error } = getServiceInput(req.body || {});
    if (error) return res.status(400).send({ message: error });

    const result = await services.updateOne(
      { _id: new ObjectId(req.params.id), technicianEmail: req.user.email },
      { $set: { ...data, approvalStatus: 'pending', updatedAt: new Date() } }
    );
    if (result.matchedCount === 0) {
      return res.status(404).send({ message: 'Service not found' });
    }
    res.send({ success: true });
  } catch (error) {
    console.error(error);
    res.status(500).send({ message: 'Failed to update service' });
  }
});

app.patch('/services/:id/availability', verifyToken, verifyTechnician, async (req, res) => {
  try {
    const { isAvailable } = req.body || {};
    if (typeof isAvailable !== 'boolean') {
      return res.status(400).send({ message: 'isAvailable must be true or false' });
    }
    if (!ObjectId.isValid(req.params.id)) {
      return res.status(404).send({ message: 'Service not found' });
    }
    const result = await services.updateOne(
      { _id: new ObjectId(req.params.id), technicianEmail: req.user.email },
      { $set: { isAvailable } }
    );
    if (result.matchedCount === 0) {
      return res.status(404).send({ message: 'Service not found' });
    }
    res.send({ success: true });
  } catch (error) {
    console.error(error);
    res.status(500).send({ message: 'Failed to update availability' });
  }
});

app.post('/services', verifyToken, verifyTechnician, async (req, res) => {
    try {
        const { data, error } = getServiceInput(req.body || {});
        if (error) return res.status(400).send({ message: error });

        const service = {
            ...data,
            technicianName: req.user.name || '',
            technicianEmail: req.user.email,
            approvalStatus: 'pending', // an admin approves it later
            isAvailable: true,
            createdAt: new Date(),
        };

        const result = await services.insertOne(service);
        res.status(201).send({ insertedId: result.insertedId });
    } catch (error) {
        console.error(error);
        res.status(500).send({ message: 'Failed to add service' });
    }
})


app.delete('/services/:id', verifyToken, verifyTechnicianOrAdmin, async (req, res) => {
    try {
        if (!ObjectId.isValid(req.params.id)) {
            return res.status(404).send({ message: 'Service not found' });
        }

        const query = { _id: new ObjectId(req.params.id) };
        // Admins can delete any service; technicians only their own
        if (req.user.role !== 'admin') {
            query.technicianEmail = req.user.email;
        }

        const result = await services.deleteOne(query);
        if (result.deletedCount === 0) {
            return res.status(404).send({ message: 'Service not found' });
        }
        res.send(result);
    } catch (error) {
        console.error(error);
        res.status(500).send({ message: 'Failed to delete service' });
    }
})


// booking related apis
const ACTIVE_BOOKING_STATUSES = ['requested', 'accepted', 'in-progress'];

app.post('/bookings', verifyToken, verifyCustomer, async (req, res) => {
  try {
    const body = req.body || {};
    const serviceId = String(body.serviceId || '').trim();
    const customerPhone = String(body.customerPhone || '').trim();
    const address = String(body.address || '').trim();
    const preferredDate = String(body.preferredDate || '').trim();
    const problemDescription = String(body.problemDescription || '').trim();

    if (!serviceId || !customerPhone || !address || !preferredDate || !problemDescription) {
      return res.status(400).send({ message: 'Missing required booking fields' });
    }
    if (!ObjectId.isValid(serviceId)) {
      return res.status(404).send({ message: 'Service not found' });
    }
    if (!/^\d{4}-\d{2}-\d{2}$/.test(preferredDate) || Number.isNaN(Date.parse(preferredDate))) {
      return res.status(400).send({ message: 'Invalid preferred date' });
    }
    if (customerPhone.length > 20) {
      return res.status(400).send({ message: 'Phone number is too long' });
    }
    if (address.length > 300) {
      return res.status(400).send({ message: 'Address is too long' });
    }
    if (problemDescription.length < 10 || problemDescription.length > 2000) {
      return res.status(400).send({ message: 'Please describe the problem in 10 to 2000 characters' });
    }

    // Trust the database, not the client: the service must exist, be approved and bookable
    const service = await services.findOne({
      _id: new ObjectId(serviceId),
      approvalStatus: 'approved',
      isAvailable: { $ne: false },
    });
    if (!service) {
      return res.status(404).send({ message: 'Service not found or not available for booking' });
    }

    const customerEmail = req.user.email;
    const duplicate = await bookings.findOne({
      serviceId,
      customerEmail,
      status: { $in: ACTIVE_BOOKING_STATUSES },
    });
    if (duplicate) {
      return res.status(409).send({ message: 'You already have an active request for this service' });
    }

    const basePrice = Number(service.basePrice);
    const now = new Date();
    const doc = {
      serviceId,
      serviceTitle: String(service.title || ''),
      serviceImage: String(service.image || ''),
      category: String(service.category || ''),
      basePrice: Number.isFinite(basePrice) ? basePrice : null,
      finalAmount: Number.isFinite(basePrice) ? basePrice : null,
      technicianName: String(service.technicianName || ''),
      technicianEmail: String(service.technicianEmail || ''),
      customerName: req.user.name || '',
      customerEmail,
      customerPhone,
      address,
      preferredDate,
      problemDescription,
      status: 'requested',
      paymentStatus: 'unpaid',
      createdAt: now,
      updatedAt: now,
    };

    const result = await bookings.insertOne(doc);
    res.status(201).send({ ...doc, _id: result.insertedId });
  } catch (error) {
    console.error(error);
    res.status(500).send({ message: 'Failed to create booking' });
  }
})


app.get('/bookings/my', verifyToken, verifyCustomer, async (req, res) => {
  try {
    const data = await bookings
      .find({ customerEmail: req.user.email })
      .sort({ createdAt: -1 })
      .toArray();
    res.send(data);
  } catch (error) {
    console.error(error);
    res.status(500).send({ message: 'Failed to fetch bookings' });
  }
});

app.patch('/bookings/:id/cancel', verifyToken, verifyCustomer, async (req, res) => {
  try {
    if (!ObjectId.isValid(req.params.id)) {
      return res.status(404).send({ message: 'Booking not found' });
    }
    const result = await bookings.updateOne(
      { _id: new ObjectId(req.params.id), customerEmail: req.user.email, status: 'requested' },
      { $set: { status: 'cancelled', updatedAt: new Date() } }
    );
    if (result.matchedCount === 0) {
      return res.status(409).send({ message: 'This booking can no longer be cancelled' });
    }
    res.send({ success: true });
  } catch (error) {
    console.error(error);
    res.status(500).send({ message: 'Failed to cancel booking' });
  }
});



const MONTH_NAMES = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

// The last 6 months, oldest first, in UTC so it matches Mongo's $year/$month.
function lastSixMonths() {
  const now = new Date();
  const months = [];
  for (let i = 5; i >= 0; i -= 1) {
    const d = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - i, 1));
    months.push({ year: d.getUTCFullYear(), monthIndex: d.getUTCMonth(), month: MONTH_NAMES[d.getUTCMonth()] });
  }
  return months;
}

// Sums `amount` per month for the last 6 months. Every month is returned (zeros included).
async function sumAmountByMonth(collection, match = {}) {
  const months = lastSixMonths();
  const start = new Date(Date.UTC(months[0].year, months[0].monthIndex, 1));

  const rows = await collection
    .aggregate([
      { $match: { ...match, paidAt: { $gte: start } } },
      {
        $group: {
          _id: { year: { $year: '$paidAt' }, month: { $month: '$paidAt' } },
          total: { $sum: '$amount' },
        },
      },
    ])
    .toArray();

  const totals = new Map(rows.map((row) => [`${row._id.year}-${row._id.month}`, row.total]));
  return months.map((m) => ({
    month: m.month,
    value: Math.round((totals.get(`${m.year}-${m.monthIndex + 1}`) || 0) * 100) / 100,
  }));
}

// Counts documents grouped by a field -> [{ [field]: value, count: n }]
async function countByField(collection, field, match = {}) {
  const rows = await collection
    .aggregate([{ $match: match }, { $group: { _id: `$${field}`, count: { $sum: 1 } } }])
    .toArray();
  return rows.map((row) => ({ [field]: row._id, count: row.count }));
}

// Overview stats
app.get('/bookings/my/stats', verifyToken, verifyCustomer, async (req, res) => {
  try {
    const customerEmail = req.user.email;
    const [totalRequests, activeJobs, completedJobs, spendingByMonth, bookingsByStatus] = await Promise.all([
      bookings.countDocuments({ customerEmail }),
      bookings.countDocuments({ customerEmail, status: { $in: ['accepted', 'in-progress'] } }),
      bookings.countDocuments({ customerEmail, status: 'completed' }),
      sumAmountByMonth(payments, { customerEmail }),
      countByField(bookings, 'status', { customerEmail }),
    ]);
    res.send({ totalRequests, activeJobs, completedJobs, spendingByMonth, bookingsByStatus });
  } catch (error) {
    console.error(error);
    res.status(500).send({ message: 'Failed to fetch stats' });
  }
});

// payments related apis


app.post('/payments/checkout', verifyToken, verifyCustomer, async (req, res) => {
  try {
    const { bookingId } = req.body || {};
    if (!ObjectId.isValid(bookingId)) {
      return res.status(404).send({ message: 'Booking not found' });
    }

    const booking = await bookings.findOne({
      _id: new ObjectId(bookingId),
      customerEmail: req.user.email,
      status: 'completed',
      paymentStatus: 'unpaid',
    });
    if (!booking) {
      return res.status(400).send({ message: 'This booking cannot be paid right now' });
    }

    const unitAmount = Math.round(Number(booking.finalAmount) * 100);
    if (!Number.isFinite(unitAmount) || unitAmount <= 0) {
      return res.status(400).send({ message: 'This booking has no payable amount' });
    }

    const idempotencyKey = `checkout_${booking._id}_${
      booking.updatedAt instanceof Date ? booking.updatedAt.getTime() : 'na'
    }`;

    const session = await stripe.checkout.sessions.create({
      mode: 'payment',
      customer_email: booking.customerEmail,
      line_items: [
        {
          quantity: 1,
          price_data: {
            currency: 'usd',
            unit_amount: unitAmount,
            product_data: { name: booking.serviceTitle },
          },
        },
      ],
      metadata: { bookingId: String(booking._id) },
      success_url: `${process.env.CLIENT_URL}/payment/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.CLIENT_URL}/payment/cancel?booking=${booking._id}`,
    }, { idempotencyKey });

    res.send({ url: session.url });
  } catch (error) {
    console.error(error);
    res.status(500).send({ message: 'Failed to start payment' });
  }
});

app.get('/payments/verify', verifyToken, verifyCustomer, async (req, res) => {
  try {
    const { session_id: sessionId } = req.query;
    if (!sessionId) {
      return res.status(400).send({ message: 'session_id is required' });
    }

    const session = await stripe.checkout.sessions.retrieve(sessionId);
    const bookingId = session.metadata?.bookingId;

    if (!bookingId || !ObjectId.isValid(bookingId)) {
      return res.status(400).send({ message: 'Invalid payment session' });
    }

    const booking = await bookings.findOne({
      _id: new ObjectId(bookingId),
      customerEmail: req.user.email,
    });
    if (!booking) {
      return res.status(404).send({ message: 'Payment not found' });
    }

    if (session.payment_status === 'paid') {
      await markBookingPaid(bookingId, session);
    }

    res.send({
      success: session.payment_status === 'paid',
      paymentStatus: session.payment_status,
      bookingId,
      transactionId:
        typeof session.payment_intent === 'string'
          ? session.payment_intent
          : session.payment_intent?.id,
      serviceTitle: booking?.serviceTitle || null,
      technicianName: booking?.technicianName || null,
      amount:
        session.amount_total != null
          ? session.amount_total / 100
          : Number(booking?.finalAmount) || null,
      currency: (session.currency || 'usd').toUpperCase(),
    });
  } catch (error) {
    console.error(error);
    res.status(500).send({ message: 'Failed to verify payment' });
  }
});

// technician related api

const FILTER_STATUSES = ['requested', 'accepted', 'in-progress', 'completed', 'rejected', 'cancelled'];

const STATUS_FLOW = {
  accepted: 'requested',
  rejected: 'requested',
  'in-progress': 'accepted',
  completed: 'in-progress',
};

app.get('/bookings/technician/stats', verifyToken, verifyTechnician, async (req, res) => {
  try {
    const technicianEmail = req.user.email;
    const [
      totalRequests,
      activeJobs,
      completedJobs,
      totalServices,
      approvedServices,
      pendingRequests,
      earningsByMonth,
      bookingsByStatus,
      servicesByApproval,
    ] = await Promise.all([
      bookings.countDocuments({ technicianEmail }),
      bookings.countDocuments({ technicianEmail, status: { $in: ['accepted', 'in-progress'] } }),
      bookings.countDocuments({ technicianEmail, status: 'completed' }),
      services.countDocuments({ technicianEmail }),
      services.countDocuments({ technicianEmail, approvalStatus: 'approved' }),
      bookings.countDocuments({ technicianEmail, status: 'requested' }),
      sumAmountByMonth(payments, { technicianEmail }),
      countByField(bookings, 'status', { technicianEmail }),
      countByField(services, 'approvalStatus', { technicianEmail }),
    ]);
    res.send({
      totalRequests,
      activeJobs,
      completedJobs,
      totalServices,
      approvedServices,
      pendingRequests,
      earningsByMonth,
      bookingsByStatus,
      servicesByApproval,
    });
  } catch (error) {
    console.error(error);
    res.status(500).send({ message: 'Failed to fetch stats' });
  }
});

app.get('/bookings/technician', verifyToken, verifyTechnician, async (req, res) => {
  try {
    const query = { technicianEmail: req.user.email };
    if (FILTER_STATUSES.includes(req.query.status)) {
      query.status = req.query.status;
    }

    const docs = await bookings.find(query).sort({ createdAt: -1 }).toArray();
    res.send(docs);
  } catch (error) {
    console.error(error);
    res.status(500).send({ message: 'Failed to fetch requests' });
  }
});

app.patch('/bookings/:id/status', verifyToken, verifyTechnician, async (req, res) => {
  try {
    const { status, finalAmount } = req.body || {};

    if (typeof status !== 'string' || !Object.hasOwn(STATUS_FLOW, status)) {
      return res.status(400).send({ message: 'Invalid status' });
    }
    if (!ObjectId.isValid(req.params.id)) {
      return res.status(404).send({ message: 'Request not found' });
    }

    const update = { status, updatedAt: new Date() };

    if (status === 'completed') {
      const amount = Number(finalAmount);
      if (!Number.isFinite(amount) || amount <= 0) {
        return res.status(400).send({ message: 'Final amount must be a number above 0' });
      }
      update.finalAmount = Math.round(amount * 100) / 100;
    }


    const result = await bookings.updateOne(
      {
        _id: new ObjectId(req.params.id),
        technicianEmail: req.user.email,
        status: STATUS_FLOW[status],
      },
      { $set: update }
    );

    if (result.matchedCount === 0) {
      return res.status(409).send({ message: 'This request can no longer be updated' });
    }
    res.send({ success: true });
  } catch (error) {
    console.error(error);
    res.status(500).send({ message: 'Failed to update request' });
  }
});

// admin related apis
app.get('/admin/stats', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const [
      totalUsers,
      totalTechnicians,
      pendingServices,
      revenueSummary,
      revenueByMonth,
      bookingsByStatus,
      usersByRole,
      servicesByApproval,
    ] = await Promise.all([
      users.countDocuments(),
      users.countDocuments({ role: 'technician' }),
      services.countDocuments({ approvalStatus: 'pending' }),
      payments.aggregate([{ $group: { _id: null, revenue: { $sum: '$amount' } } }]).toArray(),
      sumAmountByMonth(payments),
      countByField(bookings, 'status'),
      countByField(users, 'role'),
      countByField(services, 'approvalStatus'),
    ]);
    const totalRevenue = Math.round((revenueSummary[0]?.revenue || 0) * 100) / 100;
    res.send({
      totalUsers,
      totalTechnicians,
      pendingServices,
      totalRevenue,
      revenueByMonth,
      bookingsByStatus,
      usersByRole,
      servicesByApproval,
    });
  } catch (error) {
    console.error(error);
    res.status(500).send({ message: 'Failed to fetch stats' });
  }
});

const USER_ROLES = ['customer', 'technician', 'admin'];

app.get('/admin/users', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const pageNumber = Math.max(parseInt(req.query.page) || 1, 1);
    const limitNumber = Math.min(Math.max(parseInt(req.query.limit) || 10, 1), 50);

    const [docs, total] = await Promise.all([
      users
        .find({}, { projection: { name: 1, email: 1, image: 1, role: 1, banned: 1, createdAt: 1 } })
        .sort({ createdAt: -1, _id: 1 }) // _id keeps pagination order stable
        .skip((pageNumber - 1) * limitNumber)
        .limit(limitNumber)
        .toArray(),
      users.countDocuments(),
    ]);

    res.send({ users: docs, total, page: pageNumber, totalPages: Math.ceil(total / limitNumber) });
  } catch (error) {
    console.error(error);
    res.status(500).send({ message: 'Failed to fetch users' });
  }
});

// Change a user's role
app.patch('/admin/users/:id/role', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { role } = req.body || {};

    if (!USER_ROLES.includes(role)) {
      return res.status(400).send({ message: 'Invalid role' });
    }
    if (!ObjectId.isValid(req.params.id)) {
      return res.status(404).send({ message: 'User not found' });
    }

    const target = await users.findOne(
      { _id: new ObjectId(req.params.id) },
      { projection: { email: 1 } }
    );
    if (!target) return res.status(404).send({ message: 'User not found' });
    if (target.email === req.user.email) {
      return res.status(403).send({ message: 'You cannot change your own role' });
    }

    await users.updateOne({ _id: target._id }, { $set: { role, updatedAt: new Date() } });
    res.send({ success: true });
  } catch (error) {
    console.error(error);
    res.status(500).send({ message: 'Failed to update role' });
  }
});

// Ban / unban a user
app.patch('/admin/users/:id/ban', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { banned, reason } = req.body || {};

    if (typeof banned !== 'boolean') {
      return res.status(400).send({ message: 'banned must be true or false' });
    }
    if (!ObjectId.isValid(req.params.id)) {
      return res.status(404).send({ message: 'User not found' });
    }

    const target = await users.findOne(
      { _id: new ObjectId(req.params.id) },
      { projection: { email: 1 } }
    );
    if (!target) return res.status(404).send({ message: 'User not found' });

    if (target.email === req.user.email) {
      return res.status(403).send({ message: 'You cannot ban yourself' });
    }

    const update = {
      banned,
      bannedAt: banned ? new Date() : null,
      bannedReason: banned ? String(reason || '').slice(0, 500) : null,
      updatedAt: new Date(),
    };
    await users.updateOne({ _id: target._id }, { $set: update });
    res.send({ success: true, banned });
  } catch (error) {
    console.error(error);
    res.status(500).send({ message: 'Failed to update ban status' });
  }
});

const APPROVAL_FILTERS = ['pending', 'approved', 'rejected'];

// All services from all technicians, optionally filtered by approval status
app.get('/admin/services', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const query = {};
    if (APPROVAL_FILTERS.includes(req.query.status)) {
      query.approvalStatus = req.query.status;
    }

    const pageNumber = Math.max(parseInt(req.query.page) || 1, 1);
    const limitNumber = Math.min(Math.max(parseInt(req.query.limit) || 10, 1), 50);

    const [docs, total] = await Promise.all([
      services
        .aggregate([
          { $match: query },
          { $addFields: { pendingFirst: { $cond: [{ $eq: ['$approvalStatus', 'pending'] }, 0, 1] } } },
          { $sort: { pendingFirst: 1, createdAt: -1, _id: 1 } }, // _id keeps pagination stable
          { $skip: (pageNumber - 1) * limitNumber },
          { $limit: limitNumber },
          { $project: { pendingFirst: 0 } },
        ])
        .toArray(),
      services.countDocuments(query),
    ]);

    res.send({ services: docs, total, page: pageNumber, totalPages: Math.ceil(total / limitNumber) });
  } catch (error) {
    console.error(error);
    res.status(500).send({ message: 'Failed to fetch services' });
  }
});

// Approve or reject a service
app.patch('/admin/services/:id/approval', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { approvalStatus } = req.body || {};

    if (!['approved', 'rejected'].includes(approvalStatus)) {
      return res.status(400).send({ message: 'Invalid approval status' });
    }
    if (!ObjectId.isValid(req.params.id)) {
      return res.status(404).send({ message: 'Service not found' });
    }

    const result = await services.updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: { approvalStatus, reviewedAt: new Date(), reviewedBy: req.user.email } }
    );
    if (result.matchedCount === 0) {
      return res.status(404).send({ message: 'Service not found' });
    }
    res.send({ success: true });
  } catch (error) {
    console.error(error);
    res.status(500).send({ message: 'Failed to update service' });
  }
});

const BOOKING_STATUSES = ['requested', 'accepted', 'in-progress', 'completed', 'rejected', 'cancelled'];

// Every booking on the platform (read-only), optionally filtered by status
app.get('/admin/bookings', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const query = {};
    if (BOOKING_STATUSES.includes(req.query.status)) {
      query.status = req.query.status;
    }

    const pageNumber = Math.max(parseInt(req.query.page) || 1, 1);
    const limitNumber = Math.min(Math.max(parseInt(req.query.limit) || 10, 1), 50);

    const [docs, total] = await Promise.all([
      bookings
        .find(query)
        .sort({ createdAt: -1, _id: 1 })
        .skip((pageNumber - 1) * limitNumber)
        .limit(limitNumber)
        .toArray(),
      bookings.countDocuments(query),
    ]);

    res.send({ bookings: docs, total, page: pageNumber, totalPages: Math.ceil(total / limitNumber) });
  } catch (error) {
    console.error(error);
    res.status(500).send({ message: 'Failed to fetch bookings' });
  }
});


app.get('/admin/payments', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const pageNumber = Math.max(parseInt(req.query.page) || 1, 1);
    const limitNumber = Math.min(Math.max(parseInt(req.query.limit) || 10, 1), 50);

    const [docs, total, summary] = await Promise.all([
      payments
        .find()
        .sort({ paidAt: -1, _id: 1 }) // _id keeps pagination order stable
        .skip((pageNumber - 1) * limitNumber)
        .limit(limitNumber)
        .toArray(),
      payments.countDocuments(),
      payments.aggregate([{ $group: { _id: null, revenue: { $sum: '$amount' } } }]).toArray(),
    ]);

    const round = (n) => Math.round(n * 100) / 100;
    const totalRevenue = round(summary[0]?.revenue || 0);

    res.send({
      payments: docs,
      total,
      page: pageNumber,
      totalPages: Math.ceil(total / limitNumber),
      stats: {
        totalRevenue,
        transactions: total,
        averageJob: total ? round(totalRevenue / total) : 0,
      },
    });
  } catch (error) {
    console.error(error);
    res.status(500).send({ message: 'Failed to fetch payments' });
  }
});

// Payment overview of the logged-in customer
app.get('/payments/my', verifyToken,verifyCustomer , async (req, res) => {
  try {
    const customerEmail = req.user.email;
    const pageNumber = Math.max(parseInt(req.query.page) || 1, 1);
    const limitNumber = Math.min(Math.max(parseInt(req.query.limit) || 10, 1), 50);

    const [paymentDocs, total, paidSummary, dueBookings] = await Promise.all([
      payments
        .find({ customerEmail })
        .sort({ paidAt: -1, _id: 1 }) // _id keeps pagination order stable
        .skip((pageNumber - 1) * limitNumber)
        .limit(limitNumber)
        .toArray(),
      payments.countDocuments({ customerEmail }),
      payments
        .aggregate([
          { $match: { customerEmail } },
          { $group: { _id: null, totalPaid: { $sum: '$amount' } } },
        ])
        .toArray(),
      bookings
        .find({ customerEmail, status: 'completed', paymentStatus: 'unpaid' })
        .sort({ updatedAt: -1 })
        .toArray(),
    ]);

    const round = (n) => Math.round(n * 100) / 100;

    res.send({
      payments: paymentDocs,
      total,
      page: pageNumber,
      totalPages: Math.ceil(total / limitNumber),
      dueBookings,
      stats: {
        totalPaid: round(paidSummary[0]?.totalPaid || 0),
        paymentsCount: total,
        amountDue: round(
          dueBookings.reduce((sum, b) => sum + (Number(b.finalAmount) || 0), 0)
        ),
      },
    });
  } catch (error) {
    console.error(error);
    res.status(500).send({ message: 'Failed to fetch payments' });
  }
});


app.use((err, req, res, next) => {
    if (res.headersSent) return next(err);
    if (err.message === 'Not allowed by CORS') {
        return res.status(403).send({ message: 'Origin not allowed' });
    }
    console.error(err);
    res.status(500).send({ message: 'Something went wrong' });
});

app.listen(port, () => {
    console.log(`fix-mate is fixing on port ${port}`)
})

export default app;