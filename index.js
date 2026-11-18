import express from 'express';
import cors from 'cors';
import 'dotenv/config';
import { MongoClient, ObjectId } from 'mongodb';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import Stripe from 'stripe';


const app = express();
const port = process.env.PORT || 5000;

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

const corsOptions = {
    origin: ['http://localhost:3000', 'https://studio-space-ivory.vercel.app'],
    credentials: true,
};
app.use(cors(corsOptions));

const client = new MongoClient(`${process.env.DB_URL}`);

export async function connectToMongoDB() {
    try {
        await client.connect();
        console.log("You successfully connected to MongoDB!");
        return client;
    } catch (err) {
        console.dir(err);
    }
}

const connectedClient = await connectToMongoDB();
const database = connectedClient.db("fix-mate");
const services = database.collection("services");
const bookings = database.collection("bookings");
const users = database.collection("user");

async function markBookingPaid(bookingId, session) {
  if (!ObjectId.isValid(bookingId)) return;

  await bookings.updateOne(
    { _id: new ObjectId(bookingId) },
    {
      $set: {
        paymentStatus: 'paid',
        paidAt: new Date(),
        stripeSessionId: session.id,
        stripePaymentIntent:
          typeof session.payment_intent === 'string'
            ? session.payment_intent
            : session.payment_intent?.id,
        updatedAt: new Date(),
      },
    }
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

app.use(express.json());

app.get('/', (req, res) => {
    res.send('fix-mate is running')
})

// auth related api
app.post('/auth/login', async (req, res) => {
    const { token } = req.body;
    if (!token) {
        return res.status(400).send({ message: 'Token is required' });
    }
    res.cookie('token', token, {
        httpOnly: true,
        sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
        secure: process.env.NODE_ENV === 'production',
        maxAge: 7 * 24 * 60 * 60 * 1000,
    });
    res.send({ ok: true });
})


const JWKS = createRemoteJWKSet(
    new URL(`${process.env.CLIENT_URL || 'http://localhost:3000'}/api/auth/jwks`)
);

const verifyToken = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        res.status(401).send({ message: 'Unauthorized' });
        return;
    }
    const token = authHeader.split(' ')[1];
    if (!token) {
        res.status(401).send({ message: 'Unauthorized' });
        return;
    }

    let payload;
    try {
        const result = await jwtVerify(token, JWKS);
        payload = result.payload;
    } catch (err) {
        console.error('JWT verification failed:', err.code || err.message);
        res.status(401).send({ message: 'Unauthorized' });
        return;
    }

    const userQuery = { _id: new ObjectId(payload.sub) };
    const user = await users.findOne(userQuery);
    if (!user) {
        res.status(401).send({ message: 'Unauthorized' });
        return;
    }

    req.user = user;
    next();
}


// services related apis
function escapeRegex(str) {
    return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

app.get('/services', async (req, res) => {
    const { search, category, serviceMode, sort } = req.query;
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(50, Math.max(1, parseInt(req.query.limit) || 8));

    const query = { approvalStatus: 'approved' };
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

app.get(`/services/:id`, async (req, res) => {
    const id = req.params.id;
    const query = { _id: new ObjectId(id) };
    const result = await services.findOne(query);
    res.send(result);
})


app.post('/services' , async (req, res) => {
    const job = req.body;
    const result = await services.insertOne(job);
    res.send(result);
})


app.delete('/services/:id', async (req, res) => {
    const id = req.params.id;
    const query = { _id: new ObjectId(id) };
    const result = await services.deleteOne(query);
    res.send(result);
})


// booking related aplis
app.post('/bookings', async (req, res) => {
    const data = req.body;
    const result = await bookings.insertOne(data);
    res.send(result);
})


app.get('/bookings/my', verifyToken, async (req, res) => {
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

app.patch('/bookings/:id/cancel', verifyToken, async (req, res) => {
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



// Overview stats
app.get('/bookings/my/stats', verifyToken, async (req, res) => {
  try {
    const customerEmail = req.user.email;
    // console.log(customerEmail)
    const [totalRequests, activeJobs, completedJobs] = await Promise.all([
      bookings.countDocuments({ customerEmail }),
      bookings.countDocuments({ customerEmail, status: { $in: ['accepted', 'in-progress'] } }),
      bookings.countDocuments({ customerEmail, status: 'completed' }),
    ]);
    console.log(totalRequests)
    res.send({ totalRequests, activeJobs, completedJobs });
  } catch (error) {
    console.error(error);
    res.status(500).send({ message: 'Failed to fetch stats' });
  }
});

// payments related apis


app.post('/payments/checkout', verifyToken, async (req, res) => {
  try {
    const { bookingId } = req.body;
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

    const session = await stripe.checkout.sessions.create({
      mode: 'payment',
      customer_email: booking.customerEmail,
      line_items: [
        {
          quantity: 1,
          price_data: {
            currency: 'usd',
            unit_amount: unitAmount, // Stripe uses cents
            product_data: { name: booking.serviceTitle },
          },
        },
      ],
      metadata: { bookingId: String(booking._id) },
      success_url: `${process.env.CLIENT_URL}/dashboard/customer/bookings?payment=success&session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.CLIENT_URL}/dashboard/customer/bookings?payment=cancelled`,
    });

    res.send({ url: session.url });
  } catch (error) {
    console.error(error);
    res.status(500).send({ message: 'Failed to start payment' });
  }
});

// Fallback for local development when the Stripe webhook isn't being forwarded:
// the client calls this when it returns from Checkout.
app.get('/payments/verify', verifyToken, async (req, res) => {
  try {
    const { session_id: sessionId } = req.query;
    if (!sessionId) {
      return res.status(400).send({ message: 'session_id is required' });
    }

    const session = await stripe.checkout.sessions.retrieve(sessionId);
    const bookingId = session.metadata?.bookingId;

    if (bookingId && ObjectId.isValid(bookingId) && session.payment_status === 'paid') {
      const booking = await bookings.findOne({
        _id: new ObjectId(bookingId),
        customerEmail: req.user.email,
      });
      if (booking && booking.paymentStatus !== 'paid') {
        await markBookingPaid(bookingId, session);
      }
    }

    res.send({ paymentStatus: session.payment_status });
  } catch (error) {
    console.error(error);
    res.status(500).send({ message: 'Failed to verify payment' });
  }
});


app.listen(port, () => {
    console.log(`hire loop is running on port ${port}`)
})

export default app;