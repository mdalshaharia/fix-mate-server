import express from 'express';
import cors from 'cors';
import 'dotenv/config';
import { MongoClient, ObjectId } from 'mongodb';
import { createRemoteJWKSet, jwtVerify } from 'jose';


const app = express();
const port = process.env.PORT || 5000;

// middleware
app.use(express.json());

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


app.listen(port, () => {
    console.log(`hire loop is running on port ${port}`)
})

export default app;