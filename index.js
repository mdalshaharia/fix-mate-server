import express from 'express';
import cors from 'cors';
import 'dotenv/config';
import { MongoClient, ObjectId } from 'mongodb';


const app = express();
const port = process.env.PORT || 5000;

// middleware
app.use(express.json());
app.use(cors());

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

app.get('/', (req, res) => {
    res.send('fix-mate is running')
})


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

// payments related apis


app.listen(port, () => {
    console.log(`hire loop is running on port ${port}`)
})

export default app;