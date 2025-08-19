const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb+srv://elvismwangike:JFJmHvP4ktikRYDC@cluster0.vm6hrog.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0', {
    useNewUrlParser: true,
    useUnifiedTopology: true
});

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', () => {
    console.log('Connected to MongoDB');
});

// Enrollment Schema
const enrollmentSchema = new mongoose.Schema({
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    email: { type: String, required: true },
    phone: { type: String, required: true },
    dob: { type: Date, required: true },
    certificateNumber: { type: String, required: true },
    street: { type: String, required: true },
    city: { type: String, required: true },
    state: { type: String, required: true },
    zip: { type: String, required: true },
    country: { type: String, required: true },
    program: { type: String, required: true },
    paymentMethod: { type: String, required: true },
    cardNumber: { type: String },
    cardName: { type: String },
    cardExpiry: { type: String },
    cardCvv: { type: String },
    amount: { type: Number },
    timestamp: { type: Date, default: Date.now }
});

const Enrollment = mongoose.model('Enrollment', enrollmentSchema);

// Routes
app.post('/api/enroll', async (req, res) => {
    try {
        const enrollmentData = req.body;
        
        // Calculate amount based on program
        if (enrollmentData.program === 'cj1') {
            enrollmentData.amount = 24500;
        } else if (enrollmentData.program === 'cj3') {
            enrollmentData.amount = 29750;
        }
        
        const enrollment = new Enrollment(enrollmentData);
        await enrollment.save();
        
        res.status(201).json({ 
            message: 'Enrollment submitted successfully', 
            id: enrollment._id 
        });
    } catch (error) {
        console.error('Error saving enrollment:', error);
        res.status(500).json({ message: 'Error processing enrollment' });
    }
});

app.get('/api/enrollments', async (req, res) => {
    try {
        const enrollments = await Enrollment.find().sort({ timestamp: -1 });
        res.json(enrollments);
    } catch (error) {
        console.error('Error fetching enrollments:', error);
        res.status(500).json({ message: 'Error fetching enrollments' });
    }
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.status(200).json({ status: 'OK', timestamp: new Date().toISOString() });
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
