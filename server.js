// server.js
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

// MongoDB connection
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
    personalInfo: {
        firstName: String,
        lastName: String,
        email: String,
        phone: String,
        address: String,
        city: String,
        state: String,
        postalCode: String,
        country: String,
        pilotLicense: String,
        flightHours: Number
    },
    paymentMethod: String,
    paymentDetails: {
        cardNumber: String,
        cardHolder: String,
        cardExpiry: String,
        cardCvv: String,
        billingAddress: String,
        billingCity: String,
        billingPostalCode: String
    },
    amount: Number,
    status: { type: String, default: 'pending' },
    timestamp: Date
});

const Enrollment = mongoose.model('Enrollment', enrollmentSchema);

// Routes
app.post('/api/enroll', async (req, res) => {
    try {
        const enrollmentData = req.body;
        
        // Create new enrollment
        const newEnrollment = new Enrollment({
            personalInfo: enrollmentData.personalInfo,
            paymentMethod: enrollmentData.paymentMethod,
            paymentDetails: enrollmentData.paymentDetails || {},
            amount: enrollmentData.amount,
            timestamp: new Date()
        });
        
        // Save to database
        await newEnrollment.save();
        
        res.status(201).json({
            message: 'Enrollment submitted successfully',
            enrollmentId: newEnrollment._id
        });
    } catch (error) {
        console.error('Error saving enrollment:', error);
        res.status(500).json({ message: 'Error processing enrollment', error: error.message });
    }
});

app.get('/api/enrollments', async (req, res) => {
    try {
        const enrollments = await Enrollment.find().sort({ timestamp: -1 });
        res.json(enrollments);
    } catch (error) {
        console.error('Error fetching enrollments:', error);
        res.status(500).json({ message: 'Error fetching enrollments', error: error.message });
    }
});

app.get('/api/enrollment/:id', async (req, res) => {
    try {
        const enrollment = await Enrollment.findById(req.params.id);
        if (!enrollment) {
            return res.status(404).json({ message: 'Enrollment not found' });
        }
        res.json(enrollment);
    } catch (error) {
        console.error('Error fetching enrollment:', error);
        res.status(500).json({ message: 'Error fetching enrollment', error: error.message });
    }
});

app.put('/api/enrollment/:id/status', async (req, res) => {
    try {
        const { status } = req.body;
        const enrollment = await Enrollment.findByIdAndUpdate(
            req.params.id,
            { status },
            { new: true }
        );
        
        if (!enrollment) {
            return res.status(404).json({ message: 'Enrollment not found' });
        }
        
        res.json({ message: 'Status updated successfully', enrollment });
    } catch (error) {
        console.error('Error updating enrollment status:', error);
        res.status(500).json({ message: 'Error updating enrollment status', error: error.message });
    }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Start server
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
