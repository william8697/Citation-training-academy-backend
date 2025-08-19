const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));

// In-memory storage (in production, use a database)
let enrollments = [];
const ENROLLMENTS_FILE = 'enrollments.json';

// Load existing enrollments if file exists
if (fs.existsSync(ENROLLMENTS_FILE)) {
    try {
        const data = fs.readFileSync(ENROLLMENTS_FILE, 'utf8');
        enrollments = JSON.parse(data);
    } catch (err) {
        console.error('Error reading enrollments file:', err);
    }
}

// Save enrollments to file
function saveEnrollments() {
    try {
        fs.writeFileSync(ENROLLMENTS_FILE, JSON.stringify(enrollments, null, 2));
    } catch (err) {
        console.error('Error saving enrollments:', err);
    }
}

// Routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Get all enrollments (for admin purposes)
app.get('/api/enrollments', (req, res) => {
    res.json(enrollments);
});

// Submit new enrollment
app.post('/api/enroll', (req, res) => {
    try {
        const {
            firstName,
            lastName,
            email,
            phone,
            address,
            dob,
            pilotLicense,
            flightHours,
            preferredDate,
            message
        } = req.body;

        // Basic validation
        if (!firstName || !lastName || !email || !phone || !address || !dob || !pilotLicense || !flightHours || !preferredDate) {
            return res.status(400).json({ 
                success: false, 
                message: 'All required fields must be filled' 
            });
        }

        // Create enrollment object
        const enrollment = {
            id: Date.now().toString(),
            firstName,
            lastName,
            email,
            phone,
            address,
            dob,
            pilotLicense,
            flightHours: parseInt(flightHours),
            preferredDate,
            message: message || '',
            enrollmentDate: new Date().toISOString(),
            status: 'pending'
        };

        // Add to enrollments array
        enrollments.push(enrollment);
        
        // Save to file
        saveEnrollments();

        // In a real application, you would:
        // 1. Save to a database
        // 2. Send confirmation email
        // 3. Process payment, etc.

        res.json({ 
            success: true, 
            message: 'Enrollment submitted successfully',
            enrollmentId: enrollment.id
        });
    } catch (error) {
        console.error('Enrollment error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Internal server error' 
        });
    }
});

// Get specific enrollment by ID
app.get('/api/enrollment/:id', (req, res) => {
    const enrollment = enrollments.find(e => e.id === req.params.id);
    
    if (!enrollment) {
        return res.status(404).json({ 
            success: false, 
            message: 'Enrollment not found' 
        });
    }
    
    res.json({ 
        success: true, 
        enrollment 
    });
});

// Update enrollment status
app.put('/api/enrollment/:id/status', (req, res) => {
    const { status } = req.body;
    const enrollmentIndex = enrollments.findIndex(e => e.id === req.params.id);
    
    if (enrollmentIndex === -1) {
        return res.status(404).json({ 
            success: false, 
            message: 'Enrollment not found' 
        });
    }
    
    if (!['pending', 'approved', 'rejected', 'completed'].includes(status)) {
        return res.status(400).json({ 
            success: false, 
            message: 'Invalid status' 
        });
    }
    
    enrollments[enrollmentIndex].status = status;
    saveEnrollments();
    
    res.json({ 
        success: true, 
        message: 'Status updated successfully' 
    });
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
