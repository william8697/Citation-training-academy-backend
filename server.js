// server.js
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const hpp = require('hpp');
const compression = require('compression');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Security middleware
app.use(helmet());
app.use(mongoSanitize());
app.use(xss());
app.use(hpp());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/', limiter);

// Compression middleware
app.use(compression());

// CORS configuration - allow all origins for development
app.use(cors({
  origin: true,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

// Handle preflight requests
app.options('*', cors());

// Body parser middleware
app.use(bodyParser.json({ limit: '10kb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10kb' }));

// MongoDB connection with properly encoded password
const password = encodeURIComponent('JFJmHvP4ktikRYDC');
const MONGODB_URI = process.env.MONGODB_URI || `mongodb+srv://elvismwangike:${password}@cluster0.vm6hrog.mongodb.net/citation_training?retryWrites=true&w=majority&appName=Cluster0`;

// Improved MongoDB connection with better error handling
const connectDB = async () => {
  try {
    await mongoose.connect(MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
    });
    console.log('Connected to MongoDB successfully');
  } catch (error) {
    console.error('MongoDB connection error:', error);
    // Don't exit process in production, let the server try to reconnect
    if (process.env.NODE_ENV === 'development') {
      process.exit(1);
    }
  }
};

connectDB();

const db = mongoose.connection;
db.on('error', (error) => {
  console.error('MongoDB connection error:', error);
});
db.on('disconnected', () => {
  console.log('MongoDB disconnected. Attempting to reconnect...');
  setTimeout(() => connectDB(), 5000);
});

// Enrollment Schema - simplified validation for payment details
const enrollmentSchema = new mongoose.Schema({
  personalInfo: {
    firstName: {
      type: String,
      required: [true, 'First name is required'],
      trim: true,
      maxlength: [50, 'First name cannot be more than 50 characters']
    },
    lastName: {
      type: String,
      required: [true, 'Last name is required'],
      trim: true,
      maxlength: [50, 'Last name cannot be more than 50 characters']
    },
    email: {
      type: String,
      required: [true, 'Email is required'],
      lowercase: true,
      validate: {
        validator: function(email) {
          return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
        },
        message: 'Please provide a valid email'
      }
    },
    phone: {
      type: String,
      required: [true, 'Phone number is required'],
      validate: {
        validator: function(phone) {
          return /^[+]?[1-9][\d]{0,15}$/.test(phone);
        },
        message: 'Please provide a valid phone number'
      }
    },
    address: {
      type: String,
      required: [true, 'Address is required'],
      trim: true,
      maxlength: [200, 'Address cannot be more than 200 characters']
    },
    city: {
      type: String,
      required: [true, 'City is required'],
      trim: true,
      maxlength: [50, 'City cannot be more than 50 characters']
    },
    state: {
      type: String,
      required: [true, 'State is required'],
      trim: true,
      maxlength: [50, 'State cannot be more than 50 characters']
    },
    postalCode: {
      type: String,
      required: [true, 'Postal code is required'],
      trim: true,
      maxlength: [20, 'Postal code cannot be more than 20 characters']
    },
    country: {
      type: String,
      required: [true, 'Country is required'],
      trim: true,
      maxlength: [50, 'Country cannot be more than 50 characters']
    },
    pilotLicense: {
      type: String,
      required: [true, 'Pilot license information is required'],
      enum: {
        values: ['private', 'commercial', 'atp', 'none'],
        message: 'Pilot license must be private, commercial, atp, or none'
      }
    },
    flightHours: {
      type: Number,
      required: [true, 'Flight hours are required'],
      min: [0, 'Flight hours cannot be negative'],
      max: [50000, 'Flight hours cannot exceed 50,000']
    }
  },
  paymentMethod: {
    type: String,
    required: [true, 'Payment method is required'],
    enum: {
      values: ['credit-card', 'bitcoin'],
      message: 'Payment method must be credit-card or bitcoin'
    }
  },
  paymentPlan: {
    type: String,
    required: [true, 'Payment plan is required'],
    enum: {
      values: ['full', 'installment'],
      message: 'Payment plan must be full or installment'
    }
  },
  paymentDetails: {
    type: Object,
    default: {}
  },
  amount: {
    type: Number,
    required: [true, 'Amount is required'],
    min: [0, 'Amount cannot be negative']
  },
  status: { 
    type: String, 
    enum: {
      values: ['pending', 'approved', 'rejected', 'completed'],
      message: 'Status must be pending, approved, rejected, or completed'
    },
    default: 'pending' 
  },
  timestamp: {
    type: Date,
    default: Date.now
  }
});

const Enrollment = mongoose.model('Enrollment', enrollmentSchema);

// Input validation middleware - simplified
const validateEnrollmentInput = (req, res, next) => {
  const { personalInfo, paymentMethod, paymentPlan, amount } = req.body;
  
  if (!personalInfo || !paymentMethod || !paymentPlan || amount === undefined) {
    return res.status(400).json({ 
      message: 'Missing required fields: personalInfo, paymentMethod, paymentPlan, or amount' 
    });
  }
  
  next();
};

// Routes
app.post('/api/enroll', validateEnrollmentInput, async (req, res) => {
  try {
    // Check MongoDB connection
    if (mongoose.connection.readyState !== 1) {
      return res.status(503).json({ 
        message: 'Database not available. Please try again later.' 
      });
    }
    
    const enrollmentData = req.body;
    
    // Create new enrollment
    const newEnrollment = new Enrollment({
      personalInfo: enrollmentData.personalInfo,
      paymentMethod: enrollmentData.paymentMethod,
      paymentPlan: enrollmentData.paymentPlan,
      paymentDetails: enrollmentData.paymentDetails || {},
      amount: enrollmentData.amount
    });
    
    // Save to database
    await newEnrollment.save();
    
    // Log the saved data for debugging
    console.log('Enrollment saved successfully:', {
      id: newEnrollment._id,
      personalInfo: newEnrollment.personalInfo,
      paymentMethod: newEnrollment.paymentMethod,
      paymentPlan: newEnrollment.paymentPlan,
      amount: newEnrollment.amount
    });
    
    res.status(201).json({
      message: 'Enrollment submitted successfully',
      enrollmentId: newEnrollment._id,
      status: newEnrollment.status
    });
  } catch (error) {
    console.error('Error saving enrollment:', error);
    
    if (error.name === 'ValidationError') {
      const errors = Object.values(error.errors).map(el => el.message);
      return res.status(400).json({ 
        message: 'Invalid input data', 
        errors 
      });
    }
    
    res.status(500).json({ 
      message: 'Error processing enrollment', 
      error: process.env.NODE_ENV === 'production' ? 'Internal server error' : error.message 
    });
  }
});

app.get('/api/enrollments', async (req, res) => {
  try {
    // Check MongoDB connection
    if (mongoose.connection.readyState !== 1) {
      return res.status(503).json({ 
        message: 'Database not available. Please try again later.' 
      });
    }
    
    const enrollments = await Enrollment.find().sort({ timestamp: -1 });
    res.json(enrollments);
  } catch (error) {
    console.error('Error fetching enrollments:', error);
    res.status(500).json({ 
      message: 'Error fetching enrollments', 
      error: process.env.NODE_ENV === 'production' ? 'Internal server error' : error.message 
    });
  }
});

app.get('/api/enrollment/:id', async (req, res) => {
  try {
    // Check MongoDB connection
    if (mongoose.connection.readyState !== 1) {
      return res.status(503).json({ 
        message: 'Database not available. Please try again later.' 
      });
    }
    
    const enrollment = await Enrollment.findById(req.params.id);
    if (!enrollment) {
      return res.status(404).json({ message: 'Enrollment not found' });
    }
    res.json(enrollment);
  } catch (error) {
    console.error('Error fetching enrollment:', error);
    res.status(500).json({ 
      message: 'Error fetching enrollment', 
      error: process.env.NODE_ENV === 'production' ? 'Internal server error' : error.message 
    });
  }
});

app.put('/api/enrollment/:id/status', async (req, res) => {
  try {
    // Check MongoDB connection
    if (mongoose.connection.readyState !== 1) {
      return res.status(503).json({ 
        message: 'Database not available. Please try again later.' 
      });
    }
    
    const { status } = req.body;
    
    if (!status || !['pending', 'approved', 'rejected', 'completed'].includes(status)) {
      return res.status(400).json({ 
        message: 'Valid status is required: pending, approved, rejected, or completed' 
      });
    }
    
    const enrollment = await Enrollment.findByIdAndUpdate(
      req.params.id,
      { status },
      { new: true }
    );
    
    if (!enrollment) {
      return res.status(404).json({ message: 'Enrollment not found' });
    }
    
    res.json({ 
      message: 'Status updated successfully', 
      enrollment 
    });
  } catch (error) {
    console.error('Error updating enrollment status:', error);
    res.status(500).json({ 
      message: 'Error updating enrollment status', 
      error: process.env.NODE_ENV === 'production' ? 'Internal server error' : error.message 
    });
  }
});

// Health check endpoint
app.get('/api/health', async (req, res) => {
  const healthCheck = {
    status: 'OK',
    timestamp: new Date().toISOString(),
    database: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected',
    uptime: process.uptime()
  };
  
  res.status(healthCheck.database === 'Connected' ? 200 : 503).json(healthCheck);
});

// Root endpoint
app.get('/', (req, res) => {
  res.json({ 
    message: 'Citation Training Academy Backend API',
    version: '1.0.0',
    status: 'OK',
    endpoints: {
      enroll: 'POST /api/enroll',
      enrollments: 'GET /api/enrollments',
      enrollment: 'GET /api/enrollment/:id',
      updateStatus: 'PUT /api/enrollment/:id/status',
      health: 'GET /api/health'
    }
  });
});

// 404 handler for API routes
app.use('/api/*', (req, res) => {
  res.status(404).json({ message: 'API endpoint not found' });
});

// Global error handling middleware
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({ 
    message: 'Internal server error', 
    error: process.env.NODE_ENV === 'production' ? 'Something went wrong' : error.message 
  });
});

// Start server
const server = app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (err) => {
  console.log('UNHANDLED REJECTION! 💥 Shutting down...');
  console.log(err.name, err.message);
  server.close(() => {
    process.exit(1);
  });
});

// Handle SIGTERM for graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received. Shutting down gracefully...');
  server.close(() => {
    console.log('Process terminated');
  });
});
