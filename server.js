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
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/', limiter);

// Compression middleware
app.use(compression());

// CORS configuration
app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? ['https://your-frontend-domain.com'] 
    : ['http://localhost:3000', 'http://127.0.0.1:3000'],
  credentials: true
}));

// Body parser middleware
app.use(bodyParser.json({ limit: '10kb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10kb' }));

// MongoDB connection with improved options
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://elvismwangike:JFJmHvP4ktikRYDC@cluster0.vm6hrog.mongodb.net/citation_training?retryWrites=true&w=majority&appName=Cluster0';

mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverSelectionTimeoutMS: 5000,
  socketTimeoutMS: 45000,
  bufferMaxEntries: 0,
  bufferCommands: false,
});

const db = mongoose.connection;
db.on('error', (error) => {
  console.error('MongoDB connection error:', error);
  if (error.name === 'MongoNetworkError') {
    console.error('Network error connecting to MongoDB. Please check your connection.');
  }
});
db.once('open', () => {
  console.log('Connected to MongoDB successfully');
});

// Enhanced Enrollment Schema with validation
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
  paymentDetails: {
    cardNumber: {
      type: String,
      validate: {
        validator: function(cardNumber) {
          if (this.paymentMethod !== 'credit-card') return true;
          return /^\d{16}$/.test(cardNumber.replace(/\s/g, ''));
        },
        message: 'Please provide a valid card number'
      }
    },
    cardHolder: {
      type: String,
      validate: {
        validator: function(cardHolder) {
          if (this.paymentMethod !== 'credit-card') return true;
          return cardHolder && cardHolder.length >= 3;
        },
        message: 'Please provide a valid card holder name'
      }
    },
    cardExpiry: {
      type: String,
      validate: {
        validator: function(cardExpiry) {
          if (this.paymentMethod !== 'credit-card') return true;
          return /^(0[1-9]|1[0-2])\/([0-9]{2})$/.test(cardExpiry);
        },
        message: 'Please provide a valid expiry date (MM/YY)'
      }
    },
    cardCvv: {
      type: String,
      validate: {
        validator: function(cardCvv) {
          if (this.paymentMethod !== 'credit-card') return true;
          return /^\d{3,4}$/.test(cardCvv);
        },
        message: 'Please provide a valid CVV'
      }
    },
    billingAddress: {
      type: String,
      validate: {
        validator: function(billingAddress) {
          if (this.paymentMethod !== 'credit-card') return true;
          return billingAddress && billingAddress.length >= 5;
        },
        message: 'Please provide a valid billing address'
      }
    },
    billingCity: {
      type: String,
      validate: {
        validator: function(billingCity) {
          if (this.paymentMethod !== 'credit-card') return true;
          return billingCity && billingCity.length >= 2;
        },
        message: 'Please provide a valid billing city'
      }
    },
    billingPostalCode: {
      type: String,
      validate: {
        validator: function(billingPostalCode) {
          if (this.paymentMethod !== 'credit-card') return true;
          return billingPostalCode && billingPostalCode.length >= 3;
        },
        message: 'Please provide a valid billing postal code'
      }
    }
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
}, {
  timestamps: true
});

// Index for better query performance
enrollmentSchema.index({ email: 1 });
enrollmentSchema.index({ status: 1 });
enrollmentSchema.index({ timestamp: -1 });

const Enrollment = mongoose.model('Enrollment', enrollmentSchema);

// Input validation middleware
const validateEnrollmentInput = (req, res, next) => {
  const { personalInfo, paymentMethod, amount } = req.body;
  
  if (!personalInfo || !paymentMethod || amount === undefined) {
    return res.status(400).json({ 
      message: 'Missing required fields: personalInfo, paymentMethod, or amount' 
    });
  }
  
  if (paymentMethod === 'credit-card' && !req.body.paymentDetails) {
    return res.status(400).json({ 
      message: 'Payment details are required for credit card payments' 
    });
  }
  
  next();
};

// Routes with improved error handling
app.post('/api/enroll', validateEnrollmentInput, async (req, res) => {
  try {
    const enrollmentData = req.body;
    
    // Create new enrollment
    const newEnrollment = new Enrollment({
      personalInfo: enrollmentData.personalInfo,
      paymentMethod: enrollmentData.paymentMethod,
      paymentDetails: enrollmentData.paymentDetails || {},
      amount: enrollmentData.amount
    });
    
    // Save to database
    await newEnrollment.save();
    
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
    
    if (error.code === 11000) {
      return res.status(400).json({ 
        message: 'Duplicate enrollment detected' 
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
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
    
    const enrollments = await Enrollment.find()
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);
    
    const total = await Enrollment.countDocuments();
    
    res.json({
      enrollments,
      currentPage: page,
      totalPages: Math.ceil(total / limit),
      totalEnrollments: total
    });
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
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ message: 'Invalid enrollment ID' });
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
    const { status } = req.body;
    
    if (!status || !['pending', 'approved', 'rejected', 'completed'].includes(status)) {
      return res.status(400).json({ 
        message: 'Valid status is required: pending, approved, rejected, or completed' 
      });
    }
    
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ message: 'Invalid enrollment ID' });
    }
    
    const enrollment = await Enrollment.findByIdAndUpdate(
      req.params.id,
      { status },
      { new: true, runValidators: true }
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
    
    if (error.name === 'ValidationError') {
      const errors = Object.values(error.errors).map(el => el.message);
      return res.status(400).json({ 
        message: 'Invalid status value', 
        errors 
      });
    }
    
    res.status(500).json({ 
      message: 'Error updating enrollment status', 
      error: process.env.NODE_ENV === 'production' ? 'Internal server error' : error.message 
    });
  }
});

// Health check endpoint with DB status
app.get('/api/health', async (req, res) => {
  const healthCheck = {
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    database: 'Disconnected'
  };
  
  try {
    // Check database connection
    if (mongoose.connection.readyState === 1) {
      healthCheck.database = 'Connected';
      
      // Test a simple query
      await Enrollment.findOne().limit(1);
      healthCheck.database = 'Healthy';
    }
    
    res.json(healthCheck);
  } catch (error) {
    healthCheck.status = 'Unhealthy';
    healthCheck.database = 'Error';
    healthCheck.error = error.message;
    
    res.status(503).json(healthCheck);
  }
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

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('SIGINT received. Shutting down gracefully...');
  try {
    await mongoose.connection.close();
    console.log('MongoDB connection closed.');
    process.exit(0);
  } catch (error) {
    console.error('Error during shutdown:', error);
    process.exit(1);
  }
});

process.on('SIGTERM', async () => {
  console.log('SIGTERM received. Shutting down gracefully...');
  try {
    await mongoose.connection.close();
    console.log('MongoDB connection closed.');
    process.exit(0);
  } catch (error) {
    console.error('Error during shutdown:', error);
    process.exit(1);
  }
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
