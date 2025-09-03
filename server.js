const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const { OAuth2Client } = require('google-auth-library');
const redis = require('redis');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || '17581758Na';

// Redis client setup
const redisClient = redis.createClient({
  host: process.env.REDIS_HOST || 'redis-14450.c276.us-east-1-2.ec2.redns.redis-cloud.com',
  port: process.env.REDIS_PORT || 14450,
  password: process.env.REDIS_PASSWORD || 'qjXgsg0YrsLaSumlEW9HkIZbvLjXEwXR'
});

redisClient.on('error', (err) => console.log('Redis Client Error', err));
redisClient.connect();

// MongoDB connection
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/algracia_pos';
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('MongoDB connected successfully'))
.catch(err => console.log('MongoDB connection error:', err));

// Middleware
app.use(helmet());
app.use(cors({
  origin: ['https://citation-training-academy.vercel.app', 'http://localhost:3000'],
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Models
const UserSchema = new mongoose.Schema({
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  company: { type: String, required: true },
  position: { type: String, required: true },
  password: { type: String, required: function() { return !this.googleId; } },
  googleId: { type: String, unique: true, sparse: true },
  role: { type: String, default: 'cashier', enum: ['cashier', 'manager', 'admin'] },
  isApproved: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const ProductSchema = new mongoose.Schema({
  name: { type: String, required: true },
  sku: { type: String, required: true, unique: true },
  price: { type: Number, required: true },
  stock: { type: Number, required: true, default: 0 },
  category: { type: String, default: 'cosmetics' },
  description: String,
  image: String,
  createdAt: { type: Date, default: Date.now }
});

const TransactionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  items: [{
    productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product' },
    name: String,
    price: Number,
    quantity: Number,
    total: Number
  }],
  subtotal: { type: Number, required: true },
  tax: { type: Number, default: 0 },
  total: { type: Number, required: true },
  paymentMethod: { 
    type: String, 
    required: true, 
    enum: ['cash', 'mpesa', 'card_visa', 'card_mastercard'] 
  },
  paymentDetails: {
    phoneNumber: String, // for M-Pesa
    cardLast4: String,   // for card payments
    cashReceived: Number, // for cash payments
    change: Number       // for cash payments
  },
  status: { type: String, default: 'completed', enum: ['completed', 'refunded', 'failed'] },
  timestamp: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Product = mongoose.model('Product', ProductSchema);
const Transaction = mongoose.model('Transaction', TransactionSchema);

// Authentication middleware
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ success: false, message: 'Access token required' });
  }

  try {
    // Check if token is blacklisted in Redis
    const isBlacklisted = await redisClient.get(`blacklist_${token}`);
    if (isBlacklisted) {
      return res.status(401).json({ success: false, message: 'Token has been invalidated' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId).select('-password');
    
    if (!user) {
      return res.status(401).json({ success: false, message: 'User not found' });
    }
    
    if (!user.isApproved) {
      return res.status(403).json({ 
        success: false, 
        message: 'Account pending approval. Please contact administrator.' 
      });
    }
    
    req.user = user;
    next();
  } catch (error) {
    return res.status(403).json({ success: false, message: 'Invalid or expired token' });
  }
};

// Google OAuth client
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID || '634814462335-9o4t8q95c4orcsd9sijjl52374g6vm85.apps.googleusercontent.com');

// Routes

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    success: true, 
    message: 'Algracia POS API is running', 
    timestamp: new Date().toISOString() 
  });
});

// User registration
app.post('/api/auth/signup', [
  body('firstName').notEmpty().withMessage('First name is required'),
  body('lastName').notEmpty().withMessage('Last name is required'),
  body('email').isEmail().withMessage('Valid email is required'),
  body('company').notEmpty().withMessage('Company name is required'),
  body('position').notEmpty().withMessage('Position is required'),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        success: false, 
        message: 'Validation failed', 
        errors: errors.array() 
      });
    }

    const { firstName, lastName, email, company, position, password } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ 
        success: false, 
        message: 'User with this email already exists' 
      });
    }

    // Hash password
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create new user (requires approval)
    const newUser = new User({
      firstName,
      lastName,
      email,
      company,
      position,
      password: hashedPassword,
      isApproved: false // Requires admin approval
    });

    await newUser.save();

    res.status(201).json({
      success: true,
      message: 'Account request submitted successfully. Please wait for administrator approval.',
      requiresApproval: true
    });

  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Internal server error during registration' 
    });
  }
});

// User login
app.post('/api/auth/login', [
  body('email').isEmail().withMessage('Valid email is required'),
  body('password').notEmpty().withMessage('Password is required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        success: false, 
        message: 'Validation failed', 
        errors: errors.array() 
      });
    }

    const { email, password } = req.body;

    // Find user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ 
        success: false, 
        message: 'Invalid email or password' 
      });
    }

    // Check if account is approved
    if (!user.isApproved) {
      return res.status(403).json({ 
        success: false, 
        message: 'Account pending approval. Please contact administrator.' 
      });
    }

    // Check password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ 
        success: false, 
        message: 'Invalid email or password' 
      });
    }

    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id, email: user.email }, 
      JWT_SECRET, 
      { expiresIn: '24h' }
    );

    // Return user data (excluding password)
    const userData = {
      _id: user._id,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      company: user.company,
      position: user.position,
      role: user.role,
      initials: user.firstName[0] + user.lastName[0]
    };

    res.json({
      success: true,
      message: 'Login successful',
      token,
      user: userData
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Internal server error during login' 
    });
  }
});

// Google OAuth signup/login
app.post('/api/auth/google-signup', async (req, res) => {
  try {
    const { credential } = req.body;
    
    if (!credential) {
      return res.status(400).json({ 
        success: false, 
        message: 'Google credential is required' 
      });
    }

    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID
    });

    const payload = ticket.getPayload();
    const { given_name, family_name, email, sub: googleId } = payload;

    // Check if user already exists with this email
    let user = await User.findOne({ email });

    if (user) {
      // User exists but might not have googleId
      if (!user.googleId) {
        user.googleId = googleId;
        await user.save();
      }
      
      // Check if account is approved
      if (!user.isApproved) {
        return res.json({
          success: true,
          requiresApproval: true,
          message: 'Account request submitted. Please wait for administrator approval.'
        });
      }
    } else {
      // Create new user with Google auth (requires approval)
      user = new User({
        firstName: given_name,
        lastName: family_name,
        email,
        googleId,
        company: 'To be updated', // Request additional info
        position: 'To be updated',
        isApproved: false
      });

      await user.save();
      
      return res.json({
        success: true,
        requiresApproval: true,
        message: 'Account request submitted. Please wait for administrator approval.'
      });
    }

    // Generate JWT token for existing approved user
    const token = jwt.sign(
      { userId: user._id, email: user.email }, 
      JWT_SECRET, 
      { expiresIn: '24h' }
    );

    // Return user data
    const userData = {
      _id: user._id,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      company: user.company,
      position: user.position,
      role: user.role,
      initials: user.firstName[0] + user.lastName[0]
    };

    res.json({
      success: true,
      message: 'Google authentication successful',
      token,
      user: userData,
      requiresApproval: false
    });

  } catch (error) {
    console.error('Google auth error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Google authentication failed' 
    });
  }
});

// Token verification endpoint
app.get('/api/auth/verify', authenticateToken, (req, res) => {
  res.json({
    success: true,
    user: req.user
  });
});

// Get all products
app.get('/api/products', authenticateToken, async (req, res) => {
  try {
    // Try to get from Redis cache first
    const cachedProducts = await redisClient.get('products');
    if (cachedProducts) {
      return res.json({
        success: true,
        products: JSON.parse(cachedProducts)
      });
    }

    // If not in cache, get from database
    const products = await Product.find({}).sort({ name: 1 });
    
    // Cache products for 5 minutes
    await redisClient.setEx('products', 300, JSON.stringify(products));
    
    res.json({
      success: true,
      products
    });
  } catch (error) {
    console.error('Get products error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch products' 
    });
  }
});

// Get inventory
app.get('/api/inventory', authenticateToken, async (req, res) => {
  try {
    const inventory = await Product.find({})
      .select('name sku price stock category')
      .sort({ name: 1 });
    
    res.json({
      success: true,
      inventory
    });
  } catch (error) {
    console.error('Get inventory error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch inventory' 
    });
  }
});

// Add new product
app.post('/api/products', authenticateToken, [
  body('name').notEmpty().withMessage('Product name is required'),
  body('sku').notEmpty().withMessage('SKU is required'),
  body('price').isNumeric().withMessage('Valid price is required'),
  body('stock').isInt({ min: 0 }).withMessage('Valid stock quantity is required')
], async (req, res) => {
  try {
    // Check if user has permission (admin or manager)
    if (!['admin', 'manager'].includes(req.user.role)) {
      return res.status(403).json({ 
        success: false, 
        message: 'Insufficient permissions to add products' 
      });
    }

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        success: false, 
        message: 'Validation failed', 
        errors: errors.array() 
      });
    }

    const { name, sku, price, stock, category, description } = req.body;

    // Check if product with SKU already exists
    const existingProduct = await Product.findOne({ sku });
    if (existingProduct) {
      return res.status(409).json({ 
        success: false, 
        message: 'Product with this SKU already exists' 
      });
    }

    const newProduct = new Product({
      name,
      sku,
      price,
      stock,
      category: category || 'cosmetics',
      description
    });

    await newProduct.save();
    
    // Invalidate products cache
    await redisClient.del('products');
    
    res.status(201).json({
      success: true,
      message: 'Product added successfully',
      product: newProduct
    });

  } catch (error) {
    console.error('Add product error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to add product' 
    });
  }
});

// Process payment and create transaction
app.post('/api/transactions', authenticateToken, async (req, res) => {
  try {
    const { paymentMethod, amount, cashReceived, change, cart } = req.body;

    if (!paymentMethod || !amount || !cart || !cart.length) {
      return res.status(400).json({ 
        success: false, 
        message: 'Missing required transaction data' 
      });
    }

    // Calculate totals
    const subtotal = cart.reduce((sum, item) => sum + (item.price * item.quantity), 0);
    const tax = subtotal * 0.16; // 16% VAT (Kenya)
    const total = subtotal + tax;

    // Prepare transaction items
    const transactionItems = cart.map(item => ({
      productId: item.productId,
      name: item.name,
      price: item.price,
      quantity: item.quantity,
      total: item.price * item.quantity
    }));

    // Create transaction record
    const transaction = new Transaction({
      userId: req.user._id,
      items: transactionItems,
      subtotal,
      tax,
      total,
      paymentMethod,
      paymentDetails: {
        cashReceived,
        change
      }
    });

    await transaction.save();
    
    // Update product stock levels
    for (const item of cart) {
      await Product.findByIdAndUpdate(
        item.productId, 
        { $inc: { stock: -item.quantity } }
      );
    }
    
    // Invalidate dashboard cache
    await redisClient.del(`dashboard_${req.user._id}`);

    res.status(201).json({
      success: true,
      message: 'Transaction completed successfully',
      transactionId: transaction._id
    });

  } catch (error) {
    console.error('Transaction error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to process transaction' 
    });
  }
});

// M-Pesa payment processing
app.post('/api/mpesa/payment', authenticateToken, async (req, res) => {
  try {
    const { phoneNumber, amount, cart } = req.body;

    if (!phoneNumber || !amount) {
      return res.status(400).json({ 
        success: false, 
        message: 'Phone number and amount are required' 
      });
    }

    // In a real implementation, this would integrate with Safaricom M-Pesa API
    // For demonstration, we'll simulate a successful payment

    // Calculate totals
    const subtotal = cart.reduce((sum, item) => sum + (item.price * item.quantity), 0);
    const tax = subtotal * 0.16;
    const total = subtotal + tax;

    // Prepare transaction items
    const transactionItems = cart.map(item => ({
      productId: item.productId,
      name: item.name,
      price: item.price,
      quantity: item.quantity,
      total: item.price * item.quantity
    }));

    // Create transaction record
    const transaction = new Transaction({
      userId: req.user._id,
      items: transactionItems,
      subtotal,
      tax,
      total,
      paymentMethod: 'mpesa',
      paymentDetails: {
        phoneNumber
      }
    });

    await transaction.save();
    
    // Update product stock levels
    for (const item of cart) {
      await Product.findByIdAndUpdate(
        item.productId, 
        { $inc: { stock: -item.quantity } }
      );
    }
    
    // Invalidate dashboard cache
    await redisClient.del(`dashboard_${req.user._id}`);

    res.json({
      success: true,
      message: 'M-Pesa payment processed successfully',
      transactionId: transaction._id
    });

  } catch (error) {
    console.error('M-Pesa payment error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to process M-Pesa payment' 
    });
  }
});

// Card payment processing
app.post('/api/card/payment', authenticateToken, async (req, res) => {
  try {
    const { cardNumber, expiryDate, cvv, amount, cart, cardType } = req.body;

    if (!cardNumber || !expiryDate || !cvv) {
      return res.status(400).json({ 
        success: false, 
        message: 'Card details are required' 
      });
    }

    // In a real implementation, this would integrate with a payment gateway like Stripe
    // For demonstration, we'll simulate a successful payment

    // Calculate totals
    const subtotal = cart.reduce((sum, item) => sum + (item.price * item.quantity), 0);
    const tax = subtotal * 0.16;
    const total = subtotal + tax;

    // Prepare transaction items
    const transactionItems = cart.map(item => ({
      productId: item.productId,
      name: item.name,
      price: item.price,
      quantity: item.quantity,
      total: item.price * item.quantity
    }));

    // Create transaction record
    const transaction = new Transaction({
      userId: req.user._id,
      items: transactionItems,
      subtotal,
      tax,
      total,
      paymentMethod: cardType === 'visa' ? 'card_visa' : 'card_mastercard',
      paymentDetails: {
        cardLast4: cardNumber.slice(-4)
      }
    });

    await transaction.save();
    
    // Update product stock levels
    for (const item of cart) {
      await Product.findByIdAndUpdate(
        item.productId, 
        { $inc: { stock: -item.quantity } }
      );
    }
    
    // Invalidate dashboard cache
    await redisClient.del(`dashboard_${req.user._id}`);

    res.json({
      success: true,
      message: 'Card payment processed successfully',
      transactionId: transaction._id
    });

  } catch (error) {
    console.error('Card payment error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to process card payment' 
    });
  }
});

// Get dashboard data
app.get('/api/dashboard', authenticateToken, async (req, res) => {
  try {
    // Try to get from Redis cache first
    const cachedDashboard = await redisClient.get(`dashboard_${req.user._id}`);
    if (cachedDashboard) {
      return res.json(JSON.parse(cachedDashboard));
    }

    // Get today's date range
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const tomorrow = new Date(today);
    tomorrow.setDate(tomorrow.getDate() + 1);

    // Get today's transactions
    const todayTransactions = await Transaction.find({
      userId: req.user._id,
      timestamp: { $gte: today, $lt: tomorrow }
    });

    // Calculate today's sales
    const todaySales = todayTransactions.reduce((sum, transaction) => sum + transaction.total, 0);

    // Get inventory stats
    const totalProducts = await Product.countDocuments();
    const lowStockProducts = await Product.countDocuments({ stock: { $lt: 10 } });

    // Get recent transactions (last 10)
    const recentTransactions = await Transaction.find({ userId: req.user._id })
      .sort({ timestamp: -1 })
      .limit(10)
      .select('_id timestamp total paymentMethod');

    const dashboardData = {
      success: true,
      todaySales,
      todayTransactions: todayTransactions.length,
      totalProducts,
      lowStockItems: lowStockProducts,
      recentTransactions
    };

    // Cache dashboard data for 5 minutes
    await redisClient.setEx(
      `dashboard_${req.user._id}`, 
      300, 
      JSON.stringify(dashboardData)
    );

    res.json(dashboardData);

  } catch (error) {
    console.error('Dashboard error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to load dashboard data' 
    });
  }
});

// Logout endpoint (blacklist token)
app.post('/api/auth/logout', authenticateToken, async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    // Add token to blacklist with expiration time (24 hours)
    const decoded = jwt.decode(token);
    const expiresIn = decoded.exp - Math.floor(Date.now() / 1000);
    
    if (expiresIn > 0) {
      await redisClient.setEx(`blacklist_${token}`, expiresIn, 'true');
    }
    
    res.json({ 
      success: true, 
      message: 'Logged out successfully' 
    });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to logout' 
    });
  }
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({ 
    success: false, 
    message: 'Internal server error' 
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ 
    success: false, 
    message: 'API endpoint not found' 
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`Algracia POS backend server running on port ${PORT}`);
});

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('Shutting down gracefully...');
  await redisClient.quit();
  await mongoose.connection.close();
  process.exit(0);
});
