const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const redis = require('redis');
const { body, validationResult } = require('express-validator');
const moment = require('moment');
const axios = require('axios');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || '17581758Na';

// Redis Configuration
const redisClient = redis.createClient({
  host: process.env.REDIS_HOST || 'redis-14450.c276.us-east-1-2.ec2.redns.redis-cloud.com',
  port: process.env.REDIS_PORT || 14450,
  password: process.env.REDIS_PASSWORD || 'qjXgsg0YrsLaSumlEW9HkIZbvLjXEwXR'
});

redisClient.on('error', (err) => {
  console.log('Redis Client Error', err);
});

redisClient.connect().then(() => {
  console.log('Connected to Redis');
});

// MongoDB Connection
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://your-mongodb-uri';
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// MongoDB Models
const UserSchema = new mongoose.Schema({
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  company: { type: String, required: true },
  position: { type: String, required: true },
  role: { type: String, enum: ['admin', 'manager', 'cashier'], default: 'cashier' },
  status: { type: String, enum: ['pending', 'active', 'inactive'], default: 'pending' },
  createdAt: { type: Date, default: Date.now },
  lastLogin: { type: Date },
  permissions: [{ type: String }]
});

const ProductSchema = new mongoose.Schema({
  name: { type: String, required: true },
  sku: { type: String, required: true, unique: true },
  price: { type: Number, required: true },
  cost: { type: Number },
  stock: { type: Number, required: true },
  category: { type: String },
  description: { type: String },
  image: { type: String },
  lowStockThreshold: { type: Number, default: 10 },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const TransactionSchema = new mongoose.Schema({
  transactionId: { type: String, required: true, unique: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  items: [{
    productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
    name: { type: String, required: true },
    price: { type: Number, required: true },
    quantity: { type: Number, required: true },
    total: { type: Number, required: true }
  }],
  subtotal: { type: Number, required: true },
  tax: { type: Number, default: 0 },
  discount: { type: Number, default: 0 },
  total: { type: Number, required: true },
  paymentMethod: { type: String, enum: ['cash', 'mpesa', 'card', 'bank_transfer'], required: true },
  paymentDetails: { type: Object },
  status: { type: String, enum: ['pending', 'completed', 'refunded', 'failed'], default: 'completed' },
  timestamp: { type: Date, default: Date.now },
  customer: {
    name: { type: String },
    email: { type: String },
    phone: { type: String }
  }
});

const ActivitySchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  action: { type: String, required: true },
  details: { type: String },
  ipAddress: { type: String },
  userAgent: { type: String },
  timestamp: { type: Date, default: Date.now }
});

const SettingsSchema = new mongoose.Schema({
  companyName: { type: String, default: 'Algracia Cosmetics' },
  currency: { type: String, default: 'KES' },
  taxRate: { type: Number, default: 16 },
  receiptFooter: { type: String, default: 'Thank you for shopping with us!' },
  lowStockAlert: { type: Boolean, default: true },
  updatedAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Product = mongoose.model('Product', ProductSchema);
const Transaction = mongoose.model('Transaction', TransactionSchema);
const Activity = mongoose.model('Activity', ActivitySchema);
const Settings = mongoose.model('Settings', SettingsSchema);

// Middleware
app.use(helmet());
app.use(cors({
  origin: ['https://citation-training-academy.vercel.app', 'http://localhost:3000'],
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Authentication middleware
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ success: false, message: 'Access token required' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Check if user exists and is active
    const user = await User.findById(decoded.userId);
    if (!user || user.status !== 'active') {
      return res.status(403).json({ success: false, message: 'Invalid or inactive account' });
    }

    req.user = user;
    next();
  } catch (error) {
    return res.status(403).json({ success: false, message: 'Invalid token' });
  }
};

// Admin authorization middleware
const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ success: false, message: 'Admin access required' });
  }
  next();
};

// Log activity middleware
const logActivity = async (req, action, details = '') => {
  try {
    const activity = new Activity({
      userId: req.user?._id,
      action,
      details,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    });
    await activity.save();
  } catch (error) {
    console.error('Error logging activity:', error);
  }
};

// Generate unique transaction ID
const generateTransactionId = () => {
  return 'TXN' + Date.now() + Math.random().toString(36).substr(2, 9).toUpperCase();
};

// Routes

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ success: true, message: 'Server is running', timestamp: new Date() });
});

// Authentication routes
app.post('/api/auth/signup', [
  body('firstName').notEmpty().withMessage('First name is required'),
  body('lastName').notEmpty().withMessage('Last name is required'),
  body('email').isEmail().withMessage('Valid email is required'),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters'),
  body('company').notEmpty().withMessage('Company name is required'),
  body('position').notEmpty().withMessage('Position is required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, message: errors.array()[0].msg });
    }

    const { firstName, lastName, email, password, company, position } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ success: false, message: 'User already exists' });
    }

    // Hash password
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create new user (pending approval)
    const newUser = new User({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      company,
      position,
      status: 'pending'
    });

    await newUser.save();

    // Log activity
    await logActivity({}, 'USER_SIGNUP', `New user registration: ${email}`);

    res.status(201).json({
      success: true,
      message: 'Account request submitted. Please wait for administrator approval.',
      requiresApproval: true
    });

  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ success: false, message: 'Server error during registration' });
  }
});

app.post('/api/auth/login', [
  body('email').isEmail().withMessage('Valid email is required'),
  body('password').notEmpty().withMessage('Password is required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, message: errors.array()[0].msg });
    }

    const { email, password } = req.body;

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    // Check if account is approved
    if (user.status !== 'active') {
      return res.status(401).json({ success: false, message: 'Account pending approval' });
    }

    // Check password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    // Cache user data in Redis
    const userData = {
      id: user._id,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      role: user.role,
      company: user.company,
      position: user.position,
      initials: user.firstName[0] + user.lastName[0]
    };

    await redisClient.setEx(`user:${user._id}`, 86400, JSON.stringify(userData));

    // Log activity
    await logActivity({ user }, 'USER_LOGIN', `User logged in: ${email}`);

    res.json({
      success: true,
      message: 'Login successful',
      token,
      user: userData
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ success: false, message: 'Server error during login' });
  }
});

app.post('/api/auth/verify', authenticateToken, (req, res) => {
  res.json({
    success: true,
    user: {
      id: req.user._id,
      firstName: req.user.firstName,
      lastName: req.user.lastName,
      email: req.user.email,
      role: req.user.role,
      company: req.user.company,
      position: req.user.position,
      initials: req.user.firstName[0] + req.user.lastName[0]
    }
  });
});

// Admin routes
app.get('/api/admin/dashboard', authenticateToken, requireAdmin, async (req, res) => {
  try {
    // Get dashboard stats
    const todayStart = new Date();
    todayStart.setHours(0, 0, 0, 0);
    
    const todayEnd = new Date();
    todayEnd.setHours(23, 59, 59, 999);

    const [
      pendingApprovals,
      totalUsers,
      todaySales,
      lowStockItems
    ] = await Promise.all([
      User.countDocuments({ status: 'pending' }),
      User.countDocuments({ status: 'active' }),
      Transaction.aggregate([
        {
          $match: {
            timestamp: { $gte: todayStart, $lte: todayEnd },
            status: 'completed'
          }
        },
        {
          $group: {
            _id: null,
            total: { $sum: '$total' }
          }
        }
      ]),
      Product.countDocuments({ stock: { $lte: 10 } })
    ]);

    const salesTotal = todaySales.length > 0 ? todaySales[0].total : 0;

    res.json({
      success: true,
      pendingApprovals,
      totalUsers,
      todaySales: salesTotal,
      lowStockItems
    });

  } catch (error) {
    console.error('Dashboard error:', error);
    res.status(500).json({ success: false, message: 'Error loading dashboard data' });
  }
});

app.get('/api/admin/pending-approvals', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const pendingUsers = await User.find({ status: 'pending' })
      .select('-password')
      .sort({ createdAt: -1 });

    res.json(pendingUsers);
  } catch (error) {
    console.error('Pending approvals error:', error);
    res.status(500).json({ success: false, message: 'Error loading pending approvals' });
  }
});

app.post('/api/admin/approve-user/:userId', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { userId } = req.params;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    user.status = 'active';
    await user.save();

    // Log activity
    await logActivity(req, 'USER_APPROVAL', `Approved user: ${user.email}`);

    res.json({ success: true, message: 'User approved successfully' });
  } catch (error) {
    console.error('Approve user error:', error);
    res.status(500).json({ success: false, message: 'Error approving user' });
  }
});

app.post('/api/admin/reject-user/:userId', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { userId } = req.params;

    const user = await User.findByIdAndDelete(userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Log activity
    await logActivity(req, 'USER_REJECTION', `Rejected user: ${user.email}`);

    res.json({ success: true, message: 'User rejected successfully' });
  } catch (error) {
    console.error('Reject user error:', error);
    res.status(500).json({ success: false, message: 'Error rejecting user' });
  }
});

app.get('/api/admin/users/active', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const activeUsers = await User.find({ status: 'active' })
      .select('-password')
      .sort({ createdAt: -1 });

    res.json(activeUsers);
  } catch (error) {
    console.error('Active users error:', error);
    res.status(500).json({ success: false, message: 'Error loading active users' });
  }
});

app.get('/api/admin/users/inactive', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const inactiveUsers = await User.find({ status: 'inactive' })
      .select('-password')
      .sort({ createdAt: -1 });

    res.json(inactiveUsers);
  } catch (error) {
    console.error('Inactive users error:', error);
    res.status(500).json({ success: false, message: 'Error loading inactive users' });
  }
});

// Product routes
app.get('/api/products', authenticateToken, async (req, res) => {
  try {
    const products = await Product.find().sort({ name: 1 });
    res.json(products);
  } catch (error) {
    console.error('Products error:', error);
    res.status(500).json({ success: false, message: 'Error loading products' });
  }
});

app.get('/api/inventory', authenticateToken, async (req, res) => {
  try {
    const inventory = await Product.find().sort({ stock: 1 });
    res.json(inventory);
  } catch (error) {
    console.error('Inventory error:', error);
    res.status(500).json({ success: false, message: 'Error loading inventory' });
  }
});

app.post('/api/products', authenticateToken, [
  body('name').notEmpty().withMessage('Product name is required'),
  body('sku').notEmpty().withMessage('SKU is required'),
  body('price').isNumeric().withMessage('Valid price is required'),
  body('stock').isInt({ min: 0 }).withMessage('Valid stock quantity is required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, message: errors.array()[0].msg });
    }

    const { name, sku, price, stock, category, description } = req.body;

    // Check if product already exists
    const existingProduct = await Product.findOne({ sku });
    if (existingProduct) {
      return res.status(400).json({ success: false, message: 'Product with this SKU already exists' });
    }

    const product = new Product({
      name,
      sku,
      price,
      stock,
      category,
      description
    });

    await product.save();

    // Log activity
    await logActivity(req, 'PRODUCT_ADDED', `Added product: ${name}`);

    res.status(201).json({ success: true, message: 'Product added successfully', product });
  } catch (error) {
    console.error('Add product error:', error);
    res.status(500).json({ success: false, message: 'Error adding product' });
  }
});

// Transaction routes
app.get('/api/transactions', authenticateToken, async (req, res) => {
  try {
    const { date } = req.query;
    let filter = {};

    if (date) {
      const startDate = new Date(date);
      const endDate = new Date(date);
      endDate.setHours(23, 59, 59, 999);
      
      filter.timestamp = { $gte: startDate, $lte: endDate };
    }

    const transactions = await Transaction.find(filter)
      .populate('userId', 'firstName lastName email')
      .sort({ timestamp: -1 })
      .limit(50);

    res.json(transactions);
  } catch (error) {
    console.error('Transactions error:', error);
    res.status(500).json({ success: false, message: 'Error loading transactions' });
  }
});

app.post('/api/transactions', authenticateToken, async (req, res) => {
  try {
    const { items, paymentMethod, paymentDetails, customer } = req.body;
    
    // Calculate totals
    let subtotal = 0;
    const transactionItems = items.map(item => {
      const itemTotal = item.price * item.quantity;
      subtotal += itemTotal;
      
      return {
        productId: item.productId,
        name: item.name,
        price: item.price,
        quantity: item.quantity,
        total: itemTotal
      };
    });

    const tax = subtotal * 0.16; // 16% tax
    const total = subtotal + tax;

    // Create transaction
    const transaction = new Transaction({
      transactionId: generateTransactionId(),
      userId: req.user._id,
      items: transactionItems,
      subtotal,
      tax,
      total,
      paymentMethod,
      paymentDetails,
      customer,
      status: 'completed'
    });

    await transaction.save();

    // Update product stock levels
    for (const item of items) {
      await Product.findByIdAndUpdate(
        item.productId,
        { $inc: { stock: -item.quantity } }
      );
    }

    // Log activity
    await logActivity(req, 'TRANSACTION_COMPLETED', `Transaction: ${transaction.transactionId}, Amount: ${total}`);

    res.status(201).json({
      success: true,
      message: 'Transaction completed successfully',
      transactionId: transaction.transactionId,
      transaction
    });

  } catch (error) {
    console.error('Transaction error:', error);
    res.status(500).json({ success: false, message: 'Error processing transaction' });
  }
});

// Reports routes
app.get('/api/admin/reports', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { type } = req.query;
    let startDate, endDate;

    switch (type) {
      case 'daily':
        startDate = new Date();
        startDate.setHours(0, 0, 0, 0);
        endDate = new Date();
        endDate.setHours(23, 59, 59, 999);
        break;
      case 'weekly':
        startDate = new Date();
        startDate.setDate(startDate.getDate() - 7);
        endDate = new Date();
        break;
      case 'monthly':
        startDate = new Date();
        startDate.setMonth(startDate.getMonth() - 1);
        endDate = new Date();
        break;
      case 'custom':
        // Custom date range would be passed as parameters
        startDate = new Date(req.query.start);
        endDate = new Date(req.query.end);
        break;
      default:
        startDate = new Date();
        startDate.setHours(0, 0, 0, 0);
        endDate = new Date();
        endDate.setHours(23, 59, 59, 999);
    }

    const salesData = await Transaction.aggregate([
      {
        $match: {
          timestamp: { $gte: startDate, $lte: endDate },
          status: 'completed'
        }
      },
      {
        $group: {
          _id: {
            $dateToString: { format: "%Y-%m-%d", date: "$timestamp" }
          },
          totalSales: { $sum: "$total" },
          transactionCount: { $sum: 1 }
        }
      },
      { $sort: { _id: 1 } }
    ]);

    // Format data for chart
    const labels = salesData.map(item => item._id);
    const data = salesData.map(item => item.totalSales);

    res.json({
      success: true,
      reportType: type,
      period: { startDate, endDate },
      labels,
      data,
      summary: {
        totalSales: data.reduce((sum, val) => sum + val, 0),
        totalTransactions: salesData.reduce((sum, item) => sum + item.transactionCount, 0)
      }
    });

  } catch (error) {
    console.error('Reports error:', error);
    res.status(500).json({ success: false, message: 'Error generating report' });
  }
});

// Activity logs
app.get('/api/admin/activities', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const activities = await Activity.find()
      .populate('userId', 'firstName lastName email')
      .sort({ timestamp: -1 })
      .limit(50);

    res.json(activities);
  } catch (error) {
    console.error('Activities error:', error);
    res.status(500).json({ success: false, message: 'Error loading activities' });
  }
});

// Settings routes
app.get('/api/admin/settings', authenticateToken, requireAdmin, async (req, res) => {
  try {
    let settings = await Settings.findOne();
    if (!settings) {
      settings = new Settings();
      await settings.save();
    }
    res.json(settings);
  } catch (error) {
    console.error('Settings error:', error);
    res.status(500).json({ success: false, message: 'Error loading settings' });
  }
});

app.post('/api/admin/settings', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { companyName, currency, taxRate, receiptFooter, lowStockAlert } = req.body;

    let settings = await Settings.findOne();
    if (!settings) {
      settings = new Settings();
    }

    settings.companyName = companyName || settings.companyName;
    settings.currency = currency || settings.currency;
    settings.taxRate = taxRate || settings.taxRate;
    settings.receiptFooter = receiptFooter || settings.receiptFooter;
    settings.lowStockAlert = lowStockAlert !== undefined ? lowStockAlert : settings.lowStockAlert;
    settings.updatedAt = new Date();

    await settings.save();

    // Log activity
    await logActivity(req, 'SETTINGS_UPDATE', 'Updated system settings');

    res.json({ success: true, message: 'Settings updated successfully', settings });
  } catch (error) {
    console.error('Update settings error:', error);
    res.status(500).json({ success: false, message: 'Error updating settings' });
  }
});

// M-Pesa payment integration
app.post('/api/mpesa/payment', authenticateToken, async (req, res) => {
  try {
    const { phoneNumber, amount, cart } = req.body;

    // In a real implementation, this would integrate with Safaricom M-Pesa API
    // For demo purposes, we'll simulate a successful payment

    // Simulate M-Pesa API call delay
    await new Promise(resolve => setTimeout(resolve, 2000));

    // Generate mock M-Pesa transaction details
    const mpesaResponse = {
      MerchantRequestID: `MAR${Date.now()}`,
      CheckoutRequestID: `COK${Date.now()}`,
      ResponseCode: '0',
      ResponseDescription: 'Success',
      CustomerMessage: 'Please enter your M-Pesa PIN to complete the payment'
    };

    // Simulate payment processing
    await new Promise(resolve => setTimeout(resolve, 3000));

    // For demo, assume payment is always successful
    const transactionId = `MPESA${Date.now()}`;

    res.json({
      success: true,
      message: 'M-Pesa payment initiated successfully',
      transactionId,
      mpesaResponse
    });

  } catch (error) {
    console.error('M-Pesa payment error:', error);
    res.status(500).json({ success: false, message: 'Error processing M-Pesa payment' });
  }
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({ success: false, message: 'Internal server error' });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ success: false, message: 'Endpoint not found' });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('Shutting down gracefully...');
  await mongoose.connection.close();
  await redisClient.quit();
  process.exit(0);
});
