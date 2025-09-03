const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || '17581758Na';

// MongoDB Connection
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/algracia_pos';
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
  status: { type: String, enum: ['pending', 'active', 'inactive', 'suspended'], default: 'pending' },
  createdAt: { type: Date, default: Date.now },
  lastLogin: { type: Date },
  permissions: [{ type: String }],
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
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
  updatedAt: { type: Date, default: Date.now },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
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

const SettingsSchema = new mongoose.Schema({
  companyName: { type: String, default: 'Algracia Cosmetics' },
  currency: { type: String, default: 'KES' },
  taxRate: { type: Number, default: 16 },
  receiptFooter: { type: String, default: 'Thank you for shopping with us!' },
  lowStockAlert: { type: Boolean, default: true },
  updatedAt: { type: Date, default: Date.now },
  updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
}); 

const User = mongoose.model('User', UserSchema);
const Product = mongoose.model('Product', ProductSchema);
const Transaction = mongoose.model('Transaction', TransactionSchema);
const Settings = mongoose.model('Settings', SettingsSchema);

// Activity Schema (add this to your schemas)
const ActivitySchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  action: { type: String, required: true },
  details: { type: String },
  ipAddress: { type: String },
  userAgent: { type: String },
  timestamp: { type: Date, default: Date.now }
});

const Activity = mongoose.model('Activity', ActivitySchema);

// Utility function to log activities
const logActivity = async (userId, action, details, req = null) => {
  try {
    const activity = new Activity({
      userId,
      action,
      details,
      ipAddress: req ? req.ip || req.connection.remoteAddress : null,
      userAgent: req ? req.get('User-Agent') : null
    });
    await activity.save();
  } catch (error) {
    console.error('Error logging activity:', error);
  }
};





// Middleware
app.use(helmet());
app.use(cors({
  origin: ['https://citation-training-academy.vercel.app', 'http://localhost:3000', 'http://localhost:5500', 'http://127.0.0.1:5500'],
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static('public'));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 1000 // limit each IP to 1000 requests per windowMs
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

// Initialize default admin user
const initializeDefaultAdmin = async () => {
  try {
    const adminEmail = 'admin@algracia.com';
    const adminExists = await User.findOne({ email: adminEmail, role: 'admin' });
    
    if (!adminExists) {
      const saltRounds = 12;
      const defaultPassword = 'Admin@123';
      const hashedPassword = await bcrypt.hash(defaultPassword, saltRounds);
      
      const adminUser = new User({
        firstName: 'System',
        lastName: 'Administrator',
        email: adminEmail,
        password: hashedPassword,
        company: 'Algracia Cosmetics',
        position: 'System Administrator',
        role: 'admin',
        status: 'active',
        permissions: ['all']
      });
      
      await adminUser.save();
      console.log('Default admin user created successfully');
      console.log(`Email: ${adminEmail}`);
      console.log(`Password: ${defaultPassword}`);
    } else {
      console.log('Default admin user already exists');
    }
  } catch (error) {
    console.error('Error creating default admin:', error);
  }
};

// Initialize default settings
const initializeDefaultSettings = async () => {
  try {
    const settings = await Settings.findOne();
    if (!settings) {
      const defaultSettings = new Settings();
      await defaultSettings.save();
      console.log('Default settings initialized');
    }
  } catch (error) {
    console.error('Error initializing default settings:', error);
  }
};

// Routes

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ success: true, message: 'Server is running', timestamp: new Date() });
});

// Authentication routes
app.post('/api/auth/signup', [
  body('firstName').notEmpty().trim().withMessage('First name is required'),
  body('lastName').notEmpty().trim().withMessage('Last name is required'),
  body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters'),
  body('company').notEmpty().trim().withMessage('Company name is required'),
  body('position').notEmpty().trim().withMessage('Position is required')
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
  body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
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
      return res.status(401).json({ 
        success: false, 
        message: user.status === 'pending' 
          ? 'Account pending approval' 
          : 'Account is suspended. Please contact administrator.'
      });
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

    res.json({
      success: true,
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        role: user.role,
        company: user.company,
        position: user.position,
        initials: (user.firstName[0] + user.lastName[0]).toUpperCase()
      }
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
      initials: (req.user.firstName[0] + req.user.lastName[0]).toUpperCase()
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

    const weekStart = new Date();
    weekStart.setDate(weekStart.getDate() - 7);
    
    const monthStart = new Date();
    monthStart.setMonth(monthStart.getMonth() - 1);

    const [
      pendingApprovals,
      totalUsers,
      todaySales,
      weekSales,
      monthSales,
      lowStockItems,
      totalProducts,
      totalTransactions
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
            total: { $sum: '$total' },
            count: { $sum: 1 }
          }
        }
      ]),
      Transaction.aggregate([
        {
          $match: {
            timestamp: { $gte: weekStart },
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
      Transaction.aggregate([
        {
          $match: {
            timestamp: { $gte: monthStart },
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
      Product.countDocuments({ stock: { $lte: 10 } }),
      Product.countDocuments(),
      Transaction.countDocuments({ status: 'completed' })
    ]);

    const todaySalesTotal = todaySales.length > 0 ? todaySales[0].total : 0;
    const todaySalesCount = todaySales.length > 0 ? todaySales[0].count : 0;
    const weekSalesTotal = weekSales.length > 0 ? weekSales[0].total : 0;
    const monthSalesTotal = monthSales.length > 0 ? monthSales[0].total : 0;

    res.json({
      success: true,
      pendingApprovals,
      totalUsers,
      todaySales: todaySalesTotal,
      todayTransactions: todaySalesCount,
      weekSales: weekSalesTotal,
      monthSales: monthSalesTotal,
      lowStockItems,
      totalProducts,
      totalTransactions
    });

  } catch (error) {
    console.error('Dashboard error:', error);
    res.status(500).json({ success: false, message: 'Error loading dashboard data' });
  }
});

// Product routes
app.get('/api/products', authenticateToken, async (req, res) => {
  try {
    const { category, lowStock } = req.query;
    let filter = {};
    
    if (category) filter.category = category;
    if (lowStock === 'true') filter.stock = { $lte: 10 };

    const products = await Product.find(filter).sort({ name: 1 });
    res.json(products);
  } catch (error) {
    console.error('Products error:', error);
    res.status(500).json({ success: false, message: 'Error loading products' });
  }
});

// Transaction routes
app.post('/api/transactions', authenticateToken, async (req, res) => {
  try {
    const { items, paymentMethod, paymentDetails, customer, discount = 0 } = req.body;
    
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

    // Get tax rate from settings
    const settings = await Settings.findOne();
    const taxRate = settings?.taxRate || 16;
    const tax = subtotal * (taxRate / 100);
    const total = subtotal + tax - discount;

    // Create transaction
    const transaction = new Transaction({
      transactionId: 'TXN' + Date.now() + Math.random().toString(36).substr(2, 9).toUpperCase(),
      userId: req.user._id,
      items: transactionItems,
      subtotal,
      tax,
      discount,
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

// Serve frontend files
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Get pending user approvals with pagination and filtering
app.get('/api/admin/pending-approvals', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const search = req.query.search || '';
    const sortBy = req.query.sortBy || 'createdAt';
    const sortOrder = req.query.sortOrder === 'asc' ? 1 : -1;

    const skip = (page - 1) * limit;

    // Build search filter
    let filter = { status: 'pending' };
    if (search) {
      filter.$or = [
        { firstName: { $regex: search, $options: 'i' } },
        { lastName: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
        { company: { $regex: search, $options: 'i' } }
      ];
    }

    const [pendingUsers, totalCount] = await Promise.all([
      User.find(filter)
        .select('-password')
        .sort({ [sortBy]: sortOrder })
        .skip(skip)
        .limit(limit)
        .lean(),
      User.countDocuments(filter)
    ]);

    // Log activity
    await logActivity(req.user._id, 'VIEW_PENDING_APPROVALS', `Viewed page ${page} of pending approvals`, req);

    res.json({
      success: true,
      data: pendingUsers,
      pagination: {
        page,
        limit,
        totalCount,
        totalPages: Math.ceil(totalCount / limit)
      }
    });
  } catch (error) {
    console.error('Error fetching pending approvals:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error fetching pending approvals',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Get active users with advanced filtering
app.get('/api/admin/users/active', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const search = req.query.search || '';
    const role = req.query.role || '';
    const sortBy = req.query.sortBy || 'firstName';
    const sortOrder = req.query.sortOrder === 'asc' ? 1 : -1;

    const skip = (page - 1) * limit;

    // Build filter
    let filter = { status: 'active' };
    if (search) {
      filter.$or = [
        { firstName: { $regex: search, $options: 'i' } },
        { lastName: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
        { company: { $regex: search, $options: 'i' } }
      ];
    }
    if (role) {
      filter.role = role;
    }

    const [activeUsers, totalCount] = await Promise.all([
      User.find(filter)
        .select('-password')
        .sort({ [sortBy]: sortOrder })
        .skip(skip)
        .limit(limit)
        .populate('createdBy', 'firstName lastName email')
        .populate('updatedBy', 'firstName lastName email')
        .lean(),
      User.countDocuments(filter)
    ]);

    // Log activity
    await logActivity(req.user._id, 'VIEW_ACTIVE_USERS', `Viewed page ${page} of active users`, req);

    res.json({
      success: true,
      data: activeUsers,
      pagination: {
        page,
        limit,
        totalCount,
        totalPages: Math.ceil(totalCount / limit)
      }
    });
  } catch (error) {
    console.error('Error fetching active users:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error fetching active users',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Get inventory with advanced filtering and search
app.get('/api/admin/inventory', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const search = req.query.search || '';
    const category = req.query.category || '';
    const lowStock = req.query.lowStock === 'true';
    const outOfStock = req.query.outOfStock === 'true';
    const sortBy = req.query.sortBy || 'name';
    const sortOrder = req.query.sortOrder === 'asc' ? 1 : -1;

    const skip = (page - 1) * limit;

    // Build filter
    let filter = {};
    if (search) {
      filter.$or = [
        { name: { $regex: search, $options: 'i' } },
        { sku: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } }
      ];
    }
    if (category) {
      filter.category = category;
    }
    if (lowStock) {
      filter.stock = { $lte: 10, $gt: 0 };
    }
    if (outOfStock) {
      filter.stock = { $eq: 0 };
    }

    const [inventory, totalCount, categories] = await Promise.all([
      Product.find(filter)
        .sort({ [sortBy]: sortOrder })
        .skip(skip)
        .limit(limit)
        .populate('createdBy', 'firstName lastName email')
        .populate('updatedBy', 'firstName lastName email')
        .lean(),
      Product.countDocuments(filter),
      Product.distinct('category')
    ]);

    // Get inventory stats
    const inventoryStats = await Product.aggregate([
      {
        $group: {
          _id: null,
          totalProducts: { $sum: 1 },
          totalStock: { $sum: '$stock' },
          totalValue: { $sum: { $multiply: ['$price', '$stock'] } },
          lowStockItems: {
            $sum: {
              $cond: [{ $and: [{ $lte: ['$stock', 10] }, { $gt: ['$stock', 0] }] }, 1, 0]
            }
          },
          outOfStockItems: {
            $sum: {
              $cond: [{ $eq: ['$stock', 0] }, 1, 0]
            }
          }
        }
      }
    ]);

    // Log activity
    await logActivity(req.user._id, 'VIEW_INVENTORY', `Viewed page ${page} of inventory`, req);

    res.json({
      success: true,
      data: inventory,
      stats: inventoryStats[0] || {
        totalProducts: 0,
        totalStock: 0,
        totalValue: 0,
        lowStockItems: 0,
        outOfStockItems: 0
      },
      categories,
      pagination: {
        page,
        limit,
        totalCount,
        totalPages: Math.ceil(totalCount / limit)
      }
    });
  } catch (error) {
    console.error('Error fetching inventory:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error fetching inventory',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Get transactions with advanced filtering
app.get('/api/admin/transactions', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const startDate = req.query.startDate ? new Date(req.query.startDate) : null;
    const endDate = req.query.endDate ? new Date(req.query.endDate) : null;
    const paymentMethod = req.query.paymentMethod || '';
    const minAmount = parseFloat(req.query.minAmount) || 0;
    const maxAmount = parseFloat(req.query.maxAmount) || 0;
    const sortBy = req.query.sortBy || 'timestamp';
    const sortOrder = req.query.sortOrder === 'asc' ? 1 : -1;

    const skip = (page - 1) * limit;

    // Build filter
    let filter = { status: 'completed' };
    
    if (startDate || endDate) {
      filter.timestamp = {};
      if (startDate) filter.timestamp.$gte = startDate;
      if (endDate) {
        const adjustedEndDate = new Date(endDate);
        adjustedEndDate.setDate(adjustedEndDate.getDate() + 1);
        filter.timestamp.$lt = adjustedEndDate;
      }
    }
    
    if (paymentMethod) {
      filter.paymentMethod = paymentMethod;
    }
    
    if (minAmount > 0 || maxAmount > 0) {
      filter.total = {};
      if (minAmount > 0) filter.total.$gte = minAmount;
      if (maxAmount > 0) filter.total.$lte = maxAmount;
    }

    const [transactions, totalCount] = await Promise.all([
      Transaction.find(filter)
        .sort({ [sortBy]: sortOrder })
        .skip(skip)
        .limit(limit)
        .populate('userId', 'firstName lastName email')
        .lean(),
      Transaction.countDocuments(filter)
    ]);

    // Get transaction stats
    const transactionStats = await Transaction.aggregate([
      { $match: filter },
      {
        $group: {
          _id: null,
          totalTransactions: { $sum: 1 },
          totalRevenue: { $sum: '$total' },
          totalTax: { $sum: '$tax' },
          totalDiscount: { $sum: '$discount' },
          averageTransaction: { $avg: '$total' }
        }
      }
    ]);

    // Log activity
    await logActivity(req.user._id, 'VIEW_TRANSACTIONS', `Viewed page ${page} of transactions`, req);

    res.json({
      success: true,
      data: transactions,
      stats: transactionStats[0] || {
        totalTransactions: 0,
        totalRevenue: 0,
        totalTax: 0,
        totalDiscount: 0,
        averageTransaction: 0
      },
      pagination: {
        page,
        limit,
        totalCount,
        totalPages: Math.ceil(totalCount / limit)
      }
    });
  } catch (error) {
    console.error('Error fetching transactions:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error fetching transactions',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Get recent activities with filtering
app.get('/api/admin/activities', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const userId = req.query.userId || '';
    const action = req.query.action || '';
    const startDate = req.query.startDate ? new Date(req.query.startDate) : null;
    const endDate = req.query.endDate ? new Date(req.query.endDate) : null;
    const sortBy = req.query.sortBy || 'timestamp';
    const sortOrder = req.query.sortOrder === 'asc' ? 1 : -1;

    const skip = (page - 1) * limit;

    // Build filter
    let filter = {};
    
    if (userId) {
      filter.userId = userId;
    }
    
    if (action) {
      filter.action = action;
    }
    
    if (startDate || endDate) {
      filter.timestamp = {};
      if (startDate) filter.timestamp.$gte = startDate;
      if (endDate) {
        const adjustedEndDate = new Date(endDate);
        adjustedEndDate.setDate(adjustedEndDate.getDate() + 1);
        filter.timestamp.$lt = adjustedEndDate;
      }
    }

    const [activities, totalCount, distinctActions] = await Promise.all([
      Activity.find(filter)
        .sort({ [sortBy]: sortOrder })
        .skip(skip)
        .limit(limit)
        .populate('userId', 'firstName lastName email')
        .lean(),
      Activity.countDocuments(filter),
      Activity.distinct('action')
    ]);

    // Log activity
    await logActivity(req.user._id, 'VIEW_ACTIVITIES', `Viewed page ${page} of activities`, req);

    res.json({
      success: true,
      data: activities,
      distinctActions,
      pagination: {
        page,
        limit,
        totalCount,
        totalPages: Math.ceil(totalCount / limit)
      }
    });
  } catch (error) {
    console.error('Error fetching activities:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error fetching activities',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Approve user endpoint
app.post('/api/admin/approve-user/:userId', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    if (user.status !== 'pending') {
      return res.status(400).json({ 
        success: false, 
        message: `User is already ${user.status}` 
      });
    }

    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { 
        status: 'active',
        updatedBy: req.user._id,
        updatedAt: new Date()
      },
      { new: true }
    ).select('-password');

    // Log activity
    await logActivity(
      req.user._id, 
      'APPROVE_USER', 
      `Approved user: ${updatedUser.email} (${updatedUser.firstName} ${updatedUser.lastName})`,
      req
    );

    res.json({ 
      success: true, 
      message: 'User approved successfully', 
      user: updatedUser 
    });
  } catch (error) {
    console.error('Error approving user:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error approving user',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Reject user endpoint
app.post('/api/admin/reject-user/:userId', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    const { reason } = req.body;
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    if (user.status !== 'pending') {
      return res.status(400).json({ 
        success: false, 
        message: `User is already ${user.status}` 
      });
    }

    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { 
        status: 'inactive',
        updatedBy: req.user._id,
        updatedAt: new Date()
      },
      { new: true }
    ).select('-password');

    // Log activity
    await logActivity(
      req.user._id, 
      'REJECT_USER', 
      `Rejected user: ${updatedUser.email} (${updatedUser.firstName} ${updatedUser.lastName})${reason ? ` - Reason: ${reason}` : ''}`,
      req
    );

    res.json({ 
      success: true, 
      message: 'User rejected successfully', 
      user: updatedUser 
    });
  } catch (error) {
    console.error('Error rejecting user:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error rejecting user',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Get user by ID for detailed view
app.get('/api/admin/users/:userId', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    
    const user = await User.findById(userId)
      .select('-password')
      .populate('createdBy', 'firstName lastName email')
      .populate('updatedBy', 'firstName lastName email');

    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Get user's recent activities
    const recentActivities = await Activity.find({ userId })
      .sort({ timestamp: -1 })
      .limit(10)
      .lean();

    // Get user's recent transactions
    const recentTransactions = await Transaction.find({ userId })
      .sort({ timestamp: -1 })
      .limit(5)
      .lean();

    res.json({
      success: true,
      data: {
        user,
        recentActivities,
        recentTransactions
      }
    });
  } catch (error) {
    console.error('Error fetching user details:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error fetching user details',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Update user status
app.patch('/api/admin/users/:userId/status', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    const { status } = req.body;

    if (!['active', 'inactive', 'suspended'].includes(status)) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid status. Must be active, inactive, or suspended' 
      });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { 
        status,
        updatedBy: req.user._id,
        updatedAt: new Date()
      },
      { new: true }
    ).select('-password');

    // Log activity
    await logActivity(
      req.user._id, 
      'UPDATE_USER_STATUS', 
      `Updated user status to ${status} for: ${updatedUser.email}`,
      req
    );

    res.json({ 
      success: true, 
      message: `User status updated to ${status} successfully`, 
      user: updatedUser 
    });
  } catch (error) {
    console.error('Error updating user status:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error updating user status',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Update user role
app.patch('/api/admin/users/:userId/role', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    const { role } = req.body;

    if (!['admin', 'manager', 'cashier'].includes(role)) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid role. Must be admin, manager, or cashier' 
      });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Prevent demoting the only admin
    if (user.role === 'admin' && role !== 'admin') {
      const adminCount = await User.countDocuments({ role: 'admin', status: 'active' });
      if (adminCount <= 1) {
        return res.status(400).json({ 
          success: false, 
          message: 'Cannot demote the only active admin user' 
        });
      }
    }

    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { 
        role,
        updatedBy: req.user._id,
        updatedAt: new Date()
      },
      { new: true }
    ).select('-password');

    // Log activity
    await logActivity(
      req.user._id, 
      'UPDATE_USER_ROLE', 
      `Updated user role to ${role} for: ${updatedUser.email}`,
      req
    );

    res.json({ 
      success: true, 
      message: `User role updated to ${role} successfully`, 
      user: updatedUser 
    });
  } catch (error) {
    console.error('Error updating user role:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error updating user role',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
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

// Initialize default data and start server
async function startServer() {
  try {
    // Initialize default admin and settings
    await initializeDefaultAdmin();
    await initializeDefaultSettings();
    
    // Start server
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
      console.log(`Default admin: admin@algracia.com / Admin@123`);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

// Start the server
startServer();
