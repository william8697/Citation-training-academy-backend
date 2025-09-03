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
  cashierId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  cashierName: { type: String },
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
  cashReceived: { type: Number },
  change: { type: Number },
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

const ActivitySchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  action: { 
    type: String, 
    required: true,
    enum: [
      'LOGIN',
      'LOGOUT',
      'USER_APPROVAL',
      'USER_REJECTION',
      'USER_CREATION',
      'USER_UPDATE',
      'USER_DELETION',
      'PRODUCT_CREATION',
      'PRODUCT_UPDATE',
      'PRODUCT_DELETION',
      'TRANSACTION_CREATION',
      'SETTINGS_UPDATE',
      'VIEW_PENDING_APPROVALS',
      'VIEW_ACTIVE_USERS',
      'VIEW_INACTIVE_USERS',
      'VIEW_INVENTORY',
      'VIEW_TRANSACTIONS',
      'VIEW_ACTIVITIES',
      'VIEW_DASHBOARD',
      'SYSTEM_EVENT'
    ]
  },
  details: { type: String },
  ipAddress: { type: String },
  userAgent: { type: String },
  targetId: { type: mongoose.Schema.Types.ObjectId },
  targetType: { type: String },
  timestamp: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Product = mongoose.model('Product', ProductSchema);
const Transaction = mongoose.model('Transaction', TransactionSchema);
const Settings = mongoose.model('Settings', SettingsSchema);
const Activity = mongoose.model('Activity', ActivitySchema);

// Utility function to log activities
const logActivity = async (userId, action, details, req = null, targetId = null, targetType = null) => {
  try {
    const activity = new Activity({
      userId,
      action,
      details,
      ipAddress: req ? req.ip || req.connection.remoteAddress : null,
      userAgent: req ? req.get('User-Agent') : null,
      targetId,
      targetType
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
  windowMs: 15 * 60 * 1000,
  max: 1000
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

// Initialize sample data
const initializeSampleData = async () => {
  try {
    // Check if sample products exist
    const productCount = await Product.countDocuments();
    if (productCount === 0) {
      const sampleProducts = [
        {
          name: 'Luxury Face Cream',
          sku: 'LFC1001',
          price: 45.99,
          stock: 50,
          category: 'skincare',
          description: 'Premium anti-aging face cream with natural ingredients'
        },
        {
          name: 'Hydrating Serum',
          sku: 'HS2002',
          price: 32.50,
          stock: 75,
          category: 'skincare',
          description: 'Deep hydrating serum for all skin types'
        },
        {
          name: 'Matte Lipstick - Ruby Red',
          sku: 'MLR3003',
          price: 18.75,
          stock: 5,
          category: 'makeup',
          description: 'Long-lasting matte lipstick in ruby red'
        },
        {
          name: 'Volume Mascara',
          sku: 'VM4004',
          price: 24.99,
          stock: 30,
          category: 'makeup',
          description: 'Volumizing mascara for dramatic lashes'
        },
        {
          name: 'Scented Body Lotion',
          sku: 'SBL5005',
          price: 15.25,
          stock: 2,
          category: 'bodycare',
          description: 'Moisturizing body lotion with floral scent'
        },
        {
          name: 'Exfoliating Scrub',
          sku: 'ES6006',
          price: 28.50,
          stock: 40,
          category: 'bodycare',
          description: 'Gentle exfoliating scrub for smooth skin'
        }
      ];

      await Product.insertMany(sampleProducts);
      console.log('Sample products created successfully');
    }

    // Check if sample cashiers exist
    const cashierCount = await User.countDocuments({ role: 'cashier' });
    if (cashierCount === 0) {
      const saltRounds = 12;
      const hashedPassword = await bcrypt.hash('Cashier@123', saltRounds);
      
      const sampleCashiers = [
        {
          firstName: 'Sarah',
          lastName: 'Johnson',
          email: 'sarah@algracia.com',
          password: hashedPassword,
          company: 'Algracia Cosmetics',
          position: 'Senior Cashier',
          role: 'cashier',
          status: 'active'
        },
        {
          firstName: 'Michael',
          lastName: 'Williams',
          email: 'michael@algracia.com',
          password: hashedPassword,
          company: 'Algracia Cosmetics',
          position: 'Cashier',
          role: 'cashier',
          status: 'active'
        },
        {
          firstName: 'Emily',
          lastName: 'Davis',
          email: 'emily@algracia.com',
          password: hashedPassword,
          company: 'Algracia Cosmetics',
          position: 'Cashier',
          role: 'cashier',
          status: 'active'
        }
      ];

      await User.insertMany(sampleCashiers);
      console.log('Sample cashiers created successfully');
    }
  } catch (error) {
    console.error('Error creating sample data:', error);
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

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ success: false, message: 'User already exists' });
    }

    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

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

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    if (user.status !== 'active') {
      return res.status(401).json({ 
        success: false, 
        message: user.status === 'pending' 
          ? 'Account pending approval' 
          : 'Account is suspended. Please contact administrator.'
      });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    user.lastLogin = new Date();
    await user.save();

    const token = jwt.sign(
      { userId: user._id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    await logActivity(user._id, 'LOGIN', 'User logged in', req);

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

// Dashboard endpoint - FIXED
app.get('/api/dashboard', authenticateToken, async (req, res) => {
  try {
    const todayStart = new Date();
    todayStart.setHours(0, 0, 0, 0);
    
    const todayEnd = new Date();
    todayEnd.setHours(23, 59, 59, 999);

    // Calculate totals for dashboard
    const [
      todaySalesData,
      totalProducts,
      lowStockItems,
      recentTransactions
    ] = await Promise.all([
      // Today's sales
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
      // Total products
      Product.countDocuments(),
      // Low stock items
      Product.countDocuments({ stock: { $lte: 10, $gt: 0 } }),
      // Recent transactions
      Transaction.find({ status: 'completed' })
        .sort({ timestamp: -1 })
        .limit(5)
        .populate('userId', 'firstName lastName')
        .lean()
    ]);

    const todaySales = todaySalesData.length > 0 ? todaySalesData[0].total : 0;
    const todayTransactions = todaySalesData.length > 0 ? todaySalesData[0].count : 0;

    await logActivity(req.user._id, 'VIEW_DASHBOARD', 'Viewed dashboard', req);

    res.json({
      success: true,
      todaySales,
      todayTransactions,
      totalProducts,
      lowStockItems,
      recentTransactions
    });

  } catch (error) {
    console.error('Dashboard error:', error);
    res.status(500).json({ success: false, message: 'Error loading dashboard data' });
  }
});

// Product routes - FIXED
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

// Inventory endpoint - FIXED
app.get('/api/inventory', authenticateToken, async (req, res) => {
  try {
    const { lowStock } = req.query;
    let filter = {};
    
    if (lowStock === 'true') {
      filter.stock = { $lte: 10 };
    }

    const inventory = await Product.find(filter)
      .sort({ name: 1 })
      .lean();

    await logActivity(req.user._id, 'VIEW_INVENTORY', 'Viewed inventory', req);

    res.json(inventory);
  } catch (error) {
    console.error('Error fetching inventory:', error);
    res.status(500).json({ success: false, message: 'Error fetching inventory' });
  }
});

// Cashiers endpoint - FIXED to return first name and email
app.get('/api/cashiers', authenticateToken, async (req, res) => {
  try {
    const cashiers = await User.find({ 
      role: 'cashier', 
      status: 'active' 
    })
    .select('firstName lastName email position _id')
    .sort({ firstName: 1 })
    .lean();

    // Format the response to include all necessary details
    const formattedCashiers = cashiers.map(cashier => ({
      _id: cashier._id,
      name: `${cashier.firstName} ${cashier.lastName}`,
      email: cashier.email,
      position: cashier.position
    }));

    res.json(formattedCashiers);
  } catch (error) {
    console.error('Error fetching cashiers:', error);
    res.status(500).json({ success: false, message: 'Error fetching cashiers' });
  }
});

// Transaction routes - FIXED
app.post('/api/transactions', authenticateToken, async (req, res) => {
  try {
    const { items, paymentMethod, paymentDetails, customer, discount = 0, cashReceived, change, cashierId, cashierName } = req.body;
    
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

    const settings = await Settings.findOne();
    const taxRate = settings?.taxRate || 16;
    const tax = subtotal * (taxRate / 100);
    const total = subtotal + tax - discount;

    const transaction = new Transaction({
      transactionId: 'TXN' + Date.now() + Math.random().toString(36).substr(2, 9).toUpperCase(),
      userId: req.user._id,
      cashierId,
      cashierName,
      items: transactionItems,
      subtotal,
      tax,
      discount,
      total,
      paymentMethod,
      paymentDetails,
      cashReceived,
      change,
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

    await logActivity(
      req.user._id, 
      'TRANSACTION_CREATION', 
      `Created transaction ${transaction.transactionId} for ${total}`, 
      req, 
      transaction._id, 
      'Transaction'
    );

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

// M-Pesa payment endpoint - FIXED
app.post('/api/mpesa/payment', authenticateToken, async (req, res) => {
  try {
    const { phoneNumber, amount, cart, cashierId, cashierName } = req.body;
    
    if (!phoneNumber) {
      return res.status(400).json({ success: false, message: 'Phone number is required' });
    }

    // In a real implementation, you would integrate with M-Pesa API here
    // This is a simulation of a successful payment
    const transactionId = 'MPESA' + Date.now() + Math.random().toString(36).substr(2, 9).toUpperCase();
    
    // Create transaction record
    let subtotal = 0;
    const transactionItems = cart.map(item => {
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

    const settings = await Settings.findOne();
    const taxRate = settings?.taxRate || 16;
    const tax = subtotal * (taxRate / 100);
    const total = subtotal + tax;

    const transaction = new Transaction({
      transactionId,
      userId: req.user._id,
      cashierId,
      cashierName,
      items: transactionItems,
      subtotal,
      tax,
      total,
      paymentMethod: 'mpesa',
      paymentDetails: {
        phoneNumber,
        amount
      },
      status: 'completed'
    });

    await transaction.save();

    // Update product stock levels
    for (const item of cart) {
      await Product.findByIdAndUpdate(
        item.productId,
        { $inc: { stock: -item.quantity } }
      );
    }

    await logActivity(
      req.user._id, 
      'TRANSACTION_CREATION', 
      `Created M-Pesa transaction ${transaction.transactionId} for ${total}`, 
      req, 
      transaction._id, 
      'Transaction'
    );

    res.json({
      success: true,
      message: 'M-Pesa payment processed successfully',
      transactionId: transaction.transactionId
    });

  } catch (error) {
    console.error('M-Pesa payment error:', error);
    res.status(500).json({ success: false, message: 'Error processing M-Pesa payment' });
  }
});

// Card payment endpoint - FIXED
app.post('/api/card/payment', authenticateToken, async (req, res) => {
  try {
    const { cardNumber, expiryDate, cvv, amount, cart, cardType, cashierId, cashierName } = req.body;
    
    if (!cardNumber || !expiryDate || !cvv) {
      return res.status(400).json({ success: false, message: 'Card details are required' });
    }

    // In a real implementation, you would integrate with a payment gateway here
    // This is a simulation of a successful payment
    const transactionId = 'CARD' + Date.now() + Math.random().toString(36).substr(2, 9).toUpperCase();
    
    // Create transaction record
    let subtotal = 0;
    const transactionItems = cart.map(item => {
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

    const settings = await Settings.findOne();
    const taxRate = settings?.taxRate || 16;
    const tax = subtotal * (taxRate / 100);
    const total = subtotal + tax;

    const transaction = new Transaction({
      transactionId,
      userId: req.user._id,
      cashierId,
      cashierName,
      items: transactionItems,
      subtotal,
      tax,
      total,
      paymentMethod: 'card',
      paymentDetails: {
        cardType,
        lastFour: cardNumber.slice(-4),
        expiryDate
      },
      status: 'completed'
    });

    await transaction.save();

    // Update product stock levels
    for (const item of cart) {
      await Product.findByIdAndUpdate(
        item.productId,
        { $inc: { stock: -item.quantity } }
      );
    }

    await logActivity(
      req.user._id, 
      'TRANSACTION_CREATION', 
      `Created card transaction ${transaction.transactionId} for ${total}`, 
      req, 
      transaction._id, 
      'Transaction'
    );

    res.json({
      success: true,
      message: 'Card payment processed successfully',
      transactionId: transaction.transactionId
    });

  } catch (error) {
    console.error('Card payment error:', error);
    res.status(500).json({ success: false, message: 'Error processing card payment' });
  }
});

// Add product endpoint - FIXED
app.post('/api/products', authenticateToken, [
  body('name').notEmpty().withMessage('Product name is required'),
  body('sku').notEmpty().withMessage('SKU is required'),
  body('price').isNumeric().withMessage('Price must be a number'),
  body('stock').isInt({ min: 0 }).withMessage('Stock must be a non-negative integer')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, message: errors.array()[0].msg });
    }

    const { name, sku, price, stock, category, description } = req.body;

    // Check if product with same SKU already exists
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
      description,
      createdBy: req.user._id
    });

    await product.save();

    await logActivity(
      req.user._id, 
      'PRODUCT_CREATION', 
      `Created product: ${name} (${sku})`, 
      req, 
      product._id, 
      'Product'
    );

    res.status(201).json({
      success: true,
      message: 'Product created successfully',
      product
    });

  } catch (error) {
    console.error('Error creating product:', error);
    res.status(500).json({ success: false, message: 'Error creating product' });
  }
});

// Get pending user approvals
app.get('/api/admin/pending-approvals', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const pendingUsers = await User.find({ status: 'pending' })
      .select('-password')
      .sort({ createdAt: -1 })
      .lean();

    await logActivity(req.user._id, 'VIEW_PENDING_APPROVALS', 'Viewed pending approvals', req);

    res.json(pendingUsers);
  } catch (error) {
    console.error('Error fetching pending approvals:', error);
    res.status(500).json({ success: false, message: 'Error fetching pending approvals' });
  }
});

// Get active users
app.get('/api/admin/users/active', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const activeUsers = await User.find({ status: 'active' })
      .select('-password')
      .sort({ firstName: 1, lastName: 1 })
      .lean();

    await logActivity(req.user._id, 'VIEW_ACTIVE_USERS', 'Viewed active users', req);

    res.json(activeUsers);
  } catch (error) {
    console.error('Error fetching active users:', error);
    res.status(500).json({ success: false, message: 'Error fetching active users' });
  }
});

// Get all inventory
app.get('/api/admin/inventory', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { lowStock } = req.query;
    let filter = {};
    
    if (lowStock === 'true') {
      filter.stock = { $lte: 10 };
    }

    const inventory = await Product.find(filter)
      .sort({ name: 1 })
      .lean();

    await logActivity(req.user._id, 'VIEW_INVENTORY', 'Viewed inventory', req);

    res.json(inventory);
  } catch (error) {
    console.error('Error fetching inventory:', error);
    res.status(500).json({ success: false, message: 'Error fetching inventory' });
  }
});

// Get all transactions
app.get('/api/admin/transactions', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { date } = req.query;
    let filter = { status: 'completed' };
    
    if (date) {
      const startDate = new Date(date);
      const endDate = new Date(date);
      endDate.setDate(endDate.getDate() + 1);
      
      filter.timestamp = {
        $gte: startDate,
        $lt: endDate
      };
    }

    const transactions = await Transaction.find(filter)
      .populate('userId', 'firstName lastName')
      .sort({ timestamp: -1 })
      .limit(100)
      .lean();

    await logActivity(req.user._id, 'VIEW_TRANSACTIONS', 'Viewed transactions', req);

    res.json(transactions);
  } catch (error) {
    console.error('Error fetching transactions:', error);
    res.status(500).json({ success: false, message: 'Error fetching transactions' });
  }
});

// Get recent activities
app.get('/api/admin/activities', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const activities = await Activity.find()
      .populate('userId', 'firstName lastName')
      .sort({ timestamp: -1 })
      .limit(50)
      .lean();

    await logActivity(req.user._id, 'VIEW_ACTIVITIES', 'Viewed activities', req);

    res.json(activities);
  } catch (error) {
    console.error('Error fetching activities:', error);
    res.status(500).json({ success: false, message: 'Error fetching activities' });
  }
});

// Get inactive users
app.get('/api/admin/users/inactive', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const inactiveUsers = await User.find({ 
      status: { $in: ['inactive', 'suspended'] } 
    })
      .select('-password')
      .sort({ firstName: 1, lastName: 1 })
      .lean();

    await logActivity(req.user._id, 'VIEW_INACTIVE_USERS', 'Viewed inactive users', req);

    res.json(inactiveUsers);
  } catch (error) {
    console.error('Error fetching inactive users:', error);
    res.status(500).json({ success: false, message: 'Error fetching inactive users' });
  }
});

// User approval endpoint - FIXED
app.post('/api/admin/users/:id/approve', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    if (user.status === 'active') {
      return res.status(400).json({ success: false, message: 'User is already approved' });
    }

    user.status = 'active';
    user.updatedBy = req.user._id;
    await user.save();

    await logActivity(
      req.user._id, 
      'USER_APPROVAL', 
      `Approved user: ${user.firstName} ${user.lastName} (${user.email})`, 
      req, 
      user._id, 
      'User'
    );

    res.json({ 
      success: true, 
      message: 'User approved successfully',
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        company: user.company,
        position: user.position,
        status: user.status
      }
    });
  } catch (error) {
    console.error('Error approving user:', error);
    res.status(500).json({ success: false, message: 'Error approving user' });
  }
});

// User rejection endpoint - FIXED
app.post('/api/admin/users/:id/reject', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    user.status = 'inactive';
    user.updatedBy = req.user._id;
    await user.save();

    await logActivity(
      req.user._id, 
      'USER_REJECTION', 
      `Rejected user: ${user.firstName} ${user.lastName} (${user.email})`, 
      req, 
      user._id, 
      'User'
    );

    res.json({ 
      success: true, 
      message: 'User rejected successfully',
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        company: user.company,
        position: user.position,
        status: user.status
      }
    });
  } catch (error) {
    console.error('Error rejecting user:', error);
    res.status(500).json({ success: false, message: 'Error rejecting user' });
  }
});

// Add new user
app.post('/api/admin/users', authenticateToken, requireAdmin, [
  body('name').notEmpty().trim().withMessage('Name is required'),
  body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
  body('company').notEmpty().trim().withMessage('Company name is required'),
  body('position').notEmpty().trim().withMessage('Position is required'),
  body('role').isIn(['admin', 'manager', 'cashier']).withMessage('Valid role is required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, message: errors.array()[0].msg });
    }

    const { name, email, company, position, role } = req.body;
    
    // Split name into first and last name
    const nameParts = name.split(' ');
    const firstName = nameParts[0];
    const lastName = nameParts.slice(1).join(' ') || 'User';

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ success: false, message: 'User with this email already exists' });
    }

    // Generate a random password
    const randomPassword = Math.random().toString(36).slice(-10) + 'A1!';
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(randomPassword, saltRounds);

    // Create new user
    const newUser = new User({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      company,
      position,
      role,
      status: 'active',
      createdBy: req.user._id
    });

    await newUser.save();

    await logActivity(
      req.user._id, 
      'USER_CREATION', 
      `Created user: ${firstName} ${lastName} (${email}) with role: ${role}`, 
      req, 
      newUser._id, 
      'User'
    );

    res.status(201).json({
      success: true,
      message: 'User created successfully',
      user: {
        id: newUser._id,
        firstName: newUser.firstName,
        lastName: newUser.lastName,
        email: newUser.email,
        company: newUser.company,
        position: newUser.position,
        role: newUser.role,
        status: newUser.status
      }
    });

  } catch (error) {
    console.error('Error creating user:', error);
    res.status(500).json({ success: false, message: 'Error creating user' });
  }
});

// Deactivate user
app.post('/api/admin/users/:id/deactivate', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    if (user.status === 'inactive') {
      return res.status(400).json({ success: false, message: 'User is already inactive' });
    }

    user.status = 'inactive';
    user.updatedBy = req.user._id;
    await user.save();

    await logActivity(
      req.user._id, 
      'USER_UPDATE', 
      `Deactivated user: ${user.firstName} ${user.lastName} (${user.email})`, 
      req, 
      user._id, 
      'User'
    );

    res.json({ 
      success: true, 
      message: 'User deactivated successfully',
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        status: user.status
      }
    });
  } catch (error) {
    console.error('Error deactivating user:', error);
    res.status(500).json({ success: false, message: 'Error deactivating user' });
  }
});

// Activate user
app.post('/api/admin/users/:id/activate', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    if (user.status === 'active') {
      return res.status(400).json({ success: false, message: 'User is already active' });
    }

    user.status = 'active';
    user.updatedBy = req.user._id;
    await user.save();

    await logActivity(
      req.user._id, 
      'USER_UPDATE', 
      `Activated user: ${user.firstName} ${user.lastName} (${user.email})`, 
      req, 
      user._id, 
      'User'
    );

    res.json({ 
      success: true, 
      message: 'User activated successfully',
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        status: user.status
      }
    });
  } catch (error) {
    console.error('Error activating user:', error);
    res.status(500).json({ success: false, message: 'Error activating user' });
  }
});

// Delete user
app.delete('/api/admin/users/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Prevent deletion of the default admin account
    if (user.email === 'admin@algracia.com') {
      return res.status(400).json({ success: false, message: 'Cannot delete default admin account' });
    }

    await User.findByIdAndDelete(req.params.id);

    await logActivity(
      req.user._id, 
      'USER_DELETION', 
      `Deleted user: ${user.firstName} ${user.lastName} (${user.email})`, 
      req, 
      user._id, 
      'User'
    );

    res.json({ 
      success: true, 
      message: 'User deleted successfully'
    });
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({ success: false, message: 'Error deleting user' });
  }
});

// Delete inventory item
app.delete('/api/admin/inventory/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) {
      return res.status(404).json({ success: false, message: 'Product not found' });
    }

    await Product.findByIdAndDelete(req.params.id);

    await logActivity(
      req.user._id, 
      'PRODUCT_DELETION', 
      `Deleted product: ${product.name} (${product.sku})`, 
      req, 
      product._id, 
      'Product'
    );

    res.json({ 
      success: true, 
      message: 'Product deleted successfully'
    });
  } catch (error) {
    console.error('Error deleting product:', error);
    res.status(500).json({ success: false, message: 'Error deleting product' });
  }
});

// Get sales reports
app.get('/api/admin/reports', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { type } = req.query;
    let startDate, endDate = new Date();
    
    switch (type) {
      case 'daily':
        startDate = new Date();
        startDate.setHours(0, 0, 0, 0);
        break;
      case 'weekly':
        startDate = new Date();
        startDate.setDate(startDate.getDate() - 7);
        break;
      case 'monthly':
        startDate = new Date();
        startDate.setMonth(startDate.getMonth() - 1);
        break;
      case 'custom':
        // For custom range, you would need to pass start and end dates
        startDate = new Date(req.query.startDate);
        endDate = new Date(req.query.endDate);
        break;
      default:
        startDate = new Date();
        startDate.setDate(startDate.getDate() - 30); // Default to 30 days
    }

    const salesData = await Transaction.aggregate([
      {
        $match: {
          status: 'completed',
          timestamp: { $gte: startDate, $lte: endDate }
        }
      },
      {
        $group: {
          _id: {
            year: { $year: '$timestamp' },
            month: { $month: '$timestamp' },
            day: { $dayOfMonth: '$timestamp' }
          },
          totalSales: { $sum: '$total' },
          transactionCount: { $sum: 1 }
        }
      },
      { $sort: { '_id.year': 1, '_id.month': 1, '_id.day': 1 } }
    ]);

    // Format data for chart
    const labels = salesData.map(item => `${item._id.month}/${item._id.day}/${item._id.year}`);
    const data = salesData.map(item => item.totalSales);

    await logActivity(req.user._id, 'VIEW_REPORTS', `Viewed ${type} sales report`, req);

    res.json({
      success: true,
      reportType: type,
      startDate,
      endDate,
      labels,
      data,
      salesData
    });

  } catch (error) {
    console.error('Error generating report:', error);
    res.status(500).json({ success: false, message: 'Error generating report' });
  }
});

// Update system settings
app.post('/api/admin/settings', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { companyName, currency, taxRate, receiptFooter, lowStockAlert } = req.body;

    let settings = await Settings.findOne();
    if (!settings) {
      settings = new Settings();
    }

    if (companyName) settings.companyName = companyName;
    if (currency) settings.currency = currency;
    if (taxRate) settings.taxRate = taxRate;
    if (receiptFooter) settings.receiptFooter = receiptFooter;
    if (lowStockAlert !== undefined) settings.lowStockAlert = lowStockAlert;
    
    settings.updatedAt = new Date();
    settings.updatedBy = req.user._id;

    await settings.save();

    await logActivity(
      req.user._id, 
      'SETTINGS_UPDATE', 
      'Updated system settings', 
      req
    );

    res.json({ 
      success: true, 
      message: 'Settings saved successfully',
      settings
    });
  } catch (error) {
    console.error('Error saving settings:', error);
    res.status(500).json({ success: false, message: 'Error saving settings' });
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
    await initializeDefaultAdmin();
    await initializeDefaultSettings();
    await initializeSampleData();
    
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
