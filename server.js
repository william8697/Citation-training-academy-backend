const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const axios = require('axios');
const { createCanvas } = require('canvas');
const jsbarcode = require('jsbarcode');
const Quagga = require('quagga');
const { v4: uuidv4 } = require('uuid');
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
  barcode: { type: String, unique: true, sparse: true },
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
  updatedAt: { type: Date, default: Date.now },
  updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
});

const AuditLogSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  action: { type: String, required: true },
  resource: { type: String, required: true },
  resourceId: { type: mongoose.Schema.Types.ObjectId },
  changes: { type: Object },
  ipAddress: { type: String },
  timestamp: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Product = mongoose.model('Product', ProductSchema);
const Transaction = mongoose.model('Transaction', TransactionSchema);
const Activity = mongoose.model('Activity', ActivitySchema);
const Settings = mongoose.model('Settings', SettingsSchema);
const AuditLog = mongoose.model('AuditLog', AuditLogSchema);

// Middleware
app.use(helmet());
app.use(cors({
  origin: ['https://citation-training-academy.vercel.app', 'http://localhost:3000', 'http://localhost:5500'],
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use('/uploads', express.static('uploads'));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 1000 // limit each IP to 1000 requests per windowMs
});
app.use(limiter);

// File upload configuration
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const dir = 'uploads/';
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    cb(null, dir);
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname));
  }
});

const upload = multer({ 
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB limit
  },
  fileFilter: function (req, file, cb) {
    const filetypes = /jpeg|jpg|png|gif/;
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = filetypes.test(file.mimetype);

    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb(new Error('Only image files are allowed'));
    }
  }
});

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

// Manager authorization middleware
const requireManager = (req, res, next) => {
  if (!['admin', 'manager'].includes(req.user.role)) {
    return res.status(403).json({ success: false, message: 'Manager access required' });
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

// Log audit middleware
const logAudit = async (userId, action, resource, resourceId = null, changes = {}) => {
  try {
    const auditLog = new AuditLog({
      userId,
      action,
      resource,
      resourceId,
      changes,
      ipAddress: req?.ip || 'N/A'
    });
    await auditLog.save();
  } catch (error) {
    console.error('Error logging audit:', error);
  }
};

// Generate unique transaction ID
const generateTransactionId = () => {
  return 'TXN' + Date.now() + Math.random().toString(36).substr(2, 9).toUpperCase();
};

// Generate barcode image
const generateBarcode = (text) => {
  const canvas = createCanvas(300, 100);
  jsbarcode(canvas, text, {
    format: 'CODE128',
    displayValue: true,
    fontSize: 16,
    background: '#ffffff',
    lineColor: '#000000',
    margin: 10
  });
  
  const barcodeData = canvas.toDataURL('image/png');
  return barcodeData;
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
      console.log('Please change the password after first login!');
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

// Initialize sample products
const initializeSampleProducts = async () => {
  try {
    const productCount = await Product.countDocuments();
    if (productCount === 0) {
      const sampleProducts = [
        {
          name: 'Algracia Moisturizing Cream',
          sku: 'AGC001',
          price: 25.99,
          cost: 12.50,
          stock: 50,
          category: 'Skincare',
          description: 'Premium moisturizing cream for all skin types',
          lowStockThreshold: 10
        },
        {
          name: 'Algracia Facial Cleanser',
          sku: 'AFC002',
          price: 18.50,
          cost: 8.75,
          stock: 75,
          category: 'Skincare',
          description: 'Gentle facial cleanser that removes impurities',
          lowStockThreshold: 10
        },
        {
          name: 'Algracia Lip Balm',
          sku: 'ALB003',
          price: 8.99,
          cost: 3.25,
          stock: 100,
          category: 'Lip Care',
          description: 'Hydrating lip balm with natural ingredients',
          lowStockThreshold: 15
        },
        {
          name: 'Algracia Body Lotion',
          sku: 'ABL004',
          price: 22.75,
          cost: 10.50,
          stock: 40,
          category: 'Body Care',
          description: 'Nourishing body lotion for smooth skin',
          lowStockThreshold: 10
        },
        {
          name: 'Algracia Face Serum',
          sku: 'AFS005',
          price: 34.99,
          cost: 16.75,
          stock: 30,
          category: 'Skincare',
          description: 'Anti-aging face serum with vitamin C',
          lowStockThreshold: 5
        }
      ];

      for (const productData of sampleProducts) {
        const barcodeText = productData.sku + Math.random().toString(10).substr(2, 5);
        productData.barcode = barcodeText;
        
        const product = new Product(productData);
        await product.save();
      }
      
      console.log('Sample products created successfully');
    }
  } catch (error) {
    console.error('Error creating sample products:', error);
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

    // Log activity
    await logActivity({ user }, 'USER_LOGIN', `User logged in: ${email}`);

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

// Barcode scanning endpoint
app.post('/api/scan/barcode', authenticateToken, upload.single('image'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ success: false, message: 'No image file provided' });
    }

    // In a real implementation, you would use a barcode scanning library
    // For demonstration, we'll simulate scanning by looking for a barcode pattern in the filename
    // In production, integrate with a proper barcode scanning library like quagga or dynamsoft
    const filename = req.file.filename;
    
    // Simulate barcode detection (this is a placeholder)
    // In a real implementation, you would process the image to detect barcodes
    let barcode = null;
    
    // Check if this is a test barcode image
    if (filename.includes('test-barcode')) {
      barcode = 'TEST123456';
    } else {
      // For real implementation, you would use:
      // const result = await scanBarcodeFromImage(req.file.path);
      // barcode = result.code;
      
      // For now, we'll simulate a random barcode detection
      barcode = 'AGC001' + Math.random().toString(10).substr(2, 5);
    }

    if (!barcode) {
      return res.status(400).json({ success: false, message: 'No barcode detected in the image' });
    }

    // Find product by barcode
    const product = await Product.findOne({ 
      $or: [{ barcode: barcode }, { sku: barcode }] 
    });

    if (!product) {
      return res.status(404).json({ success: false, message: 'Product not found for this barcode' });
    }

    // Play beep sound (simulated in response)
    res.json({
      success: true,
      message: 'Barcode scanned successfully',
      beep: true,
      product: {
        id: product._id,
        name: product.name,
        sku: product.sku,
        price: product.price,
        stock: product.stock,
        image: product.image
      }
    });

  } catch (error) {
    console.error('Barcode scan error:', error);
    res.status(500).json({ success: false, message: 'Error scanning barcode' });
  }
});

// Product lookup by barcode
app.get('/api/products/barcode/:barcode', authenticateToken, async (req, res) => {
  try {
    const { barcode } = req.params;

    const product = await Product.findOne({ 
      $or: [{ barcode: barcode }, { sku: barcode }] 
    });

    if (!product) {
      return res.status(404).json({ success: false, message: 'Product not found' });
    }

    res.json({
      success: true,
      product: {
        id: product._id,
        name: product.name,
        sku: product.sku,
        price: product.price,
        stock: product.stock,
        image: product.image
      }
    });
  } catch (error) {
    console.error('Product lookup error:', error);
    res.status(500).json({ success: false, message: 'Error looking up product' });
  }
});

// Generate barcode for a product
app.post('/api/products/:id/barcode', authenticateToken, requireManager, async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) {
      return res.status(404).json({ success: false, message: 'Product not found' });
    }

    // Generate or update barcode
    if (!product.barcode) {
      product.barcode = product.sku + Math.random().toString(10).substr(2, 5);
      await product.save();
    }

    // Generate barcode image
    const barcodeData = generateBarcode(product.barcode);

    res.json({
      success: true,
      barcode: product.barcode,
      barcodeImage: barcodeData
    });
  } catch (error) {
    console.error('Barcode generation error:', error);
    res.status(500).json({ success: false, message: 'Error generating barcode' });
  }
});

// Product routes
app.get('/api/products', authenticateToken, async (req, res) => {
  try {
    const { category, lowStock, search } = req.query;
    let filter = {};
    
    if (category && category !== 'all') filter.category = category;
    if (lowStock === 'true') filter.stock = { $lte: 10 };
    if (search) {
      filter.$or = [
        { name: { $regex: search, $options: 'i' } },
        { sku: { $regex: search, $options: 'i' } },
        { barcode: { $regex: search, $options: 'i' } }
      ];
    }

    const products = await Product.find(filter).sort({ name: 1 });
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

app.post('/api/products', authenticateToken, requireManager, upload.single('image'), [
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

    const { name, sku, price, stock, category, description, cost, lowStockThreshold } = req.body;

    // Check if product already exists
    const existingProduct = await Product.findOne({ sku });
    if (existingProduct) {
      return res.status(400).json({ success: false, message: 'Product with this SKU already exists' });
    }

    const productData = {
      name,
      sku,
      price,
      cost,
      stock,
      category,
      description,
      lowStockThreshold,
      createdBy: req.user._id
    };

    // Handle image upload
    if (req.file) {
      productData.image = `/uploads/${req.file.filename}`;
    }

    // Generate barcode
    productData.barcode = sku + Math.random().toString(10).substr(2, 5);

    const product = new Product(productData);
    await product.save();

    // Log activity and audit
    await logActivity(req, 'PRODUCT_ADDED', `Added product: ${name}`);
    await logAudit(req.user._id, 'CREATE', 'Product', product._id, { name, sku });

    res.status(201).json({ success: true, message: 'Product added successfully', product });
  } catch (error) {
    console.error('Add product error:', error);
    res.status(500).json({ success: false, message: 'Error adding product' });
  }
});

// Transaction routes
app.get('/api/transactions', authenticateToken, async (req, res) => {
  try {
    const { date, startDate, endDate, page = 1, limit = 50 } = req.query;
    let filter = {};

    if (date) {
      const startDate = new Date(date);
      const endDate = new Date(date);
      endDate.setHours(23, 59, 59, 999);
      
      filter.timestamp = { $gte: startDate, $lte: endDate };
    } else if (startDate && endDate) {
      const start = new Date(startDate);
      const end = new Date(endDate);
      end.setHours(23, 59, 59, 999);
      
      filter.timestamp = { $gte: start, $lte: end };
    }

    const options = {
      page: parseInt(page),
      limit: parseInt(limit),
      sort: { timestamp: -1 },
      populate: 'userId'
    };

    const transactions = await Transaction.paginate(filter, options);

    res.json(transactions);
  } catch (error) {
    console.error('Transactions error:', error);
    res.status(500).json({ success: false, message: 'Error loading transactions' });
  }
});

app.post('/api/transactions', authenticateToken, async (req, res) => {
  try {
    const { items, paymentMethod, paymentDetails, customer, discount = 0 } = req.body;
    
    // Validate items
    if (!items || !Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ success: false, message: 'Transaction must contain at least one item' });
    }

    // Calculate totals
    let subtotal = 0;
    const transactionItems = [];
    
    for (const item of items) {
      const product = await Product.findById(item.productId);
      if (!product) {
        return res.status(404).json({ success: false, message: `Product not found: ${item.productId}` });
      }
      
      if (product.stock < item.quantity) {
        return res.status(400).json({ 
          success: false, 
          message: `Insufficient stock for ${product.name}. Available: ${product.stock}` 
        });
      }
      
      const itemTotal = item.price * item.quantity;
      subtotal += itemTotal;
      
      transactionItems.push({
        productId: item.productId,
        name: item.name,
        price: item.price,
        quantity: item.quantity,
        total: itemTotal
      });
    }

    // Get tax rate from settings
    const settings = await Settings.findOne();
    const taxRate = settings?.taxRate || 16;
    const tax = subtotal * (taxRate / 100);
    const total = subtotal + tax - discount;

    // Create transaction
    const transaction = new Transaction({
      transactionId: generateTransactionId(),
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

    // Log activity and audit
    await logActivity(req, 'TRANSACTION_COMPLETED', `Transaction: ${transaction.transactionId}, Amount: ${total}`);
    await logAudit(req.user._id, 'CREATE', 'Transaction', transaction._id, { 
      transactionId: transaction.transactionId, 
      total 
    });

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

// Initialize default data and start server
async function startServer() {
  try {
    // Initialize default data
    await initializeDefaultAdmin();
    await initializeDefaultSettings();
    await initializeSampleProducts();
    
    // Start server
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({ success: false, message: 'Internal server error' });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ success: false, message: 'Endpoint not found' });
});

// Start the server
startServer();
