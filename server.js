const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { body, validationResult } = require('express-validator');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/algracia_pos';

// Security middleware
app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || "http://localhost:3000",
  credentials: true
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// MongoDB connection
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('MongoDB connected successfully'))
.catch(err => console.error('MongoDB connection error:', err));

// MongoDB Schemas
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['admin', 'cashier'], default: 'cashier' },
  fullName: { type: String, required: true },
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
});

const ProductSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String },
  price: { type: Number, required: true, min: 0 },
  cost: { type: Number, min: 0 },
  barcode: { type: String, unique: true, sparse: true },
  category: { type: String, default: 'cosmetics' },
  stock: { type: Number, default: 0, min: 0 },
  minStock: { type: Number, default: 5, min: 0 },
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const TransactionSchema = new mongoose.Schema({
  items: [{
    product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
    quantity: { type: Number, required: true, min: 1 },
    price: { type: Number, required: true, min: 0 }
  }],
  total: { type: Number, required: true, min: 0 },
  tax: { type: Number, default: 0 },
  discount: { type: Number, default: 0 },
  paymentMethod: { type: String, enum: ['cash', 'card', 'mobile'], default: 'cash' },
  cashier: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  status: { type: String, enum: ['completed', 'refunded', 'pending'], default: 'completed' },
  createdAt: { type: Date, default: Date.now }
});

const InventoryLogSchema = new mongoose.Schema({
  product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
  change: { type: Number, required: true }, // Positive for addition, negative for deduction
  reason: { type: String, required: true }, // sale, restock, adjustment, etc.
  reference: { type: mongoose.Schema.Types.ObjectId, refPath: 'refModel' },
  refModel: { type: String, enum: ['Transaction', 'User'] },
  performedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  createdAt: { type: Date, default: Date.now }
});

// Models
const User = mongoose.model('User', UserSchema);
const Product = mongoose.model('Product', ProductSchema);
const Transaction = mongoose.model('Transaction', TransactionSchema);
const InventoryLog = mongoose.model('InventoryLog', InventoryLogSchema);

// Authentication middleware
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'fallback_secret');
    const user = await User.findById(decoded.userId).select('-password');
    if (!user || !user.isActive) {
      return res.status(403).json({ error: 'User not found or inactive' });
    }
    req.user = user;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
};

// Authorization middleware
const requireRole = (role) => {
  return (req, res, next) => {
    if (req.user.role !== role) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
};

// Validation middleware
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  next();
};

// Routes

// Auth routes
app.post('/api/auth/login', [
  body('username').notEmpty().withMessage('Username is required'),
  body('password').notEmpty().withMessage('Password is required')
], handleValidationErrors, async (req, res) => {
  try {
    const { username, password } = req.body;
    
    const user = await User.findOne({ username, isActive: true });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { userId: user._id, role: user.role },
      process.env.JWT_SECRET || 'fallback_secret',
      { expiresIn: '8h' }
    );

    res.json({
      token,
      user: {
        id: user._id,
        username: user.username,
        role: user.role,
        fullName: user.fullName
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Product routes
app.get('/api/products', authenticateToken, async (req, res) => {
  try {
    const { search, category, lowStock } = req.query;
    let query = { isActive: true };

    if (search) {
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { barcode: search }
      ];
    }

    if (category && category !== 'all') {
      query.category = category;
    }

    if (lowStock === 'true') {
      query.$expr = { $lte: ['$stock', '$minStock'] };
    }

    const products = await Product.find(query).sort({ name: 1 });
    res.json(products);
  } catch (error) {
    console.error('Get products error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/products/:id', authenticateToken, async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }
    res.json(product);
  } catch (error) {
    console.error('Get product error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/products', [
  authenticateToken,
  requireRole('admin'),
  body('name').notEmpty().withMessage('Product name is required'),
  body('price').isFloat({ min: 0 }).withMessage('Price must be a positive number'),
  body('stock').isInt({ min: 0 }).withMessage('Stock must be a non-negative integer')
], handleValidationErrors, async (req, res) => {
  try {
    const productData = req.body;
    productData.updatedAt = new Date();
    
    const product = new Product(productData);
    await product.save();
    
    res.status(201).json(product);
  } catch (error) {
    if (error.code === 11000) {
      return res.status(400).json({ error: 'Barcode already exists' });
    }
    console.error('Create product error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/api/products/:id', [
  authenticateToken,
  requireRole('admin'),
  body('name').notEmpty().withMessage('Product name is required'),
  body('price').isFloat({ min: 0 }).withMessage('Price must be a positive number'),
  body('stock').isInt({ min: 0 }).withMessage('Stock must be a non-negative integer')
], handleValidationErrors, async (req, res) => {
  try {
    const productData = req.body;
    productData.updatedAt = new Date();
    
    const product = await Product.findByIdAndUpdate(
      req.params.id,
      productData,
      { new: true, runValidators: true }
    );
    
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }
    
    res.json(product);
  } catch (error) {
    if (error.code === 11000) {
      return res.status(400).json({ error: 'Barcode already exists' });
    }
    console.error('Update product error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.delete('/api/products/:id', [authenticateToken, requireRole('admin')], async (req, res) => {
  try {
    const product = await Product.findByIdAndUpdate(
      req.params.id,
      { isActive: false, updatedAt: new Date() },
      { new: true }
    );
    
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }
    
    res.json({ message: 'Product deleted successfully' });
  } catch (error) {
    console.error('Delete product error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POS routes
app.post('/api/pos/scan', [
  authenticateToken,
  body('barcode').notEmpty().withMessage('Barcode is required')
], handleValidationErrors, async (req, res) => {
  try {
    const { barcode } = req.body;
    const product = await Product.findOne({ barcode, isActive: true });
    
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }
    
    res.json(product);
  } catch (error) {
    console.error('Scan product error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/pos/checkout', [
  authenticateToken,
  body('items').isArray({ min: 1 }).withMessage('At least one item is required'),
  body('items.*.productId').notEmpty().withMessage('Product ID is required'),
  body('items.*.quantity').isInt({ min: 1 }).withMessage('Quantity must be at least 1'),
  body('paymentMethod').isIn(['cash', 'card', 'mobile']).withMessage('Invalid payment method')
], handleValidationErrors, async (req, res) => {
  const session = await mongoose.startSession();
  session.startTransaction();
  
  try {
    const { items, paymentMethod, discount = 0, tax = 0 } = req.body;
    const cashierId = req.user._id;
    
    // Calculate total and prepare transaction items
    let total = 0;
    const transactionItems = [];
    const inventoryUpdates = [];
    
    for (const item of items) {
      const product = await Product.findById(item.productId).session(session);
      if (!product || !product.isActive) {
        await session.abortTransaction();
        session.endSession();
        return res.status(404).json({ error: `Product ${item.productId} not found` });
      }
      
      if (product.stock < item.quantity) {
        await session.abortTransaction();
        session.endSession();
        return res.status(400).json({ error: `Insufficient stock for ${product.name}` });
      }
      
      const itemTotal = product.price * item.quantity;
      total += itemTotal;
      
      transactionItems.push({
        product: product._id,
        quantity: item.quantity,
        price: product.price
      });
      
      // Prepare inventory update
      inventoryUpdates.push({
        updateOne: {
          filter: { _id: product._id },
          update: { $inc: { stock: -item.quantity }, $set: { updatedAt: new Date() } }
        }
      });
      
      // Prepare inventory log
      inventoryUpdates.push({
        insertOne: {
          document: {
            product: product._id,
            change: -item.quantity,
            reason: 'sale',
            reference: null, // Will be updated after transaction creation
            refModel: 'Transaction',
            performedBy: cashierId,
            createdAt: new Date()
          }
        }
      });
    }
    
    // Apply discount and tax
    total = total - discount + (total * (tax / 100));
    
    // Create transaction
    const transaction = new Transaction({
      items: transactionItems,
      total,
      tax,
      discount,
      paymentMethod,
      cashier: cashierId,
      status: 'completed'
    });
    
    await transaction.save({ session });
    
    // Update inventory logs with transaction reference
    const inventoryLogs = inventoryUpdates.filter(update => update.insertOne);
    for (const log of inventoryLogs) {
      if (log.insertOne && log.insertOne.document) {
        log.insertOne.document.reference = transaction._id;
      }
    }
    
    // Execute all inventory updates
    if (inventoryUpdates.length > 0) {
      await InventoryLog.bulkWrite(inventoryUpdates, { session });
    }
    
    await session.commitTransaction();
    session.endSession();
    
    res.status(201).json({
      message: 'Transaction completed successfully',
      transactionId: transaction._id,
      total: transaction.total
    });
    
  } catch (error) {
    await session.abortTransaction();
    session.endSession();
    console.error('Checkout error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Transaction routes
app.get('/api/transactions', authenticateToken, async (req, res) => {
  try {
    const { page = 1, limit = 50, startDate, endDate } = req.query;
    const query = {};
    
    if (startDate && endDate) {
      query.createdAt = {
        $gte: new Date(startDate),
        $lte: new Date(endDate)
      };
    }
    
    const options = {
      page: parseInt(page),
      limit: parseInt(limit),
      sort: { createdAt: -1 },
      populate: [
        { path: 'cashier', select: 'fullName' },
        { path: 'items.product', select: 'name barcode' }
      ]
    };
    
    const transactions = await Transaction.paginate(query, options);
    res.json(transactions);
  } catch (error) {
    console.error('Get transactions error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/transactions/:id', authenticateToken, async (req, res) => {
  try {
    const transaction = await Transaction.findById(req.params.id)
      .populate('cashier', 'fullName')
      .populate('items.product', 'name barcode price');
    
    if (!transaction) {
      return res.status(404).json({ error: 'Transaction not found' });
    }
    
    res.json(transaction);
  } catch (error) {
    console.error('Get transaction error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Dashboard routes
app.get('/api/dashboard/stats', authenticateToken, async (req, res) => {
  try {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    
    const tomorrow = new Date(today);
    tomorrow.setDate(tomorrow.getDate() + 1);
    
    // Today's sales
    const todaySales = await Transaction.aggregate([
      {
        $match: {
          createdAt: { $gte: today, $lt: tomorrow },
          status: 'completed'
        }
      },
      {
        $group: {
          _id: null,
          totalSales: { $sum: '$total' },
          transactionCount: { $sum: 1 }
        }
      }
    ]);
    
    // Inventory stats
    const inventoryStats = await Product.aggregate([
      {
        $match: { isActive: true }
      },
      {
        $group: {
          _id: null,
          totalProducts: { $sum: 1 },
          lowStockItems: {
            $sum: {
              $cond: [{ $lte: ['$stock', '$minStock'] }, 1, 0]
            }
          }
        }
      }
    ]);
    
    // Format response
    const result = {
      totalSales: todaySales[0]?.totalSales || 0,
      transactionCount: todaySales[0]?.transactionCount || 0,
      totalProducts: inventoryStats[0]?.totalProducts || 0,
      lowStockItems: inventoryStats[0]?.lowStockItems || 0
    };
    
    res.json(result);
  } catch (error) {
    console.error('Dashboard stats error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Admin routes
app.get('/api/admin/users', [authenticateToken, requireRole('admin')], async (req, res) => {
  try {
    const users = await User.find().select('-password').sort({ createdAt: -1 });
    res.json(users);
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/admin/users', [
  authenticateToken,
  requireRole('admin'),
  body('username').notEmpty().withMessage('Username is required'),
  body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
  body('fullName').notEmpty().withMessage('Full name is required'),
  body('role').isIn(['admin', 'cashier']).withMessage('Role must be admin or cashier')
], handleValidationErrors, async (req, res) => {
  try {
    const { username, password, fullName, role } = req.body;
    
    // Check if user already exists
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ error: 'Username already exists' });
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);
    
    // Create user
    const user = new User({
      username,
      password: hashedPassword,
      fullName,
      role
    });
    
    await user.save();
    
    res.status(201).json({
      message: 'User created successfully',
      user: {
        id: user._id,
        username: user.username,
        role: user.role,
        fullName: user.fullName,
        isActive: user.isActive
      }
    });
  } catch (error) {
    console.error('Create user error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/api/admin/users/:id', [authenticateToken, requireRole('admin')], async (req, res) => {
  try {
    const { fullName, role, isActive } = req.body;
    const updateData = { fullName, role, isActive };
    
    // Don't update password here
    if (req.body.password) {
      delete updateData.password;
    }
    
    const user = await User.findByIdAndUpdate(
      req.params.id,
      updateData,
      { new: true, runValidators: true }
    ).select('-password');
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json({
      message: 'User updated successfully',
      user
    });
  } catch (error) {
    console.error('Update user error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Initialize admin user if not exists
const initializeAdminUser = async () => {
  try {
    const adminExists = await User.findOne({ role: 'admin' });
    if (!adminExists) {
      const hashedPassword = await bcrypt.hash('admin123', 12);
      const adminUser = new User({
        username: 'admin',
        password: hashedPassword,
        fullName: 'System Administrator',
        role: 'admin'
      });
      await adminUser.save();
      console.log('Default admin user created: username=admin, password=admin123');
    }
  } catch (error) {
    console.error('Error initializing admin user:', error);
  }
};

// Add pagination plugin to mongoose
mongoose.plugin(require('mongoose-paginate-v2'));

// Start server
app.listen(PORT, async () => {
  console.log(`Server running on port ${PORT}`);
  await initializeAdminUser();
  
  // Create some sample products if none exist
  const productCount = await Product.countDocuments();
  if (productCount === 0) {
    const sampleProducts = [
      {
        name: "Hydrating Face Cream",
        price: 24.99,
        cost: 12.50,
        barcode: "800123456789",
        category: "skincare",
        stock: 50,
        minStock: 5
      },
      {
        name: "Vitamin C Serum",
        price: 34.99,
        cost: 18.00,
        barcode: "800123456790",
        category: "skincare",
        stock: 35,
        minStock: 5
      },
      {
        name: "Exfoliating Scrub",
        price: 19.99,
        cost: 9.50,
        barcode: "800123456791",
        category: "skincare",
        stock: 40,
        minStock: 5
      },
      {
        name: "Anti-Aging Eye Cream",
        price: 29.99,
        cost: 14.00,
        barcode: "800123456792",
        category: "skincare",
        stock: 25,
        minStock: 3
      },
      {
        name: "Hydrating Toner",
        price: 16.99,
        cost: 7.50,
        barcode: "800123456793",
        category: "skincare",
        stock: 60,
        minStock: 5
      },
      {
        name: "Overnight Mask",
        price: 26.50,
        cost: 12.00,
        barcode: "800123456794",
        category: "skincare",
        stock: 30,
        minStock: 5
      }
    ];
    
    await Product.insertMany(sampleProducts);
    console.log('Sample products created');
  }
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

module.exports = app;
