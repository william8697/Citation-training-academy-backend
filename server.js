const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const redis = require('redis');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || '17581758Na';

// Redis client setup
const redisClient = redis.createClient({
  host: process.env.REDIS_HOST || 'redis-14450.c276.us-east-1-2.ec2.redns.redis-cloud.com',
  port: process.env.REDIS_PORT || 14450,
  password: process.env.REDIS_PASSWORD || 'qjXgsg0YrsLaSumlEW9HkIZbvLjXEwXR',
});

redisClient.on('error', (err) => console.log('Redis Client Error', err));
redisClient.connect();

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/algracia_pos', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// Middleware
app.use(cors());
app.use(express.json());

// Models
const UserSchema = new mongoose.Schema({
  firstName: String,
  lastName: String,
  email: { type: String, unique: true },
  company: String,
  position: String,
  password: String,
  role: { type: String, default: 'cashier' },
  status: { type: String, default: 'pending' }, // pending, approved, rejected, inactive
  createdAt: { type: Date, default: Date.now },
});

const ProductSchema = new mongoose.Schema({
  name: String,
  sku: { type: String, unique: true },
  price: Number,
  stock: Number,
  category: String,
  createdAt: { type: Date, default: Date.now },
});

const TransactionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  items: [{
    productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product' },
    name: String,
    price: Number,
    quantity: Number
  }],
  total: Number,
  paymentMethod: String,
  cashReceived: Number,
  change: Number,
  timestamp: { type: Date, default: Date.now },
});

const ActivitySchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  action: String,
  details: String,
  timestamp: { type: Date, default: Date.now },
});

const SettingSchema = new mongoose.Schema({
  companyName: { type: String, default: 'Algracia Cosmetics' },
  currency: { type: String, default: 'USD' },
  taxRate: { type: Number, default: 16 },
  receiptFooter: { type: String, default: 'Thank you for shopping with us!' },
});

const User = mongoose.model('User', UserSchema);
const Product = mongoose.model('Product', ProductSchema);
const Transaction = mongoose.model('Transaction', TransactionSchema);
const Activity = mongoose.model('Activity', ActivitySchema);
const Setting = mongoose.model('Setting', SettingSchema);

// Auth middleware
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ success: false, message: 'Access token required' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId);
    
    if (!user) {
      return res.status(403).json({ success: false, message: 'Invalid token' });
    }

    req.user = user;
    next();
  } catch (error) {
    return res.status(403).json({ success: false, message: 'Invalid token' });
  }
};

const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ success: false, message: 'Admin access required' });
  }
  next();
};

// Routes

// Auth routes
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { firstName, lastName, email, company, position, password } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ success: false, message: 'User already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const user = new User({
      firstName,
      lastName,
      email,
      company,
      position,
      password: hashedPassword,
      status: 'pending'
    });

    await user.save();

    // Log activity
    const activity = new Activity({
      action: 'User Signup',
      details: `${firstName} ${lastName} from ${company} requested access`
    });
    await activity.save();

    res.status(201).json({ 
      success: true, 
      message: 'Account request submitted for approval',
      requiresApproval: true
    });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ success: false, message: 'Server error during signup' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ success: false, message: 'Invalid credentials' });
    }

    // Check status
    if (user.status !== 'approved') {
      return res.status(400).json({ success: false, message: 'Account pending approval' });
    }

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ success: false, message: 'Invalid credentials' });
    }

    // Generate token
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '24h' });

    // Cache user data in Redis
    await redisClient.setEx(`user:${user._id}`, 86400, JSON.stringify(user));

    res.json({
      success: true,
      token,
      user: {
        _id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        company: user.company,
        position: user.position,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ success: false, message: 'Server error during login' });
  }
});

app.get('/api/auth/verify', authenticateToken, (req, res) => {
  res.json({
    success: true,
    user: {
      _id: req.user._id,
      firstName: req.user.firstName,
      lastName: req.user.lastName,
      email: req.user.email,
      company: req.user.company,
      position: req.user.position,
      role: req.user.role
    }
  });
});

// Product routes
app.get('/api/products', authenticateToken, async (req, res) => {
  try {
    const cacheKey = 'products:all';
    const cachedProducts = await redisClient.get(cacheKey);
    
    if (cachedProducts) {
      return res.json(JSON.parse(cachedProducts));
    }

    const products = await Product.find({ stock: { $gt: 0 } });
    
    // Cache for 5 minutes
    await redisClient.setEx(cacheKey, 300, JSON.stringify(products));
    
    res.json(products);
  } catch (error) {
    console.error('Products error:', error);
    res.status(500).json({ success: false, message: 'Server error fetching products' });
  }
});

app.post('/api/products', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { name, sku, price, stock, category } = req.body;

    const product = new Product({
      name,
      sku,
      price,
      stock,
      category
    });

    await product.save();

    // Invalidate cache
    await redisClient.del('products:all');
    await redisClient.del('dashboard:stats');

    // Log activity
    const activity = new Activity({
      userId: req.user._id,
      action: 'Product Added',
      details: `Added product: ${name} (SKU: ${sku})`
    });
    await activity.save();

    res.status(201).json({ success: true, product });
  } catch (error) {
    console.error('Add product error:', error);
    res.status(500).json({ success: false, message: 'Server error adding product' });
  }
});

// Transaction routes
app.post('/api/transactions', authenticateToken, async (req, res) => {
  try {
    const { paymentMethod, amount, cashReceived, change, cart } = req.body;

    const transaction = new Transaction({
      userId: req.user._id,
      items: cart,
      total: amount,
      paymentMethod,
      cashReceived,
      change
    });

    await transaction.save();

    // Update product stock
    for (const item of cart) {
      await Product.findByIdAndUpdate(
        item.productId,
        { $inc: { stock: -item.quantity } }
      );
    }

    // Invalidate cache
    await redisClient.del('dashboard:stats');
    await redisClient.del('transactions:recent');

    // Log activity
    const activity = new Activity({
      userId: req.user._id,
      action: 'Transaction Completed',
      details: `Transaction #${transaction._id} for $${amount} via ${paymentMethod}`
    });
    await activity.save();

    res.status(201).json({ 
      success: true, 
      transactionId: transaction._id 
    });
  } catch (error) {
    console.error('Transaction error:', error);
    res.status(500).json({ success: false, message: 'Server error processing transaction' });
  }
});

// Admin routes
app.get('/api/admin/dashboard', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const cacheKey = 'dashboard:stats';
    const cachedStats = await redisClient.get(cacheKey);
    
    if (cachedStats) {
      return res.json(JSON.parse(cachedStats));
    }

    const pendingApprovals = await User.countDocuments({ status: 'pending' });
    const totalUsers = await User.countDocuments({ status: 'approved' });
    
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const todaySales = await Transaction.aggregate([
      { $match: { timestamp: { $gte: today } } },
      { $group: { _id: null, total: { $sum: '$total' } } }
    ]);
    
    const lowStockItems = await Product.countDocuments({ stock: { $lt: 10, $gt: 0 } });

    const stats = {
      pendingApprovals,
      totalUsers,
      todaySales: todaySales.length > 0 ? todaySales[0].total : 0,
      lowStockItems
    };

    // Cache for 5 minutes
    await redisClient.setEx(cacheKey, 300, JSON.stringify(stats));

    res.json(stats);
  } catch (error) {
    console.error('Dashboard error:', error);
    res.status(500).json({ success: false, message: 'Server error fetching dashboard data' });
  }
});

app.get('/api/admin/pending-approvals', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const users = await User.find({ status: 'pending' }).select('-password');
    res.json(users);
  } catch (error) {
    console.error('Pending approvals error:', error);
    res.status(500).json({ success: false, message: 'Server error fetching pending approvals' });
  }
});

app.post('/api/admin/approve-user/:userId', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(
      req.params.userId,
      { status: 'approved' },
      { new: true }
    ).select('-password');

    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Invalidate cache
    await redisClient.del('dashboard:stats');

    // Log activity
    const activity = new Activity({
      userId: req.user._id,
      action: 'User Approved',
      details: `Approved user: ${user.firstName} ${user.lastName} (${user.email})`
    });
    await activity.save();

    res.json({ success: true, user });
  } catch (error) {
    console.error('Approve user error:', error);
    res.status(500).json({ success: false, message: 'Server error approving user' });
  }
});

app.post('/api/admin/reject-user/:userId', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(
      req.params.userId,
      { status: 'rejected' },
      { new: true }
    ).select('-password');

    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Invalidate cache
    await redisClient.del('dashboard:stats');

    // Log activity
    const activity = new Activity({
      userId: req.user._id,
      action: 'User Rejected',
      details: `Rejected user: ${user.firstName} ${user.lastName} (${user.email})`
    });
    await activity.save();

    res.json({ success: true, user });
  } catch (error) {
    console.error('Reject user error:', error);
    res.status(500).json({ success: false, message: 'Server error rejecting user' });
  }
});

app.get('/api/admin/users/active', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const users = await User.find({ status: 'approved' }).select('-password');
    res.json(users);
  } catch (error) {
    console.error('Active users error:', error);
    res.status(500).json({ success: false, message: 'Server error fetching active users' });
  }
});

app.get('/api/admin/users/inactive', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const users = await User.find({ status: 'inactive' }).select('-password');
    res.json(users);
  } catch (error) {
    console.error('Inactive users error:', error);
    res.status(500).json({ success: false, message: 'Server error fetching inactive users' });
  }
});

app.post('/api/admin/users/:userId/deactivate', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(
      req.params.userId,
      { status: 'inactive' },
      { new: true }
    ).select('-password');

    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Log activity
    const activity = new Activity({
      userId: req.user._id,
      action: 'User Deactivated',
      details: `Deactivated user: ${user.firstName} ${user.lastName} (${user.email})`
    });
    await activity.save();

    res.json({ success: true, user });
  } catch (error) {
    console.error('Deactivate user error:', error);
    res.status(500).json({ success: false, message: 'Server error deactivating user' });
  }
});

app.post('/api/admin/users/:userId/activate', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(
      req.params.userId,
      { status: 'approved' },
      { new: true }
    ).select('-password');

    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Log activity
    const activity = new Activity({
      userId: req.user._id,
      action: 'User Activated',
      details: `Activated user: ${user.firstName} ${user.lastName} (${user.email})`
    });
    await activity.save();

    res.json({ success: true, user });
  } catch (error) {
    console.error('Activate user error:', error);
    res.status(500).json({ success: false, message: 'Server error activating user' });
  }
});

app.delete('/api/admin/users/:userId', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const user = await User.findByIdAndDelete(req.params.userId);

    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Invalidate cache
    await redisClient.del('dashboard:stats');

    // Log activity
    const activity = new Activity({
      userId: req.user._id,
      action: 'User Deleted',
      details: `Deleted user: ${user.firstName} ${user.lastName} (${user.email})`
    });
    await activity.save();

    res.json({ success: true, message: 'User deleted successfully' });
  } catch (error) {
    console.error('Delete user error:', error);
    res.status(500).json({ success: false, message: 'Server error deleting user' });
  }
});

app.get('/api/admin/inventory', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const inventory = await Product.find().sort({ name: 1 });
    res.json(inventory);
  } catch (error) {
    console.error('Inventory error:', error);
    res.status(500).json({ success: false, message: 'Server error fetching inventory' });
  }
});

app.delete('/api/admin/inventory/:productId', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const product = await Product.findByIdAndDelete(req.params.productId);

    if (!product) {
      return res.status(404).json({ success: false, message: 'Product not found' });
    }

    // Invalidate cache
    await redisClient.del('products:all');
    await redisClient.del('dashboard:stats');

    // Log activity
    const activity = new Activity({
      userId: req.user._id,
      action: 'Product Deleted',
      details: `Deleted product: ${product.name} (SKU: ${product.sku})`
    });
    await activity.save();

    res.json({ success: true, message: 'Product deleted successfully' });
  } catch (error) {
    console.error('Delete product error:', error);
    res.status(500).json({ success: false, message: 'Server error deleting product' });
  }
});

app.get('/api/admin/transactions', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { date } = req.query;
    let query = {};
    
    if (date) {
      const startDate = new Date(date);
      const endDate = new Date(date);
      endDate.setDate(endDate.getDate() + 1);
      
      query.timestamp = { $gte: startDate, $lt: endDate };
    }
    
    const transactions = await Transaction.find(query)
      .populate('userId', 'firstName lastName')
      .sort({ timestamp: -1 })
      .limit(50);
    
    res.json(transactions);
  } catch (error) {
    console.error('Transactions error:', error);
    res.status(500).json({ success: false, message: 'Server error fetching transactions' });
  }
});

app.get('/api/admin/activities', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const activities = await Activity.find()
      .populate('userId', 'firstName lastName')
      .sort({ timestamp: -1 })
      .limit(20);
    
    res.json(activities);
  } catch (error) {
    console.error('Activities error:', error);
    res.status(500).json({ success: false, message: 'Server error fetching activities' });
  }
});

app.get('/api/admin/reports', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { type } = req.query;
    let groupBy = {};
    let match = {};
    
    // Set date range based on report type
    const now = new Date();
    if (type === 'daily') {
      const startDate = new Date(now);
      startDate.setDate(startDate.getDate() - 7);
      
      match.timestamp = { $gte: startDate };
      groupBy = {
        year: { $year: '$timestamp' },
        month: { $month: '$timestamp' },
        day: { $dayOfMonth: '$timestamp' }
      };
    } else if (type === 'weekly') {
      const startDate = new Date(now);
      startDate.setDate(startDate.getDate() - 30);
      
      match.timestamp = { $gte: startDate };
      groupBy = {
        year: { $year: '$timestamp' },
        week: { $week: '$timestamp' }
      };
    } else if (type === 'monthly') {
      const startDate = new Date(now);
      startDate.setFullYear(startDate.getFullYear() - 1);
      
      match.timestamp = { $gte: startDate };
      groupBy = {
        year: { $year: '$timestamp' },
        month: { $month: '$timestamp' }
      };
    }
    
    const reportData = await Transaction.aggregate([
      { $match: match },
      {
        $group: {
          _id: groupBy,
          totalSales: { $sum: '$total' },
          count: { $sum: 1 }
        }
      },
      { $sort: { '_id.year': 1, '_id.month': 1, '_id.week': 1, '_id.day': 1 } }
    ]);
    
    // Format data for chart
    const labels = [];
    const data = [];
    
    reportData.forEach(item => {
      if (type === 'daily') {
        labels.push(`${item._id.month}/${item._id.day}/${item._id.year}`);
      } else if (type === 'weekly') {
        labels.push(`Week ${item._id.week}, ${item._id.year}`);
      } else if (type === 'monthly') {
        const monthNames = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
        labels.push(`${monthNames[item._id.month - 1]} ${item._id.year}`);
      }
      
      data.push(item.totalSales);
    });
    
    res.json({ labels, data });
  } catch (error) {
    console.error('Reports error:', error);
    res.status(500).json({ success: false, message: 'Server error generating report' });
  }
});

app.post('/api/admin/settings', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { companyName, currency, taxRate, receiptFooter } = req.body;
    
    let settings = await Setting.findOne();
    if (!settings) {
      settings = new Setting();
    }
    
    settings.companyName = companyName || settings.companyName;
    settings.currency = currency || settings.currency;
    settings.taxRate = taxRate || settings.taxRate;
    settings.receiptFooter = receiptFooter || settings.receiptFooter;
    
    await settings.save();
    
    // Log activity
    const activity = new Activity({
      userId: req.user._id,
      action: 'Settings Updated',
      details: 'System settings were updated'
    });
    await activity.save();
    
    res.json({ success: true, settings });
  } catch (error) {
    console.error('Settings error:', error);
    res.status(500).json({ success: false, message: 'Server error saving settings' });
  }
});

// Initialize settings if not exists
async function initializeSettings() {
  const settings = await Setting.findOne();
  if (!settings) {
    const defaultSettings = new Setting();
    await defaultSettings.save();
    console.log('Default settings initialized');
  }
}

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  initializeSettings();
});
