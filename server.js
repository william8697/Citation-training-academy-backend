const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const validator = require('validator');
const crypto = require('crypto');
const path = require('path');
require('dotenv').config();

const app = express();

const corsOptions = {
  origin: function (origin, callback) {
    const allowedOrigins = [
      'https://citation-training-academy.vercel.app',
      'https://citation-training-academy-1b8h.vercel.app',
      'http://localhost:3000',
      'http://127.0.0.1:3000',
      'https://bithashcapital.com',
      'https://www.bithashcapital.live'
    ];
    
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin']
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" },
  contentSecurityPolicy: false
}));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 1000,
  message: {
    status: 'error',
    message: 'Too many requests from this IP, please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false
});
app.use(limiter);

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '24h';

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://elvismwangike:JFJmHvP4ktikRYDC@cluster0.vm6hrog.mongodb.net/bithash?retryWrites=true&w=majority&appName=Cluster0';

mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('MongoDB connected successfully'))
.catch(err => {
  console.error('MongoDB connection error:', err);
  process.exit(1);
});

const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST || 'smtp.gmail.com',
  port: process.env.EMAIL_PORT || 587,
  secure: process.env.EMAIL_SECURE === 'true',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  },
  tls: {
    rejectUnauthorized: false
  }
});

transporter.verify(function(error, success) {
  if (error) {
    console.error('Email configuration error:', error);
  } else {
    console.log('Email server is ready to send messages');
  }
});

const adminUserSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: 3,
    maxlength: 50
  },
  password: {
    type: String,
    required: true,
    minlength: 6
  },
  name: {
    type: String,
    required: true,
    trim: true,
    maxlength: 100
  },
  role: {
    type: String,
    default: 'admin',
    enum: ['admin', 'superadmin']
  },
  lastLogin: {
    type: Date,
    default: Date.now
  },
  isActive: {
    type: Boolean,
    default: true
  }
}, {
  timestamps: true
});

adminUserSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

const investorSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    validate: [validator.isEmail, 'Please provide a valid email']
  },
  name: {
    type: String,
    required: true,
    trim: true,
    maxlength: 100
  },
  phone: {
    type: String,
    trim: true
  },
  country: {
    type: String,
    trim: true
  },
  joinDate: {
    type: Date,
    default: Date.now
  },
  tier: {
    type: String,
    default: 'Standard',
    enum: ['Standard', 'Premium', 'VIP']
  },
  status: {
    type: String,
    default: 'active',
    enum: ['active', 'inactive', 'new']
  },
  totalInvested: {
    type: Number,
    default: 0
  },
  lastContact: Date,
  notes: String,
  tags: [String]
}, {
  timestamps: true
});

const emailTemplateSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true,
    maxlength: 100
  },
  subject: {
    type: String,
    required: true,
    trim: true,
    maxlength: 200
  },
  content: {
    type: String,
    required: true
  },
  category: {
    type: String,
    default: 'general',
    enum: ['general', 'promotional', 'update', 'alert']
  },
  isActive: {
    type: Boolean,
    default: true
  },
  usedCount: {
    type: Number,
    default: 0
  },
  lastUsed: Date
}, {
  timestamps: true
});

const emailCampaignSchema = new mongoose.Schema({
  subject: {
    type: String,
    required: true,
    trim: true,
    maxlength: 200
  },
  content: {
    type: String,
    required: true
  },
  recipients: [{
    investorId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Investor'
    },
    email: String,
    name: String,
    status: {
      type: String,
      default: 'sent',
      enum: ['sent', 'delivered', 'opened', 'failed']
    },
    openedAt: Date,
    error: String
  }],
  sentBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'AdminUser',
    required: true
  },
  sentAt: {
    type: Date,
    default: Date.now
  },
  scheduledFor: Date,
  enableTracking: {
    type: Boolean,
    default: true
  },
  openCount: {
    type: Number,
    default: 0
  },
  status: {
    type: String,
    default: 'draft',
    enum: ['draft', 'scheduled', 'sent', 'failed']
  },
  templateId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'EmailTemplate'
  },
  metadata: {
    ipAddress: String,
    userAgent: String
  }
}, {
  timestamps: true
});

const trackingPixelSchema = new mongoose.Schema({
  campaignId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'EmailCampaign',
    required: true
  },
  recipientId: {
    type: mongoose.Schema.Types.ObjectId,
    required: true
  },
  openedAt: {
    type: Date,
    default: Date.now
  },
  ipAddress: String,
  userAgent: String
}, {
  timestamps: true
});

const AdminUser = mongoose.model('AdminUser', adminUserSchema);
const Investor = mongoose.model('Investor', investorSchema);
const EmailTemplate = mongoose.model('EmailTemplate', emailTemplateSchema);
const EmailCampaign = mongoose.model('EmailCampaign', emailCampaignSchema);
const TrackingPixel = mongoose.model('TrackingPixel', trackingPixelSchema);

const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({
        status: 'error',
        message: 'Access token required'
      });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await AdminUser.findById(decoded.id).select('-password');
    
    if (!user || !user.isActive) {
      return res.status(401).json({
        status: 'error',
        message: 'User not found or inactive'
      });
    }

    req.user = user;
    next();
  } catch (error) {
    return res.status(403).json({
      status: 'error',
      message: 'Invalid or expired token'
    });
  }
};

const generateEmailTemplate = (content, trackingPixel = null, subject = 'BitHash Capital') => {
  const logoUrl = 'https://www.dropbox.com/scl/fi/1dq16nex1borvvknpcwox/circular_dark_background.png?rlkey=sq2ujl2oxxk9vyvg1j7oz0cdb&raw=1';
  
  return `
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${subject} - BitHash Capital</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Inter', Arial, sans-serif; line-height: 1.6; color: #1a1a1a; background-color: #f8f9fa; margin: 0; padding: 0; }
        .container { max-width: 600px; margin: 0 auto; background: #ffffff; }
        .header { background: #0a0a0a; padding: 30px 40px; text-align: center; border-bottom: 3px solid #f0b90b; }
        .logo-container { display: flex; align-items: center; justify-content: center; gap: 15px; margin-bottom: 15px; }
        .logo-img { width: 40px; height: 40px; border-radius: 50%; }
        .logo-text { font-size: 24px; font-weight: 700; color: #f0b90b; letter-spacing: -0.5px; }
        .content { padding: 40px; background: #ffffff; }
        .footer { background: #0a0a0a; padding: 25px 40px; text-align: center; color: #999; }
        .footer-text { font-size: 12px; line-height: 1.5; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo-container">
                <img src="${logoUrl}" alt="BitHash Logo" class="logo-img">
                <div class="logo-text">BitHash Capital</div>
            </div>
        </div>
        <div class="content">
            ${content}
        </div>
        <div class="footer">
            <p class="footer-text">© 2024 BitHash Capital. All rights reserved.<br>
            This is an automated message. Please do not reply.</p>
        </div>
    </div>
</body>
</html>
  `;
};

const PREDEFINED_TEMPLATES = [
  {
    name: 'BitHash Investment Opportunity',
    subject: 'Grow Your Crypto with BitHash Capital - Professional Bitcoin Mining',
    content: `
      <h2>Unlock the Power of Bitcoin Mining</h2>
      
      <p>Dear Investor,</p>
      
      <p>Instead of letting your cryptocurrency sit idle in your wallet, why not put it to work with BitHash Capital? We offer professional Bitcoin mining services that allow you to earn consistent returns on your crypto investments.</p>
      
      <h3>Why Choose BitHash Capital?</h3>
      
      <p>Professional Mining Operations: State-of-the-art ASIC miners running 24/7 in our secure, energy-efficient data centers across North America and Europe.</p>
      
      <p>Competitive Returns: Earn consistent daily returns on your investment with our optimized mining operations and strategic power contracts.</p>
      
      <p>Bitcoin-Backed Loans: Access low-interest loans using your Bitcoin as collateral, giving you liquidity without selling your assets.</p>
      
      <p>50% Deposit Bonus: Enjoy a 50% bonus on your first deposit to maximize your mining power from day one.</p>
      
      <p>Ready to put your crypto to work? Log in to your dashboard to explore our investment plans and start earning today.</p>
      
      <p>Best regards,<br>
      <strong>The BitHash Capital Team</strong></p>
    `,
    category: 'promotional'
  }
];

app.get('/health', (req, res) => {
  res.json({
    status: 'success',
    message: 'Server is running smoothly',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

app.post('/admin/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        status: 'error',
        message: 'Username and password are required'
      });
    }

    const user = await AdminUser.findOne({ username, isActive: true });
    if (!user) {
      return res.status(401).json({
        status: 'error',
        message: 'Invalid credentials'
      });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({
        status: 'error',
        message: 'Invalid credentials'
      });
    }

    user.lastLogin = new Date();
    await user.save();

    const token = jwt.sign(
      { id: user._id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );

    res.json({
      status: 'success',
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        username: user.username,
        name: user.name,
        role: user.role,
        lastLogin: user.lastLogin
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      status: 'error',
      message: 'Internal server error during login'
    });
  }
});

app.get('/admin/stats', authenticateToken, async (req, res) => {
  try {
    const totalInvestors = await Investor.countDocuments({ status: 'active' });
    const emailsSent = await EmailCampaign.countDocuments({ status: 'sent' });
    
    const emailCampaigns = await EmailCampaign.find({ status: 'sent' });
    let totalRecipients = 0;
    let totalOpens = 0;

    emailCampaigns.forEach(campaign => {
      totalRecipients += campaign.recipients.length;
      totalOpens += campaign.openCount;
    });

    const openRate = totalRecipients > 0 ? (totalOpens / totalRecipients * 100).toFixed(1) : 0;

    res.json({
      status: 'success',
      data: {
        totalInvestors,
        emailsSent,
        openRate: parseFloat(openRate),
        lastActivity: new Date().toISOString()
      }
    });

  } catch (error) {
    console.error('Stats error:', error);
    res.status(500).json({
      status: 'error',
      message: 'Failed to load statistics'
    });
  }
});

app.get('/admin/investors', authenticateToken, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const search = req.query.search || '';
    const filter = req.query.filter || '';

    const skip = (page - 1) * limit;

    let query = {};
    if (search) {
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } }
      ];
    }

    if (filter && filter !== 'all') {
      query.status = filter;
    }

    const investors = await Investor.find(query)
      .sort({ joinDate: -1 })
      .skip(skip)
      .limit(limit)
      .select('-__v');

    const totalCount = await Investor.countDocuments(query);
    const totalPages = Math.ceil(totalCount / limit);

    res.json({
      status: 'success',
      data: {
        investors,
        totalCount,
        totalPages,
        currentPage: page
      }
    });

  } catch (error) {
    console.error('Investors error:', error);
    res.status(500).json({
      status: 'error',
      message: 'Failed to load investors'
    });
  }
});

app.get('/admin/investors/all', authenticateToken, async (req, res) => {
  try {
    const investors = await Investor.find({ status: 'active' })
      .select('name email')
      .sort({ name: 1 });

    res.json({
      status: 'success',
      data: investors
    });
  } catch (error) {
    console.error('Get all investors error:', error);
    res.status(500).json({
      status: 'error',
      message: 'Failed to load investors'
    });
  }
});

app.post('/admin/send-email', authenticateToken, async (req, res) => {
  try {
    const {
      recipients,
      subject,
      content,
      enableTracking = true,
      scheduleEmail = false,
      scheduleDate = null,
      saveAsTemplate = false,
      templateName = null,
      templateId = null
    } = req.body;

    if (!subject || !content) {
      return res.status(400).json({
        status: 'error',
        message: 'Subject and content are required'
      });
    }

    let recipientInvestors = [];
    
    if (Array.isArray(recipients) && recipients.length > 0) {
      if (typeof recipients[0] === 'string' && recipients[0].includes('@')) {
        recipientInvestors = recipients.map(email => ({ email, name: email }));
      } else {
        recipientInvestors = await Investor.find({ 
          _id: { $in: recipients },
          status: 'active'
        });
      }
    } else {
      recipientInvestors = await Investor.find({ status: 'active' });
    }

    if (recipientInvestors.length === 0) {
      return res.status(400).json({
        status: 'error',
        message: 'No valid recipients found'
      });
    }

    const campaign = new EmailCampaign({
      subject,
      content,
      recipients: recipientInvestors.map(inv => ({
        investorId: inv._id || null,
        email: inv.email,
        name: inv.name || inv.email,
        status: 'sent'
      })),
      sentBy: req.user._id,
      enableTracking,
      status: scheduleEmail ? 'scheduled' : 'sent',
      scheduledFor: scheduleEmail ? new Date(scheduleDate) : null,
      templateId: templateId || null
    });

    await campaign.save();

    if (saveAsTemplate && templateName) {
      const template = new EmailTemplate({
        name: templateName,
        subject,
        content,
        category: 'general'
      });
      await template.save();
    }

    if (!scheduleEmail) {
      await sendEmailCampaign(campaign);
    }

    res.json({
      status: 'success',
      message: `Email campaign created successfully. ${recipientInvestors.length} recipients.`,
      data: {
        campaignId: campaign._id,
        recipientCount: recipientInvestors.length,
        scheduled: scheduleEmail
      }
    });

  } catch (error) {
    console.error('Send email error:', error);
    res.status(500).json({
      status: 'error',
      message: 'Failed to send email campaign'
    });
  }
});

app.get('/admin/emails', authenticateToken, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const search = req.query.search || '';
    const filter = req.query.filter || '';

    const skip = (page - 1) * limit;

    let query = {};
    if (search) {
      query.subject = { $regex: search, $options: 'i' };
    }

    if (filter && filter !== 'all') {
      query.status = filter;
    }

    const emails = await EmailCampaign.find(query)
      .populate('sentBy', 'name username')
      .sort({ sentAt: -1 })
      .skip(skip)
      .limit(limit)
      .select('-content -recipients');

    const totalCount = await EmailCampaign.countDocuments(query);
    const totalPages = Math.ceil(totalCount / limit);

    const emailsWithStats = emails.map(email => ({
      id: email._id,
      subject: email.subject,
      recipientCount: email.recipients.length,
      sentDate: email.sentAt,
      openRate: email.recipients.length > 0 ? 
        ((email.openCount / email.recipients.length) * 100).toFixed(1) : 0,
      status: email.status,
      sentBy: email.sentBy?.name || 'System'
    }));

    res.json({
      status: 'success',
      data: {
        emails: emailsWithStats,
        totalCount,
        totalPages,
        currentPage: page
      }
    });

  } catch (error) {
    console.error('Email history error:', error);
    res.status(500).json({
      status: 'error',
      message: 'Failed to load email history'
    });
  }
});

app.get('/admin/templates', authenticateToken, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const search = req.query.search || '';

    const skip = (page - 1) * limit;

    let query = { isActive: true };
    if (search) {
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { subject: { $regex: search, $options: 'i' } }
      ];
    }

    const templates = await EmailTemplate.find(query)
      .sort({ updatedAt: -1 })
      .skip(skip)
      .limit(limit);

    const totalCount = await EmailTemplate.countDocuments(query);
    const totalPages = Math.ceil(totalCount / limit);

    res.json({
      status: 'success',
      data: {
        templates,
        totalCount,
        totalPages,
        currentPage: page
      }
    });

  } catch (error) {
    console.error('Templates error:', error);
    res.status(500).json({
      status: 'error',
      message: 'Failed to load templates'
    });
  }
});

app.get('/admin/templates/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    const template = await EmailTemplate.findById(id);
    if (!template) {
      return res.status(404).json({
        status: 'error',
        message: 'Template not found'
      });
    }

    res.json({
      status: 'success',
      data: { template }
    });

  } catch (error) {
    console.error('Get template error:', error);
    res.status(500).json({
      status: 'error',
      message: 'Failed to load template'
    });
  }
});

app.post('/admin/templates', authenticateToken, async (req, res) => {
  try {
    const { name, subject, content, category = 'general' } = req.body;

    if (!name || !subject || !content) {
      return res.status(400).json({
        status: 'error',
        message: 'Name, subject, and content are required'
      });
    }

    const template = new EmailTemplate({
      name,
      subject,
      content,
      category
    });

    await template.save();

    res.json({
      status: 'success',
      message: 'Template saved successfully',
      data: { template }
    });

  } catch (error) {
    console.error('Create template error:', error);
    res.status(500).json({
      status: 'error',
      message: 'Failed to create template'
    });
  }
});

app.put('/admin/templates/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, subject, content, category } = req.body;

    const template = await EmailTemplate.findByIdAndUpdate(
      id,
      { name, subject, content, category, lastUsed: new Date() },
      { new: true, runValidators: true }
    );

    if (!template) {
      return res.status(404).json({
        status: 'error',
        message: 'Template not found'
      });
    }

    res.json({
      status: 'success',
      message: 'Template updated successfully',
      data: { template }
    });

  } catch (error) {
    console.error('Update template error:', error);
    res.status(500).json({
      status: 'error',
      message: 'Failed to update template'
    });
  }
});

app.delete('/admin/templates/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    const template = await EmailTemplate.findByIdAndUpdate(
      id,
      { isActive: false },
      { new: true }
    );

    if (!template) {
      return res.status(404).json({
        status: 'error',
        message: 'Template not found'
      });
    }

    res.json({
      status: 'success',
      message: 'Template deleted successfully'
    });

  } catch (error) {
    console.error('Delete template error:', error);
    res.status(500).json({
      status: 'error',
      message: 'Failed to delete template'
    });
  }
});

app.get('/admin/templates/predefined', authenticateToken, async (req, res) => {
  try {
    res.json({
      status: 'success',
      data: {
        templates: PREDEFINED_TEMPLATES
      }
    });
  } catch (error) {
    console.error('Predefined templates error:', error);
    res.status(500).json({
      status: 'error',
      message: 'Failed to load predefined templates'
    });
  }
});

app.get('/admin/analytics', authenticateToken, async (req, res) => {
  try {
    const period = parseInt(req.query.period) || 30;

    const startDate = new Date();
    startDate.setDate(startDate.getDate() - period);

    const campaigns = await EmailCampaign.find({
      sentAt: { $gte: startDate },
      status: 'sent'
    });

    let totalSent = 0;
    let totalDelivered = 0;
    let totalOpened = 0;

    campaigns.forEach(campaign => {
      totalSent += campaign.recipients.length;
      totalOpened += campaign.openCount;
      totalDelivered += campaign.recipients.length;
    });

    const deliveryRate = totalSent > 0 ? (totalDelivered / totalSent * 100).toFixed(1) : 0;
    const openRate = totalDelivered > 0 ? (totalOpened / totalDelivered * 100).toFixed(1) : 0;

    res.json({
      status: 'success',
      data: {
        deliveryRate: parseFloat(deliveryRate),
        openRate: parseFloat(openRate)
      }
    });

  } catch (error) {
    console.error('Analytics error:', error);
    res.status(500).json({
      status: 'error',
      message: 'Failed to load analytics'
    });
  }
});

app.get('/track/:campaignId/:recipientId', async (req, res) => {
  try {
    const { campaignId, recipientId } = req.params;

    const trackingPixel = new TrackingPixel({
      campaignId,
      recipientId,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    });

    await trackingPixel.save();

    await EmailCampaign.findByIdAndUpdate(campaignId, {
      $inc: { openCount: 1 }
    });

    await EmailCampaign.updateOne(
      {
        _id: campaignId,
        'recipients._id': recipientId
      },
      {
        $set: {
          'recipients.$.status': 'opened',
          'recipients.$.openedAt': new Date()
        }
      }
    );

    const pixel = Buffer.from(
      'R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7',
      'base64'
    );

    res.writeHead(200, {
      'Content-Type': 'image/gif',
      'Content-Length': pixel.length,
      'Cache-Control': 'no-cache, no-store, must-revalidate',
      'Pragma': 'no-cache',
      'Expires': '0'
    });

    res.end(pixel);

  } catch (error) {
    console.error('Tracking pixel error:', error);
    const pixel = Buffer.from(
      'R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7',
      'base64'
    );
    res.type('gif').send(pixel);
  }
});

app.get('/admin/export/investors', authenticateToken, async (req, res) => {
  try {
    const investors = await Investor.find({})
      .sort({ joinDate: -1 })
      .select('name email phone country joinDate tier status totalInvested');

    const csvHeader = 'Name,Email,Phone,Country,Join Date,Tier,Status,Total Invested\n';
    const csvRows = investors.map(inv => 
      `"${inv.name}","${inv.email}","${inv.phone || ''}","${inv.country || ''}","${new Date(inv.joinDate).toISOString().split('T')[0]}","${inv.tier}","${inv.status}",${inv.totalInvested}`
    ).join('\n');

    const csv = csvHeader + csvRows;

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename=investors.csv');
    res.send(csv);

  } catch (error) {
    console.error('Export investors error:', error);
    res.status(500).json({
      status: 'error',
      message: 'Failed to export investors'
    });
  }
});

app.get('/admin/export/emails', authenticateToken, async (req, res) => {
  try {
    const campaigns = await EmailCampaign.find({ status: 'sent' })
      .populate('sentBy', 'name')
      .sort({ sentAt: -1 })
      .select('subject sentAt openCount recipients');

    const csvHeader = 'Subject,Sent Date,Recipients,Open Rate,Sent By\n';
    const csvRows = campaigns.map(campaign => {
      const openRate = campaign.recipients.length > 0 ? 
        ((campaign.openCount / campaign.recipients.length) * 100).toFixed(1) : 0;
      
      return `"${campaign.subject}","${new Date(campaign.sentAt).toISOString()}",${campaign.recipients.length},${openRate}%,"${campaign.sentBy?.name || 'System'}"`;
    }).join('\n');

    const csv = csvHeader + csvRows;

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename=email-history.csv');
    res.send(csv);

  } catch (error) {
    console.error('Export emails error:', error);
    res.status(500).json({
      status: 'error',
      message: 'Failed to export email history'
    });
  }
});

async function sendEmailCampaign(campaign) {
  try {
    const recipients = campaign.recipients;

    for (const recipient of recipients) {
      try {
        let trackingPixel = null;
        if (campaign.enableTracking) {
          trackingPixel = `${process.env.API_BASE_URL || 'https://tiktok-com-shop.onrender.com'}/track/${campaign._id}/${recipient._id}`;
        }

        const emailHtml = generateEmailTemplate(campaign.content, trackingPixel, campaign.subject);

        const mailOptions = {
          from: {
            name: 'BitHash Capital',
            address: process.env.EMAIL_FROM || 'noreply@bithashcapital.com'
          },
          to: recipient.email,
          subject: campaign.subject,
          html: emailHtml,
          headers: {
            'X-Campaign-ID': campaign._id.toString(),
            'X-Recipient-ID': recipient._id.toString()
          }
        };

        await transporter.sendMail(mailOptions);

        await EmailCampaign.updateOne(
          {
            _id: campaign._id,
            'recipients._id': recipient._id
          },
          {
            $set: {
              'recipients.$.status': 'delivered'
            }
          }
        );

        await new Promise(resolve => setTimeout(resolve, 100));

      } catch (emailError) {
        console.error(`Failed to send email to ${recipient.email}:`, emailError);
        
        await EmailCampaign.updateOne(
          {
            _id: campaign._id,
            'recipients._id': recipient._id
          },
          {
            $set: {
              'recipients.$.status': 'failed',
              'recipients.$.error': emailError.message
            }
          }
        );
      }
    }

    campaign.status = 'sent';
    campaign.sentAt = new Date();
    await campaign.save();

  } catch (error) {
    console.error('Send email campaign error:', error);
    campaign.status = 'failed';
    await campaign.save();
    throw error;
  }
}

async function initializeDefaultData() {
  try {
    const adminCount = await AdminUser.countDocuments();
    if (adminCount === 0) {
      const defaultAdmin = new AdminUser({
        username: 'admin',
        password: 'admin123',
        name: 'System Administrator',
        role: 'superadmin'
      });
      await defaultAdmin.save();
      console.log('Default admin user created: admin / admin123');
    } else {
      console.log('Admin user already exists');
    }

    for (const predefinedTemplate of PREDEFINED_TEMPLATES) {
      const existingTemplate = await EmailTemplate.findOne({ name: predefinedTemplate.name });
      if (!existingTemplate) {
        const template = new EmailTemplate(predefinedTemplate);
        await template.save();
        console.log(`Created predefined template: ${predefinedTemplate.name}`);
      }
    }

    console.log('All default data initialized successfully');

  } catch (error) {
    console.error('Error initializing default data:', error);
  }
}

app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({
    status: 'error',
    message: 'Internal server error'
  });
});

app.use('*', (req, res) => {
  res.status(404).json({
    status: 'error',
    message: 'Endpoint not found'
  });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, async () => {
  console.log('Starting BitHash Capital Admin Server...');
  console.log(`Port: ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`Website: https://www.bithashcapital.live`);
  
  await initializeDefaultData();
  
  console.log('BitHash Capital Admin Server running successfully!');
});

module.exports = app;
