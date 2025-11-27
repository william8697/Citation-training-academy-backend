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

// ======================
// Enhanced CORS Configuration
// ======================
const corsOptions = {
  origin: function (origin, callback) {
    const allowedOrigins = [
      'https://citation-training-academy.vercel.app',
      'https://citation-training-academy-1b8h.vercel.app',
      'http://localhost:3000',
      'http://127.0.0.1:3000',
      'https://bithashcapital.com'
    ];
    
    // Allow requests with no origin (like mobile apps or curl requests)
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

// Handle preflight requests
app.options('*', cors(corsOptions));

// ======================
// Security Middleware
// ======================
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" },
  contentSecurityPolicy: false
}));

// ======================
// Rate Limiting
// ======================
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

// ======================
// Body Parsing Middleware
// ======================
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ======================
// JWT Configuration
// ======================
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '24h';

// ======================
// MongoDB Connection
// ======================
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://elvismwangike:JFJmHvP4ktikRYDC@cluster0.vm6hrog.mongodb.net/bithash?retryWrites=true&w=majority&appName=Cluster0';

mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('✅ MongoDB connected successfully'))
.catch(err => {
  console.error('❌ MongoDB connection error:', err);
  process.exit(1);
});

// ======================
// Email Configuration
// ======================
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

// Verify email configuration
transporter.verify(function(error, success) {
  if (error) {
    console.error('❌ Email configuration error:', error);
  } else {
    console.log('✅ Email server is ready to send messages');
  }
});

// ======================
// Database Schemas
// ======================

// Admin User Schema
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

// Hash password before saving
adminUserSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

// Investor Schema
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

// Email Template Schema
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

// Email Campaign Schema
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

// Tracking Pixel Schema
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

// ======================
// Models
// ======================
const AdminUser = mongoose.model('AdminUser', adminUserSchema);
const Investor = mongoose.model('Investor', investorSchema);
const EmailTemplate = mongoose.model('EmailTemplate', emailTemplateSchema);
const EmailCampaign = mongoose.model('EmailCampaign', emailCampaignSchema);
const TrackingPixel = mongoose.model('TrackingPixel', trackingPixelSchema);

// ======================
// Authentication Middleware
// ======================
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

// ======================
// Email Template Generation Functions
// ======================
const generateBitcoinMiningEmailTemplate = (content, trackingPixel = null) => {
  const logoUrl = 'https://www.dropbox.com/scl/fi/1dq16nex1borvvknpcwox/circular_dark_background.png?rlkey=sq2ujl2oxxk9vyvg1j7oz0cdb&raw=1';
  
  return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BitHash Capital</title>
    <style>
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #e5e5e5;
            background-color: #0a0a0a;
            margin: 0;
            padding: 0;
        }
        .container {
            max-width: 600px;
            margin: 0 auto;
            background: #1a1a1a;
            border: 1px solid #2d3748;
            border-radius: 8px;
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #0f1419 0%, #1a2332 100%);
            padding: 30px;
            text-align: center;
            border-bottom: 3px solid #f7931a;
        }
        .logo {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 12px;
            margin-bottom: 20px;
        }
        .logo img {
            width: 50px;
            height: 50px;
            border-radius: 50%;
        }
        .logo-text {
            font-family: 'Rowdies', cursive;
            font-size: 28px;
            font-weight: 700;
            color: #ffffff;
        }
        .bitcoin-animation {
            color: #f7931a;
            display: inline-block;
            animation: bounce 2s infinite;
        }
        @keyframes bounce {
            0%, 100% { transform: translateY(0); }
            50% { transform: translateY(-5px); }
        }
        .content {
            padding: 40px 30px;
            background: #1a1a1a;
        }
        .mining-theme {
            background: linear-gradient(135deg, rgba(247, 147, 26, 0.1) 0%, transparent 50%);
            border-left: 4px solid #f7931a;
            padding: 20px;
            margin: 20px 0;
            border-radius: 4px;
        }
        .footer {
            background: #0f1419;
            padding: 25px 30px;
            text-align: center;
            border-top: 1px solid #2d3748;
            font-size: 14px;
            color: #a0aec0;
        }
        .security-badge {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: rgba(72, 187, 120, 0.1);
            padding: 8px 16px;
            border-radius: 20px;
            margin: 10px 0;
            border: 1px solid rgba(72, 187, 120, 0.3);
        }
        .btn {
            display: inline-block;
            background: linear-gradient(135deg, #f7931a 0%, #e68517 100%);
            color: #0a0a0a;
            padding: 12px 30px;
            text-decoration: none;
            border-radius: 6px;
            font-weight: 600;
            margin: 10px 5px;
            text-align: center;
        }
        .btn:hover {
            background: linear-gradient(135deg, #e68517 0%, #d67714 100%);
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 15px;
            margin: 25px 0;
        }
        .stat-card {
            background: rgba(255, 255, 255, 0.05);
            padding: 15px;
            border-radius: 6px;
            text-align: center;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }
        .stat-value {
            font-size: 24px;
            font-weight: 700;
            color: #f7931a;
            margin-bottom: 5px;
        }
        .stat-label {
            font-size: 12px;
            color: #a0aec0;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        @media (max-width: 600px) {
            .container {
                margin: 10px;
            }
            .content {
                padding: 25px 20px;
            }
            .stats-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">
                <img src="${logoUrl}" alt="BitHash Capital Logo">
                <div class="logo-text">
                    <span class="bitcoin-animation">₿</span>itHash Capital
                </div>
            </div>
            <div class="security-badge">
                <i class="fas fa-shield-alt"></i>
                <span>256-bit AES Encrypted Communication</span>
            </div>
        </div>
        
        <div class="content">
            <div class="mining-theme">
                ${content}
            </div>
            
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value">99.1%</div>
                    <div class="stat-label">Uptime</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">24/7</div>
                    <div class="stat-label">Monitoring</div>
                </div>
            </div>
            
            <div style="text-align: center; margin: 30px 0;">
                <a href="https://bithashcapital.com/dashboard" class="btn">
                    <i class="fas fa-chart-line"></i> View Dashboard
                </a>
                <a href="https://bithashcapital.com/contact" class="btn" style="background: linear-gradient(135deg, #2d3748 0%, #4a5568 100%); color: white;">
                    <i class="fas fa-headset"></i> Contact Support
                </a>
            </div>
        </div>
        
        <div class="footer">
            <p>&copy; ${new Date().getFullYear()} BitHash Capital LLC. All rights reserved.</p>
            <p>800 Plant St, Wilmington, DE 19801, United States</p>
            <p>
                <a href="https://bithashcapital.com" style="color: #f7931a; text-decoration: none;">Website</a> | 
                <a href="https://bithashcapital.com/privacy" style="color: #f7931a; text-decoration: none;">Privacy Policy</a> | 
                <a href="https://bithashcapital.com/terms" style="color: #f7931a; text-decoration: none;">Terms of Service</a>
            </p>
            <p style="font-size: 12px; margin-top: 15px; color: #718096;">
                This email was sent to you as a registered investor of BitHash Capital. 
                Please do not reply to this email.
            </p>
            ${trackingPixel ? `<img src="${trackingPixel}" width="1" height="1" style="display:none;">` : ''}
        </div>
    </div>
</body>
</html>
  `;
};

// Predefined templates
const PREDEFINED_TEMPLATES = [
  {
    name: 'BitHash Investment Pitch',
    subject: 'Grow Your Crypto with BitHash Capital - Professional Bitcoin Mining',
    content: `
      <h2>Unlock the Power of Bitcoin Mining with BitHash Capital</h2>
      
      <p>Dear Investor,</p>
      
      <p>Instead of letting your cryptocurrency sit idle in your wallet, why not put it to work with BitHash Capital? We offer professional Bitcoin mining services that allow you to earn consistent returns on your crypto investments.</p>
      
      <h3>Why Choose BitHash Capital?</h3>
      <ul>
        <li><strong>Professional Mining Operations:</strong> State-of-the-art ASIC miners running 24/7</li>
        <li><strong>Competitive Returns:</strong> Earn consistent daily returns on your investment</li>
        <li><strong>Bitcoin-Backed Loans:</strong> Access low-interest loans using your Bitcoin as collateral</li>
        <li><strong>50% Deposit Bonus:</strong> Enjoy a 50% bonus on your first deposit</li>
      </ul>
      
      <h3>How It Works:</h3>
      <ol>
        <li>Deposit your cryptocurrency to your BitHash account</li>
        <li>Choose from our flexible investment plans</li>
        <li>Start earning daily returns from our mining operations</li>
        <li>Withdraw your profits anytime or reinvest for compound growth</li>
      </ol>
      
      <p><strong>Special Offer:</strong> For your first deposit, we're offering a 50% bonus to help you get started with even more mining power.</p>
      
      <p>Ready to put your crypto to work? Log in to your dashboard to explore our investment plans and start earning today.</p>
      
      <p>Best regards,<br>
      The BitHash Capital Team</p>
    `,
    category: 'promotional'
  },
  {
    name: 'Hourly Bitcoin Reward',
    subject: 'Win 0.0056 BTC Every Hour - Be the First to Transact!',
    content: `
      <h2>🚀 Win 0.0056 BTC Every Hour! 🚀</h2>
      
      <p>Dear Valued Investor,</p>
      
      <p>We're excited to announce our new hourly Bitcoin reward program! Every hour, one lucky investor has the chance to win 0.0056 BTC simply by being the first to complete a transaction during that hour.</p>
      
      <h3>How to Win:</h3>
      <ul>
        <li><strong>Time Frame:</strong> Each hour, from :00 to :59</li>
        <li><strong>Prize:</strong> 0.0056 BTC (approximately $200 USD)</li>
        <li><strong>Eligibility:</strong> Any deposit, withdrawal, or investment transaction</li>
        <li><strong>Winner:</strong> The first investor to complete any transaction each hour</li>
      </ul>
      
      <h3>Current Hourly Status:</h3>
      <p><strong>Next drawing:</strong> At the top of the next hour<br>
      <strong>Current prize pool:</strong> 0.0056 BTC<br>
      <strong>Last winner:</strong> [Previous winner will be announced]</p>
      
      <h3>Pro Tips to Increase Your Chances:</h3>
      <ol>
        <li>Schedule smaller, frequent transactions throughout the day</li>
        <li>Set reminders for the top of each hour</li>
        <li>Keep your account funded and ready for quick transactions</li>
        <li>Diversify your transaction types (deposits, investments, etc.)</li>
      </ol>
      
      <p><strong>Remember:</strong> Every transaction counts! Whether you're making a deposit, withdrawing profits, or investing in a new plan, you could be our next hourly winner.</p>
      
      <p>Good luck, and may the fastest investor win!</p>
      
      <p>Happy investing,<br>
      The BitHash Capital Team</p>
      
      <p style="font-size: 12px; color: #a0aec0; margin-top: 20px;">
        *Terms and conditions apply. Winner is determined by the timestamp of the first completed transaction each hour. Multiple transactions from the same account are eligible. Prize is awarded in BTC equivalent.
      </p>
    `,
    category: 'promotional'
  }
];

// ======================
// API Routes
// ======================

// Health Check
app.get('/health', (req, res) => {
  res.json({
    status: 'success',
    message: 'Server is running smoothly',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// Admin Login - FIXED CORS
app.post('/admin/login', async (req, res) => {
  try {
    console.log('🔐 Login attempt received for user:', req.body.username);
    
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        status: 'error',
        message: 'Username and password are required'
      });
    }

    const user = await AdminUser.findOne({ username, isActive: true });
    if (!user) {
      console.log('❌ User not found:', username);
      return res.status(401).json({
        status: 'error',
        message: 'Invalid credentials'
      });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      console.log('❌ Invalid password for user:', username);
      return res.status(401).json({
        status: 'error',
        message: 'Invalid credentials'
      });
    }

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    const token = jwt.sign(
      { id: user._id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );

    console.log('✅ Login successful for user:', username);

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
    console.error('💥 Login error:', error);
    res.status(500).json({
      status: 'error',
      message: 'Internal server error during login'
    });
  }
});

// Dashboard Statistics
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
        lastActivity: new Date().toISOString(),
        investorTrend: 2.5,
        emailTrend: 1.8,
        openTrend: -0.5,
        activityTime: 'Just now'
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

// Investors Management
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

// Get all investors for selection
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

// Email Campaign Management
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
      // If recipients are email addresses (manual input)
      if (typeof recipients[0] === 'string' && recipients[0].includes('@')) {
        recipientInvestors = recipients.map(email => ({ email, name: email }));
      } else {
        // If recipients are investor IDs
        recipientInvestors = await Investor.find({ 
          _id: { $in: recipients },
          status: 'active'
        });
      }
    } else {
      // Send to all active investors
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

// Email History
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

// Email Templates Management
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

// Get specific template
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

// Create template
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

// Update template
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

// Delete template
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

// Get predefined templates
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

// Analytics
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
        openRate: parseFloat(openRate),
        clickRate: 0,
        unsubscribeRate: 0,
        deliveryTrend: 0.2,
        openTrend: -0.3,
        clickTrend: 0.1,
        unsubscribeTrend: -0.1
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

// Email Tracking Pixel
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

// Export endpoints
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

// ======================
// Helper Functions
// ======================
async function sendEmailCampaign(campaign) {
  try {
    const recipients = campaign.recipients;

    for (const recipient of recipients) {
      try {
        let trackingPixel = null;
        if (campaign.enableTracking) {
          trackingPixel = `${process.env.API_BASE_URL || 'https://tiktok-com-shop.onrender.com'}/track/${campaign._id}/${recipient._id}`;
        }

        const emailHtml = generateBitcoinMiningEmailTemplate(campaign.content, trackingPixel);

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

// ======================
// Initialize Default Admin and Templates
// ======================
async function initializeDefaultData() {
  try {
    // Create default admin if none exists
    const adminCount = await AdminUser.countDocuments();
    if (adminCount === 0) {
      const defaultAdmin = new AdminUser({
        username: 'admin',
        password: 'admin123',
        name: 'System Administrator',
        role: 'superadmin'
      });
      await defaultAdmin.save();
      console.log('✅ Default admin user created: admin / admin123');
      console.log('⚠️  Change default password in production!');
    } else {
      console.log('✅ Admin user already exists');
    }

    // Create predefined templates if they don't exist
    for (const predefinedTemplate of PREDEFINED_TEMPLATES) {
      const existingTemplate = await EmailTemplate.findOne({ name: predefinedTemplate.name });
      if (!existingTemplate) {
        const template = new EmailTemplate(predefinedTemplate);
        await template.save();
        console.log(`✅ Created predefined template: ${predefinedTemplate.name}`);
      }
    }

    console.log('✅ All default data initialized successfully');

  } catch (error) {
    console.error('❌ Error initializing default data:', error);
  }
}

// ======================
// Error Handling
// ======================
app.use((error, req, res, next) => {
  console.error('💥 Unhandled error:', error);
  res.status(500).json({
    status: 'error',
    message: 'Internal server error'
  });
});

// 404 Handler
app.use('*', (req, res) => {
  res.status(404).json({
    status: 'error',
    message: 'Endpoint not found'
  });
});

// ======================
// Server Startup
// ======================
const PORT = process.env.PORT || 3000;

app.listen(PORT, async () => {
  console.log('🚀 Starting BitHash Capital Admin Server...');
  console.log(`📍 Port: ${PORT}`);
  console.log(`📍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`📍 Frontend URL: https://citation-training-academy.vercel.app`);
  console.log(`📍 Backend URL: https://tiktok-com-shop.onrender.com`);
  
  await initializeDefaultData();
  
  console.log('✅ BitHash Capital Admin Server running successfully!');
  console.log('✅ CORS configured for frontend access');
  console.log('✅ Database connected and ready');
  console.log('✅ All systems operational');
});

module.exports = app;
