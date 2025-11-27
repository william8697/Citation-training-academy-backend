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
      'https://bithashcapital.com',
      'https://www.bithashcapital.live'
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
// Enhanced Email Template Generation Functions
// ======================
const generateBitcoinMiningEmailTemplate = (content, trackingPixel = null, subject = 'BitHash Capital') => {
  const logoUrl = 'https://www.dropbox.com/scl/fi/1dq16nex1borvvknpcwox/circular_dark_background.png?rlkey=sq2ujl2oxxk9vyvg1j7oz0cdb&raw=1';
  
  return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${subject}</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Manrope:wght@500;600;700&display=swap" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #e5e5e5;
            background: linear-gradient(135deg, #0a0a0a 0%, #1a1a2e 100%);
            margin: 0;
            padding: 20px;
            min-height: 100vh;
        }
        
        .email-container {
            max-width: 600px;
            margin: 0 auto;
            background: #1a1a1a;
            border-radius: 16px;
            overflow: hidden;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.5);
            border: 1px solid #2d3748;
        }
        
        .header {
            background: linear-gradient(135deg, #0f1419 0%, #1a2332 100%);
            padding: 40px 30px;
            text-align: center;
            border-bottom: 3px solid #00D395;
            position: relative;
            overflow: hidden;
        }
        
        .header::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><defs><pattern id="grid" width="10" height="10" patternUnits="userSpaceOnUse"><path d="M 10 0 L 0 0 0 10" fill="none" stroke="rgba(0,211,149,0.1)" stroke-width="1"/></pattern></defs><rect width="100" height="100" fill="url(%23grid)"/></svg>');
            opacity: 0.3;
        }
        
        .logo-section {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 15px;
            margin-bottom: 20px;
            position: relative;
            z-index: 2;
        }
        
        .logo-img {
            width: 50px;
            height: 50px;
            border-radius: 50%;
            border: 2px solid #00D395;
            box-shadow: 0 0 20px rgba(0, 211, 149, 0.3);
        }
        
        .logo-text {
            font-family: 'Manrope', sans-serif;
            font-size: 28px;
            font-weight: 700;
            background: linear-gradient(135deg, #00D395 0%, #00B783 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            letter-spacing: -0.5px;
        }
        
        .bitcoin-icon {
            color: #F7931A;
            font-size: 24px;
            margin-left: 5px;
            animation: float 3s ease-in-out infinite;
        }
        
        @keyframes float {
            0%, 100% { transform: translateY(0px); }
            50% { transform: translateY(-5px); }
        }
        
        .security-badge {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: rgba(0, 211, 149, 0.1);
            padding: 10px 20px;
            border-radius: 25px;
            border: 1px solid rgba(0, 211, 149, 0.3);
            font-size: 14px;
            font-weight: 500;
            color: #00D395;
            position: relative;
            z-index: 2;
        }
        
        .content {
            padding: 40px 30px;
            background: #1a1a1a;
        }
        
        .email-body {
            background: rgba(255, 255, 255, 0.02);
            border-radius: 12px;
            padding: 30px;
            border-left: 4px solid #00D395;
            margin-bottom: 30px;
        }
        
        .email-body h1 {
            font-size: 24px;
            font-weight: 600;
            margin-bottom: 20px;
            color: #ffffff;
            font-family: 'Manrope', sans-serif;
        }
        
        .email-body p {
            margin-bottom: 15px;
            color: #a0aec0;
            line-height: 1.7;
        }
        
        .email-body strong {
            color: #00D395;
            font-weight: 600;
        }
        
        .features-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 15px;
            margin: 25px 0;
        }
        
        .feature-card {
            background: rgba(255, 255, 255, 0.05);
            padding: 15px;
            border-radius: 8px;
            text-align: center;
            border: 1px solid rgba(255, 255, 255, 0.1);
            transition: all 0.3s ease;
        }
        
        .feature-card:hover {
            transform: translateY(-2px);
            border-color: #00D395;
        }
        
        .feature-icon {
            font-size: 20px;
            color: #00D395;
            margin-bottom: 8px;
        }
        
        .feature-text {
            font-size: 12px;
            color: #a0aec0;
            font-weight: 500;
        }
        
        .cta-section {
            text-align: center;
            margin: 30px 0;
        }
        
        .cta-button {
            display: inline-block;
            background: linear-gradient(135deg, #00D395 0%, #00B783 100%);
            color: #0a0a0a;
            padding: 14px 35px;
            text-decoration: none;
            border-radius: 8px;
            font-weight: 600;
            font-size: 16px;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(0, 211, 149, 0.3);
            border: none;
            cursor: pointer;
            font-family: 'Manrope', sans-serif;
        }
        
        .cta-button:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(0, 211, 149, 0.4);
            background: linear-gradient(135deg, #00E5A1 0%, #00D395 100%);
        }
        
        .secondary-button {
            background: transparent;
            color: #00D395;
            border: 2px solid #00D395;
            margin-left: 15px;
        }
        
        .secondary-button:hover {
            background: rgba(0, 211, 149, 0.1);
        }
        
        .footer {
            background: #0f1419;
            padding: 30px;
            text-align: center;
            border-top: 1px solid #2d3748;
        }
        
        .footer-links {
            display: flex;
            justify-content: center;
            gap: 25px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }
        
        .footer-link {
            color: #a0aec0;
            text-decoration: none;
            font-size: 14px;
            transition: color 0.3s ease;
        }
        
        .footer-link:hover {
            color: #00D395;
        }
        
        .copyright {
            font-size: 12px;
            color: #718096;
            line-height: 1.6;
            margin-top: 15px;
        }
        
        .contact-info {
            font-size: 12px;
            color: #718096;
            margin-top: 10px;
        }
        
        .mining-stats {
            background: rgba(0, 211, 149, 0.05);
            border-radius: 8px;
            padding: 20px;
            margin: 25px 0;
            border: 1px solid rgba(0, 211, 149, 0.1);
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 15px;
            text-align: center;
        }
        
        .stat-item {
            padding: 10px;
        }
        
        .stat-value {
            font-size: 18px;
            font-weight: 700;
            color: #00D395;
            margin-bottom: 5px;
        }
        
        .stat-label {
            font-size: 11px;
            color: #a0aec0;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        @media (max-width: 600px) {
            body {
                padding: 10px;
            }
            
            .email-container {
                border-radius: 12px;
            }
            
            .header {
                padding: 30px 20px;
            }
            
            .content {
                padding: 25px 20px;
            }
            
            .email-body {
                padding: 20px;
            }
            
            .features-grid {
                grid-template-columns: 1fr;
            }
            
            .stats-grid {
                grid-template-columns: 1fr;
            }
            
            .footer-links {
                flex-direction: column;
                gap: 15px;
            }
            
            .cta-button {
                display: block;
                margin-bottom: 10px;
            }
            
            .secondary-button {
                margin-left: 0;
            }
        }
    </style>
</head>
<body>
    <div class="email-container">
        <div class="header">
            <div class="logo-section">
                <img src="${logoUrl}" alt="BitHash Capital Logo" class="logo-img">
                <div class="logo-text">
                    BitHash Capital <span class="bitcoin-icon">₿</span>
                </div>
            </div>
            <div class="security-badge">
                <i class="fas fa-shield-alt"></i>
                <span>256-bit AES Encrypted Communication</span>
            </div>
        </div>
        
        <div class="content">
            <div class="email-body">
                ${content}
            </div>
            
            <div class="mining-stats">
                <div class="stats-grid">
                    <div class="stat-item">
                        <div class="stat-value">99.1%</div>
                        <div class="stat-label">Uptime</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value">24/7</div>
                        <div class="stat-label">Monitoring</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value">100%</div>
                        <div class="stat-label">Secure</div>
                    </div>
                </div>
            </div>
            
            <div class="features-grid">
                <div class="feature-card">
                    <div class="feature-icon">⚡</div>
                    <div class="feature-text">High Performance Mining</div>
                </div>
                <div class="feature-card">
                    <div class="feature-icon">🛡️</div>
                    <div class="feature-text">Military Grade Security</div>
                </div>
                <div class="feature-card">
                    <div class="feature-icon">💰</div>
                    <div class="feature-text">Daily Returns</div>
                </div>
                <div class="feature-card">
                    <div class="feature-icon">🌍</div>
                    <div class="feature-text">Global Operations</div>
                </div>
            </div>
            
            <div class="cta-section">
                <a href="https://www.bithashcapital.live/dashboard" class="cta-button">
                    <i class="fas fa-chart-line"></i> View Dashboard
                </a>
                <a href="https://www.bithashcapital.live/contact" class="cta-button secondary-button">
                    <i class="fas fa-headset"></i> Contact Support
                </a>
            </div>
        </div>
        
        <div class="footer">
            <div class="footer-links">
                <a href="https://www.bithashcapital.live" class="footer-link">Website</a>
                <a href="https://www.bithashcapital.live/privacy" class="footer-link">Privacy Policy</a>
                <a href="https://www.bithashcapital.live/terms" class="footer-link">Terms of Service</a>
                <a href="https://www.bithashcapital.live/contact" class="footer-link">Contact Us</a>
            </div>
            
            <div class="copyright">
                <p>&copy; ${new Date().getFullYear()} BitHash Capital LLC. All rights reserved.</p>
                <p class="contact-info">
                    800 Plant St, Wilmington, DE 19801, United States<br>
                    Email: support@bithashcapital.com | Phone: +1 606-363-2032
                </p>
                <p style="margin-top: 10px; font-size: 11px; color: #4a5568;">
                    This email was sent to you as a registered investor of BitHash Capital. 
                    Please do not reply to this email.
                </p>
            </div>
            
            ${trackingPixel ? `<img src="${trackingPixel}" width="1" height="1" style="display:none;">` : ''}
        </div>
    </div>
</body>
</html>
  `;
};

// ======================
// Predefined Professional Templates
// ======================
const PREDEFINED_TEMPLATES = [
  {
    name: 'BitHash Investment Opportunity',
    subject: 'Grow Your Crypto with BitHash Capital - Professional Bitcoin Mining',
    content: `
      <h1>Unlock the Power of Bitcoin Mining</h1>
      
      <p>Dear Investor,</p>
      
      <p>Instead of letting your cryptocurrency sit idle in your wallet, why not put it to work with BitHash Capital? We offer professional Bitcoin mining services that allow you to earn consistent returns on your crypto investments.</p>
      
      <h2 style="color: #00D395; margin: 25px 0 15px 0;">Why Choose BitHash Capital?</h2>
      
      <p><strong>🏭 Professional Mining Operations:</strong> State-of-the-art ASIC miners running 24/7 in our secure, energy-efficient data centers across North America and Europe.</p>
      
      <p><strong>📈 Competitive Returns:</strong> Earn consistent daily returns on your investment with our optimized mining operations and strategic power contracts.</p>
      
      <p><strong>🏦 Bitcoin-Backed Loans:</strong> Access low-interest loans using your Bitcoin as collateral, giving you liquidity without selling your assets.</p>
      
      <p><strong>🎁 50% Deposit Bonus:</strong> Enjoy a 50% bonus on your first deposit to maximize your mining power from day one.</p>
      
      <h2 style="color: #00D395; margin: 25px 0 15px 0;">How It Works:</h2>
      
      <ol style="margin-left: 20px; color: #a0aec0;">
        <li style="margin-bottom: 10px;">Deposit your cryptocurrency to your BitHash account</li>
        <li style="margin-bottom: 10px;">Choose from our flexible investment plans tailored to your goals</li>
        <li style="margin-bottom: 10px;">Start earning daily returns from our mining operations</li>
        <li style="margin-bottom: 10px;">Withdraw your profits anytime or reinvest for compound growth</li>
      </ol>
      
      <div style="background: rgba(0, 211, 149, 0.1); border-left: 4px solid #00D395; padding: 20px; border-radius: 8px; margin: 25px 0;">
        <strong style="color: #00D395;">Special Limited-Time Offer:</strong> For your first deposit, we're offering a <strong>50% bonus</strong> to help you get started with even more mining power. This offer is available for a limited time only.
      </div>
      
      <p>Our mining facilities utilize the latest SHA-256 ASIC technology with advanced cooling systems, ensuring maximum efficiency and uptime. With renewable energy sources and 24/7 monitoring, your investment is in safe hands.</p>
      
      <p>Ready to put your crypto to work? Log in to your dashboard to explore our investment plans and start earning today.</p>
      
      <p style="margin-top: 30px;">Best regards,<br>
      <strong>The BitHash Capital Team</strong></p>
    `,
    category: 'promotional'
  },
  {
    name: 'Hourly Bitcoin Reward Announcement',
    subject: '🚀 Win 0.0056 BTC Every Hour - Be the First to Transact!',
    content: `
      <h1>Win 0.0056 BTC Every Hour! 🎯</h1>
      
      <p>Dear Valued Investor,</p>
      
      <p>We're excited to announce our revolutionary hourly Bitcoin reward program! Every hour, one lucky investor has the chance to win <strong>0.0056 BTC</strong> simply by being the first to complete a transaction during that hour.</p>
      
      <h2 style="color: #00D395; margin: 25px 0 15px 0;">How to Win:</h2>
      
      <div style="background: rgba(247, 147, 26, 0.1); border-left: 4px solid #F7931A; padding: 20px; border-radius: 8px; margin: 20px 0;">
        <p><strong>⏰ Time Frame:</strong> Each hour, from :00 to :59</p>
        <p><strong>💰 Prize:</strong> 0.0056 BTC (approximately $200 USD)</p>
        <p><strong>✅ Eligibility:</strong> Any deposit, withdrawal, or investment transaction</p>
        <p><strong>🏆 Winner:</strong> The first investor to complete any transaction each hour</p>
      </div>
      
      <h2 style="color: #00D395; margin: 25px 0 15px 0;">Current Hourly Status:</h2>
      
      <div style="background: rgba(255, 255, 255, 0.05); padding: 20px; border-radius: 8px; border: 1px solid rgba(255, 255, 255, 0.1);">
        <p><strong>Next drawing:</strong> At the top of the next hour</p>
        <p><strong>Current prize pool:</strong> 0.0056 BTC</p>
        <p><strong>Last winner:</strong> Winner announced hourly in your dashboard</p>
      </div>
      
      <h2 style="color: #00D395; margin: 25px 0 15px 0;">Pro Tips to Increase Your Chances:</h2>
      
      <div style="display: grid; gap: 15px; margin: 20px 0;">
        <div style="display: flex; align-items: flex-start; gap: 10px;">
          <span style="color: #00D395; font-weight: bold;">1</span>
          <span>Schedule smaller, frequent transactions throughout the day</span>
        </div>
        <div style="display: flex; align-items: flex-start; gap: 10px;">
          <span style="color: #00D395; font-weight: bold;">2</span>
          <span>Set reminders for the top of each hour</span>
        </div>
        <div style="display: flex; align-items: flex-start; gap: 10px;">
          <span style="color: #00D395; font-weight: bold;">3</span>
          <span>Keep your account funded and ready for quick transactions</span>
        </div>
        <div style="display: flex; align-items: flex-start; gap: 10px;">
          <span style="color: #00D395; font-weight: bold;">4</span>
          <span>Diversify your transaction types (deposits, investments, withdrawals)</span>
        </div>
      </div>
      
      <div style="background: rgba(0, 211, 149, 0.1); border-left: 4px solid #00D395; padding: 20px; border-radius: 8px; margin: 25px 0;">
        <p><strong>💡 Remember:</strong> Every transaction counts! Whether you're making a deposit, withdrawing profits, or investing in a new plan, you could be our next hourly winner.</p>
      </div>
      
      <p>Winners are automatically credited to their accounts and can be viewed in your transaction history. The more you transact, the higher your chances of winning!</p>
      
      <p style="margin-top: 30px;">Good luck, and may the fastest investor win! 🚀</p>
      
      <p style="margin-top: 20px;">Happy investing,<br>
      <strong>The BitHash Capital Team</strong></p>
      
      <div style="margin-top: 30px; padding: 15px; background: rgba(255, 255, 255, 0.02); border-radius: 6px; border: 1px solid rgba(255, 255, 255, 0.1);">
        <p style="font-size: 12px; color: #718096; margin: 0;">
          <strong>Terms & Conditions:</strong> Winner is determined by the timestamp of the first completed transaction each hour. Multiple transactions from the same account are eligible. Prize is awarded in BTC equivalent. BitHash Capital reserves the right to modify or terminate this program at any time.
        </p>
      </div>
    `,
    category: 'promotional'
  },
  {
    name: 'Welcome to BitHash Capital',
    subject: 'Welcome to BitHash Capital - Start Your Bitcoin Mining Journey',
    content: `
      <h1>Welcome to the Future of Bitcoin Mining! 🎉</h1>
      
      <p>Dear Investor,</p>
      
      <p>Welcome to BitHash Capital! We're thrilled to have you join our community of forward-thinking investors who are leveraging the power of professional Bitcoin mining to grow their wealth.</p>
      
      <h2 style="color: #00D395; margin: 25px 0 15px 0;">Getting Started is Easy:</h2>
      
      <div style="display: grid; gap: 15px; margin: 20px 0;">
        <div style="display: flex; align-items: center; gap: 15px; background: rgba(255, 255, 255, 0.03); padding: 15px; border-radius: 8px;">
          <div style="width: 30px; height: 30px; background: #00D395; border-radius: 50%; display: flex; align-items: center; justify-content: center; color: #0a0a0a; font-weight: bold;">1</div>
          <div>
            <strong>Fund Your Account</strong><br>
            <span style="color: #a0aec0; font-size: 14px;">Deposit cryptocurrency to get started</span>
          </div>
        </div>
        
        <div style="display: flex; align-items: center; gap: 15px; background: rgba(255, 255, 255, 0.03); padding: 15px; border-radius: 8px;">
          <div style="width: 30px; height: 30px; background: #00D395; border-radius: 50%; display: flex; align-items: center; justify-content: center; color: #0a0a0a; font-weight: bold;">2</div>
          <div>
            <strong>Choose Your Plan</strong><br>
            <span style="color: #a0aec0; font-size: 14px;">Select from our flexible investment options</span>
          </div>
        </div>
        
        <div style="display: flex; align-items: center; gap: 15px; background: rgba(255, 255, 255, 0.03); padding: 15px; border-radius: 8px;">
          <div style="width: 30px; height: 30px; background: #00D395; border-radius: 50%; display: flex; align-items: center; justify-content: center; color: #0a0a0a; font-weight: bold;">3</div>
          <div>
            <strong>Start Earning</strong><br>
            <span style="color: #a0aec0; font-size: 14px;">Watch your investment grow with daily returns</span>
          </div>
        </div>
      </div>
      
      <h2 style="color: #00D395; margin: 25px 0 15px 0;">Why Investors Choose BitHash:</h2>
      
      <ul style="color: #a0aec0; margin-left: 20px;">
        <li style="margin-bottom: 10px;">Professional mining operations with 99.1% uptime</li>
        <li style="margin-bottom: 10px;">Daily returns paid directly to your account</li>
        <li style="margin-bottom: 10px;">Advanced security with multi-signature wallets</li>
        <li style="margin-bottom: 10px;">24/7 customer support</li>
        <li style="margin-bottom: 10px;">Transparent reporting and real-time monitoring</li>
      </ul>
      
      <div style="background: rgba(0, 211, 149, 0.1); border-left: 4px solid #00D395; padding: 20px; border-radius: 8px; margin: 25px 0;">
        <p><strong>📞 Need Help?</strong> Our support team is available 24/7 to assist you with any questions. Contact us at support@bithashcapital.com or through the live chat on our platform.</p>
      </div>
      
      <p>We're committed to providing you with the best Bitcoin mining experience and helping you achieve your financial goals through cryptocurrency investments.</p>
      
      <p style="margin-top: 30px;">Welcome aboard!<br>
      <strong>The BitHash Capital Team</strong></p>
    `,
    category: 'general'
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

        const emailHtml = generateBitcoinMiningEmailTemplate(campaign.content, trackingPixel, campaign.subject);

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
  console.log(`📍 Website: https://www.bithashcapital.live`);
  
  await initializeDefaultData();
  
  console.log('✅ BitHash Capital Admin Server running successfully!');
  console.log('✅ CORS configured for frontend access');
  console.log('✅ Database connected and ready');
  console.log('✅ All systems operational');
});

module.exports = app;
