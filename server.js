const express = require('express');
const mongoose = require('mongoose');
const nodemailer = require('nodemailer');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const validator = require('validator');
const crypto = require('crypto');
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
    
    // Allow requests with no origin
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
// MongoDB Connection
// ======================
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
    console.error('Email configuration error:', error);
  } else {
    console.log('Email server is ready to send messages');
  }
});

// ======================
// Database Schemas
// ======================

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

// Email Sent Log Schema
const emailLogSchema = new mongoose.Schema({
  from: {
    type: String,
    required: true
  },
  to: {
    type: [String],
    required: true
  },
  subject: {
    type: String,
    required: true
  },
  html: {
    type: String,
    required: true
  },
  text: {
    type: String
  },
  sentAt: {
    type: Date,
    default: Date.now
  },
  status: {
    type: String,
    default: 'sent',
    enum: ['sent', 'failed']
  },
  error: {
    type: String
  },
  metadata: {
    ipAddress: String,
    userAgent: String,
    frontendOrigin: String
  }
}, {
  timestamps: true
});

// ======================
// Models
// ======================
const Investor = mongoose.model('Investor', investorSchema);
const EmailLog = mongoose.model('EmailLog', emailLogSchema);

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

// Simple Email Sending Endpoint
app.post('/send-email', async (req, res) => {
  try {
    const {
      to,
      subject,
      html,
      text,
      fromName = 'BitHash Capital',
      fromEmail = process.env.EMAIL_FROM || 'noreply@bithashcapital.com'
    } = req.body;

    // Validate required fields
    if (!to || !subject || (!html && !text)) {
      return res.status(400).json({
        status: 'error',
        message: 'Missing required fields: to, subject, and either html or text content'
      });
    }

    // Validate email addresses
    const recipients = Array.isArray(to) ? to : [to];
    const invalidEmails = recipients.filter(email => !validator.isEmail(email));
    
    if (invalidEmails.length > 0) {
      return res.status(400).json({
        status: 'error',
        message: `Invalid email addresses: ${invalidEmails.join(', ')}`
      });
    }

    // Prepare email options
    const mailOptions = {
      from: {
        name: fromName,
        address: fromEmail
      },
      to: recipients,
      subject: subject,
      html: html || undefined,
      text: text || undefined
    };

    // Send email
    const info = await transporter.sendMail(mailOptions);

    // Log the email
    const emailLog = new EmailLog({
      from: `${fromName} <${fromEmail}>`,
      to: recipients,
      subject,
      html: html || '',
      text: text || '',
      status: 'sent',
      metadata: {
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        frontendOrigin: req.get('Origin') || 'unknown'
      }
    });

    await emailLog.save();

    res.json({
      status: 'success',
      message: 'Email sent successfully',
      data: {
        messageId: info.messageId,
        recipients: recipients.length,
        accepted: info.accepted,
        rejected: info.rejected,
        logId: emailLog._id
      }
    });

  } catch (error) {
    console.error('Email sending error:', error);

    // Log failed attempt
    try {
      const emailLog = new EmailLog({
        from: req.body.fromName ? `${req.body.fromName} <${req.body.fromEmail || process.env.EMAIL_FROM}>` : process.env.EMAIL_FROM,
        to: Array.isArray(req.body.to) ? req.body.to : [req.body.to],
        subject: req.body.subject || '',
        html: req.body.html || '',
        text: req.body.text || '',
        status: 'failed',
        error: error.message,
        metadata: {
          ipAddress: req.ip,
          userAgent: req.get('User-Agent'),
          frontendOrigin: req.get('Origin') || 'unknown'
        }
      });
      await emailLog.save();
    } catch (logError) {
      console.error('Failed to log error:', logError);
    }

    res.status(500).json({
      status: 'error',
      message: 'Failed to send email',
      error: error.message
    });
  }
});

// Bulk Email Sending Endpoint
app.post('/send-bulk-emails', async (req, res) => {
  try {
    const {
      recipients,
      subject,
      html,
      text,
      fromName = 'BitHash Capital',
      fromEmail = process.env.EMAIL_FROM || 'noreply@bithashcapital.com'
    } = req.body;

    // Validate required fields
    if (!recipients || !subject || (!html && !text)) {
      return res.status(400).json({
        status: 'error',
        message: 'Missing required fields: recipients, subject, and either html or text content'
      });
    }

    // Validate recipients
    const recipientList = Array.isArray(recipients) ? recipients : [recipients];
    const validRecipients = [];
    const invalidRecipients = [];

    recipientList.forEach(recipient => {
      if (validator.isEmail(recipient)) {
        validRecipients.push(recipient);
      } else {
        invalidRecipients.push(recipient);
      }
    });

    if (validRecipients.length === 0) {
      return res.status(400).json({
        status: 'error',
        message: 'No valid email addresses found in recipients list'
      });
    }

    const results = {
      total: validRecipients.length,
      sent: 0,
      failed: 0,
      details: []
    };

    // Send emails individually (better for tracking and handling failures)
    for (const recipient of validRecipients) {
      try {
        const mailOptions = {
          from: {
            name: fromName,
            address: fromEmail
          },
          to: recipient,
          subject: subject,
          html: html || undefined,
          text: text || undefined
        };

        const info = await transporter.sendMail(mailOptions);

        // Log successful email
        const emailLog = new EmailLog({
          from: `${fromName} <${fromEmail}>`,
          to: [recipient],
          subject,
          html: html || '',
          text: text || '',
          status: 'sent',
          metadata: {
            ipAddress: req.ip,
            userAgent: req.get('User-Agent'),
            frontendOrigin: req.get('Origin') || 'unknown'
          }
        });

        await emailLog.save();

        results.sent++;
        results.details.push({
          email: recipient,
          status: 'sent',
          messageId: info.messageId
        });

      } catch (error) {
        console.error(`Failed to send email to ${recipient}:`, error);

        // Log failed email
        const emailLog = new EmailLog({
          from: `${fromName} <${fromEmail}>`,
          to: [recipient],
          subject,
          html: html || '',
          text: text || '',
          status: 'failed',
          error: error.message,
          metadata: {
            ipAddress: req.ip,
            userAgent: req.get('User-Agent'),
            frontendOrigin: req.get('Origin') || 'unknown'
          }
        });

        await emailLog.save();

        results.failed++;
        results.details.push({
          email: recipient,
          status: 'failed',
          error: error.message
        });
      }

      // Small delay to prevent rate limiting
      await new Promise(resolve => setTimeout(resolve, 100));
    }

    res.json({
      status: 'success',
      message: 'Bulk email sending completed',
      data: {
        ...results,
        invalidRecipients,
        summary: {
          sent: results.sent,
          failed: results.failed,
          total: results.total,
          successRate: ((results.sent / results.total) * 100).toFixed(1) + '%'
        }
      }
    });

  } catch (error) {
    console.error('Bulk email sending error:', error);
    
    res.status(500).json({
      status: 'error',
      message: 'Failed to process bulk email request',
      error: error.message
    });
  }
});

// Get Email Logs
app.get('/email-logs', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;

    const logs = await EmailLog.find()
      .sort({ sentAt: -1 })
      .skip(skip)
      .limit(limit)
      .select('-html -text');

    const total = await EmailLog.countDocuments();

    res.json({
      status: 'success',
      data: {
        logs,
        pagination: {
          page,
          limit,
          total,
          pages: Math.ceil(total / limit)
        }
      }
    });

  } catch (error) {
    console.error('Get email logs error:', error);
    res.status(500).json({
      status: 'error',
      message: 'Failed to retrieve email logs'
    });
  }
});

// Get Investors List
app.get('/investors', async (req, res) => {
  try {
    const investors = await Investor.find({ status: 'active' })
      .select('name email phone country tier')
      .sort({ name: 1 });

    res.json({
      status: 'success',
      data: investors
    });
  } catch (error) {
    console.error('Get investors error:', error);
    res.status(500).json({
      status: 'error',
      message: 'Failed to load investors'
    });
  }
});

// Add Investor
app.post('/investors', async (req, res) => {
  try {
    const { email, name, phone, country, tier } = req.body;

    if (!email || !name) {
      return res.status(400).json({
        status: 'error',
        message: 'Email and name are required'
      });
    }

    if (!validator.isEmail(email)) {
      return res.status(400).json({
        status: 'error',
        message: 'Invalid email address'
      });
    }

    const existingInvestor = await Investor.findOne({ email });
    if (existingInvestor) {
      return res.status(400).json({
        status: 'error',
        message: 'Investor with this email already exists'
      });
    }

    const investor = new Investor({
      email,
      name,
      phone,
      country,
      tier: tier || 'Standard'
    });

    await investor.save();

    res.json({
      status: 'success',
      message: 'Investor added successfully',
      data: investor
    });

  } catch (error) {
    console.error('Add investor error:', error);
    res.status(500).json({
      status: 'error',
      message: 'Failed to add investor'
    });
  }
});

// Test Email Configuration
app.post('/test-email', async (req, res) => {
  try {
    const testEmail = process.env.TEST_EMAIL || req.body.testEmail;
    
    if (!testEmail || !validator.isEmail(testEmail)) {
      return res.status(400).json({
        status: 'error',
        message: 'Valid test email address is required'
      });
    }

    const mailOptions = {
      from: {
        name: 'BitHash Capital Test',
        address: process.env.EMAIL_FROM || 'noreply@bithashcapital.com'
      },
      to: testEmail,
      subject: 'Test Email from BitHash Capital',
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }
            .success { color: #28a745; font-weight: bold; }
          </style>
        </head>
        <body>
          <div class="container">
            <h2>Test Email Successful! 🎉</h2>
            <p>This is a test email from your BitHash Capital email system.</p>
            <p>If you're receiving this, your email configuration is working correctly.</p>
            <p class="success">✓ Email server is properly configured</p>
            <p class="success">✓ Emails can be sent successfully</p>
            <p><strong>Timestamp:</strong> ${new Date().toISOString()}</p>
          </div>
        </body>
        </html>
      `,
      text: 'Test Email from BitHash Capital\n\nThis is a test email to verify your email configuration is working correctly.\n\nTimestamp: ' + new Date().toISOString()
    };

    const info = await transporter.sendMail(mailOptions);

    // Log the test email
    const emailLog = new EmailLog({
      from: 'BitHash Capital Test <' + (process.env.EMAIL_FROM || 'noreply@bithashcapital.com') + '>',
      to: [testEmail],
      subject: mailOptions.subject,
      html: mailOptions.html,
      text: mailOptions.text,
      status: 'sent',
      metadata: {
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        frontendOrigin: req.get('Origin') || 'unknown',
        isTest: true
      }
    });

    await emailLog.save();

    res.json({
      status: 'success',
      message: 'Test email sent successfully',
      data: {
        messageId: info.messageId,
        accepted: info.accepted,
        testEmail: testEmail,
        timestamp: new Date().toISOString()
      }
    });

  } catch (error) {
    console.error('Test email error:', error);
    
    res.status(500).json({
      status: 'error',
      message: 'Failed to send test email',
      error: error.message,
      suggestion: 'Check your email configuration in environment variables'
    });
  }
});

// ======================
// Error Handling
// ======================
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
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

app.listen(PORT, () => {
  console.log('Starting Email Sending Server...');
  console.log(`Port: ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log('Email Sending Server running successfully!');
  console.log('CORS configured for frontend access');
  console.log('All systems operational');
});

module.exports = app;
