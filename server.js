// Load environment variables first
require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss');
const path = require('path');
const config = require('./config/config');

// Import routes
const authRoutes = require('./routes/auth');
const productRoutes = require('./routes/products');
const categoryRoutes = require('./routes/categories');
const cartRoutes = require('./routes/cart');
const orderRoutes = require('./routes/orders');
const couponRoutes = require('./routes/coupons');
const paymentRoutes = require('./routes/payments');
const reviewRoutes = require('./routes/reviews');
const contactRoutes = require('./routes/contact');
const adminRoutes = require('./routes/admin');
const adminProductCreateRoute = require('./routes/adminProducts');
const wishlistRoutes = require('./routes/wishlist');
const uploadsRoutes = require('./routes/uploads');
const announcementRoutes = require('./routes/announcements');

// Import middleware
const { errorHandler } = require('./middleware/errorHandler');
const { logger } = require('./utils/logger');
const { sanitizeRequest } = require('./utils/validation');

const app = express();

// Trust proxy if behind a reverse proxy (for rate limiting)
app.set('trust proxy', 1);

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "https:"],
      scriptSrc: ["'self'"],
      connectSrc: ["'self'"]
    }
  },
  crossOriginEmbedderPolicy: false
}));

// CORS configuration
app.use(cors({
  origin: function (origin, callback) {
    const allowedOrigins = [
      'http://localhost:3000',
      'http://localhost:3001',
      'http://vibebitstest-env.eba-ubvupniq.ap-south-1.elasticbeanstalk.com',
      'https://vibe-bites-frontend.vercel.app',
      'https://www.vibebites.shop',
      'https://vibe-bites-backend.onrender.com',
      'https://vibebites.shop',
      'https://snacks-front01-g1bl.vercel.app',
      'https://snacks-front01-g1bl.vercel.app/',
      'https://snacks-front01.vercel.app',
      'https://snacks-front01.vercel.app/',
      'https://snacks-back01-production.up.railway.app/',
      'https://snacks-back01-production.up.railway.app'


    ];
    
    // Allow requests with no origin (like mobile apps, curl, Postman, or same-origin requests)
    if (!origin) {
      return callback(null, true);
    }
    
    // Check if origin is in allowed list
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      // Log the blocked origin for debugging
      logger.warn(`CORS blocked origin: ${origin}`);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Cache-Control', 'Accept'],
  exposedHeaders: ['Content-Length', 'Content-Type'],
  optionsSuccessStatus: 200 // Some legacy browsers (IE11, various SmartTVs) choke on 204
}));

// Rate limiting with configuration
const limiter = rateLimit({
  windowMs: config.rateLimit.windowMs,
  max: config.rateLimit.general,
  message: {
    success: false,
    error: 'Too many requests from this IP, please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false,
  // Skip rate limiting for OPTIONS requests (CORS preflight)
  skip: (req) => req.method === 'OPTIONS'
});

// Apply rate limiting to API routes (but skip OPTIONS requests)
app.use('/api/', limiter);

// Stricter rate limiting for auth routes
const authLimiter = rateLimit({
  windowMs: config.rateLimit.windowMs,
  max: config.rateLimit.auth,
  message: {
    success: false,
    error: 'Too many authentication attempts, please try again later.'
  },
  // Skip rate limiting for OPTIONS requests (CORS preflight)
  skip: (req) => req.method === 'OPTIONS'
});

app.use('/api/auth/login', authLimiter);
app.use('/api/auth/register', authLimiter);
app.use('/api/auth/forgot-password', authLimiter);

// Stripe webhook must access the raw body, so we apply raw body parser just for that route BEFORE json parser
app.use('/api/payments/webhook', express.raw({ type: 'application/json' }));

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// Compression middleware
app.use(compression());

// Data sanitization against NoSQL query injection
app.use(mongoSanitize());

// Input sanitization middleware
app.use((req, res, next) => {
  try {
    if (req.body) {
      req.body = sanitizeRequest(req.body);
    }
    if (req.query) {
      req.query = sanitizeRequest(req.query);
    }
    if (req.params) {
      req.params = sanitizeRequest(req.params);
    }
  } catch (error) {
    logger.error('Input sanitization error:', error);
    return res.status(400).json({
      success: false,
      error: 'Invalid input data'
    });
  }
  next();
});

// Logging middleware
app.use(morgan('combined', { stream: { write: message => logger.info(message.trim()) } }));

// Serve static files from uploads directory with explicit CORS headers
app.use('/uploads', (req, res, next) => {
  res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.header('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Cache-Control, Accept');
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Cross-Origin-Resource-Policy', 'cross-origin');
  next();
}, express.static(path.join(__dirname, 'uploads')));

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'OK',
    message: 'VIBE BITES API is running',
    timestamp: new Date().toISOString()
  });
});

// API routes
app.use('/api/auth', authRoutes);
app.use('/api/products', productRoutes);
app.use('/api/categories', categoryRoutes);
app.use('/api/cart', cartRoutes);
app.use('/api/orders', orderRoutes);
app.use('/api/coupons', couponRoutes);
app.use('/api/payments', paymentRoutes);
app.use('/api/reviews', reviewRoutes);
app.use('/api/contact', contactRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/admin/products', adminProductCreateRoute);
app.use('/api/wishlist', wishlistRoutes);
app.use('/api/uploads', uploadsRoutes);
app.use('/api/announcements', announcementRoutes);

// Catch all handler for undefined routes
app.all('*', (req, res) => {
  res.status(404).json({
    success: false,
    error: `Route ${req.originalUrl} not found`
  });
});

// Error handling middleware
app.use(errorHandler);

// Connect to MongoDB
const connectDB = async () => {
  try {
    await mongoose.connect(config.mongodb.uri, config.mongodb.options);
    logger.info('MongoDB connected successfully');
  } catch (error) {
    logger.error('MongoDB connection error:', error);
    logger.warn('Continuing without MongoDB connection...');
    // Don't exit - let the app run without DB
  }
};

// Start server
const startServer = async () => {
  try {
    // Validate required config
    if (!config) {
      logger.error('Configuration is missing. Please check your NODE_ENV and config file.');
      process.exit(1);
    }

    if (!config.port) {
      logger.error('PORT is not configured. Please set PORT environment variable.');
      process.exit(1);
    }

    // Validate production environment variables
    if (process.env.NODE_ENV === 'production') {
      if (!process.env.MONGODB_URI) {
        logger.error('MONGODB_URI is required in production. Please set the environment variable.');
        process.exit(1);
      }
      if (!process.env.JWT_SECRET) {
        logger.error('JWT_SECRET is required in production. Please set the environment variable.');
        process.exit(1);
      }
    }

    // Start server first (don't wait for DB)
    const server = app.listen(config.port, '0.0.0.0', () => {
      logger.info(`Server running on port ${config.port} in ${process.env.NODE_ENV || 'development'} mode`);
    });

    // Handle server errors
    server.on('error', (error) => {
      if (error.code === 'EADDRINUSE') {
        logger.error(`Port ${config.port} is already in use`);
        process.exit(1);
      } else {
        logger.error('Server error:', error);
        process.exit(1);
      }
    });

    // Connect to database in background (non-blocking)
    connectDB().then(() => {
      // Seed default coupon if in development (after DB connects)
      if (process.env.NODE_ENV !== 'production') {
        setTimeout(async () => {
          try {
            const Coupon = require('./models/Coupon');
            const code = 'VIBE10';
            const existing = await Coupon.findOne({ code });
            if (!existing) {
              const now = new Date();
              await Coupon.create({
                code,
                description: '10% off your order',
                discount: 10,
                type: 'percentage',
                categories: [],
                minOrderAmount: 0,
                maxDiscount: 100,
                validFrom: now,
                validUntil: new Date(now.getTime() + 14 * 24 * 60 * 60 * 1000),
                isActive: true,
                isFirstTimeOnly: false
              });
              logger.info('Seeded default coupon VIBE10');
            } else {
              logger.info('Default coupon VIBE10 already present');
            }
          } catch (e) {
            logger.error('Error seeding default coupon:', e);
            // Don't exit - continue without seeding
          }
        }, 2000); // Wait 2 seconds for DB to be ready
      }
    }).catch(err => {
      logger.error('Database connection failed:', err);
    });

    // Keep-alive cron (only if fetch is available and in production)
    if (typeof fetch !== 'undefined' && process.env.NODE_ENV === 'production') {
      const baseUrl = 'https://snacks-back01.onrender.com';
      const pingHealth = async () => {
        try {
          // Create timeout controller
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), 5000);
          
          const res = await fetch(`${baseUrl}/health`, { 
            method: 'GET',
            signal: controller.signal
          });
          
          clearTimeout(timeoutId);
          if (!res.ok) throw new Error(`Health ping failed: ${res.status}`);
          logger.info('Keep-alive: health ping ok');
        } catch (err) {
          // Silently fail - don't log warnings for keep-alive
          if (err.name !== 'AbortError') {
            logger.debug(`Keep-alive: health ping error: ${err.message}`);
          }
        }
      };
      // Fire after a delay, then every 5 minutes
      setTimeout(pingHealth, 30000); // Wait 30 seconds before first ping
      setInterval(pingHealth, 5 * 60 * 1000);
      logger.info('Keep-alive cron enabled: pinging /health every 5 minutes');
    }
  } catch (error) {
    logger.error('Failed to start server:', error);
    process.exit(1);
  }
};

// Handle unhandled promise rejections
process.on('unhandledRejection', (err, promise) => {
  logger.error('Unhandled Rejection:', err);
  // In production, exit to allow process manager to restart
  if (process.env.NODE_ENV === 'production') {
    logger.error('Exiting due to unhandled rejection in production');
    process.exit(1);
  }
});

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
  logger.error('Uncaught Exception:', err);
  // Always exit on uncaught exceptions - they're dangerous
  process.exit(1);
});

// Handle SIGTERM gracefully (for Railway, Docker, etc.)
process.on('SIGTERM', () => {
  logger.info('SIGTERM received, shutting down gracefully');
  process.exit(0);
});

// Handle SIGINT gracefully (Ctrl+C)
process.on('SIGINT', () => {
  logger.info('SIGINT received, shutting down gracefully');
  process.exit(0);
});

startServer();

module.exports = app;