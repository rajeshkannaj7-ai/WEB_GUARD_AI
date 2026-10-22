require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const errorHandler = require('./middleware/errorHandler');

const scanRoutes = require('./routes/scan');
const domainRoutes = require('./routes/domain');
const dashboardRoutes = require('./routes/dashboard');

const app = express();

// Security middleware
app.use(helmet());
app.use(cors({
  origin: ['http://localhost:5173', 'http://127.0.0.1:5173', 'http://localhost:5176', 'http://127.0.0.1:5176'],
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests, please try again later.' }
});
app.use('/api/', limiter);

app.use(express.json({ limit: '10kb' }));

// Routes
const { getIPIntelligence } = require('./services/domainIntel');

app.use('/api/scan', scanRoutes);
app.use('/api/domain', domainRoutes);
app.use('/api/ip-intelligence', async (req, res, next) => {
  try {
    const { domain } = req.query;
    if (!domain) {
      return res.status(400).json({ success: false, error: 'Domain parameter is required' });
    }
    const data = await getIPIntelligence(domain);
    res.json(data);
  } catch (err) {
    next(err);
  }
});
app.use('/api/dashboard', dashboardRoutes);

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'PhishGuard AI Backend is running', timestamp: new Date().toISOString() });
});

// Error handler
app.use(errorHandler);

const PORT = process.env.PORT || 5000;

// Start server
const startServer = () => {
  app.listen(PORT, () => {
    console.log(`🚀 PhishGuard AI Backend running on http://localhost:${PORT}`);
  });
};

// Optional MongoDB Connection
const connectDB = async () => {
  if (!process.env.MONGO_URI || process.env.DISABLE_MONGO === 'true') {
    console.log('⚡ MongoDB disabled - running without database (in-memory mode)');
    startServer();
    return;
  }

  try {
    await mongoose.connect(process.env.MONGO_URI, {
      serverSelectionTimeoutMS: 2000
    });
    console.log('✅ MongoDB connected to', process.env.MONGO_URI);
    startServer();
  } catch (err) {
    console.warn(`⚠️ MongoDB connection failed: ${err.message}`);
    console.log('⚡ MongoDB disabled - running without database (in-memory mode)');
    startServer();
  }
};

connectDB();

