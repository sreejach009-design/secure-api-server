require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const morgan = require('morgan');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { startScheduler } = require('./utils/scheduler');

const app = express();
startScheduler();

// Global Security Middleware
app.use(helmet()); // Sets various HTTP headers for security

// Rate Limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 1000, // Very liberal for dev
    message: { message: 'Too many requests' },
});

// Apply rate limiter to all requests
app.use('/api/', limiter);

// Middleware
app.use(express.json({ limit: '10kb' }));
app.use(cors({
    origin: true, // Allow all origins for dev
    credentials: true
}));
app.use(morgan('dev'));

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/api-credential-platform')
    .then(() => console.log('MongoDB Connected'))
    .catch(err => console.error('MongoDB Connection Error:', err));

// Routes
app.use('/api/auth', require('./routes/auth'));
app.use('/api/credentials', require('./routes/credentials'));
app.use('/api/usage', require('./routes/usage'));
app.use('/api/security', require('./routes/security'));
app.use('/api/admin', require('./routes/admin'));
app.use('/api/external-providers', require('./routes/externalProviders'));
app.use('/api/external-usage', require('./routes/externalUsage'));
app.use('/api/oauth-connections', require('./routes/oauth'));

// Health check
app.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date() });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
