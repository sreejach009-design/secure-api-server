const mongoose = require('mongoose');

const securityAlertSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    type: {
        type: String,
        enum: ['unauthorized_attempt', 'high_usage', 'expired_key_usage', 'revoked_key_usage'],
        required: true
    },
    message: { type: String, required: true },
    severity: {
        type: String,
        enum: ['low', 'medium', 'high', 'critical'],
        default: 'low'
    },
    ipAddress: { type: String },
    apiKey: { type: String },
    timestamp: { type: Date, default: Date.now },
    status: {
        type: String,
        enum: ['unread', 'read', 'resolved'],
        default: 'unread'
    }
});

module.exports = mongoose.model('SecurityAlert', securityAlertSchema);
