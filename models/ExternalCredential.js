const mongoose = require('mongoose');

const externalCredentialSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    name: {
        type: String,
        required: true,
        trim: true
    },
    provider: {
        type: String,
        enum: ['openai', 'google', 'gemini', 'groq', 'aws', 'custom'],
        required: true
    },
    // Encrypted string stored via encryption util 
    apiKeyEncrypted: {
        type: String,
        required: true
    },
    // Masked for display: e.g. sk-...4f21
    apiKeyMasked: {
        type: String,
        required: true
    },
    status: {
        type: String,
        enum: ['active', 'inactive', 'revoked'],
        default: 'active'
    },
    rateLimits: {
        requestsPerMinute: { type: Number, default: 0 },
        requestsPerDay: { type: Number, default: 0 }
    },
    allowedIps: [{
        type: String,
        trim: true
    }],
    expiresAt: Date,
    description: String,
    usageCount: {
        type: Number,
        default: 0
    },
    lastUsedAt: Date,
    createdAt: {
        type: Date,
        default: Date.now
    }
});

module.exports = mongoose.model('ExternalCredential', externalCredentialSchema);
