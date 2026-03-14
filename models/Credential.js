const mongoose = require('mongoose');

const credentialSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    name: { type: String, required: true },
    apiKey: { type: String, unique: true, sparse: true },
    apiKeyHash: { type: String, unique: true, sparse: true },
    apiKeyMasked: { type: String },
    status: { type: String, enum: ['active', 'inactive', 'expired'], default: 'active' },
    expiresAt: { type: Date },
    lastUsedAt: { type: Date },
    usageCount: { type: Number, default: 0 },
    rateLimitPerMinute: { type: Number, default: 1000 },
    rateLimitPerHour: { type: Number, default: 5000 },
    allowedIps: { type: [String], default: [] },
    blockedIps: { type: [String], default: [] },
    rotationIntervalDays: { type: Number, default: 30 },
    lastRotatedAt: { type: Date, default: Date.now },
    createdAt: { type: Date, default: Date.now },
    metadata: { type: Object, default: {} }
});

module.exports = mongoose.model('Credential', credentialSchema);
