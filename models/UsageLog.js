const mongoose = require('mongoose');

const usageLogSchema = new mongoose.Schema({
    credentialId: { type: mongoose.Schema.Types.ObjectId, ref: 'Credential' },
    externalCredentialId: { type: mongoose.Schema.Types.ObjectId, ref: 'ExternalCredential' },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    platform: { type: String, enum: ['internal', 'external'], default: 'internal' },
    provider: { type: String, default: 'internal' }, // e.g. openai, google
    endpoint: { type: String, required: true },
    method: { type: String, required: true },
    statusCode: { type: Number },
    responseTime: { type: Number }, // in ms
    ipAddress: { type: String },
    errorMessage: { type: String },
    timestamp: { type: Date, default: Date.now }
});

module.exports = mongoose.model('UsageLog', usageLogSchema);
