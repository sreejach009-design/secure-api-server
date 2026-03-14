const mongoose = require('mongoose');

const providerAccountSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    providerName: {
        type: String,
        required: true,
        enum: ['google', 'openai', 'groq', 'github'] // example
    },
    // ID from the provider side (e.g. google userId)
    externalAccountId: {
        type: String,
        required: true
    },
    // OAuth Tokens (Encrypted)
    accessToken: String,
    refreshToken: String,

    // Scopes granted
    permissions: [String],

    // Status
    status: {
        type: String,
        default: 'connected'
    },

    lastSyncedAt: Date,
    createdAt: {
        type: Date,
        default: Date.now
    }
});

module.exports = mongoose.model('ProviderAccount', providerAccountSchema);
