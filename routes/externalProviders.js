const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const vaultService = require('../services/vaultService');
const ExternalCredential = require('../models/ExternalCredential');

/**
 * REST API for External Provider Management (Vault)
 */

// 1. Add external credential
router.post('/add', auth, async (req, res) => {
    try {
        const { name, provider, apiKey, rateLimits, allowedIps, description, expiresAt } = req.body;
        const result = await vaultService.addCredential(req.user.id, {
            name, provider, apiKey, rateLimits, allowedIps, description, expiresAt
        }, req.ip);

        res.json({
            success: true,
            message: 'External API key encrypted and stored in vault',
            data: result // Masked
        });
    } catch (err) {
        res.status(500).json({ message: 'Error storing credential', error: err.message });
    }
});

const UsageLog = require('../models/UsageLog');
const SecurityAlert = require('../models/SecurityAlert');

// 2. List items (Masked metadata only)
router.get('/list', auth, async (req, res) => {
    try {
        const list = await vaultService.listCredentials(req.user.id);
        res.json(list);
    } catch (err) {
        res.status(500).json({ message: 'Error fetching vault items', error: err.message });
    }
});

// 2b. Vault Security Health (Dynamic Calculation)
router.get('/vault-health', auth, async (req, res) => {
    try {
        const userId = req.user.id;
        const now = new Date();
        const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);

        const list = await ExternalCredential.find({ userId });
        const total = list.length;

        if (total === 0) {
            return res.json({
                encryptionCoverage: 100,
                rotationCompliance: 100,
                threatsDetected: 0,
                lastRotation: 'N/A'
            });
        }

        const overdue = list.filter(c => c.createdAt < thirtyDaysAgo && c.status === 'active').length;
        const threats = await SecurityAlert.countDocuments({ userId, status: 'unread' });

        res.json({
            encryptionCoverage: 100, // Always 100 since we only store encrypted now
            rotationCompliance: Math.round(((total - overdue) / total) * 100),
            threatsDetected: threats,
            lastRotation: list.sort((a, b) => b.createdAt - a.createdAt)[0].createdAt
        });

    } catch (err) {
        res.status(500).json({ message: 'Health analysis failed', error: err.message });
    }
});

// 3. Update Status
router.patch('/:id/status', auth, async (req, res) => {
    try {
        const { status } = req.body;
        const cred = await ExternalCredential.findOneAndUpdate(
            { _id: req.params.id, userId: req.user.id },
            { status },
            { new: true }
        ).select('-apiKeyEncrypted');

        if (!cred) return res.status(404).json({ message: 'Credential not found' });
        res.json(cred);
    } catch (err) {
        res.status(500).json({ message: 'Error updating status', error: err.message });
    }
});

// 4. Delete
router.delete('/:id', auth, async (req, res) => {
    try {
        await ExternalCredential.deleteOne({ _id: req.params.id, userId: req.user.id });
        res.json({ message: 'Credential removed from vault' });
    } catch (err) {
        res.status(500).json({ message: 'Error deleting', error: err.message });
    }
});

module.exports = router;
