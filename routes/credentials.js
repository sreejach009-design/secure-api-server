const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const Credential = require('../models/Credential');
const AuditLog = require('../models/AuditLog');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');

// Get all credentials for user
router.get('/', auth, async (req, res) => {
    try {
        const credentials = await Credential.find({ userId: req.user.id })
            .select('-apiKeyHash') // Never return the hash
            .sort({ createdAt: -1 });

        // Ensure we don't return the plain apiKey if there's a masked version available
        const safeCredentials = credentials.map(c => {
            const obj = c.toObject();
            if (obj.apiKeyMasked) {
                obj.apiKey = obj.apiKeyMasked;
            }
            return obj;
        });

        res.json(safeCredentials);
    } catch (err) {
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});

// Create new credential
router.post('/', auth, async (req, res) => {
    try {
        const { name, expiresAt } = req.body;
        const plainApiKey = `sk_${uuidv4().replace(/-/g, '')}`;
        const apiKeyHash = crypto.createHash('sha256').update(plainApiKey).digest('hex');
        const apiKeyMasked = `sk_....${plainApiKey.slice(-4)}`;

        const newCredential = new Credential({
            userId: req.user.id,
            name,
            apiKeyHash,
            apiKeyMasked,
            expiresAt: expiresAt ? new Date(expiresAt) : null,
            status: 'active'
        });

        await newCredential.save();

        // Audit Log
        await AuditLog.create({
            userId: req.user.id,
            action: 'create_credential',
            resourceType: 'credential',
            resourceId: newCredential._id,
            details: { name: newCredential.name },
            ipAddress: req.ip
        });

        // Return the plain key ONLY ONCE here
        const responseData = newCredential.toObject();
        responseData.apiKey = plainApiKey;
        res.json(responseData);
    } catch (err) {
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});

// Rotate/Regenerate API Key
router.put('/:id/rotate', auth, async (req, res) => {
    try {
        const credential = await Credential.findOne({ _id: req.params.id, userId: req.user.id });
        if (!credential) return res.status(440).json({ message: 'Credential not found' });

        const plainApiKey = `sk_${uuidv4().replace(/-/g, '')}`;
        credential.apiKeyHash = crypto.createHash('sha256').update(plainApiKey).digest('hex');
        credential.apiKeyMasked = `sk_....${plainApiKey.slice(-4)}`;
        credential.apiKey = undefined; // Remove old plain key if it existed

        credential.createdAt = new Date(); // Reset creation time to rotation time
        await credential.save();

        // Audit Log
        await AuditLog.create({
            userId: req.user.id,
            action: 'rotate_credential',
            resourceType: 'credential',
            resourceId: credential._id,
            details: { name: credential.name },
            ipAddress: req.ip
        });

        const responseData = credential.toObject();
        responseData.apiKey = plainApiKey;
        res.json(responseData);
    } catch (err) {
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});

// Update Status (Activate/Deactivate)
router.patch('/:id/status', auth, async (req, res) => {
    try {
        const { status } = req.body;
        const credential = await Credential.findOneAndUpdate(
            { _id: req.params.id, userId: req.user.id },
            { status },
            { new: true }
        );
        if (!credential) return res.status(404).json({ message: 'Credential not found' });

        // Audit Log
        await AuditLog.create({
            userId: req.user.id,
            action: 'update_credential_status',
            resourceType: 'credential',
            resourceId: credential._id,
            details: { status: credential.status },
            ipAddress: req.ip
        });

        res.json(credential);
    } catch (err) {
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});

// Delete Credential
router.delete('/:id', auth, async (req, res) => {
    try {
        const result = await Credential.deleteOne({ _id: req.params.id, userId: req.user.id });
        if (result.deletedCount === 0) return res.status(404).json({ message: 'Credential not found' });

        // Audit Log
        await AuditLog.create({
            userId: req.user.id,
            action: 'delete_credential',
            resourceType: 'credential',
            resourceId: req.params.id,
            ipAddress: req.ip
        });

        res.json({ message: 'Credential deleted' });
    } catch (err) {
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});

module.exports = router;
