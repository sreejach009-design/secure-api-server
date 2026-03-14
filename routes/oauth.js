const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const ProviderAccount = require('../models/ProviderAccount');
const AuditLog = require('../models/AuditLog');

/* 
 * OAuth Provider Connection Management
 * Handles linking external platforms (Google/OpenAI/etc)
 */

// 1. List connected accounts
router.get('/list', auth, async (req, res) => {
    try {
        const accounts = await ProviderAccount.find({ userId: req.user.id })
            .select('-accessToken -refreshToken') // Never send tokens to frontend
            .sort('-createdAt');
        res.json(accounts);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 2. Initiate Connection (Simulation for now - typically redirects to Provider Auth)
router.post('/connect/:provider', auth, async (req, res) => {
    try {
        const { provider } = req.params;
        const { externalId, email, permissions } = req.body; // In real OAuth, these come from callback

        // Check if already linked
        let account = await ProviderAccount.findOne({
            userId: req.user.id,
            providerName: provider,
            externalAccountId: externalId
        });

        if (account) {
            return res.status(400).json({ message: `This ${provider} account is already linked.` });
        }

        account = new ProviderAccount({
            userId: req.user.id,
            providerName: provider,
            externalAccountId: externalId,
            permissions: permissions || ['read', 'usage_stats'],
            lastSyncedAt: new Date()
        });

        await account.save();

        await AuditLog.create({
            userId: req.user.id,
            action: 'oauth_connect',
            resourceType: 'oauth',
            resourceId: account._id,
            details: { provider, email },
            ipAddress: req.ip
        });

        res.json({ success: true, message: `Successfully linked ${provider} account`, account });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 3. Disconnect
router.delete('/:id', auth, async (req, res) => {
    try {
        const account = await ProviderAccount.findOneAndDelete({ _id: req.params.id, userId: req.user.id });
        if (!account) return res.status(404).json({ message: 'Account not found' });

        await AuditLog.create({
            userId: req.user.id,
            action: 'oauth_disconnect',
            resourceType: 'oauth',
            details: { provider: account.providerName },
            ipAddress: req.ip
        });

        res.json({ message: 'Account unlinked successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

module.exports = router;
