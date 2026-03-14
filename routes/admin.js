const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const rbac = require('../middleware/rbac');
const User = require('../models/User');
const Credential = require('../models/Credential');
const SecurityAlert = require('../models/SecurityAlert');
const AuditLog = require('../models/AuditLog');
const ExternalCredential = require('../models/ExternalCredential');
const UsageLog = require('../models/UsageLog');

// Global middleware for this router - ONLY ADMINS
router.use(auth, rbac('admin'));

// Master Global Stats
router.get('/stats', async (req, res) => {
    try {
        const totalUsers = await User.countDocuments();
        const totalKeys = await Credential.countDocuments();
        const activeKeys = await Credential.countDocuments({ status: 'active' });
        const alertsCount = await SecurityAlert.countDocuments({ status: 'unread' });
        const blockedUsers = await User.countDocuments({ status: 'blocked' });

        const recentAlerts = await SecurityAlert.find()
            .populate('userId', 'username email')
            .sort({ timestamp: -1 })
            .limit(10);

        // Simple anomaly detection for stats
        const highUsageUsers = await UsageLog.aggregate([
            { $match: { timestamp: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } } },
            { $group: { _id: "$userId", count: { $sum: 1 } } },
            { $match: { count: { $gt: 1000 } } } // More than 1000 calls in last 24h
        ]);

        res.json({
            totalUsers,
            totalKeys,
            activeKeys,
            alertsCount,
            blockedUsers,
            recentAlerts,
            anomalyCount: highUsageUsers.length
        });
    } catch (err) {
        res.status(500).json({ message: 'Admin Stats Error', error: err.message });
    }
});

// Manage Users
router.get('/users', async (req, res) => {
    try {
        const users = await User.find({}, '-password').sort({ createdAt: -1 });
        res.json(users);
    } catch (err) {
        res.status(500).json({ message: 'Error fetching users', error: err.message });
    }
});

router.put('/users/:id/role', async (req, res) => {
    try {
        const { role } = req.body;
        const user = await User.findByIdAndUpdate(req.params.id, { role }, { new: true });

        await AuditLog.create({
            userId: req.user.id,
            action: 'change_user_role',
            resourceType: 'user',
            resourceId: user._id,
            details: { targetUserId: user._id, newRole: role }
        });

        res.json(user);
    } catch (err) {
        res.status(500).json({ message: 'Error updating user role', error: err.message });
    }
});

router.patch('/users/:id/status', async (req, res) => {
    try {
        const { status } = req.body;
        const user = await User.findByIdAndUpdate(req.params.id, { status }, { new: true });

        await AuditLog.create({
            userId: req.user.id,
            action: status === 'blocked' ? 'admin_block_user' : 'admin_unblock_user',
            resourceType: 'user',
            resourceId: user._id,
            details: { username: user.username, newStatus: status }
        });

        res.json(user);
    } catch (err) {
        res.status(500).json({ message: 'Error updating user status', error: err.message });
    }
});

router.delete('/users/:id', async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        if (!user) return res.status(404).json({ message: 'User not found' });
        
        if (user.role === 'admin') {
            const adminCount = await User.countDocuments({ role: 'admin' });
            if (adminCount <= 1) {
                return res.status(400).json({ message: 'Cannot delete the only administrator' });
            }
        }

        await User.findByIdAndDelete(req.params.id);
        // Cascading deletion could be added here for credentials etc.

        await AuditLog.create({
            userId: req.user.id,
            action: 'admin_delete_user',
            resourceType: 'user',
            resourceId: req.params.id,
            details: { username: user.username, email: user.email }
        });

        res.json({ message: 'User permanently deleted' });
    } catch (err) {
        res.status(500).json({ message: 'Error deleting user', error: err.message });
    }
});

// 3. Global Credential Management
router.get('/credentials', async (req, res) => {
    try {
        const credentials = await Credential.find()
            .populate('userId', 'username email')
            .sort({ createdAt: -1 });
        res.json(credentials);
    } catch (err) {
        res.status(500).json({ message: 'Error fetching global credentials', error: err.message });
    }
});

router.patch('/credentials/:id/status', async (req, res) => {
    try {
        const { status } = req.body;
        const cred = await Credential.findByIdAndUpdate(req.params.id, { status }, { new: true });
        
        await AuditLog.create({
            userId: req.user.id,
            action: 'admin_override_credential_status',
            resourceType: 'credential',
            resourceId: cred._id,
            details: { newStatus: status, ownerId: cred.userId }
        });

        res.json(cred);
    } catch (err) {
        res.status(500).json({ message: 'Error overriding status', error: err.message });
    }
});

router.post('/credentials/:id/rotate', async (req, res) => {
    try {
        const crypto = require('crypto');
        const { v4: uuidv4 } = require('uuid');
        
        const credential = await Credential.findById(req.params.id);
        if (!credential) return res.status(404).json({ message: 'Credential not found' });

        const plainApiKey = `sk_${uuidv4().replace(/-/g, '')}`;
        credential.apiKeyHash = crypto.createHash('sha256').update(plainApiKey).digest('hex');
        credential.apiKeyMasked = `sk_....${plainApiKey.slice(-4)}`;
        credential.lastRotatedAt = new Date();
        
        await credential.save();

        await AuditLog.create({
            userId: req.user.id,
            action: 'admin_force_rotate',
            resourceType: 'credential',
            resourceId: credential._id,
            details: { name: credential.name, ownerId: credential.userId }
        });

        res.json({ 
            message: 'Credential forcefully rotated', 
            newKey: plainApiKey,
            apiKeyMasked: credential.apiKeyMasked
        });
    } catch (err) {
        res.status(500).json({ message: 'Error forcing rotation', error: err.message });
    }
});

// 4. Global Activity Logs
router.get('/audit-logs', async (req, res) => {
    try {
        const logs = await AuditLog.find()
            .populate('userId', 'username email')
            .sort({ timestamp: -1 })
            .limit(100);
        res.json(logs);
    } catch (err) {
        res.status(500).json({ message: 'Error fetching global logs', error: err.message });
    }
});

// 5. Global External Credential Management
router.get('/external-credentials', async (req, res) => {
    try {
        const credentials = await ExternalCredential.find()
            .populate('userId', 'username email')
            .sort({ createdAt: -1 });
        res.json(credentials);
    } catch (err) {
        res.status(500).json({ message: 'Error fetching global external credentials', error: err.message });
    }
});

router.patch('/external-credentials/:id/status', async (req, res) => {
    try {
        const { status } = req.body;
        const cred = await ExternalCredential.findByIdAndUpdate(req.params.id, { status }, { new: true });
        
        await AuditLog.create({
            userId: req.user.id,
            action: 'admin_override_external_status',
            resourceType: 'external_credential',
            resourceId: cred._id,
            details: { newStatus: status, ownerId: cred.userId }
        });

        res.json(cred);
    } catch (err) {
        res.status(500).json({ message: 'Error overriding external status', error: err.message });
    }
});

// 6. Platform Analytics / Telemetry
router.get('/telemetry', async (req, res) => {
    try {
        const totalCalls = await UsageLog.countDocuments();
        const successCalls = await UsageLog.countDocuments({ statusCode: { $lt: 400 } });
        const errorCalls = await UsageLog.countDocuments({ statusCode: { $gte: 400 } });
        
        // Group by provider
        const providerStats = await UsageLog.aggregate([
            { $group: { _id: "$provider", count: { $sum: 1 } } }
        ]);

        // Recent errors
        const recentErrors = await UsageLog.find({ statusCode: { $gte: 400 } })
            .populate('userId', 'username')
            .sort({ timestamp: -1 })
            .limit(10);

        // Detect Anomalies (High error rate in last hour)
        const hourAgo = new Date(Date.now() - 60 * 60 * 1000);
        const anomalies = await UsageLog.aggregate([
            { $match: { timestamp: { $gte: hourAgo } } },
            { $group: { 
                _id: "$userId", 
                total: { $sum: 1 },
                errors: { $sum: { $cond: [{ $gte: ["$statusCode", 400] }, 1, 0] } }
            }},
            { $project: {
                userId: "$_id",
                total: 1,
                errors: 1,
                errorRate: { $multiply: [{ $divide: ["$errors", "$total"] }, 100] }
            }},
            { $match: { errorRate: { $gt: 50 }, total: { $gt: 10 } } } // Over 50% errors with > 10 calls
        ]);

        const populatedAnomalies = await User.populate(anomalies, { path: 'userId', select: 'username email' });

        res.json({
            totalCalls,
            successCalls,
            errorCalls,
            successRate: totalCalls > 0 ? ((successCalls / totalCalls) * 100).toFixed(2) : 100,
            providerStats,
            recentErrors,
            anomalies: populatedAnomalies
        });
    } catch (err) {
        res.status(500).json({ message: 'Error fetching telemetry', error: err.message });
    }
});

// 5. Platform Configuration
let platformConfig = {
    maintenanceMode: false,
    globalRateLimit: 5000,
    registrationOpen: true,
    enforceRotation: true,
    rotationDays: 30,
    minPasswordLength: 12,
    sessionTimeout: 3600
};

router.get('/config', (req, res) => {
    res.json(platformConfig);
});

router.post('/config', (req, res) => {
    platformConfig = { ...platformConfig, ...req.body };
    res.json({ message: 'Configuration updated', config: platformConfig });
});

module.exports = router;
