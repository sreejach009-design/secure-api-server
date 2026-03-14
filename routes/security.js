const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const SecurityAlert = require('../models/SecurityAlert');
const AuditLog = require('../models/AuditLog');

// Get all alerts for a user
router.get('/', auth, async (req, res) => {
    try {
        const alerts = await SecurityAlert.find({ userId: req.user.id }).sort({ timestamp: -1 });
        res.json(alerts);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});

// Get system audit logs
router.get('/audit-logs', auth, async (req, res) => {
    try {
        const logs = await AuditLog.find({ userId: req.user.id })
            .select('-__v')
            .sort({ timestamp: -1 })
            .limit(100); // Limit for performance
        res.json(logs);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});

// Update alert status
router.patch('/:id/status', auth, async (req, res) => {
    try {
        const { status } = req.body;
        const alert = await SecurityAlert.findOneAndUpdate(
            { _id: req.params.id, userId: req.user.id },
            { status },
            { new: true }
        );
        if (!alert) return res.status(404).json({ message: 'Alert not found' });
        res.json(alert);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});

module.exports = router;
