const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const User = require('../models/User');

// Register
router.post('/register', async (req, res) => {
    try {
        const { username, email, password, role } = req.body;
        console.log('Registering user:', { username, email, role });
        let user = await User.findOne({ email });
        if (user) {
            console.log('User already exists');
            return res.status(400).json({ message: 'User already exists' });
        }

        user = new User({ username, email, password, role: role || 'developer' });
        await user.save();
        console.log('User saved successfully');

        // Audit Log
        const AuditLog = require('../models/AuditLog');
        await AuditLog.create({
            userId: user.id,
            action: 'register',
            resourceType: 'auth',
            details: { username, email, role: user.role },
            ipAddress: req.ip
        });

        const payload = { user: { id: user.id, role: user.role } };
        jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '24h' }, (err, token) => {
            if (err) {
                console.error('JWT Signing Error:', err);
                throw err;
            }
            res.json({ token, user: { id: user.id, username, email, role: user.role } });
        });
    } catch (err) {
        console.error('Registration Error:', err);
        res.status(500).json({ message: err.message || 'Server error' });
    }
});

// Login
router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ message: 'Invalid credentials' });

        const isMatch = await user.comparePassword(password);
        if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

        if (user.status === 'blocked') {
            return res.status(403).json({ message: 'Your account has been restricted by an administrator.' });
        }

        user.lastLogin = new Date();
        await user.save();

        // Audit Log
        const AuditLog = require('../models/AuditLog');
        await AuditLog.create({
            userId: user.id,
            action: 'login',
            resourceType: 'auth',
            ipAddress: req.ip
        });

        const payload = { user: { id: user.id, role: user.role } };
        jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '24h' }, (err, token) => {
            if (err) {
                console.error('JWT Signing Error:', err);
                throw err;
            }
            res.json({ token, user: { id: user.id, username: user.username, email: user.email, role: user.role } });
        });
    } catch (err) {
        console.error('Login Error:', err);
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});

module.exports = router;
