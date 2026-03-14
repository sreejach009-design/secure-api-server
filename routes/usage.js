const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const UsageLog = require('../models/UsageLog');
const Credential = require('../models/Credential');
const SecurityAlert = require('../models/SecurityAlert');
const AuditLog = require('../models/AuditLog');
const Notification = require('../models/Notification');
const rbac = require('../middleware/rbac');

const mongoose = require('mongoose');

// Get usage statistics for a user
router.get('/stats', auth, async (req, res) => {
    try {
        const logs = await UsageLog.find({ userId: req.user.id }).sort({ timestamp: -1 }).limit(100);

        const userId = new mongoose.Types.ObjectId(req.user.id);

        const stats = await UsageLog.aggregate([
            { $match: { userId } },
            {
                $group: {
                    _id: { $dateToString: { format: "%Y-%m-%d", date: "$timestamp" } },
                    count: { $sum: 1 },
                    avgResponseTime: { $avg: "$responseTime" }
                }
            },
            { $sort: { _id: 1 } }
        ]);

        // Total count across all time for a direct display on the dashboard
        const totalCalls = await UsageLog.countDocuments({ userId });

        res.json({ logs, stats, totalCalls });
    } catch (err) {
        console.error('Stats Error:', err);
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});

// Detailed Analytics
router.get('/analytics', auth, async (req, res) => {
    try {
        const userId = new mongoose.Types.ObjectId(req.user.id);

        // 1. Top Endpoints
        const topEndpoints = await UsageLog.aggregate([
            { $match: { userId } },
            { $group: { _id: "$endpoint", count: { $sum: 1 } } },
            { $sort: { count: -1 } },
            { $limit: 10 }
        ]);

        // 2. Status Code Breakdown
        const statusCodes = await UsageLog.aggregate([
            { $match: { userId } },
            { $group: { _id: "$statusCode", count: { $sum: 1 } } }
        ]);

        // 3. Response Time percentile (simple)
        const avgLatency = await UsageLog.aggregate([
            { $match: { userId } },
            { $group: { _id: null, avg: { $avg: "$responseTime" }, max: { $max: "$responseTime" } } }
        ]);

        res.json({ topEndpoints, statusCodes, latency: avgLatency[0] || { avg: 0, max: 0 } });
    } catch (err) {
        res.status(500).json({ message: 'Analytics Error' });
    }
});

// Audit Logs
router.get('/audit', auth, async (req, res) => {
    try {
        let query = { userId: req.user.id };
        // Admin can see everything if they want, but default to their own
        if (req.user.role === 'admin' && req.query.global === 'true') {
            query = {};
        }

        const logs = await AuditLog.find(query).sort({ timestamp: -1 }).limit(50);
        res.json(logs);
    } catch (err) {
        res.status(500).json({ message: 'Audit Log Error' });
    }
});

// Notifications
router.get('/notifications', auth, async (req, res) => {
    try {
        const notifications = await Notification.find({ userId: req.user.id })
            .sort({ timestamp: -1 })
            .limit(20);
        res.json(notifications);
    } catch (err) {
        res.status(500).json({ message: 'Notifications Error' });
    }
});

router.put('/notifications/:id', auth, async (req, res) => {
    try {
        await Notification.findOneAndUpdate(
            { _id: req.params.id, userId: req.user.id },
            { isRead: true }
        );
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ message: 'Update Notification Error' });
    }
});

// Mock endpoint to simulate API usage
// Uses auth so the alert userId matches the logged-in user exactly
router.post('/simulate', auth, async (req, res) => {
    try {
        const { credentialId, apiKey, endpoint, method, scenario } = req.body;
        const userIdStr = req.user.id;
        const userId = new mongoose.Types.ObjectId(userIdStr);
        const fs = require('fs');
        const logPath = 'C:\\Users\\Sreeja\\OneDrive\\Desktop\\secure API credential\\server\\simulate_debug.log';
        
        const debugLog = (msg) => {
            const entry = `${new Date().toISOString()} [DEBUG] ${msg}\n`;
            try { fs.appendFileSync(logPath, entry); } catch(e) {}
            console.log(entry.trim());
        };

        debugLog(`Request from user ${userIdStr} for key ${credentialId || apiKey}, scenario: ${scenario}`);

        // Prefer lookup by _id and verify it belongs to the logged-in user
        let credential = null;
        if (credentialId) {
            credential = await Credential.findOne({ _id: credentialId, userId });
            debugLog(`Lookup by _id result: ${credential ? 'FOUND: ' + credential.name : 'NOT FOUND'}`);
        }

        // Fallback: try plain apiKey field or hash lookup
        if (!credential && apiKey) {
            // First try direct apiKey string lookup
            credential = await Credential.findOne({ apiKey, userId });
            debugLog(`Lookup by plain key result: ${credential ? 'FOUND' : 'NOT FOUND'}`);
            
            // If not found, try hash lookup
            if (!credential) {
                const crypto = require('crypto');
                const hash = crypto.createHash('sha256').update(apiKey).digest('hex');
                credential = await Credential.findOne({ apiKeyHash: hash, userId });
                debugLog(`Lookup by hash result: ${credential ? 'FOUND' : 'NOT FOUND'}`);
            }
        }

        if (!credential) {
            debugLog(`[CRITICAL] Credential not found for query: ${credentialId || apiKey}`);
            return res.status(404).json({ message: 'Credential not found. Please select a valid key.' });
        }

        debugLog(`Selected credential: ${credential.name}, status: ${credential.status}, current context scenario: ${scenario}`);

        // --- Determine outcome based on scenario + credential state ---
        const keyLabel = credential.apiKeyMasked || String(credential._id).slice(-4);
        const responseTime = Math.floor(Math.random() * 200) + 50; 
        const ipAddr = req.ip || req.headers['x-forwarded-for'] || '127.0.0.1';

        let outcomeStatus = 200;
        let outcomeMessage = 'API call successful';
        let alertData = null;

        // Forced test scenarios (override credential state)
        if (scenario === 'inactive') {
            debugLog(`Scenario 'inactive' selected - forcing 401`);
            outcomeStatus = 401;
            outcomeMessage = 'API key is inactive';
            alertData = { type: 'revoked_key_usage', message: `TEST: Attempted use of inactive key (${keyLabel})`, severity: 'high' };
        } else if (scenario === 'expired') {
            outcomeStatus = 401;
            outcomeMessage = 'API key has expired';
            alertData = { type: 'expired_key_usage', message: `TEST: Attempted use of expired key (${keyLabel})`, severity: 'medium' };
        } else if (scenario === 'high') {
            outcomeStatus = 429;
            outcomeMessage = 'Rate limit exceeded';
            alertData = { type: 'high_usage', message: `TEST: High usage detected for key (${keyLabel})`, severity: 'low' };
        } else {
            // "Normal" scenario - check actual DB state
            debugLog(`Scenario 'Normal' - checking status: ${credential.status}`);
            if (credential.status === 'inactive') {
                debugLog(`Key is INACTIVE in DB - setting status 401`);
                outcomeStatus = 401;
                outcomeMessage = 'API key is inactive';
                alertData = { type: 'revoked_key_usage', message: `Attempted use of inactive key (${keyLabel})`, severity: 'high' };
            } else if (credential.status === 'expired' || (credential.expiresAt && new Date(credential.expiresAt) < new Date())) {
                debugLog(`Key is EXPIRED in DB - setting status 401`);
                if (credential.status !== 'expired') {
                    credential.status = 'expired';
                    await credential.save();
                }
                outcomeStatus = 401;
                outcomeMessage = 'API key has expired';
                alertData = { type: 'expired_key_usage', message: `Attempted use of expired key (${keyLabel})`, severity: 'medium' };
            }
        }

        // Always log this call attempt (success or failure) 
        try {
            debugLog(`Attempting to create UsageLog for status ${outcomeStatus}`);
            await UsageLog.create({
                credentialId: credential._id,
                userId: userId,
                platform: 'internal',
                provider: 'internal',
                endpoint: endpoint || '/api/v1/data',
                method: method || 'GET',
                statusCode: outcomeStatus,
                responseTime,
                ipAddress: ipAddr,
                errorMessage: outcomeStatus !== 200 ? outcomeMessage : undefined
            });
            debugLog(`UsageLog created successfully`);
        } catch (logErr) {
            debugLog(`[ERROR] Failed to create UsageLog: ${logErr.message}`);
            // Non-critical: continue even if logging fails
        }

        let alertCreated = false;
        // Create security alert if needed
        if (alertData) {
            try {
                debugLog(`Attempting to create SecurityAlert: ${alertData.type}`);
                const newAlert = new SecurityAlert({
                    userId: userId,
                    type: alertData.type,
                    message: alertData.message,
                    severity: alertData.severity,
                    ipAddress: ipAddr,
                    apiKey: credential.apiKeyMasked
                });
                await newAlert.save();
                alertCreated = true;
                debugLog(`SecurityAlert created successfully`);
            } catch (alertErr) {
                debugLog(`[ERROR] Failed to save SecurityAlert: ${alertErr.message}`);
            }
        }

        // Update credential statistics
        try {
            credential.usageCount = (credential.usageCount || 0) + 1;
            credential.lastUsedAt = new Date();
            await credential.save();
        } catch (credErr) {
            console.error('[Simulate] Failed to update credential stats:', credErr);
        }

        // Auto-alert on real world high usage (> 100 calls)
        if (outcomeStatus === 200 && credential.usageCount > 100) {
            const lastDay = new Date(Date.now() - 24 * 60 * 60 * 1000);
            const existingAlert = await SecurityAlert.findOne({
                userId: userId,
                type: 'high_usage',
                timestamp: { $gt: lastDay }
            });
            if (!existingAlert) {
                await SecurityAlert.create({
                    userId: userId,
                    type: 'high_usage',
                    message: `High usage detected for key (${keyLabel})`,
                    severity: 'low',
                    ipAddress: ipAddr,
                    apiKey: credential.apiKeyMasked
                });
                alertCreated = true;
            }
        }

        // If outcome is failure, return early
        if (outcomeStatus !== 200) {
            return res.status(outcomeStatus).json({ 
                success: false, 
                message: outcomeMessage, 
                alertCreated 
            });
        }

        // INTEGRATION: Optional Groq API call
        let groqResponse = null;
        if (req.body.prompt) {
            try {
                // Check if fetch is available (Node 18+) or use a fallback
                const response = await fetch(process.env.GROQ_API_URL, {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${process.env.GROQ_API_KEY}`,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        model: req.body.model || 'llama-3.3-70b-versatile',
                        messages: [{ role: 'user', content: req.body.prompt }]
                    })
                });

                const data = await response.json();
                if (!response.ok) throw new Error(data.error?.message || 'Groq API error');
                groqResponse = data;
            } catch (groqErr) {
                console.error('[Simulate] Groq Integration Error:', groqErr);
                return res.status(502).json({
                    message: 'Error calling Groq API',
                    error: groqErr.message
                });
            }
        }

        res.json({
            success: true,
            message: 'API call successful',
            alertCreated: false,
            data: groqResponse || { id: 1, value: 'simulated_success', timestamp: new Date() }
        });

    } catch (err) {
        console.error('[Simulate] Critical Error:', err);
        res.status(500).json({ 
            message: 'Internal server error during simulation', 
            error: err.message 
        });
    }
});


module.exports = router;
