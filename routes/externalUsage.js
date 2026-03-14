const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const mongoose = require('mongoose');
const vaultService = require('../services/vaultService');
const ExternalCredential = require('../models/ExternalCredential');
const UsageLog = require('../models/UsageLog');

/**
 * REST API for External Usage & Monitoring
 */

// 1. Get External Usage Statistics & Trends
router.get('/stats', auth, async (req, res) => {
    try {
        const now = new Date();
        const past24h = new Date(now.getTime() - 24 * 60 * 60 * 1000);
        const past48h = new Date(now.getTime() - 48 * 60 * 60 * 1000);

        // a) Group by provider stats
        const providerStats = await UsageLog.aggregate([
            { $match: { userId: new mongoose.Types.ObjectId(req.user.id), platform: 'external' } },
            {
                $group: {
                    _id: "$provider",
                    count: { $sum: 1 },
                    avgResponseTime: { $avg: "$responseTime" },
                    errors: { $sum: { $cond: [{ $gte: ["$statusCode", 400] }, 1, 0] } }
                }
            }
        ]);

        // b) Calculate 24h volume trend
        const todayCount = await UsageLog.countDocuments({
            userId: req.user.id, platform: 'external', timestamp: { $gt: past24h }
        });
        const yesterdayCount = await UsageLog.countDocuments({
            userId: req.user.id, platform: 'external', timestamp: { $gt: past48h, $lt: past24h }
        });

        const volumeTrend = yesterdayCount === 0 ? 100 : ((todayCount - yesterdayCount) / yesterdayCount) * 100;

        res.json({
            providers: providerStats,
            trends: {
                volumeIncrease: volumeTrend.toFixed(1),
                todayTotal: todayCount,
                errorRate: todayCount === 0 ? 0 : (providerStats.reduce((a, b) => a + b.errors, 0) / todayCount * 100).toFixed(1)
            }
        });
    } catch (err) {
        res.status(500).json({ message: 'Stats calculation failed', error: err.message });
    }
});

// 2. Monitoring Bridge (Proxy call to external API)
// Support both POST (for real data) and GET (for UI health checks)
const proxyHandler = async (req, res) => {
    const startTime = Date.now();
    try {
        const targetUrl = req.body?.targetUrl || req.query?.targetUrl;
        const method = req.body?.method || req.method || 'GET';
        const data = req.body?.data;

        console.log(`[Proxy] Request to ${targetUrl} via ${method}`);

        if (!targetUrl) return res.status(400).json({ message: 'Target URL is required' });

        // Use Vault Service to get the secure key
        const apiKeyDecrypted = await vaultService.accessKey(req.user.id, req.params.credentialId, req.ip);
        const cred = await ExternalCredential.findById(req.params.credentialId);

        if (!cred) {
            console.log(`[Proxy] Credential ${req.params.credentialId} not found`);
            throw new Error('External credential not found');
        }

        // --- NEW SECURITY ENFORCEMENT ---
        // 1. Check Status
        if (cred.status !== 'active') {
            throw new Error(`Credential is ${cred.status}. Proxy access denied.`);
        }

        // 2. IP Whitelisting
        if (cred.allowedIps && cred.allowedIps.length > 0) {
            const clientIp = req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress;
            const isAllowed = cred.allowedIps.includes(clientIp) || cred.allowedIps.includes('::1') || cred.allowedIps.includes('127.0.0.1');

            if (!isAllowed) {
                console.warn(`[Security Alert] unauthorized IP ${clientIp} attempted to use key ${cred.name}`);
                throw new Error('IP Access Denied: This credential is restricted to specific IP addresses.');
            }
        }

        // 3. Expiration Check
        if (cred.expiresAt && new Date() > new Date(cred.expiresAt)) {
            throw new Error('Credential Expired: Please rotate your API key to continue using the proxy.');
        }
        // --------------------------------

        console.log(`[Proxy] Using key for ${cred.provider} (${cred.name})`);

        // 1. Make the external request using native fetch
        const response = await fetch(targetUrl, {
            method: method,
            headers: {
                'Authorization': `Bearer ${apiKeyDecrypted}`, // Injected securely
                'Content-Type': 'application/json'
            },
            body: (method !== 'GET' && method !== 'HEAD' && data) ? JSON.stringify(data) : undefined
        });

        const responseTime = Date.now() - startTime;
        console.log(`[Proxy] ${targetUrl} returned ${response.status} in ${responseTime}ms`);

        let responseData = {};
        try {
            responseData = await response.json();
        } catch (e) {
            responseData = { message: 'Response received', status: response.status, text: await response.text() };
        }

        // 2. Log External Usage
        await UsageLog.create({
            userId: req.user.id,
            externalCredentialId: cred._id,
            platform: 'external',
            provider: cred.provider,
            endpoint: targetUrl,
            method: method,
            statusCode: response.status,
            responseTime,
            ipAddress: req.ip
        });

        // 3. Update Credential Usage Count
        await ExternalCredential.findByIdAndUpdate(cred._id, {
            $inc: { usageCount: 1 },
            lastUsedAt: new Date()
        });

        res.status(response.status).json(responseData);
    } catch (err) {
        const responseTime = Date.now() - startTime;
        console.error('[Proxy Error]', err);

        // Log the failure
        await UsageLog.create({
            userId: req.user.id,
            platform: 'external',
            provider: 'proxy_error',
            endpoint: req.body?.targetUrl || req.query?.targetUrl || 'unknown',
            method: req.method || 'POST',
            statusCode: 500,
            responseTime,
            errorMessage: err.message,
            ipAddress: req.ip
        });

        res.status(500).json({
            message: 'External API Proxy Error',
            error: err.message
        });
    }
};

router.post('/proxy/:credentialId', auth, proxyHandler);
router.get('/proxy/:credentialId', auth, proxyHandler);

module.exports = router;
