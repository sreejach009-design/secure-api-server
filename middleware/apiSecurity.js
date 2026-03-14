const crypto = require('crypto');
const Credential = require('../models/Credential');
const UsageLog = require('../models/UsageLog');
const SecurityAlert = require('../models/SecurityAlert');
const Notification = require('../models/Notification');

module.exports = async function (req, res, next) {
    const apiKey = req.header('X-API-KEY') || req.query.apiKey || req.body.apiKey;

    if (!apiKey) {
        return res.status(401).json({ message: 'No API key provided' });
    }

    try {
        const apiKeyHash = crypto.createHash('sha256').update(apiKey).digest('hex');

        // Try searching by hash FIRST, then fall back to plain apiKey (for old keys)
        let credential = await Credential.findOne({ apiKeyHash });

        if (!credential) {
            credential = await Credential.findOne({ apiKey });
        }

        if (!credential) {
            return res.status(401).json({ message: 'Invalid API key' });
        }

        const ip = req.ip;

        // 1. IP Blacklisting
        if (credential.blockedIps.includes(ip)) {
            await createAlert(credential, 'unauthorized_attempt', `Blocked IP ${ip} tried to use key`, 'high', ip);
            return res.status(403).json({ message: 'IP address is blocked' });
        }

        // 2. IP Whitelisting
        if (credential.allowedIps.length > 0 && !credential.allowedIps.includes(ip)) {
            await createAlert(credential, 'unauthorized_attempt', `Unauthorized IP ${ip} tried to use key`, 'medium', ip);
            return res.status(403).json({ message: 'IP address not whitelisted' });
        }

        // 3. Status checks (Inactive/Expired)
        if (credential.status === 'inactive') {
            await createAlert(credential, 'revoked_key_usage', `Attempted use of inactive key`, 'high', ip);
            return res.status(401).json({ message: 'API key is inactive' });
        }


        if (credential.status === 'expired' || (credential.expiresAt && credential.expiresAt < new Date())) {
            if (credential.status !== 'expired') {
                credential.status = 'expired';
                await credential.save();
            }
            await createAlert(credential, 'expired_key_usage', `Attempted use of expired key`, 'medium', ip);
            return res.status(401).json({ message: 'API key has expired' });
        }

        // 4. Rate Limiting (Simple MongoDB-based)
        const now = new Date();
        const oneMinuteAgo = new Date(now.getTime() - 60000);
        const oneHourAgo = new Date(now.getTime() - 3600000);

        const requestsInLastMinute = await UsageLog.countDocuments({
            credentialId: credential._id,
            timestamp: { $gte: oneMinuteAgo }
        });

        if (requestsInLastMinute >= credential.rateLimitPerMinute) {
            await createAlert(credential, 'high_usage', `Rate limit exceeded (per minute)`, 'medium', ip);
            return res.status(429).json({ message: 'Rate limit exceeded (per minute)' });
        }

        const requestsInLastHour = await UsageLog.countDocuments({
            credentialId: credential._id,
            timestamp: { $gte: oneHourAgo }
        });

        if (requestsInLastHour >= credential.rateLimitPerHour) {
            await createAlert(credential, 'high_usage', `Rate limit exceeded (per hour)`, 'medium', ip);
            return res.status(429).json({ message: 'Rate limit exceeded (per hour)' });
        }

        // 5. Success - Attach credential to request
        req.credential = credential;

        // Log usage (deferred or immediate)
        const log = new UsageLog({
            credentialId: credential._id,
            userId: credential.userId,
            endpoint: req.originalUrl || req.url,
            method: req.method,
            statusCode: 200,
            responseTime: 0, // Should be updated at the end of request
            ipAddress: ip
        });

        const start = Date.now();
        res.on('finish', async () => {
            log.statusCode = res.statusCode;
            log.responseTime = Date.now() - start;
            await log.save();

            // Update credential usage stats
            await Credential.updateOne(
                { _id: credential._id },
                {
                    $inc: { usageCount: 1 },
                    $set: { lastUsedAt: new Date() }
                }
            );
        });

        next();
    } catch (err) {
        console.error('API Security Middleware Error:', err);
        res.status(500).json({ message: 'Server security check failed' });
    }
};

async function createAlert(credential, type, message, severity, ip) {
    await SecurityAlert.create({
        userId: credential.userId,
        type,
        message: `${message} ending in ...${credential.apiKey.slice(-4)}`,
        severity,
        ipAddress: ip,
        apiKey: credential.apiKey
    });

    // Also create a notification for the user
    await Notification.create({
        userId: credential.userId,
        type: severity === 'high' || severity === 'critical' ? 'error' : 'warning',
        title: 'Security Alert',
        message: `${message} (${credential.name})`,
        metadata: { credentialId: credential._id, type }
    });
}
