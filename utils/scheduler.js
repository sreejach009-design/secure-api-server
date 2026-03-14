const cron = require('node-cron');
const { v4: uuidv4 } = require('uuid');
const Credential = require('../models/Credential');
const Notification = require('../models/Notification');
const AuditLog = require('../models/AuditLog');
const SecurityAlert = require('../models/SecurityAlert');
const UsageLog = require('../models/UsageLog');

// Run every day at midnight
const startScheduler = () => {
    cron.schedule('0 0 * * *', async () => {
        console.log('Running daily scheduler for credential rotation and reminders...');
        await checkRotations();
        await checkExpirations();
        await checkAnomalies();
    });
};

async function checkRotations() {
    try {
        const credentials = await Credential.find({ status: 'active' });
        const now = new Date();

        for (const cred of credentials) {
            const rotationDate = new Date(cred.lastRotatedAt || cred.createdAt);
            rotationDate.setDate(rotationDate.getDate() + (cred.rotationIntervalDays || 30));

            if (now >= rotationDate) {
                console.log(`Rotating key for ${cred.name}`);
                const oldKey = cred.apiKey;
                const newKey = uuidv4();

                cred.apiKey = newKey;
                cred.lastRotatedAt = now;
                await cred.save();

                await Notification.create({
                    userId: cred.userId,
                    type: 'info',
                    title: 'Automated Key Rotation',
                    message: `API Key for "${cred.name}" was automatically rotated for security.`,
                    metadata: { credentialId: cred._id, action: 'rotated' }
                });

                await AuditLog.create({
                    userId: cred.userId,
                    action: 'automatic_rotation',
                    resourceType: 'credential',
                    resourceId: cred._id,
                    details: { oldKeyTail: oldKey.slice(-4), newKeyTail: newKey.slice(-4) }
                });
            }
        }
    } catch (err) {
        console.error('Rotation Scheduler Error:', err);
    }
}

async function checkExpirations() {
    try {
        const now = new Date();
        const sevenDaysFromNow = new Date();
        sevenDaysFromNow.setDate(now.getDate() + 7);

        const expiringSoon = await Credential.find({
            status: 'active',
            expiresAt: { $gt: now, $lte: sevenDaysFromNow }
        });

        for (const cred of expiringSoon) {
            // Check if we already sent a reminder today
            const existingNotification = await Notification.findOne({
                userId: cred.userId,
                title: 'Credential Expiry Reminder',
                'metadata.credentialId': cred._id,
                timestamp: { $gt: new Date(now.getTime() - 24 * 60 * 60 * 1000) }
            });

            if (!existingNotification) {
                await Notification.create({
                    userId: cred.userId,
                    type: 'warning',
                    title: 'Credential Expiry Reminder',
                    message: `API Key "${cred.name}" will expire on ${cred.expiresAt.toLocaleDateString()}.`,
                    metadata: { credentialId: cred._id, action: 'expiry_warning' }
                });
            }
        }
    } catch (err) {
        console.error('Expiration Scheduler Error:', err);
    }
}

async function checkAnomalies() {
    try {
        const now = new Date();
        const past24h = new Date(now.getTime() - 24 * 60 * 60 * 1000);

        // 1. High Volume Anomaly: Any user with > 10,000 requests in 24h
        const highVolumeUsage = await UsageLog.aggregate([
            { $match: { timestamp: { $gt: past24h } } },
            { $group: { _id: "$userId", count: { $sum: 1 } } },
            { $match: { count: { $gt: 10000 } } }
        ]);

        for (const user of highVolumeUsage) {
            await SecurityAlert.create({
                userId: user._id,
                type: 'high_usage',
                severity: 'medium',
                message: `Anomaly Detected: Volumetric spike of ${user.count} requests in 24h.`,
                status: 'unread'
            });
        }

        // 2. Error Rate Anomaly: 4xx/5xx spikes > 20%
        const errorRates = await UsageLog.aggregate([
            { $match: { timestamp: { $gt: past24h } } },
            {
                $group: {
                    _id: "$userId",
                    total: { $sum: 1 },
                    errors: { $sum: { $cond: [{ $gte: ["$statusCode", 400] }, 1, 0] } }
                }
            },
            { $addFields: { rate: { $divide: ["$errors", "$total"] } } },
            { $match: { rate: { $gt: 0.2 }, total: { $gt: 50 } } }
        ]);

        for (const user of errorRates) {
            await SecurityAlert.create({
                userId: user._id,
                type: 'high_usage', // Generic type for now
                severity: 'high',
                message: `Anomaly Detected: Elevated error rate (${Math.round(user.rate * 100)}%) across ${user.total} requests.`,
                status: 'unread'
            });
        }

        console.log(`Anomaly scan completed at ${now}. Detected ${highVolumeUsage.length + errorRates.length} events.`);

    } catch (err) {
        console.error('Anomaly Detection Error:', err);
    }
}

module.exports = { startScheduler };
