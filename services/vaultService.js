const ExternalCredential = require('../models/ExternalCredential');
const { encrypt, decrypt } = require('../utils/encryption');
const AuditLog = require('../models/AuditLog');

/**
 * Vault Service Layer
 * Responsibilities: Secure CRUD operations for External API keys
 */

class VaultService {

    /**
     * Add a new external credential to the vault
     */
    async addCredential(userId, data, ip) {
        const { name, provider, apiKey, rateLimits, allowedIps, description, expiresAt } = data;

        if (!apiKey) throw new Error('API Key is required');

        // 1. Mask the key for display (e.g. sk-...abcd)
        const masked = `${apiKey.substring(0, 4)}...${apiKey.slice(-4)}`;

        // 2. Encrypt the key
        const encryptedKey = encrypt(apiKey);

        const newCred = new ExternalCredential({
            userId,
            name,
            provider,
            apiKeyEncrypted: encryptedKey,
            apiKeyMasked: masked,
            rateLimits: {
                requestsPerMinute: isNaN(rateLimits?.requestsPerMinute) ? 0 : rateLimits.requestsPerMinute
            },
            allowedIps,
            description,
            expiresAt
        });

        await newCred.save();

        // 3. Audit Logging
        await AuditLog.create({
            userId,
            action: 'add_external_credential',
            resourceType: 'vault',
            resourceId: newCred._id,
            details: { provider, name },
            ipAddress: ip
        });

        return newCred;
    }

    /**
     * Get decrypted key for usage (restricted access)
     */
    async accessKey(userId, credentialId, ip) {
        const cred = await ExternalCredential.findOne({ _id: credentialId, userId });
        if (!cred) throw new Error('Credential not found');

        // 1. Decrypt
        const apiKey = decrypt(cred.apiKeyEncrypted);

        // 2. Audit access (Very high sensitivity)
        await AuditLog.create({
            userId,
            action: 'access_vault_key',
            resourceType: 'vault',
            resourceId: cred._id,
            details: { provider: cred.provider },
            ipAddress: ip
        });

        return apiKey;
    }

    /**
     * List user's vault items (Metadata only)
     */
    async listCredentials(userId) {
        return await ExternalCredential.find({ userId }).select('-apiKeyEncrypted').sort('-createdAt');
    }

    /**
     * Mark a key as revoked/compromised
     */
    async revokeCredential(userId, credentialId) {
        return await ExternalCredential.findOneAndUpdate(
            { _id: credentialId, userId },
            { status: 'revoked' },
            { new: true }
        );
    }
}

module.exports = new VaultService();
