const crypto = require('crypto');

/**
 * Encryption Utility for AES-256-GCM
 * Used for secure storage of external API keys
 */

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // Standard for GCM
const AUTH_TAG_LENGTH = 16;
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY; // Must be 32 bytes

if (!ENCRYPTION_KEY || ENCRYPTION_KEY.length !== 32) {
    console.error('CRITICAL: ENCRYPTION_KEY must be a 32-character string in .env');
}

/**
 * Encrypt a string
 * @param {string} text 
 * @returns {string} iv:authTag:encryptedText
 */
function encrypt(text) {
    if (!text) return null;

    try {
        const iv = crypto.randomBytes(IV_LENGTH);
        const cipher = crypto.createCipheriv(ALGORITHM, Buffer.from(ENCRYPTION_KEY), iv);

        let encrypted = cipher.update(text, 'utf8', 'hex');
        encrypted += cipher.final('hex');

        const authTag = cipher.getAuthTag().toString('hex');

        // Format: iv:authTag:encryptedContent
        return `${iv.toString('hex')}:${authTag}:${encrypted}`;
    } catch (err) {
        console.error('Encryption Failed:', err);
        throw new Error('Could not encrypt sensitive data');
    }
}

/**
 * Decrypt a string
 * @param {string} encryptedData iv:authTag:encryptedText
 * @returns {string} Original text
 */
function decrypt(encryptedData) {
    if (!encryptedData) return null;

    try {
        const [ivHex, authTagHex, encryptedText] = encryptedData.split(':');

        const iv = Buffer.from(ivHex, 'hex');
        const authTag = Buffer.from(authTagHex, 'hex');
        const decipher = crypto.createDecipheriv(ALGORITHM, Buffer.from(ENCRYPTION_KEY), iv);

        decipher.setAuthTag(authTag);

        let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
        decrypted += decipher.final('utf8');

        return decrypted;
    } catch (err) {
        console.error('Decryption Failed:', err);
        throw new Error('Could not decrypt sensitive data (Check ENCRYPTION_KEY)');
    }
}

module.exports = { encrypt, decrypt };
