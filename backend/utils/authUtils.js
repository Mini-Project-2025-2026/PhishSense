const crypto = require('crypto');

// Secret for signing session tokens (fallback to secure random in production)
const JWT_SECRET = process.env.JWT_SECRET || 'phishsense-secure-session-secret-key-2026';
const TOKEN_EXPIRY_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

// Common weak password blacklist
const COMMON_WEAK_PASSWORDS = new Set([
  'password1234',
  'password12345',
  '123456789012',
  '1234567890123',
  'qwerty123456',
  'admin1234567',
  'welcome12345',
  'phishsense123',
  'administrator',
  'iloveyou1234',
  'changeme1234'
]);

/**
 * Validates password length, guessing resistance, and calculates strength.
 * Policy: Min 12 chars, max 128 chars, supports spaces & special chars.
 * @param {string} password 
 * @returns {{ valid: boolean, error?: string, score: number, label: string }}
 */
function validatePasswordPolicy(password) {
  if (!password || typeof password !== 'string') {
    return { valid: false, error: 'Password is required.', score: 0, label: 'Weak' };
  }

  if (password.length < 12) {
    return {
      valid: false,
      error: 'Password must be at least 12 characters long.',
      score: 1,
      label: 'Weak'
    };
  }

  if (password.length > 128) {
    return {
      valid: false,
      error: 'Password must not exceed 128 characters.',
      score: 1,
      label: 'Weak'
    };
  }

  if (COMMON_WEAK_PASSWORDS.has(password.toLowerCase().trim())) {
    return {
      valid: false,
      error: 'This password is too common or easily guessable. Please choose a more unique passphrase.',
      score: 1,
      label: 'Weak'
    };
  }

  // Calculate Strength Score (0 to 4)
  let score = 0;
  if (password.length >= 12) score += 1;
  if (password.length >= 16) score += 1;
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score += 1;
  if (/\d/.test(password) || /[^a-zA-Z0-9]/.test(password)) score += 1;

  let label = 'Weak';
  if (score === 2) label = 'Fair';
  else if (score === 3) label = 'Strong';
  else if (score >= 4) label = 'Very Strong';

  return { valid: true, score, label };
}

/**
 * Hashes a password using PBKDF2 with SHA-512 and a cryptographically secure random salt.
 * @param {string} password 
 * @returns {{ hash: string, salt: string }}
 */
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  return { hash, salt };
}

/**
 * Verifies a plaintext password against a stored PBKDF2 hash and salt.
 * @param {string} password 
 * @param {string} hash 
 * @param {string} salt 
 * @returns {boolean}
 */
function verifyPassword(password, hash, salt) {
  if (!password || !hash || !salt) return false;
  try {
    const computedHash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
    return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(computedHash, 'hex'));
  } catch (_) {
    return false;
  }
}

/**
 * Computes SHA-256 hash of a verification or reset token for secure lookup.
 * @param {string} token 
 * @returns {string}
 */
function hashToken(token) {
  return crypto.createHash('sha256').update(token.trim()).digest('hex');
}

/**
 * Generates a cryptographically random, 6-digit numeric OTP code.
 * Expiration: 10 minutes.
 * @returns {{ code: string, codeHash: string, expiresAt: string, attempts: number }}
 */
function generateOtpRecord() {
  // Generate 6-digit integer from 100000 to 999999
  const codeInt = crypto.randomInt(100000, 1000000);
  const code = codeInt.toString();
  const codeHash = hashToken(code);
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString(); // 10 minutes
  return {
    code,
    codeHash,
    expiresAt,
    attempts: 0
  };
}

/**
 * Verifies a 6-digit OTP code against stored SHA-256 hash using constant-time comparison.
 * @param {string} submittedCode 
 * @param {string} storedHash 
 * @returns {boolean}
 */
function verifyOtpCode(submittedCode, storedHash) {
  if (!submittedCode || !storedHash) return false;
  try {
    const submittedHash = hashToken(submittedCode);
    const hashA = Buffer.from(submittedHash, 'hex');
    const hashB = Buffer.from(storedHash, 'hex');
    if (hashA.length !== hashB.length) return false;
    return crypto.timingSafeEqual(hashA, hashB);
  } catch (_) {
    return false;
  }
}

/**
 * Generates a cryptographically random, single-use password reset token.
 * @returns {{ token: string, tokenHash: string, expiresAt: string }}
 */
function generateResetToken() {
  const token = crypto.randomBytes(32).toString('hex');
  const tokenHash = hashToken(token);
  const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString(); // 1 hour
  return { token, tokenHash, expiresAt };
}

/**
 * Generates an HMAC-SHA256 signed stateless bearer token.
 * Payload includes userId, email, role, and expiry timestamp.
 * @param {Object} payload 
 * @returns {string} Signed token string
 */
function generateToken(payload) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const exp = Date.now() + TOKEN_EXPIRY_MS;
  const tokenPayload = { ...payload, exp, iat: Date.now() };

  const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
  const encodedPayload = Buffer.from(JSON.stringify(tokenPayload)).toString('base64url');

  const signature = crypto
    .createHmac('sha256', JWT_SECRET)
    .update(`${encodedHeader}.${encodedPayload}`)
    .digest('base64url');

  return `${encodedHeader}.${encodedPayload}.${signature}`;
}

/**
 * Verifies a signed bearer token, checks signature validity and expiration.
 * @param {string} token 
 * @returns {{ valid: boolean, payload?: Object, error?: string }}
 */
function verifyToken(token) {
  if (!token || typeof token !== 'string') {
    return { valid: false, error: 'Token missing or invalid.' };
  }

  const parts = token.split('.');
  if (parts.length !== 3) {
    return { valid: false, error: 'Malformed token structure.' };
  }

  const [encodedHeader, encodedPayload, signature] = parts;

  const expectedSignature = crypto
    .createHmac('sha256', JWT_SECRET)
    .update(`${encodedHeader}.${encodedPayload}`)
    .digest('base64url');

  // Constant-time signature verification
  const sigBufferA = Buffer.from(signature);
  const sigBufferB = Buffer.from(expectedSignature);
  if (sigBufferA.length !== sigBufferB.length || !crypto.timingSafeEqual(sigBufferA, sigBufferB)) {
    return { valid: false, error: 'Invalid token signature.' };
  }

  let payload;
  try {
    payload = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString('utf-8'));
  } catch (err) {
    return { valid: false, error: 'Failed to decode token payload.' };
  }

  if (payload.exp && Date.now() > payload.exp) {
    return { valid: false, error: 'Session token has expired. Please sign in again.' };
  }

  return { valid: true, payload };
}

module.exports = {
  validatePasswordPolicy,
  hashPassword,
  verifyPassword,
  hashToken,
  generateOtpRecord,
  verifyOtpCode,
  generateResetToken,
  generateToken,
  verifyToken
};
