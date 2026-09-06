const fs = require('fs');
const path = require('path');
const {
  validatePasswordPolicy,
  hashPassword,
  verifyPassword,
  hashToken,
  generateOtpRecord,
  verifyOtpCode,
  generateResetToken,
  generateToken
} = require('../utils/authUtils');
const { sendOtpEmail, sendPasswordResetEmail } = require('./emailService');
const logger = require('../utils/logger');

const DATA_DIR = path.join(__dirname, '..', 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');

const MAX_OTP_ATTEMPTS = 5;
const RESEND_COOLDOWN_MS = 30 * 1000; // 30 seconds

function initUsersStore() {
  try {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }
    if (!fs.existsSync(USERS_FILE)) {
      fs.writeFileSync(USERS_FILE, JSON.stringify({}), 'utf-8');
    }
  } catch (err) {
    logger.error(`Failed to initialize users store: ${err.message}`);
  }
}

initUsersStore();

function readAllUsers() {
  try {
    if (!fs.existsSync(USERS_FILE)) {
      return {};
    }
    const raw = fs.readFileSync(USERS_FILE, 'utf-8');
    return JSON.parse(raw || '{}');
  } catch (err) {
    logger.error(`Failed to read users file: ${err.message}`);
    return {};
  }
}

function writeAllUsers(users) {
  try {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), 'utf-8');
  } catch (err) {
    logger.error(`Failed to write users file: ${err.message}`);
  }
}

/**
 * Resets development users repository (DEVELOPMENT ENVIRONMENT ONLY).
 * Explicitly guards against execution in production.
 */
function resetDevelopmentUsersStore() {
  if (process.env.NODE_ENV === 'production') {
    throw new Error('Database reset operation is strictly forbidden in production environment.');
  }

  try {
    writeAllUsers({});
    logger.info('[DEV RESET]: Development user repository successfully cleared to 0 accounts.');
    return { success: true, count: 0 };
  } catch (err) {
    logger.error(`Failed to reset development users store: ${err.message}`);
    return { success: false, error: err.message };
  }
}

/**
 * Registers a new user account in unverified state and sends a 6-digit OTP via real email.
 * @param {{ email: string, password: string, name?: string }} param0 
 * @returns {Promise<{ success: boolean, user?: Object, message?: string, error?: string, previewUrl?: string }>}
 */
async function registerUser({ email, password, name }) {
  if (!email || typeof email !== 'string' || !email.trim()) {
    return { success: false, error: 'Email address is required.' };
  }

  const cleanEmail = email.trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
    return { success: false, error: 'Please enter a valid email address format.' };
  }

  const passValidation = validatePasswordPolicy(password);
  if (!passValidation.valid) {
    return { success: false, error: passValidation.error };
  }

  const users = readAllUsers();

  if (users[cleanEmail]) {
    return { success: false, error: 'An account with this email address already exists. Please sign in.' };
  }

  const { hash, salt } = hashPassword(password);
  const otpRecord = generateOtpRecord();
  const userId = 'usr_' + Date.now() + '_' + Math.random().toString(36).slice(2, 7);

  const newUser = {
    id: userId,
    email: cleanEmail,
    name: name ? name.trim() : cleanEmail.split('@')[0],
    passwordHash: hash,
    passwordSalt: salt,
    role: 'analyst',
    isVerified: false,
    verificationOtpHash: otpRecord.codeHash,
    verificationExpiresAt: otpRecord.expiresAt,
    verificationAttempts: 0,
    lastResendAt: Date.now(),
    createdAt: new Date().toISOString(),
    lastLoginAt: null
  };

  users[cleanEmail] = newUser;
  writeAllUsers(users);

  // Dispatch real verification email
  const emailResult = await sendOtpEmail({
    to: cleanEmail,
    code: otpRecord.code,
    name: newUser.name
  });

  if (!emailResult.success) {
    logger.error(`User registration aborted because email delivery failed: ${emailResult.error}`);
    delete users[cleanEmail];
    writeAllUsers(users);
    return {
      success: false,
      error: "We couldn't send the verification email. Please try again."
    };
  }

  const publicUser = {
    id: newUser.id,
    email: newUser.email,
    name: newUser.name,
    role: newUser.role,
    isVerified: false,
    createdAt: newUser.createdAt
  };

  return {
    success: true,
    message: 'Account created. We sent a 6-digit verification code to your email.',
    user: publicUser,
    previewUrl: emailResult.previewUrl
  };
}

/**
 * Authenticates a user with email and password.
 * Checks verification status and enforces anti-enumeration responses.
 * @param {{ email: string, password: string }} param0 
 * @returns {{ success: boolean, user?: Object, token?: string, isUnverified?: boolean, error?: string }}
 */
function loginUser({ email, password }) {
  if (!email || !password) {
    return { success: false, error: 'Email or password is required.' };
  }

  const cleanEmail = email.trim().toLowerCase();
  const users = readAllUsers();
  const user = users[cleanEmail];

  if (!user) {
    return { success: false, error: 'Email or password is incorrect.' };
  }

  const isMatch = verifyPassword(password, user.passwordHash, user.passwordSalt);
  if (!isMatch) {
    return { success: false, error: 'Email or password is incorrect.' };
  }

  if (!user.isVerified) {
    return {
      success: false,
      isUnverified: true,
      email: user.email,
      error: 'Please verify your email address before continuing.'
    };
  }

  // Update last login
  user.lastLoginAt = new Date().toISOString();
  users[cleanEmail] = user;
  writeAllUsers(users);

  const token = generateToken({
    id: user.id,
    email: user.email,
    name: user.name,
    role: user.role
  });

  const publicUser = {
    id: user.id,
    email: user.email,
    name: user.name,
    role: user.role,
    isVerified: user.isVerified,
    createdAt: user.createdAt,
    lastLoginAt: user.lastLoginAt
  };

  return { success: true, user: publicUser, token };
}

/**
 * Verifies an account using the submitted 6-digit numeric OTP code.
 * @param {{ email: string, code: string }} param0 
 * @returns {{ success: boolean, user?: Object, token?: string, error?: string }}
 */
function verifyEmailOtp({ email, code }) {
  if (!email || !code) {
    return { success: false, error: 'Email address and verification code are required.' };
  }

  const cleanEmail = email.trim().toLowerCase();
  const cleanCode = code.toString().trim();

  if (!/^\d{6}$/.test(cleanCode)) {
    return { success: false, error: 'Verification code must be exactly 6 digits.' };
  }

  const users = readAllUsers();
  const user = users[cleanEmail];

  if (!user) {
    return { success: false, error: 'That code isn\'t correct. Please check your email and try again.' };
  }

  if (user.isVerified) {
    return { success: false, error: 'This account email is already verified. You can sign in directly.' };
  }

  if (!user.verificationOtpHash || !user.verificationExpiresAt) {
    return { success: false, error: 'No active verification code found. Please request a new code.' };
  }

  // Check Expiration (10 minutes)
  if (new Date(user.verificationExpiresAt) < new Date()) {
    user.verificationOtpHash = null;
    user.verificationExpiresAt = null;
    users[cleanEmail] = user;
    writeAllUsers(users);
    return { success: false, error: 'This verification code has expired. Please request a new code.' };
  }

  // Check Attempt Limits
  if ((user.verificationAttempts || 0) >= MAX_OTP_ATTEMPTS) {
    user.verificationOtpHash = null;
    user.verificationExpiresAt = null;
    users[cleanEmail] = user;
    writeAllUsers(users);
    return { success: false, error: 'Too many incorrect attempts. Please request a new verification code.' };
  }

  // Verify OTP code hash
  const isMatch = verifyOtpCode(cleanCode, user.verificationOtpHash);
  if (!isMatch) {
    user.verificationAttempts = (user.verificationAttempts || 0) + 1;
    if (user.verificationAttempts >= MAX_OTP_ATTEMPTS) {
      user.verificationOtpHash = null;
      user.verificationExpiresAt = null;
      users[cleanEmail] = user;
      writeAllUsers(users);
      return { success: false, error: 'Too many incorrect attempts. Please request a new verification code.' };
    }
    users[cleanEmail] = user;
    writeAllUsers(users);
    return { success: false, error: 'That code isn\'t correct. Please check your email and try again.' };
  }

  // Successful verification: mark verified & wipe OTP
  user.isVerified = true;
  user.emailVerifiedAt = new Date().toISOString();
  user.verificationOtpHash = null;
  user.verificationExpiresAt = null;
  user.verificationAttempts = 0;

  users[cleanEmail] = user;
  writeAllUsers(users);

  const sessionToken = generateToken({
    id: user.id,
    email: user.email,
    name: user.name,
    role: user.role
  });

  const publicUser = {
    id: user.id,
    email: user.email,
    name: user.name,
    role: user.role,
    isVerified: true,
    createdAt: user.createdAt
  };

  logger.info(`User ${cleanEmail.split('@')[0]}@*** email successfully verified with 6-digit OTP.`);

  return {
    success: true,
    message: 'Email verified successfully. Your PhishSense account is ready.',
    user: publicUser,
    token: sessionToken
  };
}

/**
 * Dispatches a new 6-digit OTP code to an unverified user's email with rate limiting.
 * @param {string} email 
 * @returns {Promise<{ success: boolean, message?: string, error?: string, previewUrl?: string }>}
 */
async function resendVerificationOtp(email) {
  if (!email) return { success: false, error: 'Email address is required.' };

  const cleanEmail = email.trim().toLowerCase();
  const users = readAllUsers();
  const user = users[cleanEmail];

  if (!user) {
    // Return generic success to prevent account enumeration
    return {
      success: true,
      message: 'If an unverified account exists for that email, a new verification code has been sent.'
    };
  }

  if (user.isVerified) {
    return { success: false, error: 'This account email is already verified. You can sign in directly.' };
  }

  // Cooldown check (30 seconds)
  const now = Date.now();
  if (user.lastResendAt && now - user.lastResendAt < RESEND_COOLDOWN_MS) {
    const waitSec = Math.ceil((RESEND_COOLDOWN_MS - (now - user.lastResendAt)) / 1000);
    return {
      success: false,
      error: `Please wait ${waitSec} second${waitSec !== 1 ? 's' : ''} before requesting another code.`
    };
  }

  const otpRecord = generateOtpRecord();
  user.verificationOtpHash = otpRecord.codeHash;
  user.verificationExpiresAt = otpRecord.expiresAt;
  user.verificationAttempts = 0;
  user.lastResendAt = now;

  users[cleanEmail] = user;
  writeAllUsers(users);

  // Dispatch real email
  const emailResult = await sendOtpEmail({
    to: cleanEmail,
    code: otpRecord.code,
    name: user.name
  });

  if (!emailResult.success) {
    logger.error(`Resend email delivery failed for ${cleanEmail}: ${emailResult.error}`);
    return {
      success: false,
      error: "We couldn't send the verification code. Please try again in a few moments."
    };
  }

  return {
    success: true,
    message: 'A new 6-digit verification code has been sent to your email.',
    previewUrl: emailResult.previewUrl
  };
}

/**
 * Initiates a password reset request. Returns generic response to prevent account enumeration.
 * @param {string} email 
 * @returns {Promise<{ success: boolean, message: string, previewUrl?: string }>}
 */
async function requestPasswordReset(email) {
  if (!email) return { success: false, error: 'Email address is required.' };

  const cleanEmail = email.trim().toLowerCase();
  const users = readAllUsers();
  const user = users[cleanEmail];

  if (!user) {
    return {
      success: true,
      message: 'If an account exists for that email, password reset instructions have been sent.'
    };
  }

  const { token: rToken, tokenHash: rTokenHash, expiresAt: rExpiresAt } = generateResetToken();
  user.resetTokenHash = rTokenHash;
  user.resetExpiresAt = rExpiresAt;

  users[cleanEmail] = user;
  writeAllUsers(users);

  const emailResult = await sendPasswordResetEmail({
    to: cleanEmail,
    resetToken: rToken,
    name: user.name
  });

  return {
    success: true,
    message: 'If an account exists for that email, password reset instructions have been sent.',
    previewUrl: emailResult.previewUrl
  };
}

/**
 * Resets a user password using a verified single-use reset token.
 * @param {{ token: string, newPassword: string }} param0 
 * @returns {{ success: boolean, message?: string, error?: string }}
 */
function resetPasswordWithToken({ token, newPassword }) {
  if (!token || typeof token !== 'string') {
    return { success: false, error: 'Reset token is required.' };
  }

  const passValidation = validatePasswordPolicy(newPassword);
  if (!passValidation.valid) {
    return { success: false, error: passValidation.error };
  }

  const targetHash = hashToken(token);
  const users = readAllUsers();
  let matchedUser = null;

  for (const user of Object.values(users)) {
    if (user.resetTokenHash === targetHash) {
      matchedUser = user;
      break;
    }
  }

  if (!matchedUser) {
    return {
      success: false,
      error: 'This password reset link is invalid or has already been used.'
    };
  }

  if (new Date(matchedUser.resetExpiresAt) < new Date()) {
    return {
      success: false,
      error: 'This password reset link has expired. Please request a new reset link.'
    };
  }

  // Hash new password
  const { hash, salt } = hashPassword(newPassword);
  matchedUser.passwordHash = hash;
  matchedUser.passwordSalt = salt;
  matchedUser.resetTokenHash = null;
  matchedUser.resetExpiresAt = null;

  users[matchedUser.email] = matchedUser;
  writeAllUsers(users);

  logger.info(`Password successfully reset for user ${matchedUser.email.split('@')[0]}@***`);

  return {
    success: true,
    message: 'Your password has been changed successfully. You can now sign in.'
  };
}

/**
 * Retrieves public user profile by email
 * @param {string} email 
 * @returns {Object|null}
 */
function getUserByEmail(email) {
  if (!email) return null;
  const cleanEmail = email.trim().toLowerCase();
  const users = readAllUsers();
  const user = users[cleanEmail];
  if (!user) return null;

  return {
    id: user.id,
    email: user.email,
    name: user.name,
    role: user.role,
    isVerified: user.isVerified,
    createdAt: user.createdAt,
    lastLoginAt: user.lastLoginAt
  };
}

module.exports = {
  resetDevelopmentUsersStore,
  registerUser,
  loginUser,
  verifyEmailOtp,
  resendVerificationOtp,
  requestPasswordReset,
  resetPasswordWithToken,
  getUserByEmail
};
