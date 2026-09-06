const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '..', '.env') });
const nodemailer = require('nodemailer');
const logger = require('../utils/logger');

let cachedTransporter = null;
let isEthereal = false;

/**
 * Checks if real external SMTP credentials are fully provided in environment variables.
 * @returns {boolean}
 */
function isRealSmtpConfigured() {
  const host = process.env.SMTP_HOST || process.env.EMAIL_HOST;
  const user = process.env.SMTP_USER || process.env.EMAIL_USER;
  const rawPass = process.env.SMTP_PASS || process.env.EMAIL_PASSWORD || process.env.EMAIL_PASS;
  return Boolean((host || user) && rawPass && user);
}

/**
 * Initializes and returns the active Nodemailer transporter.
 * Supports Gmail SMTP (App Passwords with or without spaces), custom SMTP, and test inboxes.
 */
async function getTransporter() {
  if (cachedTransporter) {
    return cachedTransporter;
  }

  const host = process.env.SMTP_HOST || process.env.EMAIL_HOST || 'smtp.gmail.com';
  const user = (process.env.SMTP_USER || process.env.EMAIL_USER || '').trim();
  const rawPass = (process.env.SMTP_PASS || process.env.EMAIL_PASSWORD || process.env.EMAIL_PASS || '').trim();
  // Strip any spaces from Google App Password (e.g. "abcd efgh ijkl mnop" -> "abcdefghijklmnop")
  const pass = rawPass.replace(/\s+/g, '');
  const port = parseInt(process.env.SMTP_PORT || process.env.EMAIL_PORT || '587', 10);
  const secure = process.env.SMTP_SECURE === 'true' || port === 465;

  if (user && pass) {
    logger.info(`Configuring REAL Gmail/SMTP email transporter for ${user.split('@')[0]}@***...`);
    
    // If using Gmail, configure Nodemailer for Gmail TLS
    const transportOptions = (host === 'smtp.gmail.com' || host.includes('gmail'))
      ? {
          service: 'gmail',
          auth: { user, pass }
        }
      : {
          host,
          port,
          secure,
          auth: { user, pass },
          tls: {
            rejectUnauthorized: process.env.NODE_ENV === 'production'
          }
        };

    cachedTransporter = nodemailer.createTransport(transportOptions);

    try {
      await cachedTransporter.verify();
      logger.info(`[SMTP OK] Real Gmail SMTP transporter verified and ready to dispatch to recipient inboxes.`);
    } catch (verifyErr) {
      logger.error(`SMTP connection verification failed: ${verifyErr.message}`);
    }

    isEthereal = false;
    return cachedTransporter;
  }

  // Development Fallback: Create ephemeral Ethereal testing account for real email delivery testing
  try {
    logger.info('No external SMTP credentials detected in .env. Initializing Ethereal test SMTP inbox for development...');
    const testAccount = await nodemailer.createTestAccount();
    cachedTransporter = nodemailer.createTransport({
      host: 'smtp.ethereal.email',
      port: 587,
      secure: false,
      auth: {
        user: testAccount.user,
        pass: testAccount.pass
      }
    });
    isEthereal = true;
    logger.info(`Ethereal test SMTP inbox created: ${testAccount.user}`);
    return cachedTransporter;
  } catch (err) {
    logger.error(`Failed to initialize test email account: ${err.message}`);
    cachedTransporter = nodemailer.createTransport({
      host: 'localhost',
      port: 1025,
      ignoreTLS: true
    });
    isEthereal = false;
    return cachedTransporter;
  }
}

/**
 * Sends a 6-digit email OTP verification email to the user.
 * @param {{ to: string, code: string, name?: string }} param0 
 * @returns {Promise<{ success: boolean, messageId?: string, previewUrl?: string, isRealSmtp: boolean, error?: string }>}
 */
async function sendOtpEmail({ to, code, name }) {
  if (!to || !code) {
    return { success: false, isRealSmtp: isRealSmtpConfigured(), error: 'Recipient and OTP code are required.' };
  }

  try {
    const transporter = await getTransporter();
    const userEmail = (process.env.SMTP_USER || process.env.EMAIL_USER || '').trim();
    const fromAddress = userEmail ? `"PhishSense Security" <${userEmail}>` : '"PhishSense Security" <no-reply@phishsense.io>';

    const mailOptions = {
      from: fromAddress,
      to,
      subject: 'Your PhishSense verification code',
      text: `PhishSense\n\nVerify your email address\n\nThanks for creating your PhishSense account.\n\nYour verification code is:\n\n${code}\n\nThis code will expire in 10 minutes.\n\nEnter this code in PhishSense to verify your account.\n\nIf you didn't create a PhishSense account, you can safely ignore this email.\n\n--\nPhishSense Security Team`,
      html: `
        <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; max-width: 560px; margin: 0 auto; padding: 32px 24px; background-color: #ffffff; border: 1px solid #e2e8f0; border-radius: 16px;">
          <div style="text-align: center; margin-bottom: 28px;">
            <h1 style="color: #0f172a; margin: 0; font-size: 24px; font-weight: 700;">PhishSense</h1>
            <p style="color: #64748b; font-size: 14px; margin: 4px 0 0 0;">Verify your email address</p>
          </div>

          <div style="background-color: #f8fafc; border: 1px solid #e2e8f0; border-radius: 12px; padding: 24px; text-align: center; margin-bottom: 24px;">
            <p style="color: #334155; font-size: 15px; margin: 0 0 16px 0;">Thanks for creating your PhishSense account.</p>
            <p style="color: #64748b; font-size: 13px; margin: 0 0 12px 0;">Your verification code is:</p>
            
            <div style="font-family: 'JetBrains Mono', Consolas, monospace; font-size: 38px; font-weight: 800; letter-spacing: 10px; color: #0284c7; padding: 14px 20px; background: #ffffff; border: 2px dashed #0284c7; border-radius: 10px; display: inline-block; user-select: all;">
              ${code}
            </div>

            <p style="color: #64748b; font-size: 13px; margin: 16px 0 0 0;">
              This code will expire in <strong>10 minutes</strong>.
            </p>
          </div>

          <p style="color: #475569; font-size: 14px; line-height: 1.6; margin: 0 0 12px 0; text-align: center;">
            Enter this code in PhishSense to verify your account.
          </p>

          <p style="color: #64748b; font-size: 13px; line-height: 1.5; margin: 0 0 16px 0; text-align: center;">
            If you didn&apos;t create a PhishSense account, you can safely ignore this email.
          </p>

          <hr style="border: none; border-top: 1px solid #e2e8f0; margin: 24px 0;" />

          <p style="color: #94a3b8; font-size: 12px; text-align: center; margin: 0;">
            &copy; 2026 PhishSense Security Systems. All rights reserved.
          </p>
        </div>
      `
    };

    const info = await transporter.sendMail(mailOptions);
    const previewUrl = isEthereal ? nodemailer.getTestMessageUrl(info) : null;

    logger.info(`Verification email dispatched to ${to.split('@')[0]}@*** (MessageID: ${info.messageId}) [Real SMTP: ${!isEthereal}]`);
    if (previewUrl) {
      logger.info(`[ETHREAL TEST PREVIEW URL]: ${previewUrl}`);
    }

    return {
      success: true,
      messageId: info.messageId,
      previewUrl,
      isRealSmtp: !isEthereal
    };
  } catch (err) {
    logger.error(`Failed to send verification email: ${err.message}`);
    return {
      success: false,
      isRealSmtp: isRealSmtpConfigured(),
      error: err.message
    };
  }
}

/**
 * Sends a password reset email to the user.
 * @param {{ to: string, resetToken: string, name?: string }} param0 
 * @returns {Promise<{ success: boolean, messageId?: string, previewUrl?: string, isRealSmtp: boolean, error?: string }>}
 */
async function sendPasswordResetEmail({ to, resetToken, name }) {
  if (!to || !resetToken) {
    return { success: false, isRealSmtp: isRealSmtpConfigured(), error: 'Recipient and reset token are required.' };
  }

  try {
    const transporter = await getTransporter();
    const userEmail = (process.env.SMTP_USER || process.env.EMAIL_USER || '').trim();
    const fromAddress = userEmail ? `"PhishSense Security" <${userEmail}>` : '"PhishSense Security" <no-reply@phishsense.io>';
    const recipientName = name || to.split('@')[0];

    const mailOptions = {
      from: fromAddress,
      to,
      subject: 'Reset Your PhishSense Password',
      text: `Hello ${recipientName},\n\nYou requested to reset your PhishSense password.\n\nYour reset token is: ${resetToken}\n\nThis token will expire in 1 hour.\n\nIf you did not request a password reset, you can safely ignore this email.\n\n--\nPhishSense Security Team`,
      html: `
        <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; max-width: 560px; margin: 0 auto; padding: 32px 24px; background-color: #ffffff; border: 1px solid #e2e8f0; border-radius: 16px;">
          <div style="text-align: center; margin-bottom: 28px;">
            <h1 style="color: #0f172a; margin: 0; font-size: 22px; font-weight: 700;">PhishSense Password Reset</h1>
          </div>

          <div style="background-color: #f8fafc; border: 1px solid #e2e8f0; border-radius: 12px; padding: 24px; text-align: center; margin-bottom: 24px;">
            <p style="color: #334155; font-size: 15px; margin: 0 0 16px 0;">Hello <strong>${recipientName}</strong>, enter this password reset token on the reset screen:</p>
            
            <div style="font-family: monospace; font-size: 18px; font-weight: bold; color: #0284c7; padding: 12px 16px; background: #ffffff; border: 1px solid #cbd5e1; border-radius: 8px; display: inline-block; word-break: break-all;">
              ${resetToken}
            </div>

            <p style="color: #64748b; font-size: 13px; margin: 16px 0 0 0;">
              This reset token expires in <strong>1 hour</strong>. Single-use only.
            </p>
          </div>

          <p style="color: #475569; font-size: 14px; line-height: 1.6; margin: 0 0 16px 0;">
            If you did not request a password reset, please ensure your account is secure. You can safely ignore this email.
          </p>
        </div>
      `
    };

    const info = await transporter.sendMail(mailOptions);
    const previewUrl = isEthereal ? nodemailer.getTestMessageUrl(info) : null;

    logger.info(`Password reset email sent to ${to.split('@')[0]}@*** (MessageID: ${info.messageId}) [Real SMTP: ${!isEthereal}]`);
    if (previewUrl) {
      logger.info(`[ETHREAL TEST PREVIEW URL]: ${previewUrl}`);
    }

    return {
      success: true,
      messageId: info.messageId,
      previewUrl,
      isRealSmtp: !isEthereal
    };
  } catch (err) {
    logger.error(`Failed to send password reset email: ${err.message}`);
    return {
      success: false,
      isRealSmtp: isRealSmtpConfigured(),
      error: err.message
    };
  }
}

module.exports = {
  isRealSmtpConfigured,
  getTransporter,
  sendOtpEmail,
  sendPasswordResetEmail
};
