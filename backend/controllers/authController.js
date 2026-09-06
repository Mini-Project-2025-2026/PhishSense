const userService = require('../services/userService');
const logger = require('../utils/logger');

/**
 * POST /api/v1/auth/register
 */
exports.register = async (req, res) => {
  try {
    const { email, password, name } = req.body;
    logger.info(`User registration attempt for email: ${email ? email.split('@')[0] + '@***' : 'missing'}`);

    const result = await userService.registerUser({ email, password, name });
    if (!result.success) {
      return res.status(400).json({ success: false, error: result.error });
    }

    return res.status(201).json({
      success: true,
      message: result.message,
      user: result.user,
      previewUrl: result.previewUrl
    });
  } catch (error) {
    logger.error(`Registration error: ${error.message}`);
    return res.status(500).json({ success: false, error: 'Internal server error during registration.' });
  }
};

/**
 * POST /api/v1/auth/login
 */
exports.login = (req, res) => {
  try {
    const { email, password } = req.body;
    logger.info(`User login attempt for email: ${email ? email.split('@')[0] + '@***' : 'missing'}`);

    const result = userService.loginUser({ email, password });
    if (!result.success) {
      if (result.isUnverified) {
        return res.status(403).json({
          success: false,
          isUnverified: true,
          email: result.email,
          error: result.error
        });
      }
      return res.status(401).json({ success: false, error: result.error });
    }

    return res.status(200).json({
      success: true,
      message: 'Signed in successfully.',
      user: result.user,
      token: result.token
    });
  } catch (error) {
    logger.error(`Login error: ${error.message}`);
    return res.status(500).json({ success: false, error: 'Internal server error during authentication.' });
  }
};

/**
 * POST /api/v1/auth/verify-email
 * Validates 6-digit numeric OTP code.
 */
exports.verifyEmail = (req, res) => {
  try {
    const { email, code } = req.body;
    if (!email || !code) {
      return res.status(400).json({
        success: false,
        error: 'Email address and 6-digit verification code are required.'
      });
    }

    const result = userService.verifyEmailOtp({ email, code });
    if (!result.success) {
      return res.status(400).json({ success: false, error: result.error });
    }

    return res.status(200).json({
      success: true,
      message: result.message,
      user: result.user,
      token: result.token
    });
  } catch (error) {
    logger.error(`Email verification error: ${error.message}`);
    return res.status(500).json({ success: false, error: 'Internal server error during email verification.' });
  }
};

/**
 * POST /api/v1/auth/resend-verification
 */
exports.resendVerification = async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ success: false, error: 'Email address is required.' });
    }

    const result = await userService.resendVerificationOtp(email);
    if (!result.success) {
      return res.status(400).json({ success: false, error: result.error });
    }

    return res.status(200).json({
      success: true,
      message: result.message,
      previewUrl: result.previewUrl
    });
  } catch (error) {
    logger.error(`Resend verification error: ${error.message}`);
    return res.status(500).json({ success: false, error: 'Internal server error resending verification code.' });
  }
};

/**
 * POST /api/v1/auth/forgot-password
 */
exports.forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ success: false, error: 'Email address is required.' });
    }

    const result = await userService.requestPasswordReset(email);
    return res.status(200).json({
      success: true,
      message: result.message,
      previewUrl: result.previewUrl
    });
  } catch (error) {
    logger.error(`Forgot password error: ${error.message}`);
    return res.status(500).json({ success: false, error: 'Internal server error processing password reset.' });
  }
};

/**
 * POST /api/v1/auth/reset-password
 */
exports.resetPassword = (req, res) => {
  try {
    const { token, newPassword } = req.body;
    if (!token || !newPassword) {
      return res.status(400).json({ success: false, error: 'Token and new password are required.' });
    }

    const result = userService.resetPasswordWithToken({ token, newPassword });
    if (!result.success) {
      return res.status(400).json({ success: false, error: result.error });
    }

    return res.status(200).json({
      success: true,
      message: result.message
    });
  } catch (error) {
    logger.error(`Reset password error: ${error.message}`);
    return res.status(500).json({ success: false, error: 'Internal server error resetting password.' });
  }
};

/**
 * GET /api/v1/auth/me
 * Retrieves current authenticated user profile
 */
exports.getProfile = (req, res) => {
  try {
    if (!req.user || !req.user.email) {
      return res.status(401).json({ success: false, error: 'Authentication required.' });
    }

    const user = userService.getUserByEmail(req.user.email);
    if (!user) {
      return res.status(404).json({ success: false, error: 'User account not found.' });
    }

    return res.status(200).json({
      success: true,
      user
    });
  } catch (error) {
    logger.error(`Profile fetch error: ${error.message}`);
    return res.status(500).json({ success: false, error: 'Internal server error fetching profile.' });
  }
};

/**
 * POST /api/v1/auth/logout
 */
exports.logout = (req, res) => {
  return res.status(200).json({
    success: true,
    message: 'Signed out successfully.'
  });
};
