const { verifyToken } = require('../utils/authUtils');
const logger = require('../utils/logger');

/**
 * Strict authentication middleware.
 * Requires a valid Bearer token in the Authorization header.
 */
function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization || req.headers.Authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      success: false,
      error: 'Authentication required. Please sign in.'
    });
  }

  const token = authHeader.split(' ')[1];
  const { valid, payload, error } = verifyToken(token);

  if (!valid || !payload) {
    logger.warn(`Authentication rejected: ${error}`);
    return res.status(401).json({
      success: false,
      error: error || 'Invalid or expired session token. Please sign in again.'
    });
  }

  req.user = payload;
  next();
}

/**
 * Optional authentication middleware.
 * If token is present and valid, attaches req.user; otherwise allows request as guest.
 */
function optionalAuth(req, res, next) {
  const authHeader = req.headers.authorization || req.headers.Authorization;

  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.split(' ')[1];
    const { valid, payload } = verifyToken(token);
    if (valid && payload) {
      req.user = payload;
    }
  }

  next();
}

module.exports = {
  requireAuth,
  optionalAuth
};
