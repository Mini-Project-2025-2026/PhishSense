const detectionService = require('../services/detectionService');
const logger = require('../utils/logger');

/**
 * Sanitizes and normalizes incoming URL input strings.
 */
function sanitizeAndNormalizeUrl(rawUrl) {
  if (typeof rawUrl !== 'string') {
    throw new Error('URL parameter must be a string.');
  }

  let sanitized = rawUrl.trim();
  if (!sanitized) {
    throw new Error('URL parameter is required.');
  }

  if (sanitized.length > 2048) {
    throw new Error('URL length exceeds maximum permitted limit (2048 characters).');
  }

  // Remove HTML / Script tags to neutralize XSS injection payloads
  sanitized = sanitized.replace(/<[^>]*>?/g, '');

  // Prepend https:// if no protocol scheme is present (e.g. google.com -> https://google.com)
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(sanitized)) {
    sanitized = 'https://' + sanitized;
  }

  try {
    const parsed = new URL(sanitized);
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      throw new Error(`Unsupported protocol '${parsed.protocol}'. Only HTTP and HTTPS protocols are supported.`);
    }
    return parsed.href;
  } catch (err) {
    throw new Error(`Invalid URL format: ${err.message}`);
  }
}

/**
 * Analyze a URL for phishing threats.
 * POST /api/v1/phish/analyze
 */
exports.analyzeUrl = async (req, res, next) => {
  try {
    const { url } = req.body;

    if (!url) {
      return res.status(400).json({ error: 'URL parameter is required.' });
    }

    let normalizedUrl;
    try {
      normalizedUrl = sanitizeAndNormalizeUrl(url);
    } catch (validationError) {
      logger.info(`Validation rejected URL payload: ${validationError.message}`);
      return res.status(400).json({ error: validationError.message });
    }

    logger.info(`Analyzing URL: ${normalizedUrl}`);
    
    // Call services to perform the analysis pipeline
    const analysisResult = await detectionService.performAnalysis(normalizedUrl);

    return res.status(200).json(analysisResult);
  } catch (error) {
    logger.error(`Error in analyzeUrl: ${error.message}`);
    next(error);
  }
};
