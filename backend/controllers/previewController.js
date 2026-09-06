const previewService = require('../services/previewService');
const logger = require('../utils/logger');

/**
 * Controller to handle secure URL preview and availability probing.
 * POST /api/v1/phish/preview
 */
exports.generatePreview = async (req, res, next) => {
  try {
    const { url } = req.body;

    if (!url || typeof url !== 'string' || !url.trim()) {
      return res.status(400).json({
        available: false,
        status: 0,
        reason: 'INVALID_URL',
        error: 'URL parameter is required.'
      });
    }

    let targetUrl = url.trim();
    if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(targetUrl)) {
      targetUrl = 'https://' + targetUrl;
    }

    logger.info(`Generating secure URL preview for: ${targetUrl}`);

    const previewResult = await previewService.fetchSafeUrlPreview(targetUrl);

    return res.status(200).json(previewResult);
  } catch (error) {
    logger.error(`Preview controller error: ${error.message}`);
    return res.status(500).json({
      available: false,
      status: 0,
      reason: 'INTERNAL_ERROR',
      error: error.message
    });
  }
};
