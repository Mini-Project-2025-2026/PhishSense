const historyService = require('../services/historyService');
const logger = require('../utils/logger');

/**
 * Helper to get the authenticated or guest identity safely
 */
function resolveUserEmail(req) {
  if (req.user && req.user.email) {
    return req.user.email;
  }
  return req.query.userEmail || req.body?.userEmail || '';
}

/**
 * GET /api/v1/history
 * Fetch scan history for a user
 */
exports.getHistory = (req, res) => {
  try {
    const userEmail = resolveUserEmail(req);
    const history = historyService.getUserHistory(userEmail);
    return res.status(200).json({ success: true, history });
  } catch (error) {
    logger.error(`Error fetching history: ${error.message}`);
    return res.status(500).json({ success: false, error: error.message });
  }
};

/**
 * POST /api/v1/history
 * Save a scan record for a user
 */
exports.addScan = (req, res) => {
  try {
    const { scanRecord } = req.body;
    if (!scanRecord || !scanRecord.url) {
      return res.status(400).json({ success: false, error: 'Scan record with valid URL is required.' });
    }

    const userEmail = resolveUserEmail(req);
    const updatedHistory = historyService.saveUserScan(scanRecord, userEmail);
    return res.status(201).json({ success: true, history: updatedHistory });
  } catch (error) {
    logger.error(`Error saving scan history: ${error.message}`);
    return res.status(500).json({ success: false, error: error.message });
  }
};

/**
 * DELETE /api/v1/history/:id
 * Delete a single scan record
 */
exports.deleteScan = (req, res) => {
  try {
    const { id } = req.params;
    const userEmail = resolveUserEmail(req);
    const updatedHistory = historyService.deleteUserScan(id, userEmail);
    return res.status(200).json({ success: true, history: updatedHistory });
  } catch (error) {
    logger.error(`Error deleting scan record: ${error.message}`);
    return res.status(500).json({ success: false, error: error.message });
  }
};

/**
 * DELETE /api/v1/history
 * Clear all scan history for a user
 */
exports.clearHistory = (req, res) => {
  try {
    const userEmail = resolveUserEmail(req);
    const updatedHistory = historyService.clearUserHistory(userEmail);
    return res.status(200).json({ success: true, history: updatedHistory });
  } catch (error) {
    logger.error(`Error clearing scan history: ${error.message}`);
    return res.status(500).json({ success: false, error: error.message });
  }
};
