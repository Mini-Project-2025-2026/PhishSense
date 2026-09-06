const fs = require('fs');
const path = require('path');
const logger = require('../utils/logger');

const DATA_DIR = path.join(__dirname, '..', 'data');
const HISTORY_FILE = path.join(DATA_DIR, 'history.json');

// Ensure data directory and file exist
function initHistoryStore() {
  try {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }
    if (!fs.existsSync(HISTORY_FILE)) {
      fs.writeFileSync(HISTORY_FILE, JSON.stringify({}), 'utf-8');
    }
  } catch (err) {
    logger.error(`Failed to initialize history store: ${err.message}`);
  }
}

initHistoryStore();

function readAllHistory() {
  try {
    if (!fs.existsSync(HISTORY_FILE)) {
      return {};
    }
    const data = fs.readFileSync(HISTORY_FILE, 'utf-8');
    return JSON.parse(data || '{}');
  } catch (err) {
    logger.error(`Failed to read history file: ${err.message}`);
    return {};
  }
}

function writeAllHistory(data) {
  try {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }
    fs.writeFileSync(HISTORY_FILE, JSON.stringify(data, null, 2), 'utf-8');
  } catch (err) {
    logger.error(`Failed to write history file: ${err.message}`);
  }
}

function getUserKey(userEmail) {
  if (userEmail && typeof userEmail === 'string' && userEmail.trim()) {
    return userEmail.trim().toLowerCase();
  }
  return 'guest';
}

/**
 * Retrieves scan history for a specific user
 * @param {string} userEmail
 * @returns {Array} List of scan records
 */
function getUserHistory(userEmail) {
  const all = readAllHistory();
  const key = getUserKey(userEmail);
  return all[key] || [];
}

/**
 * Saves a new scan record for a user
 * @param {Object} scanRecord
 * @param {string} userEmail
 * @returns {Array} Updated scan history
 */
function saveUserScan(scanRecord, userEmail) {
  if (!scanRecord || !scanRecord.url) return getUserHistory(userEmail);

  const all = readAllHistory();
  const key = getUserKey(userEmail);
  const userScans = all[key] || [];

  const newEntry = {
    id: scanRecord.id || 'scan_' + Date.now() + '_' + Math.random().toString(36).slice(2, 7),
    url: scanRecord.url,
    timestamp: scanRecord.timestamp || new Date().toISOString(),
    score: scanRecord.score !== undefined ? scanRecord.score : 0,
    classification: scanRecord.classification || 'LOW RISK',
    reasons: scanRecord.reasons || [],
    securityEvidence: scanRecord.securityEvidence || [],
    aiPrediction: scanRecord.aiPrediction || scanRecord.details?.aiAnalysis?.prediction || 'BENIGN',
    aiConfidence: scanRecord.aiConfidence !== undefined ? scanRecord.aiConfidence : (scanRecord.details?.aiAnalysis?.confidence || 0),
    aiModelType: scanRecord.aiModelType || scanRecord.details?.aiAnalysis?.model_type || 'URLBERT Tiny v4 Classifier',
    fullResult: scanRecord.fullResult || scanRecord,
    previewData: scanRecord.previewData || null
  };

  // Prepend new scan, filter out duplicates of exact same URL, limit to 200 items
  const filtered = userScans.filter(item => item.url.toLowerCase() !== scanRecord.url.toLowerCase());
  const updated = [newEntry, ...filtered].slice(0, 200);

  all[key] = updated;
  writeAllHistory(all);
  return updated;
}

/**
 * Deletes a specific scan record by ID for a user
 * @param {string} scanId
 * @param {string} userEmail
 * @returns {Array} Updated scan history
 */
function deleteUserScan(scanId, userEmail) {
  const all = readAllHistory();
  const key = getUserKey(userEmail);
  const userScans = all[key] || [];

  const updated = userScans.filter(item => item.id !== scanId);
  all[key] = updated;
  writeAllHistory(all);
  return updated;
}

/**
 * Clears all scan records for a user
 * @param {string} userEmail
 * @returns {Array} Empty array
 */
function clearUserHistory(userEmail) {
  const all = readAllHistory();
  const key = getUserKey(userEmail);
  all[key] = [];
  writeAllHistory(all);
  return [];
}

module.exports = {
  getUserHistory,
  saveUserScan,
  deleteUserScan,
  clearUserHistory
};
