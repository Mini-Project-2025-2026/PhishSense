import { fetchScanHistory, saveScanRecordApi, deleteScanRecordApi, clearScanHistoryApi } from '../services/api';

/**
 * PhishSense Scan History Storage Utility
 * Manages per-user and guest scan records in localStorage with backend sync.
 */

const GUEST_KEY = 'phishsense_history_guest';

function getStorageKey(userEmail) {
  if (userEmail && typeof userEmail === 'string' && userEmail.trim()) {
    return 'phishsense_history_' + userEmail.trim().toLowerCase();
  }
  return GUEST_KEY;
}

export function loadScanHistory(userEmail) {
  try {
    const key = getStorageKey(userEmail);
    const raw = localStorage.getItem(key);
    if (!raw) {
      if (key !== GUEST_KEY) {
        const guestRaw = localStorage.getItem(GUEST_KEY);
        if (guestRaw) {
          const guestHistory = JSON.parse(guestRaw);
          if (Array.isArray(guestHistory) && guestHistory.length > 0) {
            localStorage.setItem(key, guestRaw);
            return guestHistory;
          }
        }
      }
      return [];
    }
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch (err) {
    console.error('Failed to load scan history:', err);
    return [];
  }
}

/**
 * Async loader to sync history from backend API and update localStorage
 */
export async function syncScanHistoryWithBackend(userEmail) {
  try {
    const backendHistory = await fetchScanHistory(userEmail);
    if (backendHistory && Array.isArray(backendHistory)) {
      const key = getStorageKey(userEmail);
      localStorage.setItem(key, JSON.stringify(backendHistory));
      return backendHistory;
    }
  } catch (_) {}
  return loadScanHistory(userEmail);
}

export function saveScanRecord(scanResult, previewData, userEmail) {
  if (!scanResult || !scanResult.url) return [];

  try {
    const key = getStorageKey(userEmail);
    const existing = loadScanHistory(userEmail);

    const newRecord = {
      id: 'scan_' + Date.now() + '_' + Math.random().toString(36).slice(2, 7),
      url: scanResult.url,
      timestamp: scanResult.timestamp || new Date().toISOString(),
      score: scanResult.score !== undefined ? scanResult.score : 0,
      classification: scanResult.classification || 'LOW RISK',
      reasons: scanResult.reasons || [],
      securityEvidence: scanResult.securityEvidence || [],
      aiPrediction: scanResult.details?.aiAnalysis?.prediction || 'BENIGN',
      aiConfidence: scanResult.details?.aiAnalysis?.confidence !== undefined ? scanResult.details?.aiAnalysis?.confidence : 0,
      aiModelType: scanResult.details?.aiAnalysis?.model_type || 'URLBERT Tiny v4 Classifier',
      fullResult: scanResult,
      previewData: previewData || null
    };

    // Keep fresh at top, avoid exact duplicate URL entries
    const filtered = existing.filter(item => item.url.toLowerCase() !== scanResult.url.toLowerCase());
    const updated = [newRecord, ...filtered].slice(0, 100);

    localStorage.setItem(key, JSON.stringify(updated));

    // Asynchronously sync with backend
    saveScanRecordApi(newRecord, userEmail).catch(() => {});

    return updated;
  } catch (err) {
    console.error('Failed to save scan record:', err);
    return [];
  }
}

export function removeScanRecord(scanId, userEmail) {
  try {
    const key = getStorageKey(userEmail);
    const existing = loadScanHistory(userEmail);
    const updated = existing.filter(item => item.id !== scanId);
    localStorage.setItem(key, JSON.stringify(updated));

    // Asynchronously delete from backend
    deleteScanRecordApi(scanId, userEmail).catch(() => {});

    return updated;
  } catch (err) {
    console.error('Failed to remove scan record:', err);
    return [];
  }
}

export function clearAllScanHistory(userEmail) {
  try {
    const key = getStorageKey(userEmail);
    localStorage.removeItem(key);

    // Asynchronously clear from backend
    clearScanHistoryApi(userEmail).catch(() => {});

    return [];
  } catch (err) {
    console.error('Failed to clear scan history:', err);
    return [];
  }
}

