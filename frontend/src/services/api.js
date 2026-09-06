/**
 * API service for communicating with the PhishSense backend engine and auth system.
 * Implements robust response parsing and error handling to eliminate "Unexpected end of JSON input".
 */

const API_BASE = (import.meta.env.VITE_API_BASE_URL || import.meta.env.VITE_API_URL || '').replace(/\/$/, '');
const TOKEN_STORAGE_KEY = 'phishsense_auth_token';

export const getAuthToken = () => {
  try {
    return localStorage.getItem(TOKEN_STORAGE_KEY) || '';
  } catch (_) {
    return '';
  }
};

export const setAuthToken = (token) => {
  try {
    if (token) {
      localStorage.setItem(TOKEN_STORAGE_KEY, token);
    } else {
      localStorage.removeItem(TOKEN_STORAGE_KEY);
    }
  } catch (_) {}
};

export const clearAuthToken = () => {
  try {
    localStorage.removeItem(TOKEN_STORAGE_KEY);
  } catch (_) {}
};

const getAuthHeaders = () => {
  const headers = { 'Content-Type': 'application/json' };
  const token = getAuthToken();
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  return headers;
};

/**
 * Safely parses HTTP response without throwing "Unexpected end of JSON input" errors.
 * Reads response as text first, attempts JSON parsing, and handles HTML/empty response fallbacks.
 */
async function safeParseResponse(res, fallbackErrorMsg = 'An unexpected server error occurred. Please try again.') {
  let data = null;
  try {
    const text = await res.text();
    if (text && text.trim()) {
      try {
        data = JSON.parse(text);
      } catch (_) {
        // Non-JSON response (e.g. HTML gateway error or plain text)
        data = { error: text.length < 200 && !text.includes('<html') ? text : fallbackErrorMsg };
      }
    } else {
      data = {};
    }
  } catch (readErr) {
    data = { error: fallbackErrorMsg };
  }

  return data || {};
}

// ================= AUTHENTICATION APIS =================

export const registerUserApi = async ({ email, password, name }) => {
  const res = await fetch(`${API_BASE}/api/v1/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password, name })
  });

  const data = await safeParseResponse(res, 'Registration failed. Please try again.');
  if (!res.ok) {
    throw new Error(data.error || data.message || 'Registration failed. Please try again.');
  }

  return data;
};

export const loginUserApi = async ({ email, password }) => {
  const res = await fetch(`${API_BASE}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password })
  });

  const data = await safeParseResponse(res, 'Authentication failed. Please check your credentials.');
  if (!res.ok) {
    const err = new Error(data.error || data.message || 'Authentication failed. Please check your credentials.');
    if (data.isUnverified) {
      err.isUnverified = true;
      err.unverifiedEmail = data.email;
    }
    throw err;
  }

  if (data.token) {
    setAuthToken(data.token);
  }
  return data;
};

export const verifyEmailApi = async ({ email, code }) => {
  const res = await fetch(`${API_BASE}/api/v1/auth/verify-email`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, code })
  });

  const data = await safeParseResponse(res, 'Email verification failed. Please try again.');
  if (!res.ok) {
    throw new Error(data.error || data.message || 'That code isn\'t correct. Please check your email and try again.');
  }

  if (data.token) {
    setAuthToken(data.token);
  }
  return data;
};

export const resendVerificationApi = async (email) => {
  const res = await fetch(`${API_BASE}/api/v1/auth/resend-verification`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email })
  });

  const data = await safeParseResponse(res, 'Failed to resend verification email. Please try again.');
  if (!res.ok) {
    throw new Error(data.error || data.message || 'Failed to resend verification email.');
  }
  return data;
};

export const forgotPasswordApi = async (email) => {
  const res = await fetch(`${API_BASE}/api/v1/auth/forgot-password`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email })
  });

  const data = await safeParseResponse(res, 'Password reset request failed.');
  if (!res.ok) {
    throw new Error(data.error || data.message || 'Password reset request failed.');
  }
  return data;
};

export const resetPasswordApi = async ({ token, newPassword }) => {
  const res = await fetch(`${API_BASE}/api/v1/auth/reset-password`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token, newPassword })
  });

  const data = await safeParseResponse(res, 'Password reset failed.');
  if (!res.ok) {
    throw new Error(data.error || data.message || 'Password reset failed.');
  }
  return data;
};

export const fetchCurrentUserApi = async () => {
  const token = getAuthToken();
  if (!token) return null;

  try {
    const res = await fetch(`${API_BASE}/api/v1/auth/me`, {
      headers: getAuthHeaders()
    });
    if (!res.ok) {
      clearAuthToken();
      return null;
    }
    const data = await safeParseResponse(res);
    return data.user || null;
  } catch (err) {
    return null;
  }
};

export const logoutUserApi = async () => {
  try {
    await fetch(`${API_BASE}/api/v1/auth/logout`, {
      method: 'POST',
      headers: getAuthHeaders()
    });
  } catch (_) {}
  clearAuthToken();
};

// ================= SCAN & PREVIEW APIS =================

export const analyzeUrl = async (url) => {
  const response = await fetch(`${API_BASE}/api/v1/phish/analyze`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: JSON.stringify({ url }),
  });

  const data = await safeParseResponse(response, 'We were unable to analyze this web address. Please verify the URL and try again.');
  if (!response.ok) {
    throw new Error(data.error || data.message || 'We were unable to analyze this web address. Please verify the URL and try again.');
  }

  return data;
};

export const fetchWebsitePreview = async (url) => {
  const response = await fetch(`${API_BASE}/api/v1/preview`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: JSON.stringify({ url }),
  });

  const data = await safeParseResponse(response);
  if (!response.ok) {
    return {
      available: false,
      status: response.status,
      statusText: 'ERROR',
      reason: data.reason || 'REQUEST_FAILED',
      error: data.error || `Server responded with status ${response.status}`,
      previewAvailable: false,
      screenshot: null
    };
  }

  return data;
};

// ================= HISTORY APIS =================

export const fetchScanHistory = async (userEmail) => {
  try {
    const url = userEmail ? `${API_BASE}/api/v1/history?userEmail=${encodeURIComponent(userEmail)}` : `${API_BASE}/api/v1/history`;
    const res = await fetch(url, { headers: getAuthHeaders() });
    if (!res.ok) return null;
    const data = await safeParseResponse(res);
    return data.history || [];
  } catch (err) {
    console.warn('Backend history fetch failed, falling back to local storage:', err.message);
    return null;
  }
};

export const saveScanRecordApi = async (scanRecord, userEmail) => {
  try {
    const res = await fetch(`${API_BASE}/api/v1/history`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify({ scanRecord, userEmail })
    });
    if (!res.ok) return null;
    const data = await safeParseResponse(res);
    return data.history || [];
  } catch (err) {
    console.warn('Backend history save failed, falling back to local storage:', err.message);
    return null;
  }
};

export const deleteScanRecordApi = async (scanId, userEmail) => {
  try {
    const url = userEmail ? `${API_BASE}/api/v1/history/${encodeURIComponent(scanId)}?userEmail=${encodeURIComponent(userEmail)}` : `${API_BASE}/api/v1/history/${encodeURIComponent(scanId)}`;
    const res = await fetch(url, { method: 'DELETE', headers: getAuthHeaders() });
    if (!res.ok) return null;
    const data = await safeParseResponse(res);
    return data.history || [];
  } catch (err) {
    console.warn('Backend history delete failed:', err.message);
    return null;
  }
};

export const clearScanHistoryApi = async (userEmail) => {
  try {
    const url = userEmail ? `${API_BASE}/api/v1/history?userEmail=${encodeURIComponent(userEmail)}` : `${API_BASE}/api/v1/history`;
    const res = await fetch(url, { method: 'DELETE', headers: getAuthHeaders() });
    if (!res.ok) return null;
    const data = await safeParseResponse(res);
    return data.history || [];
  } catch (err) {
    console.warn('Backend history clear failed:', err.message);
    return null;
  }
};
