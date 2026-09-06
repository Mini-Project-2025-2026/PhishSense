const logger = require('../utils/logger');
const config = require('../config/config');

/**
 * Encodes a URL into VirusTotal API v3 URL Identifier format.
 * VirusTotal API v3 uses a URL-safe Base64 string without trailing '=' padding characters.
 * Standard RFC 4648 Base64url encoding:
 * - Base64 encode URL
 * - Remove trailing '='
 * - Replace '+' with '-'
 * - Replace '/' with '_'
 * 
 * @param {string} targetUrl - The URL to encode
 * @returns {string} - The VirusTotal URL identifier string
/**
 * Normalizes a URL for canonical threat intelligence lookup.
 * Standardizes protocol, hostname (lowercased), and root path (ensuring trailing slash on origin).
 * 
 * @param {string} rawUrl - The input URL
 * @returns {string} - The normalized canonical URL
 */
function normalizeUrlForLookup(rawUrl) {
  if (!rawUrl || typeof rawUrl !== 'string') return '';
  try {
    const trimmed = rawUrl.trim();
    const parsed = new URL(trimmed);
    return parsed.href;
  } catch (_) {
    return rawUrl.trim();
  }
}

/**
 * Encodes a URL into VirusTotal API v3 URL Identifier format.
 * VirusTotal API v3 uses a URL-safe Base64 string without trailing '=' padding characters.
 * Standard RFC 4648 Base64url encoding:
 * - Base64 encode URL
 * - Remove trailing '='
 * - Replace '+' with '-'
 * - Replace '/' with '_'
 * 
 * @param {string} targetUrl - The URL to encode
 * @returns {string} - The VirusTotal URL identifier string
 */
function encodeVirusTotalUrlId(targetUrl) {
  const normalized = normalizeUrlForLookup(targetUrl);
  return Buffer.from(normalized)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

/**
 * Performs a reputation lookup against the VirusTotal API v3 URL analysis endpoint.
 */
async function lookupVirusTotal(url) {
  const apiKey = (process.env.VIRUSTOTAL_API_KEY || config.threatIntel.virusTotalApiKey || '').trim();
  const isKeyConfigured = Boolean(apiKey && apiKey !== '' && !apiKey.includes('your_virustotal_key'));

  if (!isKeyConfigured) {
    logger.info('VirusTotal API key not configured');
    return {
      provider: 'VirusTotal',
      status: 'NOT CONFIGURED',
      configured: false,
      malicious: false,
      detections: 0,
      harmless: 0,
      suspicious: 0,
      total: 0,
      flaggedVendors: []
    };
  }

  const normalizedUrl = normalizeUrlForLookup(url);
  logger.info(`VirusTotal lookup started for URL: ${normalizedUrl}`);

  try {
    const urlId = encodeVirusTotalUrlId(normalizedUrl);
    const apiUrl = `https://www.virustotal.com/api/v3/urls/${urlId}`;

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 8000); // 8 second timeout

    const response = await fetch(apiUrl, {
      method: 'GET',
      headers: {
        'x-apikey': apiKey,
        'Accept': 'application/json'
      },
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    if (response.status === 404) {
      logger.info(`VirusTotal URL report not found in database for URL: ${normalizedUrl}`);
      console.log(`\nVirusTotal lookup:\nURL: ${normalizedUrl}\nDetection: 0/0 (Not Found in VT Database)\nMalicious: 0\nSuspicious: 0\nHarmless: 0\nUndetected: 0\n`);
      return {
        provider: 'VirusTotal',
        status: 'CONNECTED',
        configured: true,
        malicious: false,
        detections: 0,
        harmless: 0,
        suspicious: 0,
        total: 0,
        flaggedVendors: [],
        notFound: true
      };
    }

    if (response.status === 401 || response.status === 403) {
      logger.info(`VirusTotal authentication failed: HTTP ${response.status}`);
      console.log(`\nVirusTotal lookup:\nURL: ${normalizedUrl}\nStatus: AUTHENTICATION FAILED (HTTP ${response.status})\n`);
      return {
        provider: 'VirusTotal',
        status: 'AUTHENTICATION FAILED',
        configured: true,
        error: `HTTP ${response.status} Authentication Failed`,
        malicious: false,
        detections: 0,
        harmless: 0,
        suspicious: 0,
        total: 0,
        flaggedVendors: []
      };
    }

    if (!response.ok) {
      logger.info(`VirusTotal response HTTP ${response.status}`);
      console.log(`\nVirusTotal lookup:\nURL: ${normalizedUrl}\nStatus: TEMPORARILY UNAVAILABLE (HTTP ${response.status})\n`);
      return {
        provider: 'VirusTotal',
        status: 'TEMPORARILY UNAVAILABLE',
        configured: true,
        error: `HTTP ${response.status}`,
        malicious: false,
        detections: 0,
        harmless: 0,
        suspicious: 0,
        total: 0,
        flaggedVendors: []
      };
    }

    const data = await response.json();
    const attributes = data?.data?.attributes || {};
    const stats = attributes.last_analysis_stats || {};
    const analysisResults = attributes.last_analysis_results || {};

    const maliciousCount = stats.malicious || 0;
    const suspiciousCount = stats.suspicious || 0;
    const harmlessCount = stats.harmless || 0;
    const undetectedCount = stats.undetected || 0;
    
    const detectionsCount = maliciousCount + suspiciousCount;
    const totalCount = maliciousCount + suspiciousCount + harmlessCount + undetectedCount;

    const flaggedVendors = [];
    for (const [engineName, engineResult] of Object.entries(analysisResults)) {
      if (engineResult && (engineResult.category === 'malicious' || engineResult.category === 'suspicious')) {
        flaggedVendors.push({
          engine: engineName,
          category: engineResult.category,
          result: engineResult.result || engineResult.category
        });
      }
    }

    console.log(`\nVirusTotal lookup:\nURL: ${normalizedUrl}\nDetection: ${detectionsCount}/${totalCount}\nMalicious: ${maliciousCount}\nSuspicious: ${suspiciousCount}\nHarmless: ${harmlessCount}\nUndetected: ${undetectedCount}\n`);

    return {
      provider: 'VirusTotal',
      status: detectionsCount > 0 ? 'THREAT FOUND' : 'CONNECTED',
      configured: true,
      malicious: maliciousCount > 0,
      suspicious: suspiciousCount > 0,
      detections: detectionsCount,
      maliciousCount,
      suspiciousCount,
      harmlessCount,
      undetectedCount,
      total: totalCount,
      flaggedVendors,
      analysisDate: attributes.last_analysis_date
        ? new Date(attributes.last_analysis_date * 1000).toISOString()
        : new Date().toISOString()
    };

  } catch (err) {
    logger.info(`VirusTotal lookup error: ${err.message}`);
    console.log(`\nVirusTotal lookup:\nURL: ${url}\nStatus: TEMPORARILY UNAVAILABLE (Error: ${err.message})\n`);
    return {
      provider: 'VirusTotal',
      status: 'TEMPORARILY UNAVAILABLE',
      configured: true,
      error: err.message,
      malicious: false,
      detections: 0,
      harmless: 0,
      suspicious: 0,
      total: 0
    };
  }
}

/**
 * Performs a URL reputation lookup against the URLhaus API (abuse.ch).
 */
async function lookupUrlhaus(url) {
  const apiKey = (process.env.URLHAUS_API_KEY || config.threatIntel.urlhausApiKey || '').trim();
  const isKeyConfigured = Boolean(apiKey && apiKey !== '' && !apiKey.includes('your_urlhaus_key'));

  if (!isKeyConfigured) {
    logger.info('URLhaus API key not configured');
    return {
      provider: 'URLhaus',
      status: 'NOT CONFIGURED',
      configured: false,
      threatFound: false,
      malwareFamily: '',
      dateAdded: ''
    };
  }

  logger.info(`URLhaus lookup started for URL: ${url}`);

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 8000); // 8 second timeout

    const headers = {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Accept': 'application/json',
      'Auth-Key': apiKey
    };

    const body = new URLSearchParams({ url: url.trim() }).toString();

    const response = await fetch('https://urlhaus-api.abuse.ch/v1/url/', {
      method: 'POST',
      headers,
      body,
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    if (response.status === 401 || response.status === 403) {
      logger.info(`URLhaus authentication failed: HTTP ${response.status}`);
      console.log(`\nURLhaus lookup:\nURL: ${url}\nStatus: AUTHENTICATION FAILED (HTTP ${response.status})\n`);
      return {
        provider: 'URLhaus',
        status: 'AUTHENTICATION FAILED',
        configured: true,
        error: `HTTP ${response.status} Unauthorized`,
        threatFound: false,
        malwareFamily: '',
        dateAdded: ''
      };
    }

    if (!response.ok) {
      logger.info(`URLhaus response HTTP ${response.status}`);
      console.log(`\nURLhaus lookup:\nURL: ${url}\nStatus: TEMPORARILY UNAVAILABLE (HTTP ${response.status})\n`);
      return {
        provider: 'URLhaus',
        status: 'TEMPORARILY UNAVAILABLE',
        configured: true,
        error: `HTTP ${response.status}`,
        threatFound: false,
        malwareFamily: '',
        dateAdded: ''
      };
    }

    const data = await response.json();
    const queryStatus = data?.query_status || 'no_results';
    const threatFound = (queryStatus === 'ok');

    console.log(`\nURLhaus lookup:\nURL: ${url}\nQuery status: ${queryStatus}\nThreat found: ${threatFound}\n`);
    
    if (threatFound) {
      const malwareFamily = (data.tags && data.tags.length > 0) 
        ? data.tags[0] 
        : (data.payloads && data.payloads.length > 0 && data.payloads[0].signature) 
          ? data.payloads[0].signature 
          : (data.threat || 'Malware Repository');
      
      const dateAdded = data.date_added || new Date().toISOString();

      return {
        provider: 'URLhaus',
        status: 'MALWARE URL DETECTED',
        configured: true,
        threatFound: true,
        malwareFamily,
        dateAdded
      };
    } else {
      return {
        provider: 'URLhaus',
        status: 'CONNECTED',
        configured: true,
        threatFound: false,
        malwareFamily: '',
        dateAdded: ''
      };
    }

  } catch (err) {
    logger.info(`URLhaus lookup error: ${err.message}`);
    console.log(`\nURLhaus lookup:\nURL: ${url}\nQuery status: error (${err.message})\nThreat found: false\n`);
    return {
      provider: 'URLhaus',
      status: 'CONNECTED',
      configured: true,
      threatFound: false,
      malwareFamily: '',
      dateAdded: ''
    };
  }
}

let openPhishCache = {
  data: null,
  timestamp: 0
};

/**
 * Performs a lookup against OpenPhish threat intelligence feed.
 * Fetches free community feed at https://openphish.com/feed.txt with in-memory caching.
 */
async function lookupOpenPhish(url) {
  logger.info(`OpenPhish lookup started for URL: ${url}`);

  try {
    const now = Date.now();
    // Cache feed in memory for 5 minutes (300,000 ms)
    if (!openPhishCache.data || (now - openPhishCache.timestamp) > 300000) {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 6000); // 6s timeout

      const response = await fetch('https://openphish.com/feed.txt', {
        method: 'GET',
        headers: { 'User-Agent': 'PhishSense-ThreatIntel/1.0' },
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      if (response.ok) {
        const text = await response.text();
        const urlsSet = new Set(text.split('\n').map(u => u.trim().toLowerCase()).filter(Boolean));
        openPhishCache = {
          data: urlsSet,
          timestamp: now
        };
      }
    }

    if (openPhishCache.data) {
      const normalizedUrl = url.trim().toLowerCase();
      const threatFound = openPhishCache.data.has(normalizedUrl);

      if (threatFound) {
        logger.info(`OpenPhish threat detected for URL: ${url}`);
      } else {
        logger.info(`OpenPhish lookup complete: No threat found`);
      }

      return {
        provider: 'OpenPhish',
        status: 'CONNECTED',
        configured: true,
        threatFound,
        detected: threatFound
      };
    }

    return {
      provider: 'OpenPhish',
      status: 'FEED UNAVAILABLE',
      configured: false,
      threatFound: false,
      detected: false
    };

  } catch (err) {
    logger.info(`OpenPhish API unavailable: ${err.message}`);
    return {
      provider: 'OpenPhish',
      status: 'FEED UNAVAILABLE',
      configured: false,
      threatFound: false,
      detected: false
    };
  }
}

/**
 * Performs threat intelligence lookups across configured external security feeds.
 */
exports.lookup = async (url) => {
  logger.info(`Performing Threat Intel lookup on: ${url}`);
  
  const [vtResult, urlhausResult, openPhishResult] = await Promise.all([
    lookupVirusTotal(url),
    lookupUrlhaus(url),
    lookupOpenPhish(url)
  ]);

  const isIntegrated = vtResult.configured || urlhausResult.configured || openPhishResult.configured;

  return {
    virusTotal: vtResult,
    urlhaus: urlhausResult,
    openPhish: openPhishResult,
    googleSafeBrowsing: {
      provider: 'Google Safe Browsing',
      status: 'FUTURE INTEGRATION',
      configured: false,
      isMalicious: false
    },
    integrated: isIntegrated,
    note: isIntegrated 
      ? `Threat intelligence lookup complete (VT: ${vtResult.status}, URLhaus: ${urlhausResult.status}, OpenPhish: ${openPhishResult.status}).`
      : 'External threat intelligence API keys not configured. Continuing in heuristic mode.'
  };
};

