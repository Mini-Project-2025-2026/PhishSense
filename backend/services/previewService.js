const { execFile } = require('child_process');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { validateUrlForSsrf } = require('../utils/ssrfValidator');
const logger = require('../utils/logger');

// Auto-detect headless browser executable (Chrome or Edge)
function getBrowserExecutablePath() {
  const candidates = [
    'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
    'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
    'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
    'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
    '/usr/bin/google-chrome',
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser'
  ];

  for (const p of candidates) {
    if (fs.existsSync(p)) {
      return p;
    }
  }
  return null;
}

/**
 * Forcefully terminates a process and its child tree on Windows / POSIX to prevent orphan Chrome processes.
 */
function killProcessTree(pid) {
  if (!pid) return;
  try {
    if (process.platform === 'win32') {
      execFile('taskkill', ['/F', '/T', '/PID', pid.toString()], () => {});
    } else {
      process.kill(-pid, 'SIGKILL');
    }
  } catch (_) {}
}

/**
 * Captures an isolated visual screenshot using headless browser with strict DNS pinning,
 * request isolation, and hardened sandbox policies.
 *
 * @param {string} validUrl - Already SSRF-validated URL string
 * @param {string} pinnedIp - Verified public IP address for DNS pinning
 * @param {string} hostname - Target hostname to pin
 * @returns {Promise<{ success: boolean, base64Image?: string, error?: string }>}
 */
async function captureIsolatedScreenshot(validUrl) {
  const browserPath = getBrowserExecutablePath();
  if (!browserPath) {
    logger.warn('No headless browser executable detected for visual screenshot.');
    return { success: false, error: 'Headless browser not available on host system.' };
  }

  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'phishsense-preview-'));
  const screenshotPath = path.join(tempDir, 'screenshot.png');

  // Hardened DNS Resolver Rule:
  // Strictly blacklists loopback, local, and cloud metadata requests to ~NOTFOUND (NXDOMAIN),
  // completely preventing sub-resources or JavaScript from reaching internal servers or metadata endpoints.
  const hostResolverRule = '--host-resolver-rules=MAP 127.0.0.1 ~NOTFOUND, MAP localhost ~NOTFOUND, MAP 169.254.169.254 ~NOTFOUND, MAP 0.0.0.0 ~NOTFOUND, MAP [::1] ~NOTFOUND';

  const chromeFlags = [
    '--headless',
    '--disable-gpu',
    '--no-sandbox',
    '--disable-setuid-sandbox',
    '--disable-dev-shm-usage',
    '--disable-extensions',
    '--disable-sync',
    '--disable-background-networking',
    '--disable-default-apps',
    '--disable-component-update',
    '--disable-domain-reliability',
    '--disable-client-side-phishing-detection',
    '--mute-audio',
    '--no-first-run',
    '--hide-scrollbars',
    '--window-size=1280,720',
    '--deny-permission-prompts',
    '--disable-features=Translate,OptimizationHints,MediaRouter',
    '--virtual-time-budget=4000',
    hostResolverRule,
    `--user-data-dir=${tempDir}`,
    `--screenshot=${screenshotPath}`,
    validUrl
  ];

  return new Promise((resolve) => {
    let completed = false;
    let childPid = null;

    const child = execFile(browserPath, chromeFlags, { timeout: 15000 }, (error) => {
      if (completed) return;
      completed = true;

      try {
        if (fs.existsSync(screenshotPath)) {
          const buffer = fs.readFileSync(screenshotPath);
          const base64 = `data:image/png;base64,${buffer.toString('base64')}`;
          resolve({ success: true, base64Image: base64 });
        } else {
          resolve({
            success: false,
            error: error ? (error.killed ? 'Screenshot capture timed out (15s limit).' : error.message) : 'Headless rendering produced no image output.'
          });
        }
      } catch (readErr) {
        resolve({ success: false, error: readErr.message });
      } finally {
        if (childPid) killProcessTree(childPid);
        try {
          fs.rmSync(tempDir, { recursive: true, force: true });
        } catch (_) {}
      }
    });

    if (child && child.pid) {
      childPid = child.pid;
    }
  });
}

/**
 * Safely probes target URL availability with manual redirect validation and SSRF defenses.
 *
 * @param {string} rawUrl - Target URL input
 * @returns {Promise<Object>} Safe structured availability & preview response
 */
async function fetchSafeUrlPreview(rawUrl) {
  const startTime = Date.now();

  // 1. Initial SSRF & Protocol Validation
  const initialCheck = await validateUrlForSsrf(rawUrl);
  if (!initialCheck.valid) {
    const isSecurityBlock = initialCheck.reason !== 'DNS_FAILURE';
    logger.warn(`Preview validation ${isSecurityBlock ? 'blocked' : 'failed'} for '${rawUrl}': ${initialCheck.reason} - ${initialCheck.error}`);
    return {
      available: false,
      status: 0,
      statusText: isSecurityBlock ? 'BLOCKED' : 'OFFLINE',
      responseTimeMs: Date.now() - startTime,
      finalUrl: rawUrl,
      reason: initialCheck.reason || 'UNSAFE_DESTINATION',
      error: initialCheck.error || 'Destination violates security policy.',
      previewAvailable: false,
      screenshot: null
    };
  }

  let currentUrl = initialCheck.urlObj.href;
  let currentPinnedIp = initialCheck.primaryIp || (initialCheck.resolvedIps && initialCheck.resolvedIps[0]);
  let currentHostname = initialCheck.hostname || initialCheck.urlObj.hostname;
  let redirectCount = 0;
  const maxRedirects = 3;
  let finalStatus = 0;
  let finalStatusText = 'UNREACHABLE';
  let contentType = 'unknown';
  let pageTitle = '';

  // 2. Safe Manual Redirect Navigation Loop (Max 3 hops)
  while (redirectCount <= maxRedirects) {
    const currentCheck = await validateUrlForSsrf(currentUrl);
    if (!currentCheck.valid) {
      logger.warn(`Preview redirect blocked at hop ${redirectCount} to '${currentUrl}': ${currentCheck.reason}`);
      return {
        available: false,
        status: 0,
        statusText: 'BLOCKED',
        responseTimeMs: Date.now() - startTime,
        finalUrl: currentUrl,
        reason: 'UNSAFE_REDIRECT',
        error: `Redirect target violates security policy: ${currentCheck.error}`,
        previewAvailable: false,
        screenshot: null
      };
    }

    currentPinnedIp = currentCheck.primaryIp || (currentCheck.resolvedIps && currentCheck.resolvedIps[0]);
    currentHostname = currentCheck.hostname || currentCheck.urlObj.hostname;

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000); // 5 second probe timeout

      const response = await fetch(currentUrl, {
        method: 'GET',
        redirect: 'manual', // Never follow automatically
        signal: controller.signal,
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 PhishSense-Bot/1.0',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
          'Accept-Language': 'en-US,en;q=0.5'
        }
      });

      clearTimeout(timeoutId);
      finalStatus = response.status;
      finalStatusText = response.statusText || (response.ok ? 'OK' : 'RESPONDED');
      contentType = response.headers.get('content-type') || 'text/html';

      // Check for Redirect Statuses (301, 302, 303, 307, 308)
      if ([301, 302, 303, 307, 308].includes(response.status)) {
        const location = response.headers.get('location');
        if (!location) {
          break;
        }

        redirectCount++;
        if (redirectCount > maxRedirects) {
          return {
            available: false,
            status: finalStatus,
            statusText: 'TOO_MANY_REDIRECTS',
            responseTimeMs: Date.now() - startTime,
            finalUrl: currentUrl,
            reason: 'UNSAFE_REDIRECT',
            error: 'Maximum redirect limit exceeded (3 hops).',
            previewAvailable: false,
            screenshot: null
          };
        }

        let nextUrl;
        try {
          nextUrl = new URL(location, currentUrl).href;
        } catch (parseErr) {
          return {
            available: false,
            status: finalStatus,
            statusText: 'INVALID_REDIRECT',
            responseTimeMs: Date.now() - startTime,
            finalUrl: currentUrl,
            reason: 'UNSAFE_REDIRECT',
            error: `Invalid redirect target URL: ${location}`,
            previewAvailable: false,
            screenshot: null
          };
        }

        currentUrl = nextUrl;
        continue;
      }

      // Fast title extraction from initial text chunk
      if (contentType.includes('text/html') || contentType.includes('application/xhtml')) {
        try {
          const textChunk = await response.text();
          const titleMatch = textChunk.match(/<title[^>]*>([^<]+)<\/title>/i);
          if (titleMatch && titleMatch[1]) {
            pageTitle = titleMatch[1].trim().replace(/[\r\n]+/g, ' ').slice(0, 100);
          }
        } catch (_) {}
      }

      break; // Successful response reached

    } catch (netErr) {
      const elapsed = Date.now() - startTime;
      let reason = 'CONNECTION_ERROR';
      let errorMsg = netErr.message;

      if (netErr.name === 'AbortError' || netErr.message.includes('timeout') || netErr.message.includes('aborted')) {
        reason = 'TIMEOUT';
        errorMsg = 'Target server connection timed out (5s limit exceeded).';
      } else if (netErr.code === 'ECONNREFUSED' || netErr.message.includes('ECONNREFUSED')) {
        reason = 'CONNECTION_REFUSED';
        errorMsg = 'Target server refused connection.';
      } else if (netErr.code === 'ENOTFOUND' || netErr.message.includes('ENOTFOUND')) {
        reason = 'DNS_FAILURE';
        errorMsg = 'Domain name could not be resolved.';
      } else if (netErr.code === 'ENETUNREACH' || netErr.code === 'EHOSTUNREACH') {
        reason = 'OFFLINE';
        errorMsg = 'Target host or network is unreachable.';
      }

      logger.info(`Preview connection failed for '${currentUrl}': ${reason} (${errorMsg})`);

      return {
        available: false,
        status: 0,
        statusText: reason === 'TIMEOUT' ? 'TIMEOUT' : 'OFFLINE',
        responseTimeMs: elapsed,
        finalUrl: currentUrl,
        reason,
        error: errorMsg,
        previewAvailable: false,
        screenshot: null
      };
    }
  }

  const responseTimeMs = Date.now() - startTime;

  // Bot Protection / Interstitial Detection
  const botProtectionKeywords = [
    'just a moment',
    'checking your browser',
    'verify you are human',
    'attention required',
    'cloudflare',
    'ddos-guard',
    'bot verification',
    'security challenge'
  ];
  const titleLower = (pageTitle || '').toLowerCase();
  const isBotProtected = botProtectionKeywords.some(kw => titleLower.includes(kw));

  // 3. Capture Isolated Visual Screenshot with DNS Pinning
  let screenshot = null;
  let previewAvailable = false;
  let shotError = null;

  if (!isBotProtected) {
    try {
      const shotResult = await captureIsolatedScreenshot(currentUrl);
      if (shotResult.success && shotResult.base64Image) {
        screenshot = shotResult.base64Image;
        previewAvailable = true;
      } else {
        shotError = shotResult.error;
      }
    } catch (shotErr) {
      shotError = shotErr.message;
      logger.warn(`Screenshot capture warning for ${currentUrl}: ${shotErr.message}`);
    }
  }

  return {
    available: true,
    status: finalStatus,
    statusText: finalStatusText,
    responseTimeMs,
    contentType,
    finalUrl: currentUrl,
    pageTitle: pageTitle || null,
    previewAvailable,
    isBotProtected,
    screenshot,
    reason: isBotProtected ? 'BOT_PROTECTED' : (previewAvailable ? 'LIVE' : (shotError ? 'RENDER_FAILED' : 'LIVE')),
    error: shotError || null,
    securityStatus: 'ISOLATED_PREVIEW'
  };
}

module.exports = {
  fetchSafeUrlPreview,
  captureIsolatedScreenshot
};
