const logger = require('../utils/logger');

/**
 * List of known suspicious top-level domains frequently abused in phishing campaigns.
 */
const SUSPICIOUS_TLDS = [
  '.xyz', '.top', '.club', '.info', '.work', '.gq', '.cf', '.ml', '.ga',
  '.online', '.site', '.buzz', '.icu', '.tk', '.monster', '.fit', '.kim',
  '.racing', '.surf', '.cc', '.space', '.best'
];

/**
 * List of target brands commonly spoofed via typosquatting or subdomains.
 */
/**
 * Protected target brands for typosquatting, character substitution, and Levenshtein similarity analysis.
 */
const PROTECTED_BRANDS = [
  { name: 'Google', sld: 'google', domain: 'google.com' },
  { name: 'PayPal', sld: 'paypal', domain: 'paypal.com' },
  { name: 'Microsoft', sld: 'microsoft', domain: 'microsoft.com' },
  { name: 'Amazon', sld: 'amazon', domain: 'amazon.com' },
  { name: 'Apple', sld: 'apple', domain: 'apple.com' },
  { name: 'Facebook', sld: 'facebook', domain: 'facebook.com' },
  { name: 'Instagram', sld: 'instagram', domain: 'instagram.com' },
  { name: 'Netflix', sld: 'netflix', domain: 'netflix.com' },
  { name: 'LinkedIn', sld: 'linkedin', domain: 'linkedin.com' },
  { name: 'Pinterest', sld: 'pinterest', domain: 'pinterest.com' },
  { name: 'GitHub', sld: 'github', domain: 'github.com' },
  { name: 'Twitter', sld: 'twitter', domain: 'twitter.com' },
  { name: 'Binance', sld: 'binance', domain: 'binance.com' },
  { name: 'Coinbase', sld: 'coinbase', domain: 'coinbase.com' },
  { name: 'Steam', sld: 'steam', domain: 'steampowered.com' },
  { name: 'Chase', sld: 'chase', domain: 'chase.com' },
  { name: 'WellsFargo', sld: 'wellsfargo', domain: 'wellsfargo.com' }
];

/**
 * High-risk authentication, credential, and urgency keywords commonly found in phishing URLs.
 */
const SUSPICIOUS_KEYWORDS = [
  'login', 'signin', 'verify', 'verification', 'update', 'account',
  'banking', 'secure', 'security', 'webscr', 'cmd', 'password',
  'credential', 'wallet', 'confirm', 'authenticate', 'billing',
  'authorize', 'validation', 'checkpoint', 'relogin', 'passcode'
];

/**
 * Known URL shortener domain names.
 */
const URL_SHORTENERS = [
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'buff.ly',
  'ow.ly', 'rb.gy', 'cutt.ly', 'shorturl.at', 'tiny.cc', 'bc.vc',
  'v.gd', 'qr.ae', 'adf.ly'
];

/**
 * Calculates the Levenshtein edit distance between two strings.
 */
function levenshteinDistance(str1, str2) {
  const m = str1.length;
  const n = str2.length;
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));

  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = str1[i - 1] === str2[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,       // Deletion
        dp[i][j - 1] + 1,       // Insertion
        dp[i - 1][j - 1] + cost // Substitution
      );
    }
  }
  return dp[m][n];
}

/**
 * Normalizes common character substitutions used in typosquatting attacks.
 */
function normalizeSubstitutions(str) {
  return str
    .replace(/0/g, 'o')
    .replace(/1/g, 'l')
    .replace(/3/g, 'e')
    .replace(/4/g, 'a')
    .replace(/5/g, 's')
    .replace(/8/g, 'b')
    .replace(/@/g, 'a')
    .replace(/\$/g, 's')
    .replace(/vv/g, 'w');
}

/**
 * Heuristics Rule Engine for parsing and identifying suspicious URL signals.
 * Evaluates both legacy and enhanced phishing heuristics including IDN/homoglyph spoofing.
 *
 * @param {string} urlStr - The URL string to analyze.
 * @returns {Object} Object containing boolean flags, booleanResults, triggeredRules, and readable reasons.
 */
exports.evaluate = (urlStr) => {
  logger.info(`Evaluating heuristic rules on: ${urlStr}`);

  const booleanResults = {
    // Existing rules
    suspiciousTld: false,
    hasIpHost: false,
    excessiveSubdomains: false,
    lookalikeDomain: false,

    // Additional phishing heuristics
    unicodeLookalikeDomain: false,
    hasHttps: false,
    noHttps: false,
    excessiveUrlLength: false,
    suspiciousKeywords: false,
    urlShortener: false,
    excessiveHyphens: false,
    excessiveNumbers: false,
    suspiciousSymbols: false,
    deepUrlPath: false,
  };

  const triggeredRules = [];
  const reasons = [];

  try {
    const parsedUrl = new URL(urlStr);
    const host = parsedUrl.hostname.toLowerCase();
    const fullUrlLower = urlStr.toLowerCase();

    // Rule 1: Check for IP Address hostname
    const ipPattern = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^\[?[0-9a-fA-F:]+\]?$/;
    if (ipPattern.test(host)) {
      booleanResults.hasIpHost = true;
      triggeredRules.push('hasIpHost');
      reasons.push(`URL uses an IP address hostname: ${host}`);
    }

    // Rule 2: Check for suspicious TLDs
    const matchedTld = SUSPICIOUS_TLDS.find(tld => host.endsWith(tld));
    if (matchedTld) {
      booleanResults.suspiciousTld = true;
      triggeredRules.push('suspiciousTld');
      reasons.push(`Suspicious TLD detected: ${matchedTld}`);
    }

    // Rule 3: Check for excessive subdomains
    const subdomainsCount = host.split('.').length - 2;
    if (subdomainsCount > 3) {
      booleanResults.excessiveSubdomains = true;
      triggeredRules.push('excessiveSubdomains');
      reasons.push(`URL contains excessive subdomains (${subdomainsCount} levels)`);
    }

    // Rule 4: Advanced Brand Impersonation & Typosquatting Detection (Levenshtein + Substitutions)
    const hostParts = host.split('.');
    const candidateSld = hostParts.length >= 2 ? hostParts[hostParts.length - 2] : host;
    const normalizedSld = normalizeSubstitutions(candidateSld);

    let detectedImpersonation = null;

    for (const brand of PROTECTED_BRANDS) {
      const isLegitimateDomain = (host === brand.domain) || 
                                host.endsWith('.' + brand.domain) || 
                                (brand.domain.includes('steampowered') && host.endsWith('steamcommunity.com'));

      if (isLegitimateDomain) {
        continue;
      }

      const sldContainsBrand = candidateSld.includes(brand.sld) || normalizedSld.includes(brand.sld) || host.includes(brand.sld);
      
      const distRaw = levenshteinDistance(candidateSld, brand.sld);
      const distNorm = levenshteinDistance(normalizedSld, brand.sld);
      const minDistance = Math.min(distRaw, distNorm);

      const isTyposquat = (candidateSld.length >= 4) && (
        (minDistance === 1) || 
        (minDistance === 2 && brand.sld.length >= 6)
      );

      if (sldContainsBrand || isTyposquat) {
        detectedImpersonation = brand;
        break;
      }
    }

    if (detectedImpersonation) {
      booleanResults.lookalikeDomain = true;
      triggeredRules.push('lookalikeDomain');
      reasons.push(`Possible ${detectedImpersonation.name} impersonation detected. Domain differs from legitimate brand domain (${detectedImpersonation.domain}).`);
    }

    // Rule 5: Unicode Homoglyph / IDN Spoofing Detection
    const hasNonAscii = /[^\x00-\x7F]/.test(urlStr) || /[^\x00-\x7F]/.test(host);
    const hasPunycode = host.includes('xn--');
    const homoglyphRegex = /[\u0400-\u04FF\u0370-\u03FF\u0100-\u017F\u0180-\u024F\u1E00-\u1EFF]/;
    const hasHomoglyphs = homoglyphRegex.test(host) || homoglyphRegex.test(urlStr);

    if (hasNonAscii || hasPunycode || hasHomoglyphs) {
      booleanResults.unicodeLookalikeDomain = true;
      triggeredRules.push('unicodeLookalikeDomain');
      reasons.push('Unicode lookalike character detected. Possible brand impersonation attempt.');
    }

    // Rule 6: HTTPS / Security Protocol Checking
    booleanResults.hasHttps = (parsedUrl.protocol === 'https:');
    if (!booleanResults.hasHttps) {
      booleanResults.noHttps = true;
      triggeredRules.push('noHttps');
      reasons.push('Insecure HTTP protocol detected. Website traffic is not encrypted.');
    }

    // Rule 7: URL Length Analysis
    if (urlStr.length > 75) {
      booleanResults.excessiveUrlLength = true;
      triggeredRules.push('excessiveUrlLength');
      reasons.push(`URL length exceeds recommended threshold (${urlStr.length} characters)`);
    }

    // Rule 8: Suspicious Keywords Detection
    const foundKeywords = SUSPICIOUS_KEYWORDS.filter(kw => fullUrlLower.includes(kw));
    if (foundKeywords.length > 0) {
      booleanResults.suspiciousKeywords = true;
      triggeredRules.push('suspiciousKeywords');
      reasons.push(`Suspicious keyword detected: ${foundKeywords.join(', ')}`);
    }

    // Rule 9: URL Shortener Detection
    const isShortener = URL_SHORTENERS.some(s => host === s || host.endsWith('.' + s));
    if (isShortener) {
      booleanResults.urlShortener = true;
      triggeredRules.push('urlShortener');
      reasons.push(`URL shortener detected: ${host}`);
    }

    // Rule 10: Excessive Hyphen Detection
    const hyphenCount = (host.match(/-/g) || []).length;
    if (hyphenCount > 2) {
      booleanResults.excessiveHyphens = true;
      triggeredRules.push('excessiveHyphens');
      reasons.push(`Excessive hyphenation detected in domain name (${hyphenCount} hyphens). Often used to mimic legitimate organization domains.`);
    }

    // Rule 11: Excessive Numbers Detection
    if (!booleanResults.hasIpHost) {
      const digitCount = (host.match(/\d/g) || []).length;
      if (digitCount > 3) {
        booleanResults.excessiveNumbers = true;
        triggeredRules.push('excessiveNumbers');
        reasons.push(`Suspicious numeric pattern detected in domain name (${digitCount} digits). This may indicate generated or disposable domains.`);
      }
    }

    // Rule 12: Suspicious Symbols Detection
    const hasAtSymbol = urlStr.includes('@');
    const hasDoubleSlashInPath = parsedUrl.pathname.includes('//');
    const hasSpecialSymbols = /[~$\*]/.test(urlStr);

    if (hasAtSymbol || hasDoubleSlashInPath || hasSpecialSymbols) {
      booleanResults.suspiciousSymbols = true;
      triggeredRules.push('suspiciousSymbols');
      reasons.push(`Suspicious symbols detected in URL`);
    }

    // Rule 13: Deep URL Path Detection
    const pathSegments = parsedUrl.pathname.split('/').filter(Boolean);
    if (pathSegments.length > 3) {
      booleanResults.deepUrlPath = true;
      triggeredRules.push('deepUrlPath');
      reasons.push(`Deep URL path structure detected (${pathSegments.length} directory levels)`);
    }

  } catch (error) {
    logger.error(`Rule engine parsing error: ${error.message}`);
    booleanResults.lookalikeDomain = true;
    booleanResults.suspiciousSymbols = true;
    triggeredRules.push('lookalikeDomain', 'suspiciousSymbols');
    reasons.push('URL structure is malformed or unparseable, indicating potential evasion technique.');
  }

  return {
    ...booleanResults,
    booleanResults,
    triggeredRules,
    reasons
  };
};

