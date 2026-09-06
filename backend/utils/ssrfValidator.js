const dns = require('dns').promises;
const net = require('net');

/**
 * Known forbidden hostnames and cloud metadata endpoints.
 */
const FORBIDDEN_HOSTS = new Set([
  'localhost',
  'localhost.localdomain',
  'local',
  'broadcasthost',
  'metadata.google.internal',
  'metadata.google',
  'instance-data',
  '169.254.169.254'
]);

/**
 * Checks whether an IPv4 string belongs to private, loopback, link-local,
 * multicast, carrier-grade NAT, or test network ranges.
 *
 * @param {string} ip - IPv4 address string (e.g. "127.0.0.1")
 * @returns {boolean} - true if IP is private/unsafe, false if safe/public
 */
function isPrivateIPv4(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(n => isNaN(n) || n < 0 || n > 255)) {
    return true; // Invalid IPv4 format is considered unsafe
  }

  const [a, b, c, d] = parts;

  // 0.0.0.0/8 (Current network)
  if (a === 0) return true;

  // 10.0.0.0/8 (Private Class A)
  if (a === 10) return true;

  // 100.64.0.0/10 (Carrier-grade NAT)
  if (a === 100 && b >= 64 && b <= 127) return true;

  // 127.0.0.0/8 (Loopback)
  if (a === 127) return true;

  // 169.254.0.0/16 (Link-Local / Cloud Metadata 169.254.169.254)
  if (a === 169 && b === 254) return true;

  // 172.16.0.0/12 (Private Class B)
  if (a === 172 && b >= 16 && b <= 31) return true;

  // 192.0.0.0/24 (IETF Protocol Assignments)
  if (a === 192 && b === 0 && c === 0) return true;

  // 192.0.2.0/24 (TEST-NET-1)
  if (a === 192 && b === 0 && c === 2) return true;

  // 192.168.0.0/16 (Private Class C)
  if (a === 192 && b === 168) return true;

  // 198.18.0.0/15 (Network benchmark tests)
  if (a === 198 && (b === 18 || b === 19)) return true;

  // 198.51.100.0/24 (TEST-NET-2)
  if (a === 198 && b === 51 && c === 100) return true;

  // 203.0.113.0/24 (TEST-NET-3)
  if (a === 203 && b === 0 && c === 113) return true;

  // 224.0.0.0/4 (Multicast)
  if (a >= 224 && a <= 239) return true;

  // 240.0.0.0/4 (Reserved for Future Use)
  if (a >= 240) return true;

  // 255.255.255.255 (Limited Broadcast)
  if (a === 255 && b === 255 && c === 255 && d === 255) return true;

  return false;
}

/**
 * Checks whether an IPv6 string belongs to loopback, link-local, unique-local,
 * multicast, or IPv4-mapped private ranges.
 *
 * @param {string} ip - IPv6 address string
 * @returns {boolean} - true if IP is private/unsafe, false if safe/public
 */
function isPrivateIPv6(ip) {
  const cleanIp = ip.toLowerCase().trim();

  // Loopback (::1)
  if (cleanIp === '::1' || cleanIp === '0:0:0:0:0:0:0:1' || /^0*(:0*)*:1$/.test(cleanIp)) {
    return true;
  }

  // Unspecified (::)
  if (cleanIp === '::' || cleanIp === '0:0:0:0:0:0:0:0' || /^0*(:0*)*:0$/.test(cleanIp)) {
    return true;
  }

  // IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1 or ::ffff:7f00:1)
  if (cleanIp.includes('::ffff:')) {
    const mapped = cleanIp.split('::ffff:')[1];
    if (net.isIPv4(mapped)) {
      return isPrivateIPv4(mapped);
    }
  }

  // Unique Local Addresses (ULA - fc00::/7)
  if (cleanIp.startsWith('fc') || cleanIp.startsWith('fd')) {
    return true;
  }

  // Link-Local Unicast (fe80::/10)
  if (cleanIp.startsWith('fe8') || cleanIp.startsWith('fe9') || cleanIp.startsWith('fea') || cleanIp.startsWith('feb')) {
    return true;
  }

  // Multicast (ff00::/8)
  if (cleanIp.startsWith('ff')) {
    return true;
  }

  // Discard Prefix (100::/64)
  if (cleanIp.startsWith('100::')) {
    return true;
  }

  // Documentation Prefix (2001:db8::/32)
  if (cleanIp.startsWith('2001:db8:') || cleanIp.startsWith('2001:0db8:')) {
    return true;
  }

  return false;
}

/**
 * Validates a single IP address against all private/internal network constraints.
 *
 * @param {string} ip
 * @returns {boolean} - true if safe and public, false if internal/private
 */
function isSafePublicIp(ip) {
  const version = net.isIP(ip);
  if (version === 4) {
    return !isPrivateIPv4(ip);
  } else if (version === 6) {
    return !isPrivateIPv6(ip);
  }
  return false;
}

/**
 * Performs rigorous SSRF validation on a given URL string.
 *
 * Steps:
 * 1. WHATWG URL Parsing
 * 2. Scheme & Protocol verification (http:, https: only)
 * 3. Credential & port verification
 * 4. DNS Hostname resolution (inspects ALL IPv4 and IPv6 addresses)
 * 5. Rejects any private, loopback, multicast, or cloud metadata address
 *
 * @param {string} targetUrl - The target URL to validate
 * @returns {Promise<{ valid: boolean, reason?: string, error?: string, urlObj?: URL, resolvedIps?: string[] }>}
 */
async function validateUrlForSsrf(targetUrl) {
  if (typeof targetUrl !== 'string' || !targetUrl.trim()) {
    return { valid: false, reason: 'INVALID_URL', error: 'Target URL is required.' };
  }

  const raw = targetUrl.trim();

  // 1. WHATWG URL Parsing
  let parsed;
  try {
    parsed = new URL(raw);
  } catch (err) {
    return { valid: false, reason: 'INVALID_URL', error: `Malformed URL format: ${err.message}` };
  }

  // 2. Strict Protocol Validation
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    return {
      valid: false,
      reason: 'UNSUPPORTED_PROTOCOL',
      error: `Protocol '${parsed.protocol}' is not allowed. Only HTTP and HTTPS are permitted.`
    };
  }

  // 3. Reject Embedded Credentials
  if (parsed.username || parsed.password) {
    return {
      valid: false,
      reason: 'UNSAFE_DESTINATION',
      error: 'URLs containing embedded credentials are not permitted.'
    };
  }

  const hostname = parsed.hostname.toLowerCase().trim();

  if (!hostname) {
    return { valid: false, reason: 'INVALID_URL', error: 'Hostname cannot be empty.' };
  }

  // 4. Check explicit forbidden hostname list
  if (FORBIDDEN_HOSTS.has(hostname) || hostname.endsWith('.localhost') || hostname.endsWith('.local')) {
    return {
      valid: false,
      reason: 'UNSAFE_DESTINATION',
      error: `Access to local/internal host '${hostname}' is strictly blocked.`
    };
  }

  // 5. If hostname is already a direct IP address literal
  if (net.isIP(hostname)) {
    if (!isSafePublicIp(hostname)) {
      return {
        valid: false,
        reason: 'UNSAFE_DESTINATION',
        error: `Direct connection to private/internal IP '${hostname}' is strictly blocked.`
      };
    }
    return {
      valid: true,
      urlObj: parsed,
      resolvedIps: [hostname],
      primaryIp: hostname,
      hostname
    };
  }

  // 6. Resolve Hostname to ALL IPv4 and IPv6 records
  let addresses = [];
  try {
    addresses = await dns.lookup(hostname, { all: true });
  } catch (dnsErr) {
    return {
      valid: false,
      reason: 'DNS_FAILURE',
      error: `DNS resolution failed for '${hostname}': ${dnsErr.code || dnsErr.message}`
    };
  }

  if (!addresses || addresses.length === 0) {
    return {
      valid: false,
      reason: 'DNS_FAILURE',
      error: `No DNS A/AAAA records found for '${hostname}'.`
    };
  }

  const resolvedIps = addresses.map(a => a.address);

  // 7. Validate ALL resolved IP addresses
  for (const item of addresses) {
    const ip = item.address;
    if (!isSafePublicIp(ip)) {
      return {
        valid: false,
        reason: 'UNSAFE_DESTINATION',
        error: `Hostname '${hostname}' resolved to forbidden internal/private address '${ip}'.`,
        resolvedIps
      };
    }
  }

  return {
    valid: true,
    urlObj: parsed,
    resolvedIps,
    primaryIp: resolvedIps[0],
    hostname
  };
}

module.exports = {
  validateUrlForSsrf,
  isSafePublicIp,
  isPrivateIPv4,
  isPrivateIPv6
};
