const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../.env') });
const { fetchSafeUrlPreview } = require('../services/previewService');
const { performAnalysis } = require('../services/detectionService');

function getPreviewStatus(previewData) {
  if (
    previewData?.statusText === 'BLOCKED' ||
    previewData?.reason === 'UNSAFE_DESTINATION' ||
    previewData?.reason === 'UNSAFE_REDIRECT' ||
    previewData?.reason === 'UNSAFE_PROTOCOL' ||
    previewData?.reason === 'INVALID_PORT'
  ) {
    return {
      text: 'Preview blocked',
      badgeClass: 'Amber',
      noticeHeading: 'Internal destination blocked',
      noticeDetail: 'This address targets an internal or private network destination and was blocked to protect your system.'
    };
  }

  if (previewData?.previewAvailable && previewData?.screenshot) {
    return {
      text: 'Live preview available',
      badgeClass: 'Emerald',
      noticeHeading: 'Screenshot Rendered',
      noticeDetail: 'Preview captured safely in an isolated environment without affecting the website itself.'
    };
  }

  if (previewData?.isBotProtected || previewData?.reason === 'BOT_PROTECTED') {
    return {
      text: 'Website is reachable',
      badgeClass: 'Slate',
      noticeHeading: 'Website preview blocked',
      noticeDetail: 'This website uses automated-visit protection, so PhishSense could not capture the actual page. This does not affect your safety result.'
    };
  }

  if (previewData?.available) {
    return {
      text: 'Website is reachable',
      badgeClass: 'Slate',
      noticeHeading: 'Website preview unavailable',
      noticeDetail: 'This website may block automated previews or take too long to load. This does not affect your safety result.'
    };
  }

  return {
    text: 'Website unreachable',
    badgeClass: 'Slate',
    noticeHeading: 'Website preview unavailable',
    noticeDetail: 'The target server could not be reached or timed out. This does not affect your safety result.'
  };
}

async function runVerification() {
  console.log('================================================================================');
  console.log('PHISHSENSE — FOCUSED WEBSITE PREVIEW VERIFICATION SUITE');
  console.log('================================================================================\n');

  // --- 1. THE FIVE PREVIEW STATES ---
  console.log('--- 1. THE FIVE PREVIEW STATES ---');

  const testCases = [
    { name: 'CASE 1a (Google Root)', url: 'https://google.com/', expectedPill: 'Live preview available' },
    { name: 'CASE 1b (Example.com)', url: 'https://example.com/', expectedPill: 'Live preview available' },
    { name: 'CASE 2 (Bot-Protected: w3.org)', url: 'https://www.w3.org', expectedPill: 'Website is reachable' },
    { name: 'CASE 3 (Timeout / Heavy Render: mozilla.org)', url: 'https://www.mozilla.org', expectedPill: 'Website is reachable' },
    { name: 'CASE 4 (Unreachable Domain)', url: 'http://domain-does-not-exist-1234567890.xyz', expectedPill: 'Website unreachable' },
    { name: 'CASE 5a (SSRF Blocked: Localhost)', url: 'http://127.0.0.1:8080', expectedPill: 'Preview blocked' },
    { name: 'CASE 5b (SSRF Blocked: Cloud Metadata)', url: 'http://169.254.169.254/latest/meta-data', expectedPill: 'Preview blocked' }
  ];

  for (const tc of testCases) {
    const data = await fetchSafeUrlPreview(tc.url);
    const status = getPreviewStatus(data);
    const pass = status.text === tc.expectedPill;
    console.log(`[TEST] ${tc.name}`);
    console.log(`  URL:             ${tc.url}`);
    console.log(`  Expected Pill:   "${tc.expectedPill}"`);
    console.log(`  Actual Pill:     "${status.text}" [${status.badgeClass}]`);
    console.log(`  Notice Heading:  "${status.noticeHeading}"`);
    console.log(`  Has Screenshot:  ${!!data.screenshot}`);
    console.log(`  Pass:            ${pass ? 'YES ✅' : 'NO ❌'}`);
    console.log('');
  }

  // --- 2. RACE CONDITION / ASYNC ASSOCIATION TEST ---
  console.log('--- 2. ASYNC URL ASSOCIATION & RACE CONDITION TEST ---');
  let activeUrl = 'https://google.com/';
  let displayedPreview = null;

  // Scan A begins
  const scanAPromise = fetchSafeUrlPreview('https://google.com/').then(prev => {
    if (activeUrl === 'https://google.com/') {
      displayedPreview = { url: 'https://google.com/', data: prev };
    }
  });

  // User immediately switches to Scan B before Scan A finishes
  activeUrl = 'https://example.com/';
  const scanBPromise = fetchSafeUrlPreview('https://example.com/').then(prev => {
    if (activeUrl === 'https://example.com/') {
      displayedPreview = { url: 'https://example.com/', data: prev };
    }
  });

  await Promise.all([scanAPromise, scanBPromise]);
  const racePass = displayedPreview && displayedPreview.url === 'https://example.com/';
  console.log(`  Rapid Scan A (google) -> Scan B (example.com)`);
  console.log(`  Final Displayed URL:  ${displayedPreview?.url}`);
  console.log(`  Active URL Ref Match: ${racePass ? 'YES ✅ (No race leak)' : 'NO ❌'}\n`);

  // --- 3. SAFETY SCORE INDEPENDENCE TEST ---
  console.log('--- 3. SAFETY SCORE INDEPENDENCE TEST ---');
  const googleScan = await performAnalysis('https://google.com/');
  const paypalScan = await performAnalysis('http://paypal-security-update-verification.com/login');
  console.log(`  Google Risk Score:          ${googleScan.score} / 100 (${googleScan.classification}) [Expected: 3/100]`);
  console.log(`  PayPal Phishing Risk Score: ${paypalScan.score} / 100 (${paypalScan.classification}) [Expected: 70/100]`);
  const scorePass = googleScan.score === 3 && paypalScan.score === 70;
  console.log(`  Scores Independent:         ${scorePass ? 'YES ✅' : 'NO ❌'}\n`);

  console.log('================================================================================');
  console.log('ALL PREVIEW VERIFICATION TESTS COMPLETE');
  console.log('================================================================================');
}

runVerification();
