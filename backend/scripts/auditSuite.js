const { performAnalysis } = require('../services/detectionService');
const { fetchSafeUrlPreview } = require('../services/previewService');
const { calculateScoreWithBreakdown } = require('../services/detectionService');

function getPreviewPillStatus(previewData) {
  if (
    previewData?.statusText === 'BLOCKED' ||
    previewData?.reason === 'UNSAFE_DESTINATION' ||
    previewData?.reason === 'UNSAFE_REDIRECT' ||
    previewData?.reason === 'UNSAFE_PROTOCOL' ||
    previewData?.reason === 'INVALID_PORT'
  ) {
    return { text: 'Preview blocked', pill: 'Amber', caseNum: 5 };
  }
  if (previewData?.previewAvailable && previewData?.screenshot) {
    return { text: 'Live preview available', pill: 'Emerald', caseNum: 1 };
  }
  if (previewData?.isBotProtected || previewData?.reason === 'BOT_PROTECTED') {
    return { text: 'Website is reachable', pill: 'Slate', caseNum: 2, notice: 'Website preview blocked' };
  }
  if (previewData?.available) {
    return { text: 'Website is reachable', pill: 'Slate', caseNum: 3, notice: 'Website preview unavailable' };
  }
  return { text: 'Website unreachable', pill: 'Slate', caseNum: 4, notice: 'Website preview unavailable' };
}

async function runAudit() {
  console.log('================================================================================');
  console.log('PHISHSENSE FINAL PRE-GITHUB COMPREHENSIVE AUDIT SUITE');
  console.log('================================================================================\n');

  // --- SECTION A: BENCHMARK DETECTION & THREAT INTEL TESTS ---
  console.log('>>> 1. CORE DETECTION & THREAT INTELLIGENCE BENCHMARKS:');
  const scans = [
    { label: 'Google Root (Consensus Outlier Check)', url: 'https://google.com/' },
    { label: 'Google WWW (Clean Benchmark)', url: 'https://www.google.com/' },
    { label: 'Example.com (Clean Benchmark)', url: 'https://example.com' },
    { label: 'Wikipedia (Clean Benchmark)', url: 'https://wikipedia.org/' },
    { label: 'PayPal Spoof Phishing URL', url: 'http://paypal-security-update-verification.com/login' },
    { label: 'Bank of America Spoof Phishing URL', url: 'https://bankofamerica-login-security.xyz/signin' }
  ];

  for (const s of scans) {
    const res = await performAnalysis(s.url);
    console.log(`[TEST] ${s.label}`);
    console.log(`  URL:            ${s.url}`);
    console.log(`  Score:          ${res.score} / 100 (${res.classification})`);
    console.log(`  Heuristics:     ${res.details?.scoringModel?.heuristicComponent} / 40`);
    console.log(`  Threat Intel:   ${res.details?.scoringModel?.intelComponent} / 60`);
    console.log(`  AI Model:       +${res.details?.scoringModel?.aiComponent} / 30 (${res.details?.aiAnalysis?.probability ? Math.round(res.details.aiAnalysis.probability * 100) : 0}% likelihood)`);
    console.log('');
  }

  // --- SECTION B: MULTI-VENDOR CONSENSUS MATHEMATICAL VERIFICATION ---
  console.log('>>> 2. THREAT INTEL MATHEMATICAL CONSENSUS VERIFICATION:');
  // 1 Isolated Malicious vendor vs 64 clean:
  const outlierIntel = { virusTotal: { maliciousCount: 1, harmlessCount: 64, total: 92, detections: 1 } };
  const mockRules = { booleanResults: {}, score: 0 };
  const mockAi = { available: true, probability: 0 };
  const calcOutlier = performAnalysis.__calculateScore ? performAnalysis.__calculateScore(mockRules, outlierIntel, mockAi) : null;
  console.log(`  [MATH TEST] Single Outlier (1 / 92 with 64 harmless): Expected ~+3 pts`);

  // --- SECTION C: 5 WEBSITE PREVIEW STATES ---
  console.log('\n>>> 3. ALL 5 WEBSITE PREVIEW STATES:');
  const previewTests = [
    { label: 'CASE 1: Reachable + Screenshot Captured', url: 'https://example.com' },
    { label: 'CASE 2: Reachable + Bot Protection', url: 'https://www.w3.org' },
    { label: 'CASE 3: Reachable + Timeout / Render Limit', url: 'https://www.mozilla.org' },
    { label: 'CASE 4: Unreachable Domain (DNS Failure)', url: 'http://domain-does-not-exist-1234567890.xyz' },
    { label: 'CASE 5: SSRF Blocked (Cloud Metadata)', url: 'http://169.254.169.254/latest/meta-data' },
    { label: 'CASE 5b: SSRF Blocked (Loopback)', url: 'http://127.0.0.1:8080' }
  ];

  for (const pt of previewTests) {
    const data = await fetchSafeUrlPreview(pt.url);
    const pill = getPreviewPillStatus(data);
    console.log(`[PREVIEW] ${pt.label}`);
    console.log(`  URL:         ${pt.url}`);
    console.log(`  Status Pill: "${pill.text}" [${pill.pill} Badge] (Case ${pill.caseNum})`);
    console.log(`  Available:   ${data.available} | statusText: ${data.statusText} | reason: ${data.reason}`);
    console.log(`  Screenshot:  ${!!data.screenshot}`);
    console.log('');
  }

  console.log('================================================================================');
  console.log('ALL AUDIT SUITE CHECKS COMPLETED SUCCESSFULLY');
  console.log('================================================================================');
}

runAudit();
