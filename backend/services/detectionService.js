const ruleEngine = require('../ruleEngine/engine');
const intelProvider = require('../threatIntel/intelProvider');
const aiService = require('./aiService');
const logger = require('../utils/logger');

/**
 * Orchestrator service to perform multi-layered URL analysis.
 * Combines heuristics (rule engine), threat intelligence, and AI/ML classifier prediction.
 */
exports.performAnalysis = async (url) => {
  logger.info(`Starting detection pipeline for: ${url}`);
  const startTime = Date.now();

  // 1. Run local heuristic rules checks
  const ruleResults = ruleEngine.evaluate(url);

  // 2. Fetch threat intelligence feeds and AI ML model prediction concurrently with fail-safe error boundaries
  const [intelResults, aiResult] = await Promise.all([
    intelProvider.lookup(url).catch((err) => {
      logger.warn(`Threat intelligence lookup exception: ${err.message}`);
      return {
        virusTotal: { status: 'TEMPORARILY UNAVAILABLE', configured: false, malicious: false, detections: 0, total: 0 },
        urlhaus: { status: 'TEMPORARILY UNAVAILABLE', configured: false, threatFound: false },
        openPhish: { status: 'FEED UNAVAILABLE', configured: false, threatFound: false },
        googleSafeBrowsing: { status: 'FUTURE INTEGRATION', configured: false, isMalicious: false },
        integrated: false,
        note: 'Threat intelligence services temporarily unavailable.'
      };
    }),
    aiService.predictUrl(url).catch((err) => {
      logger.warn(`AI service prediction exception: ${err.message}`);
      return {
        available: false,
        status: 'TEMPORARILY UNAVAILABLE',
        error: err.message,
        prediction: 'UNAVAILABLE',
        probability: 0.0,
        confidence: 0,
        importantFeatures: [],
        model_type: 'URLBERT Tiny v4 Classifier',
        model_version: '4.0.0',
        latencyMs: 0
      };
    })
  ]);

  // 3. Compute explainable risk score & breakdown
  const { score, breakdown, scoringModel } = calculateScoreWithBreakdown(ruleResults, intelResults, aiResult);

  // 4. Determine classification cleanly based on updated risk score ranges
  let classification = 'LOW RISK';
  if (score >= 81) {
    classification = 'MALICIOUS';
  } else if (score >= 51) {
    classification = 'HIGH RISK';
  } else if (score >= 21) {
    classification = 'SUSPICIOUS';
  } else {
    classification = 'LOW RISK';
  }

  // 5. Aggregate readable risk reasons and distinct security evidence
  const securityEvidence = [];
  const reasons = [];

  if (ruleResults.reasons && Array.isArray(ruleResults.reasons)) {
    reasons.push(...ruleResults.reasons);
    securityEvidence.push(...ruleResults.reasons);
  }

  if (aiResult && aiResult.available && aiResult.probability >= 0.50) {
    reasons.push(`AI detected strong phishing patterns (${aiResult.confidence}% pattern match).`);
  }

  if (intelResults) {
    if (intelResults.googleSafeBrowsing && intelResults.googleSafeBrowsing.isMalicious) {
      const gsbMsg = 'Flagged as malicious by Google Safe Browsing threat intelligence.';
      reasons.push(gsbMsg);
      securityEvidence.push(gsbMsg);
    }
    if (intelResults.virusTotal && intelResults.virusTotal.configured) {
      const vt = intelResults.virusTotal;
      const mCount = typeof vt.maliciousCount === 'number' ? vt.maliciousCount : (vt.malicious ? 1 : 0);
      const sCount = typeof vt.suspiciousCount === 'number' ? vt.suspiciousCount : (vt.suspicious ? 1 : 0);
      const hCount = vt.harmlessCount || 0;
      const totalCount = vt.total || 92;
      const vendorNames = (vt.flaggedVendors || []).map(v => v.engine).filter(Boolean).join(', ');

      if (mCount >= 3) {
        const vtMsg = `VirusTotal detected malicious indicators across ${mCount}/${totalCount} security vendors${vendorNames ? ` (${vendorNames})` : ''}.`;
        reasons.push(vtMsg);
        securityEvidence.push(vtMsg);
      } else if (mCount === 2) {
        const vtMsg = `VirusTotal detected malicious indicators in 2/${totalCount} security vendors${vendorNames ? ` (${vendorNames})` : ''}.`;
        reasons.push(vtMsg);
        securityEvidence.push(vtMsg);
      } else if (mCount === 1) {
        if (hCount >= 20) {
          const vtMsg = `One security vendor flagged this address${vendorNames ? ` (${vendorNames})` : ''}, while ${hCount} vendors verified it as harmless.`;
          reasons.push(vtMsg);
          securityEvidence.push(vtMsg);
        } else {
          const vtMsg = `VirusTotal security vendor flagged this address${vendorNames ? ` (${vendorNames})` : ''} (1/${totalCount} vendors).`;
          reasons.push(vtMsg);
          securityEvidence.push(vtMsg);
        }
      } else if (sCount > 0) {
        const vtMsg = `VirusTotal noted suspicious activity in ${sCount}/${totalCount} security vendors.`;
        reasons.push(vtMsg);
        securityEvidence.push(vtMsg);
      }
    }
    if (intelResults.urlhaus && (intelResults.urlhaus.detected || intelResults.urlhaus.status === 'MALICIOUS')) {
      const uhMsg = 'URL detected in URLhaus malicious URL intelligence database.';
      reasons.push(uhMsg);
      securityEvidence.push(uhMsg);
    }
    if (intelResults.openPhish && (intelResults.openPhish.detected || intelResults.openPhish.status === 'PHISHING')) {
      const opMsg = 'URL detected in OpenPhish active phishing intelligence feed.';
      reasons.push(opMsg);
      securityEvidence.push(opMsg);
    }
  }

  if (reasons.length === 0) {
    reasons.push('No phishing indicators detected.');
    if (ruleResults.booleanResults?.hasHttps || /^https:/i.test(url)) {
      reasons.push('HTTPS transport enabled.');
    }
    reasons.push('Domain structure appears normal.');
  }

  if (securityEvidence.length === 0) {
    securityEvidence.push('No suspicious heuristic anomalies or threat feed detections.');
    if (ruleResults.booleanResults?.hasHttps || /^https:/i.test(url)) {
      securityEvidence.push('HTTPS transport security active.');
    }
  }

  const totalTimeMs = Date.now() - startTime;

  return {
    url,
    timestamp: new Date().toISOString(),
    score, // Score from 0 (Low Risk) to 100 (Malicious)
    classification,
    reasons,
    securityEvidence,
    scoreBreakdown: breakdown,
    details: {
      heuristics: ruleResults,
      threatIntel: intelResults,
      aiAnalysis: aiResult,
      securityEvidence,
      scoringModel
    },
    performance: {
      aiInferenceMs: aiResult.latencyMs || 0,
      totalAnalysisMs: totalTimeMs
    }
  };
};

/**
 * Calculates an aggregated risk score and detailed contribution breakdown based on the
 * Multi-Layered Risk Architecture:
 * - Heuristic Engine Component: Max 40 points
 * - Threat Intelligence Feeds Component: Max 60 points
 * - Intelligent AI/ML Model Component: Max 30 points
 * - Total Platform Risk Score: Bounded between 0 and 100 points
 */
function calculateScoreWithBreakdown(rules, intel, ai) {
  let rawHeuristicScore = 0;
  let rawIntelScore = 0;
  let rawAiScore = 0;
  const breakdown = [];
  const flags = rules.booleanResults || rules;

  // ---------------------------------------------------------
  // 1. HEURISTIC ENGINE EVALUATION (Max Weight: 40 Points)
  // ---------------------------------------------------------
  if (flags.hasIpHost) {
    rawHeuristicScore += 30;
    breakdown.push({ name: 'IP Address Hostname Risk', points: 30, category: 'heuristic' });
  }
  if (flags.lookalikeDomain) {
    rawHeuristicScore += 25;
    breakdown.push({ name: 'Domain Impersonation Risk', points: 25, category: 'heuristic' });
  }
  if (flags.unicodeLookalikeDomain) {
    rawHeuristicScore += 25;
    breakdown.push({ name: 'Unicode / IDN Spoofing Risk', points: 25, category: 'heuristic' });
  }
  if (flags.suspiciousTld) {
    rawHeuristicScore += 20;
    breakdown.push({ name: 'Suspicious TLD Extension Risk', points: 20, category: 'heuristic' });
  }
  if (flags.noHttps) {
    rawHeuristicScore += 15;
    breakdown.push({ name: 'Protocol Security Risk (HTTP)', points: 15, category: 'heuristic' });
  }
  if (flags.urlShortener) {
    rawHeuristicScore += 15;
    breakdown.push({ name: 'URL Shortener Obfuscation Risk', points: 15, category: 'heuristic' });
  }
  if (flags.excessiveSubdomains) {
    rawHeuristicScore += 15;
    breakdown.push({ name: 'Excessive Subdomain Complexity Risk', points: 15, category: 'heuristic' });
  }
  if (flags.suspiciousKeywords) {
    rawHeuristicScore += 10;
    breakdown.push({ name: 'Suspicious Keywords Risk', points: 10, category: 'heuristic' });
  }
  if (flags.excessiveHyphens) {
    rawHeuristicScore += 10;
    breakdown.push({ name: 'Excessive Hyphenation Risk', points: 10, category: 'heuristic' });
  }
  if (flags.excessiveUrlLength) {
    rawHeuristicScore += 10;
    breakdown.push({ name: 'Excessive URL Length Risk', points: 10, category: 'heuristic' });
  }
  if (flags.suspiciousSymbols) {
    rawHeuristicScore += 10;
    breakdown.push({ name: 'Suspicious URL Symbols Risk', points: 10, category: 'heuristic' });
  }
  if (flags.excessiveNumbers) {
    rawHeuristicScore += 10;
    breakdown.push({ name: 'Suspicious Numeric Pattern Risk', points: 10, category: 'heuristic' });
  }
  if (flags.deepUrlPath) {
    rawHeuristicScore += 10;
    breakdown.push({ name: 'Deep Directory Path Risk', points: 10, category: 'heuristic' });
  }

  // Cap heuristic contribution to max 40 points
  const heuristicComponent = Math.min(rawHeuristicScore, 40);

  // ---------------------------------------------------------
  // 2. THREAT INTELLIGENCE EVALUATION (Max Weight: 60 Points)
  // ---------------------------------------------------------
  if (intel) {
    if (intel.googleSafeBrowsing && intel.googleSafeBrowsing.isMalicious) {
      rawIntelScore += 40;
      breakdown.push({ name: 'Google Safe Browsing Match', points: 40, category: 'intel' });
    }

    if (intel.virusTotal && intel.virusTotal.configured) {
      const vt = intel.virusTotal;
      const mCount = typeof vt.maliciousCount === 'number' ? vt.maliciousCount : (vt.malicious ? 1 : 0);
      const sCount = typeof vt.suspiciousCount === 'number' ? vt.suspiciousCount : (vt.suspicious ? 1 : 0);
      const hCount = vt.harmlessCount || 0;
      const totalCount = vt.total || 92;

      if (mCount >= 5) {
        // High multi-vendor malicious consensus (5+ engines): Maximum Threat Intel contribution
        rawIntelScore += 60;
        breakdown.push({ 
          name: `VirusTotal Multi-Vendor Threat Consensus`, 
          points: 60, 
          category: 'intel',
          detail: `${mCount}/${totalCount} vendors flagged malicious`
        });
      } else if (mCount >= 3) {
        // Multi-vendor verified malicious consensus (3–4 engines): Strong threat signal
        rawIntelScore += 45;
        breakdown.push({ 
          name: `VirusTotal Multi-Vendor Threat`, 
          points: 45, 
          category: 'intel',
          detail: `${mCount}/${totalCount} vendors flagged malicious`
        });
      } else if (mCount === 2) {
        // Dual-vendor malicious confirmation
        if (hCount >= 20) {
          // Dual flag on established domain with clean consensus
          rawIntelScore += 15;
          breakdown.push({ 
            name: `VirusTotal Dual Vendor Indicator`, 
            points: 15, 
            category: 'intel',
            detail: `2/${totalCount} vendors flagged (${hCount} verified harmless)`
          });
        } else {
          // Dual flag on unvetted / new domain
          rawIntelScore += 30;
          breakdown.push({ 
            name: `VirusTotal Dual-Vendor Threat`, 
            points: 30, 
            category: 'intel',
            detail: `2/${totalCount} vendors flagged malicious`
          });
        }
      } else if (mCount === 1) {
        if (hCount >= 20) {
          // Single isolated vendor outlier against massive clean consensus (20+ harmless engines, e.g. 64 harmless vs 1 outlier)
          rawIntelScore += 3;
          breakdown.push({ 
            name: `VirusTotal Isolated Vendor Flag`, 
            points: 3, 
            category: 'intel',
            detail: `1/${totalCount} vendor flagged (${hCount} verified harmless)`
          });
        } else {
          // Single vendor flag on unvetted / new / low-reputation domain without clean consensus
          rawIntelScore += 25;
          breakdown.push({ 
            name: `VirusTotal Threat Flag`, 
            points: 25, 
            category: 'intel',
            detail: `1/${totalCount} vendor flagged`
          });
        }
      } else if (sCount > 0) {
        // Suspicious-only flags (0 confirmed malicious)
        if (hCount >= 20) {
          const sPoints = sCount >= 2 ? 5 : 2;
          rawIntelScore += sPoints;
          breakdown.push({ 
            name: `VirusTotal Suspicious Indicator`, 
            points: sPoints, 
            category: 'intel',
            detail: `${sCount}/${totalCount} vendors flagged suspicious (${hCount} verified harmless)`
          });
        } else {
          const sPoints = sCount >= 2 ? 15 : 10;
          rawIntelScore += sPoints;
          breakdown.push({ 
            name: `VirusTotal Suspicious Flag`, 
            points: sPoints, 
            category: 'intel',
            detail: `${sCount}/${totalCount} vendors flagged suspicious`
          });
        }
      } else if (hCount >= 20 && mCount === 0 && sCount === 0) {
        // Fully verified clean consensus across engines
        rawIntelScore -= 10;
        breakdown.push({ 
          name: 'VirusTotal Verified Clean Reputation', 
          points: -10, 
          category: 'intel',
          detail: `${hCount} vendors verified clean (0 detections)`
        });
      }
    }

    if (intel.urlhaus && (intel.urlhaus.threatFound || intel.urlhaus.detected || intel.urlhaus.status === 'MALICIOUS' || intel.urlhaus.status === 'MALWARE URL DETECTED')) {
      rawIntelScore += 30;
      breakdown.push({ 
        name: 'URLhaus Malware Detection', 
        points: 30, 
        category: 'intel',
        detail: intel.urlhaus.malwareFamily || 'Malware Record Found'
      });
    }

    if (intel.openPhish && (intel.openPhish.threatFound || intel.openPhish.detected || intel.openPhish.status === 'PHISHING')) {
      rawIntelScore += 30;
      breakdown.push({ 
        name: 'OpenPhish Phishing Feed Match', 
        points: 30, 
        category: 'intel',
        detail: 'Active Phishing Match'
      });
    }
  }

  const intelComponent = Math.min(Math.max(rawIntelScore, -10), 60);

  // ---------------------------------------------------------
  // 3. AI / ML MODEL EVALUATION (Max Dynamic Contribution: 30 Points)
  // ---------------------------------------------------------
  if (ai && ai.available && typeof ai.probability === 'number' && !isNaN(ai.probability)) {
    if (ai.probability >= 0.50) {
      // Standardized formula: Math.round(probability * 30), strictly clamped to [0, 30]
      const aiPoints = Math.min(30, Math.max(0, Math.round(ai.probability * 30)));
      rawAiScore += aiPoints;
      breakdown.push({
        name: `AI Model Phishing Contributor`,
        points: aiPoints,
        category: 'ai',
        detail: `Probability: ${ai.confidence}% (${ai.prediction})`
      });
    }
  }

  // Combine Components & Strictly Bound between 0 and 100
  const rawSum = (heuristicComponent || 0) + (intelComponent || 0) + (rawAiScore || 0);
  const combinedScore = Math.min(100, Math.max(0, Math.round(rawSum)));

  return {
    score: isNaN(combinedScore) ? 0 : combinedScore,
    breakdown,
    scoringModel: {
      heuristicComponent: isNaN(heuristicComponent) ? 0 : heuristicComponent,
      heuristicMax: 40,
      intelComponent: isNaN(intelComponent) ? 0 : intelComponent,
      intelMax: 60,
      aiComponent: isNaN(rawAiScore) ? 0 : rawAiScore,
      aiMax: 30,
      weightAllocation: 'Multi-Layer Hybrid Scoring (Heuristics 0–40, Threat Intel 0–60, AI 0–30)'
    }
  };
}
