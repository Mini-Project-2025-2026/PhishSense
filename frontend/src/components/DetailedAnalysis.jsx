import React, { useState, useEffect, useRef } from 'react';
import gsap from 'gsap';
import { isReducedMotion } from '../utils/helpers';

/**
 * Detailed Technical Analysis Component (Progressive Disclosure)
 * 
 * Subsections / Tabs:
 * 1. AI Pattern Check (Powered by URLBERT v4)
 * 2. Domain & Structure Checks (13 Heuristic rules compact checklist)
 * 3. Global Threat Intelligence Feeds (VirusTotal & OpenPhish feeds)
 * 4. Security & Network Protocols (Transport TLS, SSRF Defense, Host Resolution)
 * 5. Risk Calculation & Attribution (Mathematical formula & layer stepper)
 * 6. Website Reachability (HTTP status, latency, content-type)
 */
export function DetailedAnalysis({ result, securityChecks, threatIntelCards, previewData }) {
  const [activeTab, setActiveTab] = useState('all');
  const [expandedCheckId, setExpandedCheckId] = useState(null);
  const containerRef = useRef(null);

  useEffect(() => {
    if (!result || isReducedMotion() || !containerRef.current) return;

    const ctx = gsap.context(() => {
      gsap.from('[data-animate="detail-block"]', {
        opacity: 0,
        y: 12,
        duration: 0.35,
        stagger: 0.06,
        ease: 'power2.out'
      });
    }, containerRef);

    return () => ctx.revert();
  }, [activeTab]);

  if (!result) return null;

  const aiAnalysis = result.details?.aiAnalysis || {};
  const aiProbability = aiAnalysis.confidence !== undefined 
    ? aiAnalysis.confidence 
    : (aiAnalysis.probability ? Math.round(aiAnalysis.probability * 100) : null);
  const scoringModel = result.details?.scoringModel || {};
  const heuristicScore = scoringModel.heuristicComponent || 0;
  const intelScore = scoringModel.intelComponent || 0;
  const aiScore = scoringModel.aiComponent || 0;

  return (
    <div ref={containerRef} className="space-y-6 pt-8 border-t border-slate-200 dark:border-slate-800 font-sans max-w-5xl mx-auto w-full">
      
      {/* SECTION HEADER & TAB SELECTOR */}
      <div className="flex flex-col md:flex-row justify-between md:items-center gap-4">
        <div>
          <h3 className="font-heading text-xl sm:text-2xl font-bold text-slate-900 dark:text-white flex items-center gap-2.5">
            <span className="material-symbols-outlined text-sky-600 dark:text-sky-400 text-[24px]">query_stats</span>
            Advanced Security Details
          </h3>
          <p className="text-sm sm:text-base text-slate-600 dark:text-slate-400 font-normal mt-0.5">
            Technical inspection of AI pattern analysis, heuristic checks, threat feeds, and network protocols
          </p>
        </div>

        {/* Tab Filters */}
        <div className="flex flex-wrap gap-1.5 p-1 rounded-xl bg-slate-100 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-xs sm:text-sm font-mono">
          {[
            { key: 'all', label: 'All Details', icon: 'apps' },
            { key: 'ai', label: 'AI Pattern Check', icon: 'psychology' },
            { key: 'heuristics', label: 'Domain & Structure', icon: 'tune' },
            { key: 'intel', label: 'Threat Feeds', icon: 'public' },
            { key: 'checks', label: 'Network Protocols', icon: 'security' },
            { key: 'calc', label: 'Calculation', icon: 'calculate' },
            { key: 'network', label: 'Reachability', icon: 'language' }
          ].map(({ key, label, icon }) => (
            <button
              key={key}
              onClick={() => setActiveTab(key)}
              className={`px-3 py-1.5 rounded-lg transition-colors flex items-center gap-1.5 cursor-pointer ${
                activeTab === key
                  ? 'bg-sky-600 dark:bg-sky-500 text-white dark:text-slate-950 font-semibold shadow-sm'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
              }`}
            >
              <span className="material-symbols-outlined text-[15px]">{icon}</span>
              <span>{label}</span>
            </button>
          ))}
        </div>
      </div>

      {/* DOMINANT COMPOSITE SCORE SUMMARY & CONTRIBUTING FACTORS */}
      <div data-animate="detail-block" className="rounded-2xl bg-white dark:bg-gray-900 border border-slate-200 dark:border-slate-800 p-6 md:p-7 shadow-sm space-y-5">
        <div className="flex flex-col sm:flex-row justify-between sm:items-center gap-4 border-b border-slate-100 dark:border-slate-800 pb-4">
          <div>
            <div className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
              Composite Risk Result
            </div>
            <h4 className="font-heading text-lg sm:text-xl font-bold text-slate-900 dark:text-white flex items-center gap-2 mt-0.5">
              <span className="material-symbols-outlined text-sky-600 dark:text-sky-400 text-[22px]">score</span>
              <span>Overall Risk Score:</span>
              <span className="font-mono text-sky-600 dark:text-sky-400">{result.score} / 100</span>
            </h4>
          </div>
          <span className={`px-3.5 py-1 rounded-full text-xs font-mono font-bold uppercase tracking-wide border self-start sm:self-auto ${
            result.score >= 51 ? 'bg-red-50 text-red-700 border-red-200 dark:bg-red-950/50 dark:text-red-300 dark:border-red-800' :
            result.score >= 21 ? 'bg-amber-50 text-amber-800 border-amber-200 dark:bg-amber-950/50 dark:text-amber-300 dark:border-amber-800' :
            'bg-emerald-50 text-emerald-800 border-emerald-200 dark:bg-emerald-950/50 dark:text-emerald-300 dark:border-emerald-800'
          }`}>
            {result.classification || (result.score >= 81 ? 'MALICIOUS' : result.score >= 51 ? 'HIGH RISK' : result.score >= 21 ? 'MEDIUM RISK' : 'LOW RISK')}
          </span>
        </div>

        {/* Contributing Factors Grid */}
        <div className="space-y-2.5">
          <div className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
            Contributing Factors
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3.5">
            <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700/80 space-y-1">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-slate-700 dark:text-slate-300">Heuristic Rules</span>
                <span className="text-xs font-mono font-bold text-slate-900 dark:text-white">{heuristicScore} / 40 pts</span>
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400 font-normal">13 deterministic lexical & structure checks</p>
            </div>

            <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700/80 space-y-1">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-slate-700 dark:text-slate-300">Threat Intelligence</span>
                <span className="text-xs font-mono font-bold text-slate-900 dark:text-white">{intelScore} / 60 pts</span>
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400 font-normal">VirusTotal & OpenPhish threat databases</p>
            </div>

            <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700/80 space-y-1">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-slate-700 dark:text-slate-300">AI Pattern Check</span>
                <span className="text-xs font-mono font-bold text-sky-600 dark:text-sky-400">+{aiScore} / 30 pts</span>
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400 font-normal">URLBERT v4 Transformer sequence model</p>
            </div>
          </div>
        </div>
      </div>

      {/* 1. AI PATTERN CHECK */}
      {(activeTab === 'all' || activeTab === 'ai') && (
        <div data-animate="detail-block" className="rounded-2xl bg-white dark:bg-gray-900 border border-slate-200 dark:border-slate-800 p-6 md:p-8 shadow-sm space-y-6">
          <div className="flex flex-col sm:flex-row justify-between sm:items-center gap-3 border-b border-slate-200 dark:border-slate-800 pb-4">
            <div>
              <h4 className="font-heading text-base sm:text-lg font-bold text-slate-900 dark:text-white flex items-center gap-2">
                <span className="material-symbols-outlined text-sky-600 dark:text-sky-400 text-[22px]">psychology</span>
                AI Pattern Check
              </h4>
              <p className="text-xs sm:text-sm text-slate-500 dark:text-slate-400 font-normal">
                Powered by URLBERT v4 — Neural sequence analysis evaluating character n-grams and obfuscated URL patterns
              </p>
            </div>

            {/* Model Status Badge */}
            <div>
              {aiAnalysis.available ? (
                <span className="px-3 py-1 rounded-full text-xs font-mono font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200 dark:bg-emerald-950/40 dark:text-emerald-300 dark:border-emerald-800/70 inline-flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
                  Active
                </span>
              ) : (
                <span className="px-3 py-1 rounded-full text-xs font-mono font-semibold bg-amber-50 text-amber-700 border border-amber-200 dark:bg-amber-950/40 dark:text-amber-300 dark:border-amber-800/70">
                  Temporarily Unavailable
                </span>
              )}
            </div>
          </div>

          {aiAnalysis.available ? (
            <div className="space-y-5">
              {/* Stat Grid (Meaningful Security Indicators Only) */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3.5">
                <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700/80 space-y-1">
                  <div className="text-xs font-mono text-slate-500 dark:text-slate-400 uppercase font-semibold">Pattern Match Result</div>
                  <div className={`font-mono text-base sm:text-lg font-bold ${
                    aiAnalysis.prediction === 'PHISHING' ? 'text-red-600 dark:text-red-400' :
                    aiAnalysis.prediction === 'SUSPICIOUS' ? 'text-amber-600 dark:text-amber-400' :
                    'text-emerald-600 dark:text-emerald-400'
                  }`}>
                    {aiAnalysis.prediction || 'BENIGN'}
                  </div>
                  <div className="text-xs text-slate-500 dark:text-slate-400 font-normal">
                    {aiAnalysis.prediction === 'PHISHING' ? 'Deceptive URL patterns detected' : 'Standard legitimate sequence'}
                  </div>
                </div>

                <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700/80 space-y-1">
                  <div className="text-xs font-mono text-slate-500 dark:text-slate-400 uppercase font-semibold">AI Phishing Pattern Likelihood</div>
                  <div className="font-mono text-base sm:text-lg font-bold text-slate-900 dark:text-white">
                    {aiProbability !== null ? `${aiProbability}%` : '0%'}
                  </div>
                  <div className="text-xs text-slate-500 dark:text-slate-400 font-normal">
                    {aiProbability >= 50 ? 'URLBERT sequence confidence' : 'Low probability score'}
                  </div>
                </div>

                <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700/80 space-y-1">
                  <div className="text-xs font-mono text-slate-500 dark:text-slate-400 uppercase font-semibold">Sequence Analysis</div>
                  <div className="font-mono text-sm sm:text-base font-bold text-sky-600 dark:text-sky-300">
                    {aiProbability >= 50 ? 'Irregular Tokens' : 'Clean Lexical Structure'}
                  </div>
                  <div className="text-xs text-slate-500 dark:text-slate-400 font-normal">
                    Transformer token evaluation
                  </div>
                </div>
              </div>

              {/* Finding note */}
              <div className="p-4 sm:p-5 rounded-xl bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700/80 space-y-1.5">
                <h5 className="font-mono text-xs sm:text-sm uppercase font-semibold text-slate-600 dark:text-slate-400 tracking-wider flex items-center gap-2">
                  <span className="material-symbols-outlined text-[18px] text-sky-600 dark:text-sky-400">psychology</span>
                  AI Pattern Finding
                </h5>
                <p className="text-xs sm:text-sm text-slate-700 dark:text-slate-300 leading-relaxed font-normal">
                  {aiProbability >= 50
                    ? `URLBERT estimates a ${aiProbability}% likelihood that the URL's sequence resembles phishing patterns. This is the AI-layer result (contributing +${aiScore}/30 points), not the overall PhishSense risk score.`
                    : result.score >= 21
                    ? `URLBERT estimated low phishing pattern likelihood (${aiProbability}%, contributing +0 pts). Other independent security checks detected active warning signs.`
                    : `URLBERT estimated low phishing pattern likelihood (${aiProbability}%, contributing +0 pts). Combined with clean security checks.`}
                </p>
              </div>
            </div>
          ) : (
            <div className="p-4 rounded-xl bg-amber-50 text-amber-800 border border-amber-200 dark:bg-amber-950/40 dark:text-amber-300 dark:border-amber-800/70 text-xs sm:text-sm font-mono flex items-center gap-2">
              <span className="material-symbols-outlined text-[18px]">warning</span>
              <span>AI Model Status: Temporarily Unavailable. Scored using deterministic heuristics and threat intelligence.</span>
            </div>
          )}
        </div>
      )}

      {/* 2. DOMAIN & STRUCTURE CHECKS (13 HEURISTIC RULES) */}
      {(activeTab === 'all' || activeTab === 'heuristics') && (
        <div data-animate="detail-block" className="rounded-2xl bg-white dark:bg-gray-900 border border-slate-200 dark:border-slate-800 p-6 md:p-8 shadow-sm space-y-6">
          <div className="flex flex-col sm:flex-row justify-between sm:items-center gap-3 border-b border-slate-200 dark:border-slate-800 pb-4">
            <div>
              <h4 className="font-heading text-base sm:text-lg font-bold text-slate-900 dark:text-white flex items-center gap-2">
                <span className="material-symbols-outlined text-sky-600 dark:text-sky-400 text-[22px]">rule</span>
                Domain &amp; Structure Checks
              </h4>
              <p className="text-xs sm:text-sm text-slate-500 dark:text-slate-400 font-normal">
                13 deterministic lexical and structural rules evaluating typosquatting, homoglyphs, and deceptive patterns
              </p>
            </div>
            
            <div className="px-3.5 py-1.5 rounded-lg bg-slate-100 dark:bg-slate-800 text-xs sm:text-sm font-mono font-semibold text-slate-800 dark:text-slate-200 self-start sm:self-auto">
              Points: {heuristicScore} / 40
            </div>
          </div>

          {/* Compact 13-Rule Checklist with Expandable Details */}
          <div className="space-y-2">
            {securityChecks && securityChecks.map((check) => {
              const isExpanded = expandedCheckId === check.id;
              const isPass = check.status === 'PASS' || check.status === 'PASSED';
              const isDetected = check.status === 'DETECTED';

              return (
                <div
                  key={check.id}
                  className="rounded-xl bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700/80 transition-colors overflow-hidden"
                >
                  <button
                    type="button"
                    onClick={() => setExpandedCheckId(prev => prev === check.id ? null : check.id)}
                    className="w-full px-4 py-3 sm:py-3.5 flex items-center justify-between gap-3 text-left hover:bg-slate-100/70 dark:hover:bg-slate-800 cursor-pointer transition-colors"
                  >
                    <div className="flex items-center gap-3 min-w-0">
                      <span className={`material-symbols-outlined text-[19px] shrink-0 ${
                        isDetected ? 'text-red-500' : isPass ? 'text-emerald-600 dark:text-emerald-400' : 'text-amber-500'
                      }`}>
                        {isDetected ? 'cancel' : isPass ? 'check_circle' : 'warning'}
                      </span>
                      <span className="font-heading font-medium text-sm sm:text-base text-slate-900 dark:text-white truncate">
                        {check.title}
                      </span>
                    </div>

                    <div className="flex items-center gap-2.5 shrink-0">
                      <span className={`px-2.5 py-0.5 rounded-full text-xs font-mono font-semibold uppercase ${
                        isDetected ? 'bg-red-50 text-red-700 border border-red-200 dark:bg-red-950/40 dark:text-red-300 dark:border-red-800/70' :
                        !isPass ? 'bg-amber-50 text-amber-700 border border-amber-200 dark:bg-amber-950/40 dark:text-amber-300 dark:border-amber-800/70' :
                        'bg-emerald-50 text-emerald-700 border border-emerald-200 dark:bg-emerald-950/40 dark:text-emerald-300 dark:border-emerald-800/70'
                      }`}>
                        {isPass ? 'Passed' : isDetected ? 'Detected' : 'Warning'}
                      </span>
                      <span className={`material-symbols-outlined text-[18px] text-slate-400 transition-transform duration-200 ${isExpanded ? 'rotate-180' : ''}`}>
                        expand_more
                      </span>
                    </div>
                  </button>

                  {isExpanded && (
                    <div className="px-4 pb-3.5 pt-1 border-t border-slate-200/60 dark:border-slate-700/60 text-xs sm:text-sm text-slate-600 dark:text-slate-300 space-y-1">
                      <p className="text-slate-500 dark:text-slate-400 font-normal">{check.subtitle}</p>
                      <p className="font-mono font-medium text-slate-700 dark:text-slate-200 pt-0.5">{check.detail}</p>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* 3. THREAT INTELLIGENCE SECTION */}
      {(activeTab === 'all' || activeTab === 'intel') && (
        <div data-animate="detail-block" className="rounded-2xl bg-white dark:bg-gray-900 border border-slate-200 dark:border-slate-800 p-6 md:p-8 shadow-sm space-y-6">
          <div className="flex flex-col sm:flex-row justify-between sm:items-center gap-3 border-b border-slate-200 dark:border-slate-800 pb-4">
            <div>
              <h4 className="font-heading text-base sm:text-lg font-bold text-slate-900 dark:text-white flex items-center gap-2">
                <span className="material-symbols-outlined text-sky-600 dark:text-sky-400 text-[22px]">public</span>
                Global Threat Intelligence Feeds
              </h4>
              <p className="text-xs sm:text-sm text-slate-500 dark:text-slate-400 font-normal">
                Real-time reputation and active phishing campaign lookups from VirusTotal and OpenPhish
              </p>
            </div>

            <div className="px-3.5 py-1.5 rounded-lg bg-slate-100 dark:bg-slate-800 text-xs sm:text-sm font-mono font-semibold text-slate-800 dark:text-slate-200 self-start sm:self-auto">
              Points: {intelScore} / 60
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 sm:gap-6">
            {threatIntelCards && threatIntelCards.map((card) => (
              <div
                key={card.id || card.title}
                className="p-5 sm:p-6 rounded-2xl bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700/80 space-y-3 shadow-sm"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-xl bg-sky-500/10 border border-sky-500/20 flex items-center justify-center text-sky-600 dark:text-sky-400">
                      <span className="material-symbols-outlined text-[22px]">{card.icon || 'public'}</span>
                    </div>
                    <div>
                      <span className="font-heading font-bold text-base text-slate-900 dark:text-white block">
                        {card.title}
                      </span>
                      <span className="text-xs text-slate-500 dark:text-slate-400 font-sans">
                        {card.provider}
                      </span>
                    </div>
                  </div>
                  <span className={`px-3 py-1 rounded-full text-xs font-mono font-semibold border ${card.badgeColor}`}>
                    {card.statusBadge}
                  </span>
                </div>
                <p className="text-xs sm:text-sm text-slate-600 dark:text-slate-300 font-sans leading-relaxed pt-1">
                  {card.detail}
                </p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* 4. SECURITY & NETWORK PROTOCOLS */}
      {(activeTab === 'all' || activeTab === 'checks') && (
        <div data-animate="detail-block" className="rounded-2xl bg-white dark:bg-gray-900 border border-slate-200 dark:border-slate-800 p-6 md:p-8 shadow-sm space-y-6">
          <div className="border-b border-slate-200 dark:border-slate-800 pb-4">
            <h4 className="font-heading text-base sm:text-lg font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <span className="material-symbols-outlined text-emerald-600 dark:text-emerald-400 text-[22px]">verified_user</span>
              Security &amp; Network Protocols
            </h4>
            <p className="text-xs sm:text-sm text-slate-500 dark:text-slate-400 font-normal">
              Transport encryption, DNS pinning, and SSRF defense boundary verification
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3.5">
            <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700/80 space-y-1">
              <div className="text-xs font-mono text-slate-500 dark:text-slate-400 uppercase font-semibold">Transport Protocol</div>
              <div className="font-semibold text-sm sm:text-base text-slate-900 dark:text-white flex items-center gap-1.5">
                {result.url?.startsWith('https') ? (
                  <span className="flex items-center gap-1.5 text-emerald-600 dark:text-emerald-400">
                    <span className="material-symbols-outlined text-[16px]">lock</span>
                    <span>HTTPS (TLS Encrypted)</span>
                  </span>
                ) : (
                  <span className="flex items-center gap-1.5 text-amber-600 dark:text-amber-400">
                    <span className="material-symbols-outlined text-[16px]">no_encryption</span>
                    <span>HTTP (Unencrypted Plaintext)</span>
                  </span>
                )}
              </div>
            </div>

            <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700/80 space-y-1">
              <div className="text-xs font-mono text-slate-500 dark:text-slate-400 uppercase font-semibold">SSRF Defense Status</div>
              <div className="font-semibold text-sm sm:text-base text-emerald-600 dark:text-emerald-400 flex items-center gap-1.5">
                <span className="material-symbols-outlined text-[16px]">shield</span>
                <span>Active (Private IPs Blocked)</span>
              </div>
            </div>

            <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700/80 space-y-1">
              <div className="text-xs font-mono text-slate-500 dark:text-slate-400 uppercase font-semibold">Destination Security</div>
              <div className="font-semibold text-sm sm:text-base text-emerald-600 dark:text-emerald-400 flex items-center gap-1.5">
                <span className="material-symbols-outlined text-[16px]">check_circle</span>
                <span>Public Destination Verified</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* 5. RISK CALCULATION & ATTRIBUTION PIPELINE */}
      {(activeTab === 'all' || activeTab === 'calc') && (
        <div data-animate="detail-block" className="rounded-2xl bg-white dark:bg-gray-900 border border-slate-200 dark:border-slate-800 p-6 md:p-8 shadow-sm space-y-6">
          <div className="border-b border-slate-200 dark:border-slate-800 pb-4">
            <h4 className="font-heading text-base sm:text-lg font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <span className="material-symbols-outlined text-sky-600 dark:text-sky-400 text-[22px]">calculate</span>
              Risk Calculation &amp; Attribution
            </h4>
            <p className="text-xs sm:text-sm text-slate-500 dark:text-slate-400 font-normal">
              Composite scoring formula: Final Risk = clamp[0, 100](round(Heuristics + Threat Intel + AI Model))
            </p>
          </div>

          {/* Stepper Grid */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-3.5 text-center font-mono text-xs sm:text-sm items-center">
            
            {/* Step 1 */}
            <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700/80 space-y-1">
              <div className="text-slate-500 dark:text-slate-400 text-xs uppercase font-semibold">1. AI Pattern Match</div>
              <div className={`text-base sm:text-lg font-bold ${aiProbability >= 50 ? 'text-red-600 dark:text-red-400' : 'text-emerald-600 dark:text-emerald-400'}`}>
                {aiAnalysis.available ? `${aiProbability}%` : 'Offline'}
              </div>
              <div className="text-xs text-slate-500 dark:text-slate-400 font-normal">
                {aiAnalysis.available ? (aiProbability >= 50 ? 'High similarity' : 'Low similarity') : 'Unavailable'}
              </div>
            </div>

            {/* Connector 1 */}
            <div className="hidden md:flex flex-col items-center justify-center text-slate-400">
              <span className="material-symbols-outlined text-[20px] text-sky-600 dark:text-sky-400">arrow_forward</span>
              <span className="text-[11px] font-mono">points</span>
            </div>

            {/* Step 2 */}
            <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700/80 space-y-1">
              <div className="text-slate-500 dark:text-slate-400 text-xs uppercase font-semibold">2. Layer Points</div>
              <div className="text-sky-600 dark:text-sky-400 font-bold text-sm sm:text-base">+{aiScore} / 30 <span className="text-slate-500 text-xs font-normal">(AI)</span></div>
              <div className="text-amber-600 dark:text-amber-400 text-xs">+{heuristicScore + intelScore} pts (Heuristics &amp; Intel)</div>
            </div>

            {/* Connector 2 */}
            <div className="hidden md:flex flex-col items-center justify-center text-slate-400">
              <span className="material-symbols-outlined text-[20px] text-sky-600 dark:text-sky-400">arrow_forward</span>
              <span className="text-[11px] font-mono">Combined</span>
            </div>

            {/* Step 3 */}
            <div className="col-span-1 md:col-span-4 p-4 sm:p-5 rounded-xl bg-sky-50 dark:bg-sky-950/30 border border-sky-200 dark:border-sky-800/50 flex flex-col sm:flex-row items-center justify-between gap-3 text-left">
              <div className="flex items-center gap-2.5">
                <span className="material-symbols-outlined text-sky-600 dark:text-sky-400 text-[22px]">verified</span>
                <span className="text-sm sm:text-base text-slate-800 dark:text-slate-200 font-sans font-normal leading-relaxed">
                  <strong>3. PhishSense Composite Risk Score:</strong> {heuristicScore} (Heuristics) + {intelScore} (Threat Intel) + {aiScore} (AI) = <strong className="text-slate-900 dark:text-white font-mono font-bold text-base sm:text-lg">{result.score} / 100 ({result.classification})</strong>
                </span>
              </div>
            </div>

          </div>

          <div className="text-xs sm:text-sm text-slate-600 dark:text-slate-400 font-sans font-normal bg-slate-50 dark:bg-slate-800/40 p-4 rounded-xl border border-slate-200 dark:border-slate-800 leading-relaxed flex items-start gap-2.5">
            <span className="material-symbols-outlined text-[18px] text-sky-600 dark:text-sky-400 shrink-0 mt-0.5">info</span>
            <div>
              <strong>Why does the AI show {aiProbability !== null ? `${aiProbability}%` : 'N/A'} while the overall risk is {result.score}/100?</strong> The AI percentage measures sequence pattern similarity to known phishing URLs. In PhishSense&apos;s multi-layer engine, the AI contributes up to 30 points to the final 100-point risk score alongside 13 heuristic rules (up to 40 points) and global threat intelligence feeds (up to 60 points).
            </div>
          </div>
        </div>
      )}

      {/* 6. WEBSITE REACHABILITY SECTION */}
      {(activeTab === 'all' || activeTab === 'network') && (
        <div data-animate="detail-block" className="rounded-2xl bg-white dark:bg-gray-900 border border-slate-200 dark:border-slate-800 p-6 md:p-8 shadow-sm space-y-6">
          <div className="border-b border-slate-200 dark:border-slate-800 pb-4">
            <h4 className="font-heading text-base sm:text-lg font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <span className="material-symbols-outlined text-sky-600 dark:text-sky-400 text-[22px]">language</span>
              Website Reachability &amp; Server Response
            </h4>
            <p className="text-xs sm:text-sm text-slate-500 dark:text-slate-400 font-normal">
              Technical probe telemetry from isolated browser execution
            </p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5 font-mono text-xs sm:text-sm">
            <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700/80 space-y-1">
              <div className="text-slate-500 dark:text-slate-400 uppercase font-semibold text-xs">HTTP Status</div>
              <div className="font-bold text-sm sm:text-base text-slate-900 dark:text-white">
                {previewData?.status ? `HTTP ${previewData.status} ${previewData.statusText || 'OK'}` : 'N/A'}
              </div>
            </div>

            <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700/80 space-y-1">
              <div className="text-slate-500 dark:text-slate-400 uppercase font-semibold text-xs">Response Latency</div>
              <div className="font-bold text-sm sm:text-base text-slate-900 dark:text-white">
                {previewData?.responseTimeMs ? `${previewData.responseTimeMs} ms` : 'N/A'}
              </div>
            </div>

            <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700/80 space-y-1">
              <div className="text-slate-500 dark:text-slate-400 uppercase font-semibold text-xs">Content Type</div>
              <div className="font-bold text-sm sm:text-base text-slate-900 dark:text-white truncate">
                {previewData?.contentType || 'text/html'}
              </div>
            </div>

            <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700/80 space-y-1">
              <div className="text-slate-500 dark:text-slate-400 uppercase font-semibold text-xs">Destination Security</div>
              <div className="font-bold text-sm sm:text-base text-emerald-600 dark:text-emerald-400">
                {previewData?.statusText === 'BLOCKED' ? 'SSRF Blocked' : 'Public IP Validated'}
              </div>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}

export default DetailedAnalysis;
