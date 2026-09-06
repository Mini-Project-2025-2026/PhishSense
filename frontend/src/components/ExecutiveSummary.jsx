import React, { useState, useEffect, useRef } from 'react';
import gsap from 'gsap';
import { isSafeImageDataUrl, isReducedMotion } from '../utils/helpers';
import Button from './Button';

/**
 * Human-Centered Executive Summary Component (PhishSense Typography & Readability Pass)
 * 
 * Hierarchy:
 * 1. Verdict Banner (Large, clear, 28-36px desktop / 24-30px mobile)
 * 2. Scanned URL (16-18px) & Risk Score (40-52px)
 * 3. Why we flagged it (Heading 20-24px, Detail 16-17px)
 * 4. What should you do? (Heading 20-24px, Recommendations 16-17px)
 * 5. Website Preview (Heading 18-22px, Status 15-17px)
 * 6. "View Security Details →" CTA button (16-18px)
 */
export function ExecutiveSummary({
  result,
  previewData,
  previewLoading,
  isDetailsExpanded,
  onToggleDetails,
  onOpenPreviewModal
}) {
  const [copied, setCopied] = useState(false);
  const cardRef = useRef(null);
  const score = Math.min(100, Math.max(0, result?.score || 0));
  const [animatedScore, setAnimatedScore] = useState(isReducedMotion() ? score : 0);
  const scoreTracker = useRef({ val: 0 });

  useEffect(() => {
    if (!result) return;
    if (isReducedMotion()) {
      setAnimatedScore(score);
      return;
    }

    scoreTracker.current.val = 0;
    const tween = gsap.to(scoreTracker.current, {
      val: score,
      duration: 1.1,
      ease: 'power2.out',
      delay: 0.1,
      onUpdate: () => {
        setAnimatedScore(Math.round(scoreTracker.current.val));
      }
    });

    return () => tween.kill();
  }, [result?.url, score]);

  useEffect(() => {
    if (!result || isReducedMotion() || !cardRef.current) return;

    const ctx = gsap.context(() => {
      gsap.from(cardRef.current, {
        opacity: 0,
        y: 20,
        scale: 0.99,
        duration: 0.5,
        ease: 'power2.out'
      });
      gsap.from('[data-animate="result-section"]', {
        opacity: 0,
        y: 12,
        duration: 0.4,
        stagger: 0.08,
        ease: 'power2.out',
        delay: 0.1
      });
    }, cardRef);

    return () => ctx.revert();
  }, [result?.url]);

  if (!result) return null;

  const classification = result.classification || (score >= 81 ? 'MALICIOUS' : score >= 51 ? 'HIGH RISK' : score >= 21 ? 'SUSPICIOUS' : 'LOW RISK');

  const handleCopy = () => {
    navigator.clipboard.writeText(result.url);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Verdict Configuration
  const getVerdictDetails = () => {
    if (score >= 81 || classification === 'MALICIOUS') {
      return {
        title: 'MALICIOUS',
        subtitle: 'This link has strong signs of phishing or malicious activity.',
        levelText: 'Malicious',
        icon: 'dangerous',
        badgeBg: 'bg-red-50 text-red-700 border-red-200 dark:bg-red-950/50 dark:text-red-300 dark:border-red-800/80',
        cardBorder: 'border-red-300 dark:border-red-900/60',
        scoreColor: 'text-red-600 dark:text-red-400'
      };
    }
    if (score >= 51 || classification === 'HIGH RISK') {
      return {
        title: 'HIGH RISK',
        subtitle: 'We found several warning signs associated with phishing or fraud.',
        levelText: 'High Risk',
        icon: 'warning',
        badgeBg: 'bg-red-50 text-red-700 border-red-200 dark:bg-red-950/50 dark:text-red-300 dark:border-red-800/80',
        cardBorder: 'border-red-300 dark:border-red-900/60',
        scoreColor: 'text-red-600 dark:text-red-400'
      };
    }
    if (score >= 21 || classification === 'SUSPICIOUS' || classification === 'MEDIUM RISK') {
      return {
        title: 'MEDIUM RISK',
        subtitle: 'We found some warning signs. Check the details before continuing.',
        levelText: 'Medium Risk',
        icon: 'warning',
        badgeBg: 'bg-amber-50 text-amber-800 border-amber-200 dark:bg-amber-950/50 dark:text-amber-300 dark:border-amber-800/80',
        cardBorder: 'border-amber-300 dark:border-amber-900/60',
        scoreColor: 'text-amber-600 dark:text-amber-400'
      };
    }
    return {
      title: 'LOW RISK',
      subtitle: "This link does not show significant warning signs based on our security checks.",
      levelText: 'Low Risk',
      icon: 'check_circle',
      badgeBg: 'bg-emerald-50 text-emerald-800 border-emerald-200 dark:bg-emerald-950/50 dark:text-emerald-300 dark:border-emerald-800/80',
      cardBorder: 'border-emerald-300 dark:border-emerald-900/60',
      scoreColor: 'text-emerald-600 dark:text-emerald-400'
    };
  };

  const verdict = getVerdictDetails();

  // Plain-English Explanation
  const getPlainEnglishExplanation = () => {
    const reasons = result.reasons || [];
    const reasonText = reasons.join(' ').toLowerCase();

    // Brand impersonation
    if (reasonText.includes('impersonation') || reasonText.includes('typosquat') || reasonText.includes('differs from legitimate')) {
      let brand = 'a well-known brand';
      if (/paypal/i.test(reasonText)) brand = 'PayPal';
      else if (/microsoft/i.test(reasonText)) brand = 'Microsoft';
      else if (/google/i.test(reasonText)) brand = 'Google';
      else if (/amazon/i.test(reasonText)) brand = 'Amazon';
      else if (/apple/i.test(reasonText)) brand = 'Apple';
      else if (/netflix/i.test(reasonText)) brand = 'Netflix';
      else if (/chase/i.test(reasonText)) brand = 'Chase';

      return {
        heading: `This website appears to be pretending to be ${brand}.`,
        detail: `Its address is very similar to the real ${brand} website, which is a common tactic used to steal passwords or payment details.`
      };
    }

    // Single isolated vendor outlier flag (low overall risk, e.g. 1 out of 92 with 60+ harmless)
    if (reasonText.includes('one security vendor') || (reasonText.includes('security vendor') && score < 21)) {
      return {
        heading: 'An isolated vendor flag was observed against clean consensus.',
        detail: 'One security vendor flagged this address, while most other security vendors found no issue.'
      };
    }

    // Threat intelligence (multi-vendor or confirmed feed match)
    if (reasonText.includes('virustotal') || reasonText.includes('urlhaus') || reasonText.includes('openphish') || reasonText.includes('security vendors')) {
      return {
        heading: 'Security databases have reported warnings about this link.',
        detail: 'Global threat intelligence services flagged this link as suspicious or malicious.'
      };
    }

    // AI detection
    if (reasonText.includes('ai detected') || reasonText.includes('phishing patterns')) {
      return {
        heading: 'Our AI found patterns commonly seen in phishing links.',
        detail: 'The web address structure matches patterns used in fraudulent links.'
      };
    }

    // Structural / suspicious URL patterns
    if (score >= 21) {
      return {
        heading: 'The web address contains unusual patterns.',
        detail: 'Suspicious domain extensions or deceptive address structures were detected.'
      };
    }

    // Clean link
    return {
      heading: 'No major warning signs were found for this web address.',
      detail: 'The domain structure appears authentic and no security alerts were found in global databases.'
    };
  };

  const explanation = getPlainEnglishExplanation();

  // Plain English reachability and preview status
  const getPreviewStatus = () => {
    if (previewLoading) {
      return { 
        text: 'Generating preview...', 
        badgeClass: 'bg-sky-50 text-sky-700 border-sky-200 dark:bg-sky-950/50 dark:text-sky-300 dark:border-sky-800/80 animate-pulse' 
      };
    }

    // CASE 5: SSRF / security validation blocks destination
    if (previewData?.statusText === 'BLOCKED' || previewData?.reason === 'UNSAFE_DESTINATION' || previewData?.reason === 'UNSAFE_REDIRECT' || previewData?.reason === 'UNSAFE_PROTOCOL' || previewData?.reason === 'INVALID_PORT') {
      return { 
        text: 'Preview blocked', 
        badgeClass: 'bg-amber-50 text-amber-800 border-amber-200 dark:bg-amber-950/50 dark:text-amber-300 dark:border-amber-800/80' 
      };
    }

    // CASE 1: Reachable + screenshot successfully captured
    if (previewData?.previewAvailable && isSafeImageDataUrl(previewData?.screenshot)) {
      return { 
        text: 'Live preview available', 
        badgeClass: 'bg-emerald-50 text-emerald-800 border-emerald-200 dark:bg-emerald-950/50 dark:text-emerald-300 dark:border-emerald-800/80' 
      };
    }

    // CASE 2 & CASE 3: Reachable (either bot-protected or screenshot timeout/render failure)
    if (previewData?.available) {
      return { 
        text: 'Website is reachable', 
        badgeClass: 'bg-slate-100 text-slate-700 border-slate-200 dark:bg-slate-800 dark:text-slate-300 dark:border-slate-700' 
      };
    }

    // CASE 4: Cannot be reached (offline, DNS failure, timeout)
    return { 
      text: 'Website unreachable', 
      badgeClass: 'bg-slate-100 text-slate-700 border-slate-200 dark:bg-slate-800 dark:text-slate-300 dark:border-slate-700' 
    };
  };

  const previewStatus = getPreviewStatus();

  return (
    <div className="space-y-6 max-w-5xl mx-auto w-full font-sans">
      
      {/* PRIMARY RESULT CARD */}
      <div ref={cardRef} className={`relative rounded-2xl bg-white dark:bg-gray-900 border-2 ${verdict.cardBorder} p-6 sm:p-9 shadow-sm dark:shadow-xl overflow-hidden space-y-7 transition-colors`}>
        
        {/* 1. Verdict Banner */}
        <div data-animate="result-section" className="text-center space-y-3">
          <div className={`inline-flex items-center gap-2.5 px-6 py-2.5 rounded-full font-heading font-bold text-base sm:text-lg md:text-xl tracking-wide uppercase border ${verdict.badgeBg}`}>
            <span className="material-symbols-outlined text-[24px] sm:text-[26px]">{verdict.icon}</span>
            <span>{verdict.title}</span>
          </div>

          <p className="text-slate-700 dark:text-slate-300 text-base sm:text-lg font-normal max-w-xl mx-auto leading-relaxed">
            {verdict.subtitle}
          </p>
        </div>

        {/* 2. Scanned URL & Risk Score Strip */}
        <div data-animate="result-section" className="flex flex-col sm:flex-row items-center justify-between gap-5 p-5 sm:p-6 rounded-xl bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700/80">
          
          {/* Target URL */}
          <div className="w-full sm:w-auto flex-1 min-w-0">
            <div className="text-xs font-mono uppercase font-semibold tracking-wider text-slate-500 dark:text-slate-400 mb-1.5">
              Scanned Web Address
            </div>
            <div className="flex items-center gap-2.5">
              <span className="font-mono text-sm sm:text-base md:text-lg font-medium text-slate-900 dark:text-slate-100 break-all select-all leading-normal">
                {result.url}
              </span>
              <button
                onClick={handleCopy}
                title="Copy URL"
                className="p-2 rounded-lg hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-500 hover:text-slate-900 dark:hover:text-white transition-colors shrink-0 flex items-center gap-1 cursor-pointer"
              >
                <span className="material-symbols-outlined text-[18px]">
                  {copied ? 'check' : 'content_copy'}
                </span>
                <span className="text-xs font-mono font-semibold uppercase">{copied ? 'Copied' : 'Copy'}</span>
              </button>
            </div>
          </div>

          {/* Risk Score */}
          <div className="shrink-0 flex items-center gap-4 border-t sm:border-t-0 sm:border-l border-slate-200 dark:border-slate-700/80 pt-4 sm:pt-0 sm:pl-6 w-full sm:w-auto justify-between sm:justify-start">
            <div className="text-right sm:text-left">
              <div className="text-xs font-mono uppercase font-semibold tracking-wider text-slate-500 dark:text-slate-400 mb-0.5">
                Risk Level
              </div>
              <div className="text-sm sm:text-base font-semibold text-slate-800 dark:text-slate-200">
                {verdict.levelText}
              </div>
            </div>
            <div className={`font-mono text-4xl sm:text-5xl font-bold ${verdict.scoreColor}`}>
              {animatedScore}
              <span className="text-sm font-normal text-slate-400 dark:text-slate-500 ml-1">/ 100</span>
            </div>
          </div>

        </div>

        {/* 3. Why we flagged it */}
        <div data-animate="result-section" className="p-5 sm:p-6 rounded-xl bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700/80 space-y-2">
          <div className="flex items-start gap-3.5">
            <span className={`material-symbols-outlined text-[26px] shrink-0 mt-0.5 ${
              score >= 51 ? 'text-red-600 dark:text-red-400' : score >= 21 ? 'text-amber-600 dark:text-amber-400' : 'text-emerald-600 dark:text-emerald-400'
            }`}>
              {score >= 21 ? 'warning' : 'check_circle'}
            </span>
            <div className="space-y-1.5">
              <h4 className="font-heading font-semibold text-slate-900 dark:text-white text-base sm:text-lg md:text-xl leading-snug">
                {explanation.heading}
              </h4>
              <p className="text-sm sm:text-base text-slate-600 dark:text-slate-400 leading-relaxed font-normal">
                {explanation.detail}
              </p>
            </div>
          </div>
        </div>

        {/* 4. Actionable Recommendations */}
        <div data-animate="result-section" className="p-5 sm:p-6 rounded-xl bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700/80 space-y-3.5">
          <h4 className="font-heading font-semibold text-slate-900 dark:text-white text-sm sm:text-base uppercase tracking-wider">
            What should you do?
          </h4>

          {score >= 21 ? (
            <ul className="space-y-2.5 text-sm sm:text-base text-slate-700 dark:text-slate-300 font-normal leading-relaxed">
              <li className="flex items-start gap-3">
                <span className="material-symbols-outlined text-red-500 text-[18px] shrink-0 mt-0.5">cancel</span>
                <span><strong>Don&apos;t enter passwords or payment details</strong> on this website.</span>
              </li>
              <li className="flex items-start gap-3">
                <span className="material-symbols-outlined text-red-500 text-[18px] shrink-0 mt-0.5">cancel</span>
                <span><strong>Don&apos;t download files</strong> from this link.</span>
              </li>
              <li className="flex items-start gap-3">
                <span className="material-symbols-outlined text-emerald-600 dark:text-emerald-400 text-[18px] shrink-0 mt-0.5">check_circle</span>
                <span><strong>Visit the official website directly</strong> by searching for it or typing the known address.</span>
              </li>
            </ul>
          ) : (
            <ul className="space-y-2.5 text-sm sm:text-base text-slate-700 dark:text-slate-300 font-normal leading-relaxed">
              <li className="flex items-start gap-3">
                <span className="material-symbols-outlined text-emerald-600 dark:text-emerald-400 text-[18px] shrink-0 mt-0.5">check_circle</span>
                <span><strong>You can safely proceed</strong> to this web address.</span>
              </li>
              <li className="flex items-start gap-3">
                <span className="material-symbols-outlined text-emerald-600 dark:text-emerald-400 text-[18px] shrink-0 mt-0.5">check_circle</span>
                <span><strong>Always verify the domain in your browser bar</strong> before entering account passwords or sensitive information.</span>
              </li>
            </ul>
          )}
        </div>

        {/* 5. Website Preview Frame */}
        <div data-animate="result-section" className="rounded-xl bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700/80 p-5 sm:p-6 space-y-3.5">
          <div className="flex flex-col sm:flex-row justify-between sm:items-center gap-2">
            <div className="flex items-center gap-2">
              <span className="material-symbols-outlined text-sky-600 dark:text-sky-400 text-[20px]">visibility</span>
              <span className="font-heading font-semibold text-slate-900 dark:text-white text-sm sm:text-base">
                Website Preview
              </span>
            </div>

            {/* Reachability Badge */}
            <span className={`px-3 py-1 rounded-full text-xs sm:text-sm font-medium border inline-flex items-center gap-2 self-start sm:self-auto ${previewStatus.badgeClass}`}>
              <span className="h-2 w-2 rounded-full bg-current"></span>
              {previewStatus.text}
            </span>
          </div>

          {/* 3 PREVIEW STATES: 1. Loading Skeleton -> 2. Screenshot -> 3. Error/Unavailable */}
          {previewLoading ? (
            /* STATE 1: PREVIEW REQUEST PENDING / LOADING SKELETON */
            <div className="space-y-3 animate-fade-in" aria-busy="true" aria-label="Generating website preview">
              <div className="relative w-full aspect-[16/9] max-h-[380px] rounded-xl overflow-hidden border border-slate-200 dark:border-slate-700 bg-slate-100/90 dark:bg-slate-800/70 flex flex-col items-center justify-center p-6 text-center shadow-inner">
                {/* Subtle Animated Shimmer / Pulse */}
                <div className="absolute inset-0 bg-gradient-to-r from-transparent via-slate-200/60 dark:via-slate-700/50 to-transparent animate-pulse pointer-events-none" />
                
                {/* Center Loading Spinner & Status Text */}
                <div className="relative z-10 flex flex-col items-center gap-3">
                  <div className="w-12 h-12 rounded-2xl bg-sky-500/10 dark:bg-sky-500/20 border border-sky-500/30 flex items-center justify-center text-sky-600 dark:text-sky-400 shadow-sm">
                    <span className="material-symbols-outlined text-[24px] animate-spin">progress_activity</span>
                  </div>
                  <div className="space-y-1">
                    <div className="font-heading font-semibold text-slate-900 dark:text-white text-sm sm:text-base">
                      Generating secure website preview...
                    </div>
                    <div className="text-xs text-slate-500 dark:text-slate-400 font-normal max-w-sm">
                      Rendering page safely in an isolated sandbox. This may take a few seconds.
                    </div>
                  </div>
                </div>
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400 text-center font-normal flex items-center justify-center gap-1.5">
                <span className="material-symbols-outlined text-[14px] text-sky-500">lock</span>
                <span>Isolated sandbox rendering in progress...</span>
              </p>
            </div>
          ) : previewData?.previewAvailable && isSafeImageDataUrl(previewData?.screenshot) ? (
            /* STATE 2: SUCCESSFUL PREVIEW SCREENSHOT */
            <div className="space-y-2 animate-fade-in">
              <div
                onClick={onOpenPreviewModal}
                className="relative w-full aspect-[16/9] max-h-[380px] rounded-xl overflow-hidden border border-slate-200 dark:border-slate-700 bg-slate-950 shadow-inner cursor-pointer group flex items-center justify-center"
              >
                <img
                  src={previewData.screenshot}
                  alt="Website preview capture"
                  className="w-full h-full object-contain object-top transition-transform duration-200 group-hover:scale-[1.01]"
                />
                <div className="absolute inset-0 bg-slate-950/40 opacity-0 group-hover:opacity-100 transition-opacity flex items-center justify-center">
                  <span className="px-3.5 py-2 rounded-lg bg-slate-900/90 text-white font-sans text-xs sm:text-sm border border-white/20 flex items-center gap-2 shadow-lg">
                    <span className="material-symbols-outlined text-[18px]">zoom_in</span>
                    Click to Zoom
                  </span>
                </div>
              </div>
              <p className="text-xs sm:text-sm text-slate-500 dark:text-slate-400 text-center font-normal pt-1.5 flex flex-wrap items-center justify-center gap-1.5 leading-relaxed max-w-xl mx-auto">
                <span className="material-symbols-outlined text-[15px] text-emerald-600 dark:text-emerald-400 shrink-0">shield</span>
                <span>Preview captured safely in an isolated environment without affecting the website itself.</span>
              </p>
            </div>
          ) : (
            /* STATE 3: ACTUAL FAILURE / UNAVAILABLE AFTER REQUEST COMPLETES */
            <div className="p-5 rounded-xl bg-slate-100/80 dark:bg-slate-800/80 text-xs sm:text-sm text-slate-600 dark:text-slate-400 font-normal leading-relaxed border border-slate-200 dark:border-slate-700 space-y-1.5 animate-fade-in">
              {previewData?.statusText === 'BLOCKED' || previewData?.reason === 'UNSAFE_DESTINATION' || previewData?.reason === 'UNSAFE_REDIRECT' ? (
                <>
                  <div className="flex items-center gap-2 font-semibold text-slate-800 dark:text-slate-200 text-sm">
                    <span className="material-symbols-outlined text-[18px] text-amber-600 dark:text-amber-400">lock</span>
                    <span>Internal destination blocked</span>
                  </div>
                  <p>This address targets an internal or private network destination and was blocked to protect your system.</p>
                </>
              ) : previewData?.isBotProtected || previewData?.reason === 'BOT_PROTECTED' ? (
                <>
                  <div className="flex items-center gap-2 font-semibold text-slate-800 dark:text-slate-200 text-sm">
                    <span className="material-symbols-outlined text-[18px] text-sky-600 dark:text-sky-400">shield_lock</span>
                    <span>Website preview blocked</span>
                  </div>
                  <p>This website uses automated-visit protection, so PhishSense could not capture the actual page.</p>
                  <p className="font-medium text-slate-700 dark:text-slate-300 pt-0.5">This does not affect your safety result.</p>
                </>
              ) : (
                <>
                  <div className="flex items-center gap-2 font-semibold text-slate-800 dark:text-slate-200 text-sm">
                    <span className="material-symbols-outlined text-[18px] text-slate-500 dark:text-slate-400">hide_image</span>
                    <span>Website preview unavailable</span>
                  </div>
                  <p>{previewData?.available ? 'This website may block automated previews or take too long to load.' : 'The target server could not be reached or timed out.'}</p>
                  <p className="font-medium text-slate-700 dark:text-slate-300 pt-0.5">This does not affect your safety result.</p>
                </>
              )}
            </div>
          )}
        </div>

        {/* 6. Primary Action: 'View Security Details' CTA Button */}
        <div data-animate="result-section" className="pt-3 border-t border-slate-200 dark:border-slate-700/80 flex flex-col items-center gap-1.5">
          <Button
            onClick={onToggleDetails}
            size="md"
            variant="primary"
            className="w-full sm:w-auto min-w-[260px] h-12 sm:h-13 px-8 text-sm sm:text-base font-semibold"
            icon={isDetailsExpanded ? 'expand_less' : 'arrow_forward'}
            iconPosition="right"
          >
            {isDetailsExpanded ? 'Hide Security Details' : 'View Security Details'}
          </Button>
          <p className="text-xs text-slate-500 dark:text-slate-400 font-normal">
            See the technical checks behind this result.
          </p>
        </div>

      </div>

    </div>
  );
}

export default ExecutiveSummary;
