import React, { useState, useEffect } from 'react';

/**
 * Animated Circular Risk Gauge Component (Theme-Aware)
 */
export function RiskGauge({ score, classification }) {
  const [animatedScore, setAnimatedScore] = useState(0);

  useEffect(() => {
    let start = 0;
    const end = Math.min(100, Math.max(0, score || 0));
    if (start === end) {
      setAnimatedScore(end);
      return;
    }

    const startTime = performance.now();
    const duration = 1000;

    const updateScore = (now) => {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const easeProgress = progress * (2 - progress);
      const currentScore = Math.floor(easeProgress * end);

      setAnimatedScore(currentScore);

      if (progress < 1) {
        requestAnimationFrame(updateScore);
      } else {
        setAnimatedScore(end);
      }
    };

    requestAnimationFrame(updateScore);
  }, [score]);

  const circleColorClass =
    classification === 'MALICIOUS' ? 'text-red-500 dark:text-red-400' :
    classification === 'HIGH RISK' ? 'text-orange-500 dark:text-orange-400' :
    classification === 'SUSPICIOUS' ? 'text-amber-500 dark:text-amber-400' :
    'text-emerald-500 dark:text-emerald-400';

  const textColorClass =
    classification === 'MALICIOUS' ? 'text-red-600 dark:text-red-400' :
    classification === 'HIGH RISK' ? 'text-orange-600 dark:text-orange-400' :
    classification === 'SUSPICIOUS' ? 'text-amber-600 dark:text-amber-400' :
    'text-emerald-600 dark:text-emerald-400';

  return (
    <div className="relative w-44 h-44 shrink-0 mx-auto md:mx-0">
      <svg className="w-full h-full transform -rotate-90" viewBox="0 0 192 192">
        <circle
          className="text-slate-200 dark:text-slate-800"
          cx="96"
          cy="96"
          fill="transparent"
          r="84"
          stroke="currentColor"
          strokeWidth="10"
        ></circle>
        <circle
          className={'transition-all duration-500 ' + circleColorClass}
          cx="96"
          cy="96"
          fill="transparent"
          r="84"
          stroke="currentColor"
          strokeWidth="10"
          strokeDasharray="527"
          strokeDashoffset={527 - (527 * animatedScore) / 100}
          strokeLinecap="round"
        ></circle>
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className={'font-mono text-4xl leading-none transition-colors duration-500 font-bold ' + textColorClass}>
          {animatedScore}
        </span>
        <span className="text-[11px] uppercase font-mono font-bold tracking-wider text-slate-500 dark:text-slate-400 mt-1">
          / 100 Risk Score
        </span>
      </div>
    </div>
  );
}

export default RiskGauge;
