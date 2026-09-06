import React, { useState, useEffect, useRef } from 'react';
import gsap from 'gsap';
import { isReducedMotion } from '../utils/helpers';
import { loadScanHistory, syncScanHistoryWithBackend, removeScanRecord, clearAllScanHistory } from '../utils/historyStorage';
import Button from './Button';

function getDomainFromUrl(rawUrl) {
  try {
    let clean = rawUrl || '';
    if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(clean)) {
      clean = 'https://' + clean;
    }
    const parsed = new URL(clean);
    return parsed.hostname.replace(/^www\./, '');
  } catch (_) {
    return rawUrl || 'unknown';
  }
}

/**
 * Scan History Component (Simplicity & Clarity Pass)
 * 
 * Clean, domain-first list with simple date, risk status, and 1-click inspection.
 */
export function ScanHistory({
  isSignedIn,
  userEmail,
  onInspectScan,
  onOpenAuthModal
}) {
  const [historyList, setHistoryList] = useState(() => loadScanHistory(userEmail));
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [isSyncing, setIsSyncing] = useState(false);
  const listRef = useRef(null);

  // Sync with backend on mount or when user changes
  useEffect(() => {
    setIsSyncing(true);
    syncScanHistoryWithBackend(userEmail)
      .then((records) => {
        if (records && Array.isArray(records)) {
          setHistoryList(records);
        }
      })
      .finally(() => setIsSyncing(false));
  }, [userEmail, isSignedIn]);

  const handleDelete = (id, e) => {
    e.stopPropagation();
    const updated = removeScanRecord(id, userEmail);
    setHistoryList(updated);
  };

  const handleClearAll = () => {
    if (window.confirm('Are you sure you want to clear your entire scan history?')) {
      const updated = clearAllScanHistory(userEmail);
      setHistoryList(updated);
    }
  };

  // Filtered scans
  const filteredList = historyList.filter((item) => {
    const domain = getDomainFromUrl(item.url);
    const query = searchQuery.toLowerCase().trim();
    const matchesSearch = item.url.toLowerCase().includes(query) || domain.toLowerCase().includes(query);
    const matchesStatus = statusFilter === 'ALL' || item.classification === statusFilter;
    return matchesSearch && matchesStatus;
  });

  // GSAP subtle entrance for history rows
  useEffect(() => {
    if (isReducedMotion() || !listRef.current || filteredList.length === 0) return;

    const ctx = gsap.context(() => {
      gsap.from('[data-animate="history-row"]', {
        opacity: 0,
        y: 10,
        duration: 0.3,
        stagger: 0.04,
        ease: 'power2.out'
      });
    }, listRef);

    return () => ctx.revert();
  }, [statusFilter, searchQuery, filteredList.length]);

  // KPI counters
  const totalScans = historyList.length;
  const maliciousCount = historyList.filter(i => i.classification === 'MALICIOUS' || i.classification === 'HIGH RISK').length;
  const suspiciousCount = historyList.filter(i => i.classification === 'SUSPICIOUS').length;
  const safeCount = historyList.filter(i => i.classification === 'LOW RISK').length;

  return (
    <div className="max-w-5xl mx-auto w-full space-y-6 animate-fade-in font-sans">
      
      {/* HEADER & CONTEXT BAR */}
      <div className="flex flex-col sm:flex-row justify-between sm:items-center gap-3 pb-4 border-b border-slate-200 dark:border-slate-800">
        <div>
          <h2 className="font-heading text-2xl sm:text-3xl font-bold text-slate-900 dark:text-white flex items-center gap-2.5">
            <img src="/phishsense_icon.png" alt="PhishSense Logo" className="w-7 h-7 object-contain" />
            <span>Scan History</span>
          </h2>
          <p className="text-sm sm:text-base text-slate-600 dark:text-slate-400 font-normal mt-0.5">
            {isSignedIn ? (
              <span>Your saved scan history for <strong className="text-slate-800 dark:text-slate-200">{userEmail}</strong></span>
            ) : (
              <span>Saved in your browser. <button onClick={() => onOpenAuthModal('signup', 'Sign up for free to save your history permanently across all devices.')} className="text-sky-600 dark:text-sky-400 hover:underline font-semibold cursor-pointer">Sign up</button> to save across devices.</span>
            )}
          </p>
        </div>

        {totalScans > 0 && (
          <Button
            onClick={handleClearAll}
            size="sm"
            variant="danger"
            icon="delete_sweep"
            className="text-xs sm:text-sm self-start sm:self-auto"
          >
            Clear History
          </Button>
        )}
      </div>

      {/* KPI METRICS STRIP */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3.5">
        <div className="p-4 sm:p-5 rounded-2xl bg-white dark:bg-gray-900 border border-slate-200 dark:border-slate-800 space-y-1 shadow-sm">
          <div className="text-xs font-sans text-slate-500 dark:text-slate-400 uppercase font-semibold">Total Scans</div>
          <div className="font-mono text-2xl sm:text-3xl font-bold text-slate-900 dark:text-white flex items-center justify-between">
            <span>{totalScans}</span>
            {isSyncing && <span className="material-symbols-outlined text-[18px] text-sky-600 dark:text-sky-400 animate-spin">sync</span>}
          </div>
        </div>
        <div className="p-4 sm:p-5 rounded-2xl bg-white dark:bg-gray-900 border border-slate-200 dark:border-slate-800 space-y-1 shadow-sm">
          <div className="text-xs font-sans text-slate-500 dark:text-slate-400 uppercase font-semibold">Dangerous</div>
          <div className="font-mono text-2xl sm:text-3xl font-bold text-red-600 dark:text-red-400">{maliciousCount}</div>
        </div>
        <div className="p-4 sm:p-5 rounded-2xl bg-white dark:bg-gray-900 border border-slate-200 dark:border-slate-800 space-y-1 shadow-sm">
          <div className="text-xs font-sans text-slate-500 dark:text-slate-400 uppercase font-semibold">Suspicious</div>
          <div className="font-mono text-2xl sm:text-3xl font-bold text-amber-600 dark:text-amber-400">{suspiciousCount}</div>
        </div>
        <div className="p-4 sm:p-5 rounded-2xl bg-white dark:bg-gray-900 border border-slate-200 dark:border-slate-800 space-y-1 shadow-sm">
          <div className="text-xs font-sans text-slate-500 dark:text-slate-400 uppercase font-semibold">Safe</div>
          <div className="font-mono text-2xl sm:text-3xl font-bold text-emerald-600 dark:text-emerald-400">{safeCount}</div>
        </div>
      </div>

      {/* SEARCH & CLASSIFICATION FILTER BAR */}
      <div className="flex flex-col md:flex-row gap-3.5 items-center justify-between">
        {/* Search Input */}
        <div className="relative w-full md:w-88">
          <span className="absolute left-4 top-1/2 -translate-y-1/2 material-symbols-outlined text-slate-400 text-[20px]">search</span>
          <input
            type="text"
            placeholder="Search history by URL or website..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full h-12 pl-11 pr-4 rounded-xl bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-800 text-slate-900 dark:text-white text-sm sm:text-base font-sans placeholder:text-slate-400 dark:placeholder:text-slate-500 focus:outline-none focus:border-sky-500 shadow-sm"
          />
        </div>

        {/* Filter Pills */}
        <div className="flex flex-wrap gap-1.5 w-full md:w-auto text-xs sm:text-sm font-sans">
          {[
            { key: 'ALL', label: 'All Scans' },
            { key: 'MALICIOUS', label: 'Dangerous' },
            { key: 'HIGH RISK', label: 'High Risk' },
            { key: 'SUSPICIOUS', label: 'Suspicious' },
            { key: 'LOW RISK', label: 'Safe' }
          ].map(({ key, label }) => (
            <button
              key={key}
              onClick={() => setStatusFilter(key)}
              className={`px-3.5 py-2 rounded-xl border transition-colors cursor-pointer ${
                statusFilter === key
                  ? 'bg-sky-600 dark:bg-sky-500 text-white dark:text-slate-950 font-semibold border-sky-600 dark:border-sky-500 shadow-sm'
                  : 'bg-white dark:bg-slate-900 text-slate-600 dark:text-slate-400 border-slate-200 dark:border-slate-800 hover:text-slate-900 dark:hover:text-white hover:bg-slate-50 dark:hover:bg-slate-800'
              }`}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      {/* SCAN HISTORY LIST */}
      {filteredList.length > 0 ? (
        <div ref={listRef} className="space-y-3.5">
          {filteredList.map((item) => {
            const domain = getDomainFromUrl(item.url);
            const formattedDate = new Date(item.timestamp).toLocaleDateString(undefined, {
              month: 'short',
              day: 'numeric',
              year: 'numeric'
            });
            const formattedTime = new Date(item.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

            const isMalicious = item.classification === 'MALICIOUS' || item.classification === 'HIGH RISK';
            const isSuspicious = item.classification === 'SUSPICIOUS';

            const statusIcon = isMalicious ? 'dangerous' : isSuspicious ? 'warning' : 'verified_user';
            const statusIconColor = isMalicious ? 'text-red-500' : isSuspicious ? 'text-amber-500' : 'text-emerald-500';
            
            const badgeClass =
              item.classification === 'MALICIOUS' ? 'bg-red-50 text-red-700 border-red-200 dark:bg-red-950/40 dark:text-red-300 dark:border-red-800/70' :
              item.classification === 'HIGH RISK' ? 'bg-red-50 text-red-700 border-red-200 dark:bg-red-950/40 dark:text-red-300 dark:border-red-800/70' :
              item.classification === 'SUSPICIOUS' ? 'bg-amber-50 text-amber-700 border-amber-200 dark:bg-amber-950/40 dark:text-amber-300 dark:border-amber-800/70' :
              'bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-950/40 dark:text-emerald-300 dark:border-emerald-800/70';

            const statusLabel =
              item.classification === 'MALICIOUS' ? 'Dangerous' :
              item.classification === 'HIGH RISK' ? 'High Risk' :
              item.classification === 'SUSPICIOUS' ? 'Suspicious' : 'Safe';

            return (
              <div
                key={item.id}
                data-animate="history-row"
                onClick={() => onInspectScan(item)}
                className="p-5 sm:p-6 rounded-2xl bg-white dark:bg-gray-900 border border-slate-200 dark:border-slate-800 hover:border-sky-300 dark:hover:border-sky-500/50 hover:bg-slate-50/70 dark:hover:bg-slate-800/70 transition-all cursor-pointer flex flex-col md:flex-row md:items-center justify-between gap-4 group shadow-sm"
              >
                {/* Left: Domain, URL & Date */}
                <div className="space-y-1.5 flex-1 min-w-0">
                  <div className="flex items-center gap-2.5">
                    <span className={`material-symbols-outlined text-[20px] ${statusIconColor} shrink-0`}>{statusIcon}</span>
                    <span className="font-heading text-base sm:text-lg font-semibold text-slate-900 dark:text-white group-hover:text-sky-600 dark:group-hover:text-sky-400 transition-colors truncate">
                      {domain}
                    </span>
                    <span className={`px-2.5 py-0.5 rounded-full text-xs font-sans font-semibold border ${badgeClass}`}>
                      {statusLabel}
                    </span>
                  </div>

                  <div className="font-mono text-xs sm:text-sm text-slate-600 dark:text-slate-400 truncate max-w-xl group-hover:underline">
                    {item.url}
                  </div>

                  <div className="text-xs text-slate-500 dark:text-slate-400 pt-0.5">
                    {formattedDate} at {formattedTime}
                  </div>
                </div>

                {/* Right: Score, Reopen Button & Delete */}
                <div className="flex items-center gap-3.5 shrink-0 self-end md:self-center">
                  {/* Score Indicator */}
                  <div className="text-right">
                    <div className="text-xs font-sans uppercase text-slate-500 dark:text-slate-400 font-semibold">Risk Score</div>
                    <div className={`font-mono text-lg sm:text-xl font-bold ${
                      isMalicious ? 'text-red-600 dark:text-red-400' : isSuspicious ? 'text-amber-600 dark:text-amber-400' : 'text-emerald-600 dark:text-emerald-400'
                    }`}>
                      {item.score} / 100
                    </div>
                  </div>

                  {/* Reopen / Inspect Button */}
                  <Button
                    onClick={() => onInspectScan(item)}
                    size="sm"
                    variant="secondary"
                    icon="arrow_forward"
                    iconPosition="right"
                    className="h-10 px-4 text-xs sm:text-sm font-semibold"
                  >
                    View Result
                  </Button>

                  {/* Delete Item */}
                  <button
                    onClick={(e) => handleDelete(item.id, e)}
                    title="Delete record"
                    className="p-2 rounded-xl text-slate-400 hover:text-red-600 hover:bg-red-50 dark:text-slate-500 dark:hover:text-red-400 dark:hover:bg-red-950/40 transition-colors cursor-pointer"
                  >
                    <span className="material-symbols-outlined text-[20px]">delete</span>
                  </button>
                </div>

              </div>
            );
          })}
        </div>
      ) : (
        /* Empty State */
        <div className="p-12 rounded-2xl bg-white dark:bg-gray-900 border border-slate-200 dark:border-slate-800 text-center space-y-3.5 shadow-sm">
          <div className="w-16 h-16 rounded-full bg-slate-100 dark:bg-slate-800 mx-auto flex items-center justify-center text-slate-400">
            <span className="material-symbols-outlined text-[32px]">history_toggle_off</span>
          </div>
          <div className="space-y-1.5">
            <h3 className="font-heading font-semibold text-slate-900 dark:text-white text-lg sm:text-xl">
              {searchQuery || statusFilter !== 'ALL' ? 'No matching scans' : 'No scans yet'}
            </h3>
            <p className="text-sm sm:text-base text-slate-600 dark:text-slate-400 max-w-md mx-auto font-normal">
              {searchQuery || statusFilter !== 'ALL'
                ? 'No past scans match your search or filter criteria.'
                : 'Your analyzed links will appear here automatically.'}
            </p>
          </div>
        </div>
      )}

    </div>
  );
}

export default ScanHistory;
