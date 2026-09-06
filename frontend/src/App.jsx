import React, { useState, useEffect, useRef } from 'react';
import gsap from 'gsap';
import { analyzeUrl, fetchWebsitePreview, fetchCurrentUserApi, logoutUserApi, setAuthToken, clearAuthToken } from './services/api';
import { loadScanHistory, saveScanRecord } from './utils/historyStorage';
import { ExecutiveSummary } from './components/ExecutiveSummary';
import { DetailedAnalysis } from './components/DetailedAnalysis';
import { ScanHistory } from './components/ScanHistory';
import { AuthModal } from './components/AuthModal';
import Button from './components/Button';
import { isSafeImageDataUrl, isReducedMotion } from './utils/helpers';

export function App() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [scanStep, setScanStep] = useState(0);
  const [currentView, setCurrentView] = useState('scanner'); // 'scanner' | 'history'
  const [isDetailsExpanded, setIsDetailsExpanded] = useState(false);
  const [historyCount, setHistoryCount] = useState(0);
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const activeScanUrlRef = useRef('');

  // GSAP animation container refs
  const heroRef = useRef(null);
  const howItWorksRef = useRef(null);
  const aboutRef = useRef(null);

  // Theme State Management (Light by default, persistent with localStorage)
  const [theme, setTheme] = useState(() => {
    try {
      const savedTheme = localStorage.getItem('phishsense_theme');
      if (savedTheme === 'light' || savedTheme === 'dark') {
        return savedTheme;
      }
      if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
        return 'dark';
      }
    } catch (_) {}
    return 'light';
  });

  // Apply theme class to <html> and save to localStorage
  useEffect(() => {
    if (theme === 'dark') {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
    try {
      localStorage.setItem('phishsense_theme', theme);
    } catch (_) {}
  }, [theme]);

  const toggleTheme = () => {
    setTheme(prev => (prev === 'dark' ? 'light' : 'dark'));
  };

  // Close mobile navigation on Escape key or viewport expansion
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape' && isMobileMenuOpen) {
        setIsMobileMenuOpen(false);
      }
    };
    const handleResize = () => {
      if (window.innerWidth >= 1024 && isMobileMenuOpen) {
        setIsMobileMenuOpen(false);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    window.addEventListener('resize', handleResize);
    return () => {
      window.removeEventListener('keydown', handleKeyDown);
      window.removeEventListener('resize', handleResize);
    };
  }, [isMobileMenuOpen]);

  // Preview & Screenshot Modal State
  const [previewData, setPreviewData] = useState(null);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [previewModalOpen, setPreviewModalOpen] = useState(false);

  // Authentication State
  const [isSignedIn, setIsSignedIn] = useState(() => {
    return !!localStorage.getItem('phishsense_auth_token') || !!localStorage.getItem('phishsense_token');
  });
  const [userEmail, setUserEmail] = useState(() => {
    return localStorage.getItem('phishsense_user_email') || '';
  });
  const [isAuthModalOpen, setIsAuthModalOpen] = useState(false);
  const [authModalView, setAuthModalView] = useState('signup'); // 'signin' | 'signup' | 'verify' | 'forgot' | 'reset'
  const [authModalNotice, setAuthModalNotice] = useState('');

  // Scan Quota for Guests (3 free scans)
  const [scansLeft, setScansLeft] = useState(() => {
    if (localStorage.getItem('phishsense_auth_token') || localStorage.getItem('phishsense_token')) return Infinity;
    const used = parseInt(localStorage.getItem('phishsense_guest_scans') || '0', 10);
    return Math.max(0, 3 - used);
  });

  // Restrained Real-Time Scan Steps
  const scanSteps = [
    'Checking domain…',
    'Checking threat intelligence…',
    'Analyzing URL patterns…',
    'Preparing result…'
  ];

  // Rehydrate session from backend on mount
  useEffect(() => {
    const checkSession = async () => {
      const user = await fetchCurrentUserApi();
      if (user) {
        setIsSignedIn(true);
        setUserEmail(user.email);
        setScansLeft(Infinity);
      }
    };
    checkSession();
  }, []);

  // Refresh history counter on mount & auth change
  useEffect(() => {
    try {
      const history = loadScanHistory(userEmail);
      setHistoryCount(history.length);
    } catch (_) {}
  }, [userEmail, isSignedIn]);

  // GSAP Entrance & Scroll Trigger Micro-Animations
  useEffect(() => {
    if (isReducedMotion() || currentView !== 'scanner') return;

    // 1. Hero Entrance Sequence
    let heroCtx;
    if (heroRef.current) {
      heroCtx = gsap.context(() => {
        gsap.from('[data-animate="hero-badge"]', { opacity: 0, y: 14, duration: 0.5, ease: 'power2.out', delay: 0.05 });
        gsap.from('[data-animate="hero-title"]', { opacity: 0, y: 20, duration: 0.6, ease: 'power2.out', delay: 0.15 });
        gsap.from('[data-animate="hero-subtitle"]', { opacity: 0, y: 14, duration: 0.5, ease: 'power2.out', delay: 0.28 });
        gsap.from('[data-animate="hero-scanner"]', { opacity: 0, y: 16, duration: 0.55, ease: 'power2.out', delay: 0.38 });
        gsap.from('[data-animate="hero-allowance"]', { opacity: 0, duration: 0.4, ease: 'power2.out', delay: 0.5 });
      }, heroRef);
    }

    // 2. How It Works Scroll Observer (Single Trigger)
    let howObserver;
    if (howItWorksRef.current) {
      howObserver = new IntersectionObserver((entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            gsap.from('#how-it-works [data-animate="step-card"]', {
              opacity: 0,
              y: 18,
              duration: 0.45,
              stagger: 0.1,
              ease: 'power2.out'
            });
            howObserver.disconnect();
          }
        });
      }, { threshold: 0.12 });
      howObserver.observe(howItWorksRef.current);
    }

    // 3. About Section Scroll Observer (Single Trigger)
    let aboutObserver;
    if (aboutRef.current) {
      aboutObserver = new IntersectionObserver((entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            gsap.from('#about [data-animate="about-narrative"]', {
              opacity: 0,
              y: 18,
              duration: 0.55,
              ease: 'power2.out'
            });
            gsap.from('#about [data-animate="about-pillar"]', {
              opacity: 0,
              y: 14,
              duration: 0.4,
              stagger: 0.08,
              ease: 'power2.out',
              delay: 0.1
            });
            aboutObserver.disconnect();
          }
        });
      }, { threshold: 0.12 });
      aboutObserver.observe(aboutRef.current);
    }

    return () => {
      if (heroCtx) heroCtx.revert();
      if (howObserver) howObserver.disconnect();
      if (aboutObserver) aboutObserver.disconnect();
    };
  }, [currentView]);

  // Handle URL Analysis
  const handleAnalyze = async (e) => {
    if (e) e.preventDefault();
    if (!url.trim()) {
      setError('Please enter a website address to analyze.');
      return;
    }

    // Check guest scan limit
    if (!isSignedIn && scansLeft <= 0) {
      openAuthModal('signup', "You've used your 3 free scans. Sign up for free to unlock unlimited analysis!");
      return;
    }

    const targetUrl = url.trim();
    activeScanUrlRef.current = targetUrl;

    setLoading(true);
    setError(null);
    setResult(null);
    setPreviewData(null);
    setPreviewLoading(true);
    setIsDetailsExpanded(false);
    setScanStep(0);

    // Step progress timer
    const stepInterval = setInterval(() => {
      setScanStep((prev) => (prev < scanSteps.length - 1 ? prev + 1 : prev));
    }, 350);

    // Trigger website preview probing in parallel
    const previewPromise = fetchWebsitePreview(targetUrl)
      .then((preview) => {
        if (activeScanUrlRef.current === targetUrl && preview) {
          setPreviewData(preview);
          return preview;
        }
        return null;
      })
      .catch((err) => {
        console.warn('Website preview fetch failed:', err.message);
        return null;
      })
      .finally(() => {
        if (activeScanUrlRef.current === targetUrl) {
          setPreviewLoading(false);
        }
      });

    try {
      const data = await analyzeUrl(targetUrl);
      clearInterval(stepInterval);
      if (activeScanUrlRef.current === targetUrl) {
        setResult(data);
      }

      // Decrement guest quota if not signed in
      if (!isSignedIn) {
        const used = parseInt(localStorage.getItem('phishsense_guest_scans') || '0', 10) + 1;
        localStorage.setItem('phishsense_guest_scans', used.toString());
        setScansLeft(Math.max(0, 3 - used));
      }

      // Save initial scan record to history
      saveScanRecord(data, null, userEmail);
      setHistoryCount(prev => prev + 1);

      // Update history record once preview resolves
      previewPromise.then((resolvedPreview) => {
        if (resolvedPreview && activeScanUrlRef.current === targetUrl) {
          saveScanRecord(data, resolvedPreview, userEmail);
        }
      });

    } catch (err) {
      clearInterval(stepInterval);
      if (activeScanUrlRef.current === targetUrl) {
        setError(err.message || 'We were unable to analyze this web address. Please verify the URL and try again.');
      }
    } finally {
      if (activeScanUrlRef.current === targetUrl) {
        setLoading(false);
      }
    }
  };

  // Inspect Historical Scan in Detail
  const handleInspectScan = (historicalItem) => {
    setUrl(historicalItem.url);
    setResult(historicalItem);
    if (historicalItem.previewData) {
      setPreviewData(historicalItem.previewData);
    }
    setCurrentView('scanner');
    setIsDetailsExpanded(false);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  // Open Auth Modal helper
  const openAuthModal = (view = 'signup', notice = '') => {
    setAuthModalView(view);
    setAuthModalNotice(notice);
    setIsAuthModalOpen(true);
  };

  const closeAuthModal = () => {
    setIsAuthModalOpen(false);
    setAuthModalNotice('');
  };

  // Handle successful login or verification
  const handleAuthSuccess = (user, token) => {
    if (token) {
      setAuthToken(token);
      localStorage.setItem('phishsense_token', token);
    }
    if (user && user.email) {
      localStorage.setItem('phishsense_user_email', user.email);
      setUserEmail(user.email);
    }
    setIsSignedIn(true);
    setScansLeft(Infinity);
    closeAuthModal();
  };

  const handleSignOut = async () => {
    await logoutUserApi();
    clearAuthToken();
    localStorage.removeItem('phishsense_token');
    localStorage.removeItem('phishsense_user_email');
    setIsSignedIn(false);
    setUserEmail('');
    const used = parseInt(localStorage.getItem('phishsense_guest_scans') || '0', 10);
    setScansLeft(Math.max(0, 3 - used));
    setCurrentView('scanner');
  };

  // Transform Result Data for Technical Forensics (All 13 Heuristic Rules)
  const computeSecurityChecks = (res) => {
    if (!res) return [];
    const heuristics = res.details?.heuristics || {};
    const b = heuristics.booleanResults || heuristics.rules || {};

    return [
      {
        id: 'typosquatting',
        title: 'Brand Impersonation & Typosquatting',
        subtitle: 'Detects if domain mimics established organization or brand names',
        detail: b.lookalikeDomain ? 'Possible brand impersonation detected (+25 pts)' : 'Clean brand signature',
        status: b.lookalikeDomain ? 'DETECTED' : 'PASS'
      },
      {
        id: 'homoglyphs',
        title: 'Lookalike Character Deception',
        subtitle: 'Checks for Unicode homoglyphs and Punycode spoofing',
        detail: b.unicodeLookalikeDomain ? 'Lookalike characters detected (+25 pts)' : 'Standard ASCII characters',
        status: b.unicodeLookalikeDomain ? 'DETECTED' : 'PASS'
      },
      {
        id: 'ipHost',
        title: 'Direct IP Host Address',
        subtitle: 'Checks if link connects directly to raw IP numbers',
        detail: b.hasIpHost ? 'Raw IP host detected (+30 pts)' : 'Standard domain hostname',
        status: b.hasIpHost ? 'DETECTED' : 'PASS'
      },
      {
        id: 'suspiciousTld',
        title: 'High-Risk Domain Extension',
        subtitle: 'Checks extension against known high-abuse TLD registries',
        detail: b.suspiciousTld ? 'High-risk extension detected (+20 pts)' : 'Standard extension reputation',
        status: b.suspiciousTld ? 'WARNING' : 'PASS'
      },
      {
        id: 'https',
        title: 'Transport Encryption (HTTPS)',
        subtitle: 'Verifies TLS encryption is enforced',
        detail: b.noHttps ? 'Unencrypted HTTP transport (+15 pts)' : 'Valid HTTPS encryption active',
        status: b.noHttps ? 'WARNING' : 'PASS'
      },
      {
        id: 'urlShortener',
        title: 'URL Shortener Obfuscation',
        subtitle: 'Identifies redirection masking via link shortening services',
        detail: b.urlShortener ? 'URL shortener service detected (+15 pts)' : 'Direct destination address',
        status: b.urlShortener ? 'WARNING' : 'PASS'
      },
      {
        id: 'subdomains',
        title: 'Subdomain Nesting & Complexity',
        subtitle: 'Checks for multi-level subdomain prefixes',
        detail: b.excessiveSubdomains ? 'Excessive subdomains detected (+15 pts)' : 'Normal domain hierarchy',
        status: b.excessiveSubdomains ? 'WARNING' : 'PASS'
      },
      {
        id: 'keywords',
        title: 'Suspicious Security Keywords',
        subtitle: 'Flags deceptive urgency, credential, or banking terms',
        detail: b.suspiciousKeywords ? 'Deceptive keywords present (+10 pts)' : 'No deceptive keywords found',
        status: b.suspiciousKeywords ? 'WARNING' : 'PASS'
      },
      {
        id: 'hyphens',
        title: 'Excessive Domain Hyphenation',
        subtitle: 'Detects excessive hyphens commonly used in spoofed domains',
        detail: b.excessiveHyphens ? 'Excessive hyphens detected (+10 pts)' : 'Normal hyphenation structure',
        status: b.excessiveHyphens ? 'WARNING' : 'PASS'
      },
      {
        id: 'length',
        title: 'Abnormal URL Length',
        subtitle: 'Identifies abnormally long URLs designed to obscure parameters',
        detail: b.excessiveUrlLength ? 'Abnormally long URL (+10 pts)' : 'Standard URL length',
        status: b.excessiveUrlLength ? 'WARNING' : 'PASS'
      },
      {
        id: 'symbols',
        title: 'Suspicious URL Symbols',
        subtitle: 'Checks for embedded @ signs, double-slash, and abnormal characters',
        detail: b.suspiciousSymbols ? 'Suspicious characters detected (+10 pts)' : 'Clean URL syntax',
        status: b.suspiciousSymbols ? 'WARNING' : 'PASS'
      },
      {
        id: 'numbers',
        title: 'Suspicious Numeric Patterns',
        subtitle: 'Flags excessive digits often seen in disposable domains',
        detail: b.excessiveNumbers ? 'Suspicious digit count (+10 pts)' : 'Normal character distribution',
        status: b.excessiveNumbers ? 'WARNING' : 'PASS'
      },
      {
        id: 'pathDepth',
        title: 'Deep Directory Path Structure',
        subtitle: 'Evaluates deeply nested directory hierarchies',
        detail: b.deepUrlPath ? 'Deep path hierarchy (+10 pts)' : 'Standard directory depth',
        status: b.deepUrlPath ? 'WARNING' : 'PASS'
      }
    ];
  };

  const computeThreatIntelCards = (res) => {
    if (!res) return [];
    const threatIntel = res.details?.threatIntel || {};
    const vt = threatIntel.virusTotal || threatIntel.sources?.virusTotal || {};
    const op = threatIntel.openPhish || threatIntel.sources?.openPhish || {};

    const vtDetections = typeof vt.detections === 'number' ? vt.detections : (vt.maliciousCount || (vt.malicious ? 1 : 0));
    const vtHarmless = vt.harmlessCount || 0;
    const vtTotal = vt.total || 92;
    const isVtThreat = vtDetections > 0 || vt.malicious;
    const isSingleOutlier = vtDetections === 1 && vtHarmless >= 20;
    const vendorNames = (vt.flaggedVendors || []).map(v => v.engine).filter(Boolean).join(', ');

    const isOpThreat = Boolean(op.threatFound || op.detected || op.isPhishing || op.status === 'PHISHING');

    return [
      {
        id: 'virustotal',
        title: 'VirusTotal',
        provider: 'Global Security Vendors',
        statusBadge: isSingleOutlier
          ? `1 / ${vtTotal} Flagged (Outlier)`
          : isVtThreat
          ? `${vtDetections} / ${vtTotal} Flagged`
          : 'Clean',
        badgeColor: isSingleOutlier
          ? 'bg-amber-50 text-amber-800 border-amber-200 dark:bg-amber-950/40 dark:text-amber-300 dark:border-amber-800/70'
          : isVtThreat
          ? 'bg-red-50 text-red-700 border-red-200 dark:bg-red-950/40 dark:text-red-300 dark:border-red-800/70'
          : 'bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-950/40 dark:text-emerald-300 dark:border-emerald-800/70',
        detail: isSingleOutlier
          ? `1 of ${vtTotal} vendors flagged this URL${vendorNames ? ` (${vendorNames})` : ''}. ${vtHarmless} explicitly marked it as harmless; the remaining vendors returned other/undetected results.`
          : isVtThreat
          ? `${vtDetections} of ${vtTotal} security vendors flagged this URL${vendorNames ? ` (${vendorNames})` : ''}.`
          : `0 of ${vtTotal} security vendors flagged this URL. No threat detected across antivirus engines.`,
        icon: 'public'
      },
      {
        id: 'openphish',
        title: 'OpenPhish',
        provider: 'Phishing Intelligence Feed',
        statusBadge: isOpThreat ? 'Phishing Match' : 'Clean',
        badgeColor: isOpThreat
          ? 'bg-red-50 text-red-700 border-red-200 dark:bg-red-950/40 dark:text-red-300 dark:border-red-800/70'
          : 'bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-950/40 dark:text-emerald-300 dark:border-emerald-800/70',
        detail: isOpThreat
          ? 'Potential phishing match detected in active intelligence feed.'
          : 'No matching phishing record found in active feeds.',
        icon: 'travel_explore'
      }
    ];
  };

  const securityChecks = computeSecurityChecks(result);
  const threatIntelCards = computeThreatIntelCards(result);

  return (
    <div className="font-sans min-h-screen text-slate-800 dark:text-slate-100 bg-slate-50 dark:bg-slate-950 relative overflow-x-hidden selection:bg-sky-500/20 selection:text-sky-600 transition-colors duration-200 flex flex-col justify-between">
      
      {/* Top Navigation Bar */}
      <nav className="fixed top-0 w-full z-50 bg-white/90 dark:bg-slate-950/90 backdrop-blur-xl border-b border-slate-200 dark:border-slate-800 transition-colors">
        <div className="flex justify-between items-center h-16 sm:h-18 px-4 sm:px-6 lg:px-8 xl:px-12 max-w-[1360px] mx-auto">
          
          {/* LEFT: Brand Logo */}
          <button
            onClick={() => { setCurrentView('scanner'); setIsMobileMenuOpen(false); }}
            className="font-heading text-lg sm:text-xl md:text-2xl font-bold text-slate-900 dark:text-white tracking-tight flex items-center gap-2 sm:gap-2.5 group cursor-pointer shrink-0"
          >
            <img src="/phishsense_icon.png" alt="PhishSense Logo" className="w-7 h-7 sm:w-8 sm:h-8 object-contain transition-transform group-hover:scale-105" />
            <span className="bg-gradient-to-r from-slate-900 via-sky-800 to-sky-600 dark:from-white dark:via-slate-100 dark:to-sky-300 bg-clip-text text-transparent">
              PhishSense
            </span>
          </button>
          
          {/* RIGHT: Desktop Navigation Links + Single Sign In Button + Theme Toggle (>= 1024px) */}
          <div className="hidden lg:flex items-center gap-6 xl:gap-8">
            <button
              onClick={() => setCurrentView('scanner')}
              className={`transition-colors duration-150 cursor-pointer text-[15px] sm:text-base ${
                currentView === 'scanner'
                  ? 'text-sky-600 dark:text-sky-400 font-semibold border-b-2 border-sky-600 dark:border-sky-400 pb-0.5'
                  : 'text-slate-600 dark:text-slate-400 font-medium hover:text-slate-900 dark:hover:text-white'
              }`}
            >
              Scanner
            </button>
            <button
              onClick={() => setCurrentView('history')}
              className={`transition-colors duration-150 flex items-center gap-2 cursor-pointer text-[15px] sm:text-base ${
                currentView === 'history'
                  ? 'text-sky-600 dark:text-sky-400 font-semibold border-b-2 border-sky-600 dark:border-sky-400 pb-0.5'
                  : 'text-slate-600 dark:text-slate-400 font-medium hover:text-slate-900 dark:hover:text-white'
              }`}
            >
              <span>History</span>
              {historyCount > 0 && (
                <span className="px-2 py-0.5 rounded-full text-xs font-mono font-bold bg-sky-500/15 text-sky-600 dark:text-sky-400 border border-sky-500/30">
                  {historyCount}
                </span>
              )}
            </button>
            <a
              className="text-slate-600 dark:text-slate-400 font-medium hover:text-slate-900 dark:hover:text-white transition-colors duration-150 text-[15px] sm:text-base"
              href="#how-it-works"
              onClick={() => { if (currentView !== 'scanner') setCurrentView('scanner'); }}
            >
              How It Works
            </a>
            <a
              className="text-slate-600 dark:text-slate-400 font-medium hover:text-slate-900 dark:hover:text-white transition-colors duration-150 text-[15px] sm:text-base"
              href="#about"
              onClick={() => { if (currentView !== 'scanner') setCurrentView('scanner'); }}
            >
              About
            </a>

            {/* Theme Toggle Button (Desktop) */}
            <button
              onClick={toggleTheme}
              title={theme === 'dark' ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
              className="p-2 rounded-xl bg-slate-100 hover:bg-slate-200 dark:bg-slate-900 dark:hover:bg-slate-800 border border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-300 transition-colors cursor-pointer flex items-center justify-center"
              aria-label="Toggle theme"
            >
              <span className="material-symbols-outlined text-[19px]">
                {theme === 'dark' ? 'light_mode' : 'dark_mode'}
              </span>
            </button>

            {/* Single Authentication Entry Point (Desktop) */}
            {!isSignedIn ? (
              <Button
                onClick={() => openAuthModal('signin')}
                size="md"
                variant="primary"
                className="px-5 text-sm sm:text-base font-semibold"
              >
                Sign In
              </Button>
            ) : (
              <div className="flex items-center gap-2">
                <div className="flex items-center gap-2 px-3.5 py-1.5 rounded-xl bg-slate-100 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-xs sm:text-sm text-slate-700 dark:text-slate-300 font-mono">
                  <span className="material-symbols-outlined text-[18px] text-sky-600 dark:text-sky-400">account_circle</span>
                  <span className="truncate max-w-[150px]">{userEmail}</span>
                </div>
                <Button
                  onClick={handleSignOut}
                  size="sm"
                  variant="outline"
                  className="text-xs sm:text-sm font-semibold"
                >
                  Sign Out
                </Button>
              </div>
            )}
          </div>

          {/* RIGHT: Mobile & Tablet Controls (< 1024px: Theme Toggle + Hamburger) */}
          <div className="flex lg:hidden items-center gap-1.5 sm:gap-2">
            <button
              onClick={toggleTheme}
              title={theme === 'dark' ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
              className="p-2 sm:p-2.5 rounded-xl bg-slate-100 hover:bg-slate-200 dark:bg-slate-900 dark:hover:bg-slate-800 border border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-300 transition-colors cursor-pointer flex items-center justify-center"
              aria-label="Toggle theme"
            >
              <span className="material-symbols-outlined text-[19px]">
                {theme === 'dark' ? 'light_mode' : 'dark_mode'}
              </span>
            </button>
            <button
              onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
              className="p-2 sm:p-2.5 rounded-xl bg-slate-100 hover:bg-slate-200 dark:bg-slate-900 dark:hover:bg-slate-800 border border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-300 transition-colors cursor-pointer flex items-center justify-center"
              aria-label="Toggle navigation menu"
              aria-expanded={isMobileMenuOpen}
            >
              <span className="material-symbols-outlined text-[22px]">
                {isMobileMenuOpen ? 'close' : 'menu'}
              </span>
            </button>
          </div>

        </div>

        {/* Mobile & Tablet Backdrop Overlay */}
        {isMobileMenuOpen && (
          <div
            onClick={() => setIsMobileMenuOpen(false)}
            className="fixed inset-0 top-16 sm:top-18 bg-slate-950/40 backdrop-blur-xs z-40 lg:hidden animate-fade-in"
            aria-hidden="true"
          />
        )}

        {/* Mobile & Tablet Navigation Drawer */}
        {isMobileMenuOpen && (
          <div className="relative z-50 lg:hidden px-4 sm:px-6 py-5 bg-white dark:bg-slate-950 border-b border-slate-200 dark:border-slate-800 space-y-4 animate-fade-in shadow-2xl text-base max-h-[calc(100vh-4.5rem)] overflow-y-auto">
            <div className="flex flex-col gap-2">
              <button
                onClick={() => { setCurrentView('scanner'); setIsMobileMenuOpen(false); }}
                className={`text-left px-3.5 py-2.5 rounded-xl font-semibold flex items-center gap-2.5 transition-colors cursor-pointer ${
                  currentView === 'scanner' ? 'bg-sky-50 dark:bg-sky-950/40 text-sky-600 dark:text-sky-400' : 'text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-900'
                }`}
              >
                <span className="material-symbols-outlined text-[20px]">search</span>
                <span>Scanner</span>
              </button>
              <button
                onClick={() => { setCurrentView('history'); setIsMobileMenuOpen(false); }}
                className={`text-left px-3.5 py-2.5 rounded-xl font-semibold flex items-center justify-between transition-colors cursor-pointer ${
                  currentView === 'history' ? 'bg-sky-50 dark:bg-sky-950/40 text-sky-600 dark:text-sky-400' : 'text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-900'
                }`}
              >
                <span className="flex items-center gap-2.5">
                  <span className="material-symbols-outlined text-[20px]">history</span>
                  <span>History</span>
                </span>
                {historyCount > 0 && (
                  <span className="px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-sky-500/15 text-sky-600 dark:text-sky-400">
                    {historyCount}
                  </span>
                )}
              </button>
              <a
                href="#how-it-works"
                onClick={() => { setCurrentView('scanner'); setIsMobileMenuOpen(false); }}
                className="px-3.5 py-2.5 rounded-xl font-semibold flex items-center gap-2.5 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-900 transition-colors"
              >
                <span className="material-symbols-outlined text-[20px]">tune</span>
                <span>How It Works</span>
              </a>
              <a
                href="#about"
                onClick={() => { setCurrentView('scanner'); setIsMobileMenuOpen(false); }}
                className="px-3.5 py-2.5 rounded-xl font-semibold flex items-center gap-2.5 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-900 transition-colors"
              >
                <span className="material-symbols-outlined text-[20px]">info</span>
                <span>About</span>
              </a>
            </div>

            {/* Mobile Auth Actions */}
            <div className="pt-4 border-t border-slate-200 dark:border-slate-800">
              {!isSignedIn ? (
                <Button
                  onClick={() => { openAuthModal('signin'); setIsMobileMenuOpen(false); }}
                  size="md"
                  variant="primary"
                  fullWidth
                >
                  Sign In
                </Button>
              ) : (
                <div className="flex items-center justify-between gap-3">
                  <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-slate-100 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-xs sm:text-sm text-slate-700 dark:text-slate-300 font-mono min-w-0">
                    <span className="material-symbols-outlined text-[16px] text-sky-500 shrink-0">account_circle</span>
                    <span className="truncate">{userEmail}</span>
                  </div>
                  <Button
                    onClick={() => { handleSignOut(); setIsMobileMenuOpen(false); }}
                    size="sm"
                    variant="outline"
                    className="text-xs font-semibold shrink-0"
                  >
                    Sign Out
                  </Button>
                </div>
              )}
            </div>
          </div>
        )}
      </nav>

      {/* Main Content Area */}
      <main className="pt-26 sm:pt-28 pb-20 px-4 sm:px-6 lg:px-8 xl:px-12 max-w-[1360px] mx-auto relative z-10 w-full flex-1">
        
        {/* VIEW 1: SCANNER DASHBOARD */}
        {currentView === 'scanner' && (
          <div className="space-y-16 sm:space-y-20">
            
            {/* HERO SCAN INPUT SECTION */}
            <section ref={heroRef} className="text-center relative z-10 pt-6 sm:pt-10 pb-4">
              {/* Eyebrow Label */}
              <div data-animate="hero-badge" className="inline-flex items-center gap-2.5 px-4 py-1.5 rounded-full bg-sky-500/10 text-sky-700 dark:text-sky-300 font-mono text-xs sm:text-[13px] font-semibold mb-6 border border-sky-500/20 shadow-sm tracking-wider uppercase">
                <img src="/phishsense_icon.png" alt="PhishSense" className="w-4 h-4 object-contain shrink-0" />
                <span>EXPLAINABLE PHISHING DETECTION</span>
              </div>
              
              {/* Main Hero Heading */}
              <h1 data-animate="hero-title" className="max-w-4xl mx-auto mb-5 text-center">
                <span className="hero-title">
                  Is this a safe link or a trap?
                </span>
              </h1>

              {/* Subtitle */}
              <p data-animate="hero-subtitle" className="text-slate-600 dark:text-slate-300 text-base sm:text-lg md:text-xl max-w-3xl mx-auto mb-9 font-normal leading-relaxed">
                Check if a web address is safe, suspicious, or dangerous in seconds with transparent, explainable analysis.
              </p>

              {/* URL Input Form */}
              <div data-animate="hero-scanner" className="max-w-4xl mx-auto mb-4 w-full">
                <form onSubmit={handleAnalyze} className="relative flex flex-col sm:flex-row gap-3 transition-all duration-200 w-full">
                  <div className="flex-grow relative flex items-center">
                    <span className="absolute left-4.5 sm:left-5 top-1/2 -translate-y-1/2 material-symbols-outlined text-slate-400 dark:text-slate-500 text-[22px] pointer-events-none select-none z-10">
                      link
                    </span>
                    <input
                      className="w-full h-14 sm:h-15 pl-13 sm:pl-14 pr-4 rounded-xl bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-800 text-slate-900 dark:text-white placeholder:text-slate-400 dark:placeholder:text-slate-500 focus:ring-2 focus:ring-sky-500/30 focus:border-sky-500 focus:outline-none transition-all font-mono text-base sm:text-lg shadow-sm placeholder:text-sm sm:placeholder:text-base"
                      placeholder="Paste a web address (e.g. https://paypal-security-update.com)"
                      type="text"
                      value={url}
                      onChange={(e) => setUrl(e.target.value)}
                      disabled={loading}
                    />
                  </div>
                  <Button
                    type="submit"
                    disabled={loading}
                    loading={loading}
                    size="lg"
                    variant="primary"
                    icon="search"
                    className="h-14 sm:h-15 px-8 text-base sm:text-lg shrink-0 w-full sm:w-auto"
                  >
                    Analyze Link
                  </Button>
                </form>
                
                {error && (
                  <div className="text-red-600 dark:text-red-400 text-sm sm:text-base mt-3.5 font-normal text-left p-3.5 rounded-xl bg-red-50 dark:bg-red-950/40 border border-red-200 dark:border-red-800/70 flex items-center gap-2">
                    <span className="material-symbols-outlined text-[20px]">error</span>
                    <span>{error}</span>
                  </div>
                )}
              </div>

              {/* Scan Allowance Display */}
              <div data-animate="hero-allowance" className="text-sm sm:text-[15px] font-mono text-slate-600 dark:text-slate-400 mt-4 flex items-center justify-center gap-2">
                {!isSignedIn ? (
                  scansLeft > 0 ? (
                    <span className="flex items-center gap-1.5">
                      <span className="material-symbols-outlined text-[16px] text-sky-600 dark:text-sky-400">shield</span>
                      <span>{scansLeft} of 3 free scans remaining</span>
                    </span>
                  ) : (
                    <span className="flex items-center gap-1.5">
                      <span className="material-symbols-outlined text-[16px] text-amber-500">lock_clock</span>
                      <span>
                        0 of 3 free scans remaining.{' '}
                        <button
                          onClick={() => openAuthModal('signup', "You've used your 3 free scans. Sign up for free to unlock unlimited analysis!")}
                          className="text-sky-600 dark:text-sky-400 font-semibold hover:underline cursor-pointer ml-1"
                        >
                          Sign up for unlimited scans
                        </button>
                      </span>
                    </span>
                  )
                ) : (
                  <span className="inline-flex items-center gap-1.5 text-emerald-600 dark:text-emerald-400 font-medium">
                    <span className="material-symbols-outlined text-[16px]">verified_user</span>
                    <span>Unlimited scans active</span>
                  </span>
                )}
              </div>
            </section>

            {/* RESTRAINED REAL-TIME LOADING STEP PANEL */}
            {loading && (
              <div className="max-w-xl mx-auto p-5 sm:p-6 rounded-2xl bg-white dark:bg-gray-900 border border-slate-200 dark:border-slate-800 shadow-sm space-y-3">
                <div className="flex items-center gap-3 text-sm sm:text-base text-slate-800 dark:text-slate-200 font-sans font-medium">
                  <span className="w-2.5 h-2.5 rounded-full bg-sky-500 animate-ping shrink-0"></span>
                  <span>{scanSteps[scanStep]}</span>
                </div>
              </div>
            )}

            {/* RESULTS DASHBOARD (PROGRESSIVE DISCLOSURE) */}
            {result && !loading && (
              <section id="scan-results" className="max-w-6xl mx-auto space-y-8 animate-fade-in w-full">
                
                {/* 1. EXECUTIVE SUMMARY (PRIMARY HUMAN-CENTERED VERDICT) */}
                <ExecutiveSummary
                  result={result}
                  previewData={previewData}
                  previewLoading={previewLoading}
                  isDetailsExpanded={isDetailsExpanded}
                  onToggleDetails={() => setIsDetailsExpanded(prev => !prev)}
                  onOpenPreviewModal={() => setPreviewModalOpen(true)}
                />

                {/* 2. ADVANCED SECURITY DETAILS (TECHNICAL EXPANDABLE DETAILS) */}
                {isDetailsExpanded && (
                  <DetailedAnalysis
                    result={result}
                    securityChecks={securityChecks}
                    threatIntelCards={threatIntelCards}
                    previewData={previewData}
                  />
                )}

              </section>
            )}

            {/* HOW IT WORKS SECTION */}
            <section ref={howItWorksRef} id="how-it-works" className="mt-20 pt-16 border-t border-slate-200 dark:border-slate-800 space-y-12 max-w-6xl mx-auto w-full">
              {/* Header */}
              <div className="text-center max-w-2xl mx-auto space-y-3">
                <div className="inline-flex items-center gap-2 px-3.5 py-1 rounded-full bg-sky-500/10 text-sky-700 dark:text-sky-300 font-mono text-xs font-semibold tracking-wider uppercase border border-sky-500/20">
                  <span className="material-symbols-outlined text-[15px]">timeline</span>
                  <span>STEP-BY-STEP PROCESS</span>
                </div>
                <h2 className="font-heading text-2xl sm:text-3xl md:text-4xl font-bold text-slate-900 dark:text-white leading-tight">
                  How It Works
                </h2>
                <p className="text-slate-600 dark:text-slate-400 text-base sm:text-lg font-normal leading-relaxed">
                  What happens after you paste a link into PhishSense?
                </p>
              </div>

              {/* 4-Step Process Grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                {/* Step 1 */}
                <div data-animate="step-card" className="p-6 sm:p-7 rounded-2xl bg-white dark:bg-gray-900 border border-slate-200 dark:border-slate-800 space-y-4 shadow-sm relative flex flex-col justify-between group hover:border-sky-300 dark:hover:border-sky-500/40 transition-colors">
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <div className="w-12 h-12 rounded-xl bg-sky-500/10 border border-sky-500/20 flex items-center justify-center text-sky-600 dark:text-sky-400">
                        <span className="material-symbols-outlined text-[24px]">link</span>
                      </div>
                      <span className="font-mono text-2xl font-black text-slate-300 dark:text-slate-700 select-none">
                        01
                      </span>
                    </div>
                    <div>
                      <h3 className="font-heading font-bold text-slate-900 dark:text-white text-base sm:text-lg uppercase tracking-tight">
                        Check the Link
                      </h3>
                      <p className="text-sm text-slate-600 dark:text-slate-400 font-normal leading-relaxed pt-2">
                        We examine the website address for suspicious patterns, unusual characters, deceptive structures, and signs of impersonation.
                      </p>
                    </div>
                  </div>
                </div>

                {/* Step 2 */}
                <div data-animate="step-card" className="p-6 sm:p-7 rounded-2xl bg-white dark:bg-gray-900 border border-slate-200 dark:border-slate-800 space-y-4 shadow-sm relative flex flex-col justify-between group hover:border-indigo-300 dark:hover:border-indigo-500/40 transition-colors">
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <div className="w-12 h-12 rounded-xl bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-600 dark:text-indigo-400">
                        <span className="material-symbols-outlined text-[24px]">public</span>
                      </div>
                      <span className="font-mono text-2xl font-black text-slate-300 dark:text-slate-700 select-none">
                        02
                      </span>
                    </div>
                    <div>
                      <h3 className="font-heading font-bold text-slate-900 dark:text-white text-base sm:text-lg uppercase tracking-tight">
                        Check Security Sources
                      </h3>
                      <p className="text-sm text-slate-600 dark:text-slate-400 font-normal leading-relaxed pt-2">
                        We compare the link with trusted security information, including VirusTotal and OpenPhish, to identify known warnings and threats.
                      </p>
                    </div>
                  </div>
                </div>

                {/* Step 3 */}
                <div data-animate="step-card" className="p-6 sm:p-7 rounded-2xl bg-white dark:bg-gray-900 border border-slate-200 dark:border-slate-800 space-y-4 shadow-sm relative flex flex-col justify-between group hover:border-cyan-300 dark:hover:border-cyan-500/40 transition-colors">
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <div className="w-12 h-12 rounded-xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-600 dark:text-cyan-400">
                        <span className="material-symbols-outlined text-[24px]">psychology</span>
                      </div>
                      <span className="font-mono text-2xl font-black text-slate-300 dark:text-slate-700 select-none">
                        03
                      </span>
                    </div>
                    <div>
                      <h3 className="font-heading font-bold text-slate-900 dark:text-white text-base sm:text-lg uppercase tracking-tight">
                        Analyze with AI
                      </h3>
                      <p className="text-sm text-slate-600 dark:text-slate-400 font-normal leading-relaxed pt-2">
                        Our AI examines the link for patterns commonly associated with phishing and suspicious websites.
                      </p>
                    </div>
                  </div>
                </div>

                {/* Step 4 */}
                <div data-animate="step-card" className="p-6 sm:p-7 rounded-2xl bg-white dark:bg-gray-900 border border-slate-200 dark:border-slate-800 space-y-4 shadow-sm relative flex flex-col justify-between group hover:border-emerald-300 dark:hover:border-emerald-500/40 transition-colors">
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <div className="w-12 h-12 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-600 dark:text-emerald-400">
                        <span className="material-symbols-outlined text-[24px]">verified_user</span>
                      </div>
                      <span className="font-mono text-2xl font-black text-slate-300 dark:text-slate-700 select-none">
                        04
                      </span>
                    </div>
                    <div>
                      <h3 className="font-heading font-bold text-slate-900 dark:text-white text-base sm:text-lg uppercase tracking-tight">
                        Give You a Clear Answer
                      </h3>
                      <p className="text-sm text-slate-600 dark:text-slate-400 font-normal leading-relaxed pt-2">
                        We combine the analysis into an understandable risk assessment and explain why the link was flagged.
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            </section>

            {/* ABOUT PHISHSENSE SECTION */}
            <section ref={aboutRef} id="about" className="mt-20 pt-16 border-t border-slate-200 dark:border-slate-800 space-y-12 max-w-6xl mx-auto w-full">
              {/* Header */}
              <div className="text-center max-w-3xl mx-auto space-y-3">
                <div className="inline-flex items-center gap-2 px-3.5 py-1 rounded-full bg-sky-500/10 text-sky-700 dark:text-sky-300 font-mono text-xs font-semibold tracking-wider uppercase border border-sky-500/20">
                  <span className="material-symbols-outlined text-[15px]">info</span>
                  <span>MISSION &amp; PURPOSE</span>
                </div>
                <h2 className="font-heading text-2xl sm:text-3xl md:text-4xl font-bold text-slate-900 dark:text-white leading-tight">
                  About PhishSense
                </h2>
                <p className="font-heading text-lg sm:text-xl font-semibold text-sky-700 dark:text-sky-300 leading-snug">
                  Helping people make safer decisions before they click.
                </p>
              </div>

              {/* Editorial Narrative + Product Pillars Grid */}
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 lg:gap-10 items-start">
                {/* Left Narrative (7 Cols) */}
                <div data-animate="about-narrative" className="lg:col-span-7 space-y-6 text-slate-700 dark:text-slate-300 leading-relaxed text-base sm:text-lg font-normal">
                  <p>
                    PhishSense is an explainable phishing detection platform designed to help people make safer decisions when they encounter suspicious links.
                  </p>

                  <p className="text-slate-600 dark:text-slate-400 text-sm sm:text-base">
                    Phishing attacks are designed to look legitimate. A link may appear to belong to a familiar company or service while secretly leading to a fraudulent website.
                  </p>

                  <p className="text-slate-600 dark:text-slate-400 text-sm sm:text-base">
                    PhishSense analyzes suspicious links and turns the results into a clear explanation that helps people understand whether they should continue, be cautious, or stay away.
                  </p>

                  {/* Core Goal Quote Box */}
                  <div className="p-5 sm:p-6 rounded-2xl bg-sky-500/5 dark:bg-sky-500/10 border border-sky-500/20 space-y-2">
                    <div className="text-xs font-mono font-semibold uppercase tracking-wider text-sky-700 dark:text-sky-300">
                      Our Core Goal
                    </div>
                    <p className="font-heading font-semibold text-base sm:text-lg text-slate-900 dark:text-white leading-snug">
                      Help people answer one question before they click:
                    </p>
                    <p className="font-heading italic font-bold text-lg sm:text-xl text-sky-600 dark:text-sky-400">
                      &ldquo;Can I trust this link?&rdquo;
                    </p>
                  </div>
                </div>

                {/* Right Product Values (5 Cols) */}
                <div className="lg:col-span-5 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-1 gap-4">
                  {/* Pillar 1 */}
                  <div data-animate="about-pillar" className="p-5 rounded-2xl bg-white dark:bg-gray-900 border border-slate-200 dark:border-slate-800 space-y-2 shadow-sm">
                    <div className="flex items-center gap-2.5">
                      <div className="w-8 h-8 rounded-lg bg-sky-500/10 border border-sky-500/20 flex items-center justify-center text-sky-600 dark:text-sky-400">
                        <span className="material-symbols-outlined text-[18px]">visibility</span>
                      </div>
                      <h4 className="font-heading font-bold text-sm sm:text-base text-slate-900 dark:text-white uppercase tracking-tight">
                        Explainable
                      </h4>
                    </div>
                    <p className="text-xs sm:text-sm text-slate-600 dark:text-slate-400 font-normal leading-relaxed">
                      Understand why a link was flagged with clear explanations instead of confusing technical reports.
                    </p>
                  </div>

                  {/* Pillar 2 */}
                  <div data-animate="about-pillar" className="p-5 rounded-2xl bg-white dark:bg-gray-900 border border-slate-200 dark:border-slate-800 space-y-2 shadow-sm">
                    <div className="flex items-center gap-2.5">
                      <div className="w-8 h-8 rounded-lg bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-600 dark:text-indigo-400">
                        <span className="material-symbols-outlined text-[18px]">layers</span>
                      </div>
                      <h4 className="font-heading font-bold text-sm sm:text-base text-slate-900 dark:text-white uppercase tracking-tight">
                        Multi-Layered
                      </h4>
                    </div>
                    <p className="text-xs sm:text-sm text-slate-600 dark:text-slate-400 font-normal leading-relaxed">
                      Combines AI, link analysis, and trusted global security intelligence from VirusTotal and OpenPhish.
                    </p>
                  </div>

                  {/* Pillar 3 */}
                  <div data-animate="about-pillar" className="p-5 rounded-2xl bg-white dark:bg-gray-900 border border-slate-200 dark:border-slate-800 space-y-2 shadow-sm">
                    <div className="flex items-center gap-2.5">
                      <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-600 dark:text-cyan-400">
                        <span className="material-symbols-outlined text-[18px]">person_check</span>
                      </div>
                      <h4 className="font-heading font-bold text-sm sm:text-base text-slate-900 dark:text-white uppercase tracking-tight">
                        User-Focused
                      </h4>
                    </div>
                    <p className="text-xs sm:text-sm text-slate-600 dark:text-slate-400 font-normal leading-relaxed">
                      Clear recommendations and safety guidance designed to support everyday browsing decisions.
                    </p>
                  </div>

                  {/* Pillar 4 */}
                  <div data-animate="about-pillar" className="p-5 rounded-2xl bg-white dark:bg-gray-900 border border-slate-200 dark:border-slate-800 space-y-2 shadow-sm">
                    <div className="flex items-center gap-2.5">
                      <div className="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-600 dark:text-emerald-400">
                        <span className="material-symbols-outlined text-[18px]">security</span>
                      </div>
                      <h4 className="font-heading font-bold text-sm sm:text-base text-slate-900 dark:text-white uppercase tracking-tight">
                        Security-First
                      </h4>
                    </div>
                    <p className="text-xs sm:text-sm text-slate-600 dark:text-slate-400 font-normal leading-relaxed">
                      Designed to analyze suspicious links without exposing users to unnecessary risk.
                    </p>
                  </div>
                </div>
              </div>
            </section>

          </div>
        )}

        {/* VIEW 2: SCAN HISTORY */}
        {currentView === 'history' && (
          <div className="pt-2">
            <ScanHistory
              isSignedIn={isSignedIn}
              userEmail={userEmail}
              onInspectScan={handleInspectScan}
              onOpenAuthModal={openAuthModal}
            />
          </div>
        )}

      </main>

      {/* ISOLATED PREVIEW MODAL */}
      {previewModalOpen && isSafeImageDataUrl(previewData?.screenshot) && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-md animate-fade-in font-sans">
          <div className="relative w-full max-w-5xl max-h-[90vh] bg-white dark:bg-gray-900 border border-slate-200 dark:border-slate-800 rounded-2xl overflow-hidden shadow-2xl flex flex-col">
            {/* Modal Header */}
            <div className="px-6 py-4 bg-slate-50 dark:bg-slate-800/80 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <span className="material-symbols-outlined text-sky-600 dark:text-sky-400 text-[22px]">preview</span>
                <div>
                  <div className="font-heading font-semibold text-slate-900 dark:text-white text-base">Website Preview</div>
                  <div className="font-mono text-xs sm:text-sm text-slate-500 dark:text-slate-400">{previewData.finalUrl || result?.url}</div>
                </div>
              </div>
              <button
                onClick={() => setPreviewModalOpen(false)}
                className="h-9 w-9 rounded-xl bg-slate-200 dark:bg-slate-800 hover:bg-slate-300 dark:hover:bg-slate-700 flex items-center justify-center text-slate-600 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white transition-colors cursor-pointer"
              >
                <span className="material-symbols-outlined text-[20px]">close</span>
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-4 sm:p-6 overflow-auto flex-1 flex items-center justify-center bg-slate-950">
              <img
                src={previewData.screenshot}
                alt="Website preview capture"
                className="max-w-full h-auto rounded-xl border border-slate-800 shadow-xl"
              />
            </div>

            {/* Modal Footer */}
            <div className="px-6 py-3.5 bg-slate-50 dark:bg-slate-800/80 border-t border-slate-200 dark:border-slate-800 flex items-center justify-between text-xs sm:text-sm font-sans text-slate-500 dark:text-slate-400">
              <span className="flex items-center gap-2 text-emerald-600 dark:text-emerald-400 font-medium">
                <span className="material-symbols-outlined text-[16px]">lock</span>
                Safe Preview (Captured in an isolated environment)
              </span>
              <span className="font-mono">HTTP {previewData.status}</span>
            </div>
          </div>
        </div>
      )}

      {/* AUTHENTICATION & VERIFICATION MODAL */}
      <AuthModal
        isOpen={isAuthModalOpen}
        initialView={authModalView}
        initialNotice={authModalNotice}
        onClose={closeAuthModal}
        onAuthSuccess={handleAuthSuccess}
      />

      {/* Footer */}
      <footer className="w-full py-10 border-t border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-950 transition-colors relative z-10">
        <div className="flex flex-col md:flex-row justify-between items-center px-4 sm:px-6 lg:px-8 xl:px-12 max-w-[1360px] mx-auto gap-4">
          <div className="flex items-center gap-2.5 font-heading text-lg font-bold text-slate-900 dark:text-white">
            <img src="/phishsense_icon.png" alt="PhishSense Logo" className="w-7 h-7 object-contain" />
            <span>PhishSense</span>
          </div>
          <div className="flex flex-wrap justify-center gap-7 text-slate-600 dark:text-slate-400 text-sm sm:text-[15px] font-normal">
            <a className="hover:text-sky-600 dark:hover:text-sky-400 transition-colors" href="#privacy">Privacy Policy</a>
            <a className="hover:text-sky-600 dark:hover:text-sky-400 transition-colors" href="#terms">Terms of Service</a>
            <a className="hover:text-sky-600 dark:hover:text-sky-400 transition-colors" href="#disclosure">Security Disclosure</a>
            <a className="hover:text-sky-600 dark:hover:text-sky-400 transition-colors" href="#api">API Docs</a>
          </div>
          <div className="text-slate-400 dark:text-slate-500 font-mono text-xs sm:text-sm">
            &copy; 2026 PhishSense Security. All rights reserved.
          </div>
        </div>
      </footer>

    </div>
  );
}

export default App;
