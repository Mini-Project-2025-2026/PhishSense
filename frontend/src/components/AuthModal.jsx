import React, { useState, useEffect, useRef } from 'react';
import gsap from 'gsap';
import { isReducedMotion } from '../utils/helpers';
import {
  registerUserApi,
  loginUserApi,
  verifyEmailApi,
  resendVerificationApi,
  forgotPasswordApi,
  resetPasswordApi
} from '../services/api';
import Button from './Button';
import secureLoginIllustration from '../assets/secure-login.svg';

/**
 * Helper to mask email address for privacy (e.g. m********@gmail.com)
 */
function maskEmail(rawEmail) {
  if (!rawEmail || typeof rawEmail !== 'string') return '';
  const parts = rawEmail.split('@');
  if (parts.length !== 2) return rawEmail;
  const [username, domain] = parts;
  if (username.length <= 2) {
    return `${username[0]}*@${domain}`;
  }
  const visible = username.slice(0, 1);
  const masked = '*'.repeat(Math.min(8, username.length - 1));
  return `${visible}${masked}@${domain}`;
}

export function AuthModal({
  isOpen,
  initialView = 'signin', // 'signin' | 'signup' | 'verify' | 'verified_success' | 'forgot' | 'reset'
  initialEmail = '',
  initialNotice = '',
  onClose,
  onAuthSuccess
}) {
  const [view, setView] = useState(initialView);
  const [email, setEmail] = useState(initialEmail);
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [resetToken, setResetToken] = useState('');
  const [name, setName] = useState('');

  // 6-digit OTP State
  const [otp, setOtp] = useState(['', '', '', '', '', '']);
  const otpInputRefs = useRef([]);

  // Password Visibility Toggles
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);

  // Status & Feedback
  const [loading, setLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');
  const [successMessage, setSuccessMessage] = useState('');
  const [notice, setNotice] = useState(initialNotice);
  const [unverifiedEmail, setUnverifiedEmail] = useState('');

  // Resend countdown timer (30 seconds)
  const [resendCooldown, setResendCooldown] = useState(30);

  // Verified User Session Cache
  const [verifiedSession, setVerifiedSession] = useState(null);
  const dialogRef = useRef(null);
  const leftPanelRef = useRef(null);
  const rightPanelRef = useRef(null);

  useEffect(() => {
    setView(initialView);
    setEmail(initialEmail);
    setNotice(initialNotice);
    setErrorMessage('');
    setSuccessMessage('');
    setPassword('');
    setConfirmPassword('');
    setOtp(['', '', '', '', '', '']);
    setResetToken('');
    setVerifiedSession(null);
  }, [isOpen, initialView, initialEmail, initialNotice]);

  // GSAP Entrance & View Switch Micro-Animation
  useEffect(() => {
    if (!isOpen || isReducedMotion() || !dialogRef.current) return;

    const ctx = gsap.context(() => {
      gsap.from(dialogRef.current, {
        opacity: 0,
        scale: 0.98,
        y: 8,
        duration: 0.28,
        ease: 'power2.out'
      });
      if (leftPanelRef.current) {
        gsap.from(leftPanelRef.current, {
          opacity: 0,
          x: -10,
          duration: 0.35,
          ease: 'power2.out'
        });
      }
      if (rightPanelRef.current) {
        gsap.from(rightPanelRef.current, {
          opacity: 0,
          x: 10,
          duration: 0.35,
          ease: 'power2.out'
        });
      }
    }, dialogRef);

    return () => ctx.revert();
  }, [isOpen, view]);

  // Handle countdown interval for resend cooldown
  useEffect(() => {
    let timer = null;
    if ((view === 'verify' || view === 'unverified') && resendCooldown > 0) {
      timer = setInterval(() => {
        setResendCooldown((prev) => (prev > 0 ? prev - 1 : 0));
      }, 1000);
    }
    return () => {
      if (timer) clearInterval(timer);
    };
  }, [view, resendCooldown]);

  // Focus the first OTP box when entering verify view
  useEffect(() => {
    if (view === 'verify' || view === 'unverified') {
      setTimeout(() => {
        if (otpInputRefs.current[0]) {
          otpInputRefs.current[0].focus();
        }
      }, 100);
    }
  }, [view]);

  // Close modal on Escape key press
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape' && isOpen && !loading) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, loading, onClose]);

  if (!isOpen) return null;

  // Password Strength Calculation (Client-side mirror of backend policy)
  const calculateStrength = (pass) => {
    if (!pass) return { score: 0, label: 'Weak', barColor: 'bg-slate-200 dark:bg-slate-700', width: '0%' };
    if (pass.length < 12) return { score: 1, label: 'Too short (minimum 12 characters)', barColor: 'bg-red-500', width: '25%' };

    let score = 1;
    if (pass.length >= 16) score += 1;
    if (/[a-z]/.test(pass) && /[A-Z]/.test(pass)) score += 1;
    if (/\d/.test(pass) || /[^a-zA-Z0-9]/.test(pass)) score += 1;

    if (score === 2) return { score: 2, label: 'Fair', barColor: 'bg-amber-500', width: '50%' };
    if (score === 3) return { score: 3, label: 'Strong', barColor: 'bg-sky-500', width: '75%' };
    return { score: 4, label: 'Very Strong', barColor: 'bg-emerald-500', width: '100%' };
  };

  const strength = calculateStrength(password);
  const passwordsMatch = password && confirmPassword && password === confirmPassword;
  const passwordsMismatched = confirmPassword && password !== confirmPassword;

  // Handle OTP Box Input Change
  const handleOtpChange = (index, value) => {
    const cleanValue = value.replace(/\D/g, '').slice(-1);
    const newOtp = [...otp];
    newOtp[index] = cleanValue;
    setOtp(newOtp);
    setErrorMessage('');

    // Advance focus to next input if digit entered
    if (cleanValue && index < 5 && otpInputRefs.current[index + 1]) {
      otpInputRefs.current[index + 1].focus();
    }
  };

  // Handle OTP Box KeyDown (Backspace & Arrows)
  const handleOtpKeyDown = (index, e) => {
    if (e.key === 'Backspace') {
      if (!otp[index] && index > 0 && otpInputRefs.current[index - 1]) {
        otpInputRefs.current[index - 1].focus();
      }
    } else if (e.key === 'ArrowLeft' && index > 0) {
      otpInputRefs.current[index - 1].focus();
    } else if (e.key === 'ArrowRight' && index < 5) {
      otpInputRefs.current[index + 1].focus();
    }
  };

  // Handle Full OTP Paste Event
  const handleOtpPaste = (e) => {
    e.preventDefault();
    const pastedData = e.clipboardData.getData('text').replace(/\D/g, '').slice(0, 6);
    if (!pastedData) return;

    const newOtp = [...otp];
    for (let i = 0; i < 6; i++) {
      newOtp[i] = pastedData[i] || '';
    }
    setOtp(newOtp);
    setErrorMessage('');

    const focusIndex = Math.min(5, pastedData.length);
    if (otpInputRefs.current[focusIndex]) {
      otpInputRefs.current[focusIndex].focus();
    }
  };

  // Handle Sign In Submit
  const handleSignIn = async (e) => {
    e.preventDefault();
    setErrorMessage('');
    setSuccessMessage('');
    setNotice('');

    if (!email || !password) {
      setErrorMessage('Please enter your email and password.');
      return;
    }

    setLoading(true);
    try {
      const data = await loginUserApi({ email, password });
      onAuthSuccess(data.user, data.token);
      onClose();
    } catch (err) {
      if (err.isUnverified) {
        setUnverifiedEmail(err.unverifiedEmail || email);
        setView('verify');
        setNotice('Please verify your email address before signing in.');
        setResendCooldown(30);
      } else {
        setErrorMessage(err.message || 'Email or password is incorrect.');
      }
    } finally {
      setLoading(false);
    }
  };

  // Handle Sign Up Submit
  const handleSignUp = async (e) => {
    e.preventDefault();
    setErrorMessage('');
    setSuccessMessage('');

    if (password.length < 12) {
      setErrorMessage('Password must be at least 12 characters long.');
      return;
    }

    if (password !== confirmPassword) {
      setErrorMessage('Passwords do not match.');
      return;
    }

    setLoading(true);
    try {
      await registerUserApi({ email, password, name });
      setUnverifiedEmail(email);
      setView('verify');
      setResendCooldown(30);
      setSuccessMessage('Account created! We sent a 6-digit verification code to your email.');
    } catch (err) {
      setErrorMessage(err.message || 'Registration failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  // Handle 6-Digit Email OTP Verification Submit
  const handleVerifyEmail = async (e) => {
    if (e) e.preventDefault();
    setErrorMessage('');
    setSuccessMessage('');

    const code = otp.join('');
    if (code.length !== 6) {
      setErrorMessage('Please enter all 6 digits of your verification code.');
      return;
    }

    const targetEmail = unverifiedEmail || email;
    if (!targetEmail) {
      setErrorMessage('Email address is missing. Please sign up or sign in again.');
      return;
    }

    setLoading(true);
    try {
      const data = await verifyEmailApi({ email: targetEmail, code });
      setVerifiedSession({ user: data.user, token: data.token });
      setView('verified_success');
    } catch (err) {
      setErrorMessage(err.message || "That code isn't correct. Please check your email and try again.");
    } finally {
      setLoading(false);
    }
  };

  // Handle Resend Verification Code
  const handleResendVerification = async () => {
    if (resendCooldown > 0) return;
    const targetEmail = unverifiedEmail || email;
    if (!targetEmail) return;

    setLoading(true);
    setErrorMessage('');
    setSuccessMessage('');
    try {
      await resendVerificationApi(targetEmail);
      setResendCooldown(30);
      setOtp(['', '', '', '', '', '']);
      setSuccessMessage('A fresh 6-digit code has been sent to your email.');
      if (otpInputRefs.current[0]) {
        otpInputRefs.current[0].focus();
      }
    } catch (err) {
      setErrorMessage(err.message || 'Failed to resend verification code.');
    } finally {
      setLoading(false);
    }
  };

  // Continue after successful verification
  const handleContinueToPhishSense = () => {
    if (verifiedSession) {
      onAuthSuccess(verifiedSession.user, verifiedSession.token);
    }
    onClose();
  };

  // Handle Forgot Password Request
  const handleForgotPassword = async (e) => {
    e.preventDefault();
    setErrorMessage('');
    setSuccessMessage('');

    if (!email) {
      setErrorMessage('Please enter your email address.');
      return;
    }

    setLoading(true);
    try {
      const data = await forgotPasswordApi(email);
      setSuccessMessage(data.message || 'Password reset instructions sent.');
      setTimeout(() => setView('reset'), 1500);
    } catch (err) {
      setErrorMessage(err.message || 'Error requesting password reset.');
    } finally {
      setLoading(false);
    }
  };

  // Handle Reset Password Submit
  const handleResetPassword = async (e) => {
    e.preventDefault();
    setErrorMessage('');
    setSuccessMessage('');

    if (!resetToken) {
      setErrorMessage('Reset token is required.');
      return;
    }

    if (password.length < 12) {
      setErrorMessage('New password must be at least 12 characters.');
      return;
    }

    if (password !== confirmPassword) {
      setErrorMessage('Passwords do not match.');
      return;
    }

    setLoading(true);
    try {
      const data = await resetPasswordApi({ token: resetToken.trim(), newPassword: password });
      setSuccessMessage(data.message || 'Password changed successfully!');
      setTimeout(() => {
        setView('signin');
        setPassword('');
        setConfirmPassword('');
        setSuccessMessage('Your password was updated. Please sign in with your new password.');
      }, 1500);
    } catch (err) {
      setErrorMessage(err.message || 'Failed to reset password.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-6 bg-slate-950/75 backdrop-blur-md animate-fade-in font-sans overflow-y-auto"
      role="dialog"
      aria-modal="true"
      aria-labelledby="auth-modal-title"
    >
      <div
        ref={dialogRef}
        className="relative w-full max-w-md md:max-w-4xl lg:max-w-[1000px] rounded-3xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-2xl overflow-hidden my-auto grid grid-cols-1 md:grid-cols-12 transition-all duration-300 min-h-[560px]"
      >
        {/* ======================================================== */}
        {/* LEFT COLUMN: HERO VISUAL PANEL (DESKTOP / TABLET: 45-48%) */}
        {/* ======================================================== */}
        <div
          ref={leftPanelRef}
          className="hidden md:flex md:col-span-5 lg:col-span-5 flex-col justify-between p-8 lg:p-10 bg-gradient-to-br from-sky-50/70 via-slate-50 to-indigo-50/40 dark:from-slate-950 dark:via-slate-900 dark:to-slate-900 border-r border-slate-200 dark:border-slate-800 relative select-none"
        >
          {/* Subtle Ambient Radial Glow */}
          <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-72 h-72 bg-sky-500/10 dark:bg-sky-500/15 rounded-full blur-3xl pointer-events-none" />

          {/* Top Brand Header */}
          <div className="space-y-1 relative z-10">
            <div className="flex items-center gap-3">
              <img src="/phishsense_icon.png" alt="PhishSense" className="w-8 h-8 object-contain drop-shadow-sm" />
              <span className="font-heading font-bold text-slate-900 dark:text-white text-2xl tracking-tight">PhishSense</span>
            </div>
            <p className="text-xs sm:text-sm font-semibold text-sky-600 dark:text-sky-400">
              Scan smarter. Stay safer.
            </p>
          </div>

          {/* Hero Illustration (Prominent, Filling Available Panel Space) */}
          <div className="relative z-10 my-auto py-6 flex items-center justify-center w-full">
            <img
              src={secureLoginIllustration}
              alt="PhishSense Secure Authentication"
              aria-hidden="true"
              className="w-full max-w-[320px] lg:max-w-[380px] max-h-[280px] lg:max-h-[320px] object-contain drop-shadow-md transition-transform duration-500 hover:scale-[1.02]"
            />
          </div>

          {/* Lower Security Feature Badges */}
          <div className="relative z-10 space-y-2.5 pt-5 border-t border-slate-200/90 dark:border-slate-800/90 text-xs text-slate-600 dark:text-slate-300 font-medium">
            <div className="flex items-center gap-2.5">
              <span className="material-symbols-outlined text-[17px] text-sky-500 shrink-0">verified_user</span>
              <span>Multi-layer heuristic threat detection</span>
            </div>
            <div className="flex items-center gap-2.5">
              <span className="material-symbols-outlined text-[17px] text-sky-500 shrink-0">shield_lock</span>
              <span>Zero-execution isolated preview engine</span>
            </div>
            <div className="flex items-center gap-2.5">
              <span className="material-symbols-outlined text-[17px] text-sky-500 shrink-0">bolt</span>
              <span>Real-time URLBERT v4 AI inference</span>
            </div>
          </div>
        </div>

        {/* ======================================================== */}
        {/* RIGHT COLUMN: AUTHENTICATION FORMS (52-55%)              */}
        {/* ======================================================== */}
        <div
          ref={rightPanelRef}
          className="col-span-1 md:col-span-7 lg:col-span-7 p-6 sm:p-8 lg:p-11 flex flex-col justify-center relative bg-white dark:bg-slate-900"
        >
          {/* Close Button */}
          <button
            onClick={onClose}
            className="absolute top-4 right-4 text-slate-400 hover:text-slate-600 dark:hover:text-white transition-colors cursor-pointer p-1.5 rounded-xl hover:bg-slate-100 dark:hover:bg-slate-800 flex items-center justify-center z-20"
            aria-label="Close modal"
          >
            <span className="material-symbols-outlined text-[20px]">close</span>
          </button>

          {/* Mobile-Only Header */}
          <div className="md:hidden flex items-center gap-2.5 mb-5">
            <img src="/phishsense_icon.png" alt="PhishSense" className="w-7 h-7 object-contain" />
            <div className="flex flex-col">
              <span className="font-heading font-bold text-slate-900 dark:text-white text-lg leading-tight">PhishSense</span>
              <span className="text-[11px] font-semibold text-sky-600 dark:text-sky-400 leading-tight">Scan smarter. Stay safer.</span>
            </div>
          </div>

          {/* Global Alert / Notice */}
          {notice && (
            <div className="mb-4 p-3.5 rounded-xl bg-amber-50 text-amber-800 border border-amber-200 dark:bg-amber-950/40 dark:text-amber-300 dark:border-amber-800/70 text-xs sm:text-sm font-sans flex items-center gap-2">
              <span className="material-symbols-outlined text-[18px] text-amber-600 dark:text-amber-400 shrink-0">info</span>
              <span>{notice}</span>
            </div>
          )}

          {/* Success Message Banner */}
          {successMessage && (
            <div className="mb-4 p-3.5 rounded-xl bg-emerald-50 text-emerald-800 border border-emerald-200 dark:bg-emerald-950/40 dark:text-emerald-300 dark:border-emerald-800/70 text-xs sm:text-sm font-sans flex items-center gap-2">
              <span className="material-symbols-outlined text-[18px] text-emerald-600 dark:text-emerald-400 shrink-0">check_circle</span>
              <span>{successMessage}</span>
            </div>
          )}

          {/* ======================================================== */}
          {/* VIEW 1: SIGN IN                                          */}
          {/* ======================================================== */}
          {view === 'signin' && (
            <div className="space-y-4">
              <div>
                <h3 id="auth-modal-title" className="font-heading text-2xl font-bold text-slate-900 dark:text-white mb-1">
                  Welcome back
                </h3>
                <p className="text-sm text-slate-600 dark:text-slate-400 font-normal">
                  Sign in to access your PhishSense account.
                </p>
              </div>

              <form onSubmit={handleSignIn} className="space-y-3.5">
                <div>
                  <label className="block text-xs font-mono text-slate-600 dark:text-slate-400 mb-1">
                    Email
                  </label>
                  <input
                    type="email"
                    required
                    className="w-full h-12 px-3.5 rounded-xl bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white text-sm sm:text-base focus:outline-none focus:border-sky-500 font-mono shadow-sm"
                    placeholder="you@example.com"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                  />
                </div>

                <div>
                  <div className="flex justify-between items-center mb-1">
                    <label className="block text-xs font-mono text-slate-600 dark:text-slate-400">
                      Password
                    </label>
                    <button
                      type="button"
                      onClick={() => { setView('forgot'); setErrorMessage(''); setSuccessMessage(''); }}
                      className="text-xs text-sky-600 dark:text-sky-400 hover:underline cursor-pointer"
                    >
                      Forgot password?
                    </button>
                  </div>
                  <div className="relative">
                    <input
                      type={showPassword ? 'text' : 'password'}
                      required
                      className="w-full h-12 pl-3.5 pr-10 rounded-xl bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white text-sm sm:text-base focus:outline-none focus:border-sky-500 font-mono shadow-sm"
                      placeholder="••••••••••••"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 cursor-pointer flex items-center justify-center"
                      aria-label={showPassword ? 'Hide password' : 'Show password'}
                    >
                      <span className="material-symbols-outlined text-[20px]">
                        {showPassword ? 'visibility_off' : 'visibility'}
                      </span>
                    </button>
                  </div>
                </div>

                {errorMessage && (
                  <div className="p-3 rounded-xl bg-red-50 text-red-700 border border-red-200 dark:bg-red-950/40 dark:text-red-300 dark:border-red-800/70 text-xs sm:text-sm font-sans flex items-center gap-2">
                    <span className="material-symbols-outlined text-[16px] shrink-0">error</span>
                    <span>{errorMessage}</span>
                  </div>
                )}

                <Button
                  type="submit"
                  size="md"
                  variant="primary"
                  fullWidth
                  loading={loading}
                >
                  Sign In
                </Button>
              </form>

              <div className="text-center pt-3 border-t border-slate-200 dark:border-slate-800 text-xs sm:text-sm text-slate-600 dark:text-slate-400">
                Don&apos;t have an account?{' '}
                <button
                  type="button"
                  onClick={() => { setView('signup'); setErrorMessage(''); setSuccessMessage(''); }}
                  className="text-sky-600 dark:text-sky-400 font-semibold hover:underline cursor-pointer ml-1"
                >
                  Sign Up
                </button>
              </div>
            </div>
          )}

          {/* ======================================================== */}
          {/* VIEW 2: SIGN UP                                          */}
          {/* ======================================================== */}
          {view === 'signup' && (
            <div className="space-y-4">
              <div>
                <h3 id="auth-modal-title" className="font-heading text-2xl font-bold text-slate-900 dark:text-white mb-1">
                  Create your account
                </h3>
                <p className="text-sm text-slate-600 dark:text-slate-400 font-normal">
                  Protect yourself from suspicious links with PhishSense.
                </p>
              </div>

              <form onSubmit={handleSignUp} className="space-y-3.5">
                <div>
                  <label className="block text-xs font-mono text-slate-600 dark:text-slate-400 mb-1">
                    Full name <span className="text-slate-400 dark:text-slate-500 font-sans">(Optional)</span>
                  </label>
                  <input
                    type="text"
                    className="w-full h-12 px-3.5 rounded-xl bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white text-sm sm:text-base focus:outline-none focus:border-sky-500 font-sans shadow-sm"
                    placeholder="Jane Doe"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                  />
                </div>

                <div>
                  <label className="block text-xs font-mono text-slate-600 dark:text-slate-400 mb-1">
                    Email
                  </label>
                  <input
                    type="email"
                    required
                    className="w-full h-12 px-3.5 rounded-xl bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white text-sm sm:text-base focus:outline-none focus:border-sky-500 font-mono shadow-sm"
                    placeholder="you@example.com"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                  />
                </div>

                <div>
                  <div className="flex justify-between items-center mb-1">
                    <label className="block text-xs font-mono text-slate-600 dark:text-slate-400">
                      Password
                    </label>
                    {password && (
                      <span className="text-xs font-sans font-medium text-slate-500 dark:text-slate-400">
                        Strength: <strong>{strength.label}</strong>
                      </span>
                    )}
                  </div>
                  <div className="relative">
                    <input
                      type={showPassword ? 'text' : 'password'}
                      required
                      minLength={12}
                      className="w-full h-12 pl-3.5 pr-10 rounded-xl bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white text-sm sm:text-base focus:outline-none focus:border-sky-500 font-mono shadow-sm"
                      placeholder="Create a password (min. 12 chars)"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 cursor-pointer flex items-center justify-center"
                      aria-label={showPassword ? 'Hide password' : 'Show password'}
                    >
                      <span className="material-symbols-outlined text-[20px]">
                        {showPassword ? 'visibility_off' : 'visibility'}
                      </span>
                    </button>
                  </div>

                  {/* Password Strength Bar */}
                  {password && (
                    <div className="mt-1.5 space-y-1">
                      <div className="w-full h-1.5 bg-slate-200 dark:bg-slate-800 rounded-full overflow-hidden">
                        <div
                          className={`h-full ${strength.barColor} transition-all duration-300 rounded-full`}
                          style={{ width: strength.width }}
                        ></div>
                      </div>
                    </div>
                  )}
                </div>

                <div>
                  <div className="flex justify-between items-center mb-1">
                    <label className="block text-xs font-mono text-slate-600 dark:text-slate-400">
                      Confirm password
                    </label>
                    {passwordsMatch && (
                      <span className="text-xs font-sans text-emerald-600 dark:text-emerald-400 font-semibold flex items-center gap-1">
                        <span className="material-symbols-outlined text-[15px]">check_circle</span>
                        <span>Passwords match</span>
                      </span>
                    )}
                    {passwordsMismatched && (
                      <span className="text-xs font-sans text-red-500 font-semibold">
                        Passwords do not match
                      </span>
                    )}
                  </div>
                  <div className="relative">
                    <input
                      type={showConfirmPassword ? 'text' : 'password'}
                      required
                      minLength={12}
                      className="w-full h-12 pl-3.5 pr-10 rounded-xl bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white text-sm sm:text-base focus:outline-none focus:border-sky-500 font-mono shadow-sm"
                      placeholder="Repeat password"
                      value={confirmPassword}
                      onChange={(e) => setConfirmPassword(e.target.value)}
                    />
                    <button
                      type="button"
                      onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 cursor-pointer flex items-center justify-center"
                      aria-label={showConfirmPassword ? 'Hide confirm password' : 'Show confirm password'}
                    >
                      <span className="material-symbols-outlined text-[20px]">
                        {showConfirmPassword ? 'visibility_off' : 'visibility'}
                      </span>
                    </button>
                  </div>
                </div>

                {errorMessage && (
                  <div className="p-3 rounded-xl bg-red-50 text-red-700 border border-red-200 dark:bg-red-950/40 dark:text-red-300 dark:border-red-800/70 text-xs sm:text-sm font-sans flex items-center gap-2">
                    <span className="material-symbols-outlined text-[16px] shrink-0">error</span>
                    <span>{errorMessage}</span>
                  </div>
                )}

                <Button
                  type="submit"
                  size="md"
                  variant="primary"
                  fullWidth
                  loading={loading}
                >
                  Create Account
                </Button>
              </form>

              <div className="text-center pt-3 border-t border-slate-200 dark:border-slate-800 text-xs sm:text-sm text-slate-600 dark:text-slate-400">
                Already have an account?{' '}
                <button
                  type="button"
                  onClick={() => { setView('signin'); setErrorMessage(''); setSuccessMessage(''); }}
                  className="text-sky-600 dark:text-sky-400 font-semibold hover:underline cursor-pointer ml-1"
                >
                  Sign In
                </button>
              </div>
            </div>
          )}

          {/* ======================================================== */}
          {/* VIEW 3: 6-DIGIT EMAIL OTP VERIFICATION SCREEN            */}
          {/* ======================================================== */}
          {(view === 'verify' || view === 'unverified') && (
            <div className="space-y-5 text-center">
              <div className="w-14 h-14 mx-auto rounded-2xl bg-sky-500/10 border border-sky-500/20 p-2.5 flex items-center justify-center shadow-sm">
                <img src="/phishsense_icon.png" alt="PhishSense" className="w-full h-full object-contain" />
              </div>

              <div className="space-y-1">
                <h3 className="font-heading text-2xl font-bold text-slate-900 dark:text-white">
                  Check your email
                </h3>
                <p className="text-sm text-slate-600 dark:text-slate-400 font-normal">
                  We sent a 6-digit verification code to:
                </p>
                <div className="font-mono text-base font-semibold text-sky-600 dark:text-sky-400 pt-0.5">
                  {maskEmail(unverifiedEmail || email)}
                </div>
                <p className="text-xs text-slate-500 dark:text-slate-400 pt-1">
                  Enter the code below to verify your account.
                </p>
              </div>

              <form onSubmit={handleVerifyEmail} className="space-y-4">
                {/* 6 Visual OTP Input Boxes */}
                <div className="flex justify-center gap-2 sm:gap-3 my-2" onPaste={handleOtpPaste}>
                  {otp.map((digit, index) => (
                    <input
                      key={index}
                      ref={(el) => (otpInputRefs.current[index] = el)}
                      type="text"
                      inputMode="numeric"
                      pattern="[0-9]*"
                      maxLength={1}
                      value={digit}
                      onChange={(e) => handleOtpChange(index, e.target.value)}
                      onKeyDown={(e) => handleOtpKeyDown(index, e)}
                      className="w-10 h-13 sm:w-12 sm:h-14 text-center text-xl sm:text-2xl font-mono font-bold rounded-xl bg-slate-50 dark:bg-slate-800 border-2 border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white focus:border-sky-500 focus:ring-2 focus:ring-sky-500/20 focus:outline-none transition-all shadow-sm select-all"
                    />
                  ))}
                </div>

                {errorMessage && (
                  <div className="p-3 rounded-xl bg-red-50 text-red-700 border border-red-200 dark:bg-red-950/40 dark:text-red-300 dark:border-red-800/70 text-xs sm:text-sm font-sans flex items-center justify-center gap-2">
                    <span className="material-symbols-outlined text-[16px] shrink-0">error</span>
                    <span>{errorMessage}</span>
                  </div>
                )}

                <Button
                  type="submit"
                  size="md"
                  variant="primary"
                  fullWidth
                  disabled={otp.join('').length !== 6}
                  loading={loading}
                >
                  Verify Email
                </Button>
              </form>

              <div className="space-y-2 pt-2 border-t border-slate-200 dark:border-slate-800 text-xs sm:text-sm font-normal">
                <div className="text-slate-600 dark:text-slate-400">
                  Didn&apos;t receive the code?{' '}
                  {resendCooldown > 0 ? (
                    <span className="text-slate-400 dark:text-slate-500 font-mono">
                      New code available in {resendCooldown}s
                    </span>
                  ) : (
                    <button
                      type="button"
                      onClick={handleResendVerification}
                      disabled={loading}
                      className="text-sky-600 dark:text-sky-400 font-semibold hover:underline cursor-pointer"
                    >
                      Resend Code
                    </button>
                  )}
                </div>

                <div>
                  <button
                    type="button"
                    onClick={() => { setView('signup'); setErrorMessage(''); setSuccessMessage(''); }}
                    className="text-slate-500 hover:text-slate-800 dark:hover:text-slate-200 hover:underline cursor-pointer text-xs"
                  >
                    Change email address
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* ======================================================== */}
          {/* VIEW 4: SUCCESSFUL EMAIL VERIFICATION CONFIRMATION       */}
          {/* ======================================================== */}
          {view === 'verified_success' && (
            <div className="space-y-5 text-center py-2 animate-fade-in">
              <div className="w-16 h-16 mx-auto rounded-full bg-emerald-500/10 border-2 border-emerald-500/20 flex items-center justify-center shadow-sm">
                <span className="material-symbols-outlined text-[32px] text-emerald-600 dark:text-emerald-400">check_circle</span>
              </div>

              <div className="space-y-1.5">
                <h3 className="font-heading text-2xl font-bold text-slate-900 dark:text-white">
                  Email verified
                </h3>
                <p className="text-sm sm:text-base text-slate-600 dark:text-slate-400 font-normal">
                  Your PhishSense account is ready.
                </p>
              </div>

              <Button
                type="button"
                onClick={handleContinueToPhishSense}
                size="md"
                variant="primary"
                fullWidth
                icon="arrow_forward"
                iconPosition="right"
              >
                Continue to PhishSense
              </Button>
            </div>
          )}

          {/* ======================================================== */}
          {/* VIEW 5: FORGOT PASSWORD                                  */}
          {/* ======================================================== */}
          {view === 'forgot' && (
            <div className="space-y-4">
              <div>
                <h3 className="font-heading text-2xl font-bold text-slate-900 dark:text-white mb-1">
                  Reset your password
                </h3>
                <p className="text-sm text-slate-600 dark:text-slate-400 font-normal">
                  Enter your email address to receive password reset instructions.
                </p>
              </div>

              <form onSubmit={handleForgotPassword} className="space-y-3.5">
                <div>
                  <label className="block text-xs font-mono text-slate-600 dark:text-slate-400 mb-1">
                    Email address
                  </label>
                  <input
                    type="email"
                    required
                    className="w-full h-12 px-3.5 rounded-xl bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white text-sm sm:text-base focus:outline-none focus:border-sky-500 font-mono shadow-sm"
                    placeholder="you@example.com"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                  />
                </div>

                {errorMessage && (
                  <div className="p-3 rounded-xl bg-red-50 text-red-700 border border-red-200 dark:bg-red-950/40 dark:text-red-300 dark:border-red-800/70 text-xs sm:text-sm font-sans flex items-center gap-2">
                    <span className="material-symbols-outlined text-[16px] shrink-0">error</span>
                    <span>{errorMessage}</span>
                  </div>
                )}

                <Button
                  type="submit"
                  size="md"
                  variant="primary"
                  fullWidth
                  loading={loading}
                >
                  Send Reset Instructions
                </Button>
              </form>

              <div className="text-center pt-3 border-t border-slate-200 dark:border-slate-800 text-xs sm:text-sm text-slate-600 dark:text-slate-400">
                Remember your password?{' '}
                <button
                  type="button"
                  onClick={() => { setView('signin'); setErrorMessage(''); setSuccessMessage(''); }}
                  className="text-sky-600 dark:text-sky-400 font-semibold hover:underline cursor-pointer ml-1"
                >
                  Sign In
                </button>
              </div>
            </div>
          )}

          {/* ======================================================== */}
          {/* VIEW 6: RESET PASSWORD FORM                              */}
          {/* ======================================================== */}
          {view === 'reset' && (
            <div className="space-y-4">
              <div>
                <h3 className="font-heading text-2xl font-bold text-slate-900 dark:text-white mb-1">
                  Create new password
                </h3>
                <p className="text-sm text-slate-600 dark:text-slate-400 font-normal">
                  Enter your reset token and your new password.
                </p>
              </div>

              <form onSubmit={handleResetPassword} className="space-y-3.5">
                <div>
                  <label className="block text-xs font-mono text-slate-600 dark:text-slate-400 mb-1">
                    Reset Token
                  </label>
                  <input
                    type="text"
                    required
                    className="w-full h-12 px-3.5 rounded-xl bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white text-sm font-mono focus:outline-none focus:border-sky-500 shadow-sm"
                    placeholder="Paste reset token from email"
                    value={resetToken}
                    onChange={(e) => setResetToken(e.target.value)}
                  />
                </div>

                <div>
                  <div className="flex justify-between items-center mb-1">
                    <label className="block text-xs font-mono text-slate-600 dark:text-slate-400">
                      New Password (Min. 12 characters)
                    </label>
                    {password && (
                      <span className="text-xs font-sans font-medium text-slate-500 dark:text-slate-400">
                        Strength: <strong>{strength.label}</strong>
                      </span>
                    )}
                  </div>
                  <div className="relative">
                    <input
                      type={showPassword ? 'text' : 'password'}
                      required
                      minLength={12}
                      className="w-full h-12 pl-3.5 pr-10 rounded-xl bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white text-sm sm:text-base focus:outline-none focus:border-sky-500 font-mono shadow-sm"
                      placeholder="Enter new password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 cursor-pointer flex items-center justify-center"
                      aria-label={showPassword ? 'Hide password' : 'Show password'}
                    >
                      <span className="material-symbols-outlined text-[20px]">
                        {showPassword ? 'visibility_off' : 'visibility'}
                      </span>
                    </button>
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-mono text-slate-600 dark:text-slate-400 mb-1">
                    Confirm New Password
                  </label>
                  <div className="relative">
                    <input
                      type={showConfirmPassword ? 'text' : 'password'}
                      required
                      minLength={12}
                      className="w-full h-12 pl-3.5 pr-10 rounded-xl bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white text-sm sm:text-base focus:outline-none focus:border-sky-500 font-mono shadow-sm"
                      placeholder="Repeat new password"
                      value={confirmPassword}
                      onChange={(e) => setConfirmPassword(e.target.value)}
                    />
                    <button
                      type="button"
                      onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 cursor-pointer flex items-center justify-center"
                      aria-label={showConfirmPassword ? 'Hide confirm password' : 'Show confirm password'}
                    >
                      <span className="material-symbols-outlined text-[20px]">
                        {showConfirmPassword ? 'visibility_off' : 'visibility'}
                      </span>
                    </button>
                  </div>
                </div>

                {errorMessage && (
                  <div className="p-3 rounded-xl bg-red-50 text-red-700 border border-red-200 dark:bg-red-950/40 dark:text-red-300 dark:border-red-800/70 text-xs sm:text-sm font-sans flex items-center gap-2">
                    <span className="material-symbols-outlined text-[16px] shrink-0">error</span>
                    <span>{errorMessage}</span>
                  </div>
                )}

                <Button
                  type="submit"
                  size="md"
                  variant="primary"
                  fullWidth
                  loading={loading}
                >
                  Reset Password
                </Button>
              </form>
            </div>
          )}

        </div>
      </div>
    </div>
  );
}

export default AuthModal;
