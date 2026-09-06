/**
 * Utility functions for PhishSense frontend.
 */

/**
 * Validates whether a given string is a valid URL.
 * @param {string} urlString
 * @returns {boolean}
 */
export const isValidUrl = (urlString) => {
  try {
    new URL(urlString);
    return true;
  } catch (_) {
    return false;
  }
};

/**
 * Validates whether a given string is a safe, allowed image data URL.
 * Prevents javascript: or malicious SVG injection payloads in img src.
 * @param {string} dataUrl
 * @returns {boolean}
 */
export const isSafeImageDataUrl = (dataUrl) => {
  if (!dataUrl || typeof dataUrl !== 'string') return false;
  return /^data:image\/(png|jpeg|jpg|webp);base64,[A-Za-z0-9+/=\s]+$/.test(dataUrl);
};

/**
 * Checks if the user's OS has requested reduced motion.
 * @returns {boolean}
 */
export const isReducedMotion = () => {
  if (typeof window === 'undefined' || !window.matchMedia) return false;
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
};


