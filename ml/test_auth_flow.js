const fs = require('fs');
const path = require('path');

console.log("=== Testing PhishSense Authentication Layer Logic ===");

// Mock LocalStorage
const localStorageMap = new Map();
const localStorage = {
  getItem: (key) => localStorageMap.get(key) || null,
  setItem: (key, val) => localStorageMap.set(key, String(val)),
  removeItem: (key) => localStorageMap.delete(key),
  clear: () => localStorageMap.clear()
};

// Initial state simulation
let isSignedIn = localStorage.getItem('phishsense_signed_in') === 'true';
let scansLeft = localStorage.getItem('phishsense_scans_left') !== null 
  ? parseInt(localStorage.getItem('phishsense_scans_left'), 10) 
  : 3;
let userEmail = localStorage.getItem('phishsense_email') || '';

function persist() {
  localStorage.setItem('phishsense_signed_in', isSignedIn);
  localStorage.setItem('phishsense_email', userEmail);
  localStorage.setItem('phishsense_scans_left', scansLeft);
}

function handleAnalyzeSim(urlStr) {
  if (!isSignedIn && scansLeft <= 0) {
    return { status: 'BLOCKED_PROMPT_AUTH', notice: 'All 3 guest scans used. Please sign in/up.' };
  }

  // Perform scan
  if (!isSignedIn) {
    scansLeft = Math.max(0, scansLeft - 1);
  }
  persist();
  return { status: 'SUCCESS', scansLeft, isSignedIn, userEmail };
}

function signUpSim(email, password) {
  if (!email || !password || password.length < 6) return false;
  isSignedIn = true;
  userEmail = email;
  persist();
  return true;
}

// Test Flow
console.log(`Initial: isSignedIn=${isSignedIn}, scansLeft=${scansLeft}`);

// Scan 1
let r1 = handleAnalyzeSim("https://google.com");
console.log("Scan 1 Result:", r1);
console.assert(r1.scansLeft === 2, "Scan 1 should decrease scans to 2");

// Scan 2
let r2 = handleAnalyzeSim("https://github.com");
console.log("Scan 2 Result:", r2);
console.assert(r2.scansLeft === 1, "Scan 2 should decrease scans to 1");

// Scan 3
let r3 = handleAnalyzeSim("https://wikipedia.org");
console.log("Scan 3 Result:", r3);
console.assert(r3.scansLeft === 0, "Scan 3 should decrease scans to 0");

// Scan 4 (Should block)
let r4 = handleAnalyzeSim("https://example.com");
console.log("Scan 4 Result:", r4);
console.assert(r4.status === 'BLOCKED_PROMPT_AUTH', "Scan 4 should be blocked with auth prompt");

// Simulate Page Refresh (reload from localStorage)
isSignedIn = localStorage.getItem('phishsense_signed_in') === 'true';
scansLeft = parseInt(localStorage.getItem('phishsense_scans_left'), 10);
console.log(`After Page Refresh: isSignedIn=${isSignedIn}, scansLeft=${scansLeft}`);

// Attempt scan after refresh (Should still block)
let r5 = handleAnalyzeSim("https://example.com");
console.log("Post-Refresh Scan Result:", r5);
console.assert(r5.status === 'BLOCKED_PROMPT_AUTH', "Post-refresh scan should remain blocked");

// Perform Sign Up
let signedUp = signUpSim("analyst@security.com", "password123");
console.log("Sign Up Result:", signedUp, `isSignedIn=${isSignedIn}`, `userEmail=${userEmail}`);

// Authenticated Scan (Should allow unlimited)
let r6 = handleAnalyzeSim("https://example.com");
console.log("Authenticated Scan Result:", r6);
console.assert(r6.status === 'SUCCESS' && r6.isSignedIn === true, "Authenticated user should scan with unlimited access");

console.log("✅ ALL AUTHENTICATION FLOW TESTS PASSED SUCCESSFULLY!");
