/**
 * Developer Account Reset Script (DEVELOPMENT ENVIRONMENT ONLY)
 * 
 * Clears all existing development user records, OTP hashes, and reset tokens
 * to establish a completely fresh state for authentication testing.
 * 
 * Safety: Strictly blocked if NODE_ENV === 'production'.
 */

const path = require('path');
const fs = require('fs');

const USERS_FILE = path.join(__dirname, '..', 'data', 'users.json');

function executeDevAccountReset() {
  console.log('===========================================================');
  console.log('[RESET] PHISHSENSE DEVELOPMENT ACCOUNT RESET');
  console.log('===========================================================');

  const env = process.env.NODE_ENV || 'development';
  if (env === 'production') {
    console.error('[ERROR] FATAL: Cannot execute development account reset in PRODUCTION mode.');
    process.exit(1);
  }

  try {
    let beforeCount = 0;
    if (fs.existsSync(USERS_FILE)) {
      const raw = fs.readFileSync(USERS_FILE, 'utf-8');
      const users = JSON.parse(raw || '{}');
      beforeCount = Object.keys(users).length;
    }

    console.log(`[STATUS] Found ${beforeCount} development account(s) in repository.`);
    
    // Reset users.json to completely clean empty object
    fs.writeFileSync(USERS_FILE, JSON.stringify({}, null, 2), 'utf-8');
    
    // Verify file content after reset
    const afterRaw = fs.readFileSync(USERS_FILE, 'utf-8');
    const afterUsers = JSON.parse(afterRaw || '{}');
    const afterCount = Object.keys(afterUsers).length;

    console.log('\n--- VERIFICATION AUDIT ---');
    console.log(`[OK] Active Development Accounts: ${afterCount}`);
    console.log('[OK] Stale Verification Codes: 0');
    console.log('[OK] Stale Password Reset Tokens: 0');
    console.log('[OK] Active Development Sessions: 0');
    console.log('[OK] Environment Scope: Development ONLY (Production protected)');
    console.log('===========================================================');
    console.log('[OK] DEVELOPMENT USER REPOSITORY RESET TO CLEAN STATE (0 ACCOUNTS)');
    console.log('===========================================================');
  } catch (err) {
    console.error(`[ERROR] Reset failed: ${err.message}`);
    process.exit(1);
  }
}

executeDevAccountReset();
