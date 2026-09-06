const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '..', '.env') });
const { sendOtpEmail, isRealSmtpConfigured, getTransporter } = require('../services/emailService');

async function runEmailDiagnostic() {
  console.log('===========================================================');
  console.log('[DIAGNOSTIC] PHISHSENSE EMAIL DELIVERY PIPELINE DIAGNOSTIC');
  console.log('===========================================================\n');

  const host = process.env.SMTP_HOST || process.env.EMAIL_HOST;
  const port = process.env.SMTP_PORT || process.env.EMAIL_PORT;
  const user = process.env.SMTP_USER || process.env.EMAIL_USER;
  const pass = process.env.SMTP_PASS || process.env.EMAIL_PASSWORD || process.env.EMAIL_PASS;
  const from = process.env.SMTP_FROM || process.env.EMAIL_FROM;

  console.log('--- 1. Configuration Variable Audit ---');
  console.log('SMTP_HOST / EMAIL_HOST:', host ? `Configured (${host})` : 'MISSING');
  console.log('SMTP_PORT / EMAIL_PORT:', port ? `Configured (${port})` : 'MISSING (Defaults to 587)');
  console.log('SMTP_USER / EMAIL_USER:', user ? `Configured (${user.replace(/(?<=.{2}).(?=.*@)/g, '*')})` : 'MISSING');
  console.log('SMTP_PASS / EMAIL_PASS:', pass ? 'Configured (Secret present)' : 'MISSING');
  console.log('SMTP_FROM / EMAIL_FROM:', from ? `Configured (${from})` : 'Default');
  console.log('Real SMTP Configured:', isRealSmtpConfigured() ? 'YES (Live mail server)' : 'NO (Using Ethereal fallback)');

  console.log('\n--- 2. Transporter Initialization & Verification ---');
  try {
    const transporter = await getTransporter();
    console.log('Transporter initialized: YES');
  } catch (err) {
    console.log('Transporter initialization error:', err.message);
  }

  console.log('\n--- 3. Test Message Dispatch ---');
  const testRecipient = process.argv[2] || user || 'test_diagnostic@phishsense.io';
  console.log(`Dispatching test verification OTP email to: ${testRecipient}...`);

  const sendResult = await sendOtpEmail({
    to: testRecipient,
    code: '482731',
    name: 'PhishSense User'
  });

  console.log('Dispatch success:', sendResult.success);
  if (sendResult.success) {
    console.log('Provider Message ID:', sendResult.messageId);
    console.log('Real SMTP delivery:', sendResult.isRealSmtp ? 'YES (Live Gmail SMTP)' : 'NO (Ethereal test sandbox)');
    if (sendResult.previewUrl) {
      console.log('Ethereal Test Preview URL:', sendResult.previewUrl);
    }
  } else {
    console.log('Delivery Error:', sendResult.error);
  }

  console.log('\n===========================================================');
  console.log('DIAGNOSTIC COMPLETE');
  console.log('===========================================================');
}

runEmailDiagnostic();
