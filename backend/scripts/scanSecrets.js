const fs = require('fs');
const path = require('path');

const SECRET_PATTERNS = [
  /(?:api[_-]?key|secret|password|token|auth[_-]?key|private[_-]?key)[\s]*[=:][\s]*['"]([^'"]{12,})['"]/gi,
  /AIza[0-9A-Za-z-_]{35}/g,
  /sk_live_[0-9a-zA-Z]{24}/g,
  /ghp_[0-9a-zA-Z]{36}/g,
  /re_[0-9a-zA-Z]{24,}/g,
];

const IGNORE_DIRS = new Set(['node_modules', '.git', 'dist', 'package-lock.json']);

function scanFile(filePath) {
  const rel = path.relative(process.cwd(), filePath);
  if (rel.includes('.env.example') || rel.includes('package-lock.json')) return;
  const content = fs.readFileSync(filePath, 'utf8');
  for (const pat of SECRET_PATTERNS) {
    let match;
    while ((match = pat.exec(content)) !== null) {
      const val = match[1] || match[0];
      if (
        val.includes('your_') ||
        val.includes('placeholder') ||
        val.includes('example') ||
        val.includes('test') ||
        val.includes('phishsense_') ||
        val.includes('Content-Type') ||
        val.includes('Authorization')
      ) {
        continue;
      }
      console.log(`[ALERT] Potential secret found in ${rel} — value redacted.`);
    }
  }
}

function traverse(dir) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const e of entries) {
    if (IGNORE_DIRS.has(e.name)) continue;
    const full = path.join(dir, e.name);
    if (e.isDirectory()) traverse(full);
    else if (e.isFile() && /\.(js|jsx|json|py|md|html|env)$/i.test(e.name)) scanFile(full);
  }
}

traverse('.');
console.log('[OK] Secret audit scan completed.');
