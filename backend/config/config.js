require('dotenv').config();

module.exports = {
  port: process.env.PORT || 5000,
  env: process.env.NODE_ENV || 'development',
  threatIntel: {
    // Future API keys and endpoints
    virusTotalApiKey: process.env.VIRUSTOTAL_API_KEY || '',
    googleSafeBrowsingApiKey: process.env.GOOGLE_SAFE_BROWSING_API_KEY || '',
    urlhausApiKey: process.env.URLHAUS_API_KEY || '',
  },
  database: {
    uri: process.env.MONGODB_URI || 'mongodb://localhost:27017/phishsense',
  }
};
