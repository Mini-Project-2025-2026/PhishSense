const path = require('path');
const fs = require('fs');
const logger = require('../utils/logger');

let ort;
try {
  ort = require('onnxruntime-node');
} catch (err) {
  logger.warn(`onnxruntime-node import failed: ${err.message}`);
}

/**
 * Fast WordPiece Tokenizer for URLBERT.
 * Reads vocabulary from ml/urlbert/tokenizer.json and performs BERT pre-tokenization and WordPiece subword encoding.
 */
class UrlBertTokenizer {
  constructor(tokenizerJsonPath) {
    const raw = fs.readFileSync(tokenizerJsonPath, 'utf8');
    const data = JSON.parse(raw);
    this.vocab = data.model.vocab;
    this.unkTokenId = this.vocab['[UNK]'] ?? 1;
    this.clsTokenId = this.vocab['[CLS]'] ?? 2;
    this.sepTokenId = this.vocab['[SEP]'] ?? 3;
    this.padTokenId = this.vocab['[PAD]'] ?? 0;
    this.maxLength = 64;
  }

  // Pre-tokenization: splits on punctuation and whitespace, preserving punctuation as individual tokens
  preTokenize(text) {
    const clean = text.trim().toLowerCase();
    const tokens = [];
    let currentWord = '';

    const isPunct = (ch) => {
      const code = ch.charCodeAt(0);
      return (code >= 33 && code <= 47) ||
             (code >= 58 && code <= 64) ||
             (code >= 91 && code <= 96) ||
             (code >= 123 && code <= 126);
    };

    const isWhitespace = (ch) => /\s/.test(ch);

    for (let i = 0; i < clean.length; i++) {
      const ch = clean[i];
      if (isWhitespace(ch)) {
        if (currentWord) {
          tokens.push(currentWord);
          currentWord = '';
        }
      } else if (isPunct(ch)) {
        if (currentWord) {
          tokens.push(currentWord);
          currentWord = '';
        }
        tokens.push(ch);
      } else {
        currentWord += ch;
      }
    }
    if (currentWord) {
      tokens.push(currentWord);
    }
    return tokens;
  }

  // WordPiece tokenization per sub-word
  wordPiece(word) {
    if (this.vocab.hasOwnProperty(word)) {
      return [this.vocab[word]];
    }

    const subwordIds = [];
    let start = 0;
    let isBad = false;

    while (start < word.length) {
      let end = word.length;
      let curSubstrId = null;

      while (start < end) {
        let substr = word.substring(start, end);
        if (start > 0) {
          substr = '##' + substr;
        }

        if (this.vocab.hasOwnProperty(substr)) {
          curSubstrId = this.vocab[substr];
          break;
        }
        end -= 1;
      }

      if (curSubstrId === null) {
        isBad = true;
        break;
      }

      subwordIds.push(curSubstrId);
      start = end;
    }

    if (isBad) {
      return [this.unkTokenId];
    }
    return subwordIds;
  }

  encode(text) {
    const words = this.preTokenize(text);
    const tokenIds = [];

    for (const w of words) {
      const ids = this.wordPiece(w);
      tokenIds.push(...ids);
    }

    // Truncate to maxLength - 2 to allow room for [CLS] and [SEP]
    const truncated = tokenIds.slice(0, this.maxLength - 2);
    const fullIds = [this.clsTokenId, ...truncated, this.sepTokenId];
    const actualLength = fullIds.length;

    const inputIds = new Array(this.maxLength).fill(BigInt(this.padTokenId));
    const attentionMask = new Array(this.maxLength).fill(0n);
    const tokenTypeIds = new Array(this.maxLength).fill(0n);

    for (let i = 0; i < actualLength; i++) {
      inputIds[i] = BigInt(fullIds[i]);
      attentionMask[i] = 1n;
    }

    return {
      inputIds: new BigInt64Array(inputIds),
      attentionMask: new BigInt64Array(attentionMask),
      tokenTypeIds: new BigInt64Array(tokenTypeIds)
    };
  }
}

// Session and Tokenizer Singleton State
let session = null;
let tokenizer = null;
let isInitializing = false;
let initPromise = null;

/**
 * Initializes and warms up the URLBERT ONNX session.
 */
async function initModel() {
  if (session && tokenizer) return true;
  if (isInitializing) return initPromise;

  isInitializing = true;
  initPromise = (async () => {
    try {
      if (!ort) {
        throw new Error('onnxruntime-node is not installed or available.');
      }

      const modelDir = path.resolve(__dirname, '../../ml/urlbert');
      const modelPath = path.join(modelDir, 'model.onnx');
      const tokenizerPath = path.join(modelDir, 'tokenizer.json');

      if (!fs.existsSync(modelPath) || !fs.existsSync(tokenizerPath)) {
        throw new Error(`URLBERT model files not found in ${modelDir}`);
      }

      logger.info('Initializing URLBERT v4 ONNX Inference Session...');
      tokenizer = new UrlBertTokenizer(tokenizerPath);
      session = await ort.InferenceSession.create(modelPath, {
        executionProviders: ['cpu']
      });

      // Warmup inference
      const warmupEnc = tokenizer.encode('https://warmup.example.com');
      const warmupFeeds = {
        input_ids: new ort.Tensor('int64', warmupEnc.inputIds, [1, 64]),
        attention_mask: new ort.Tensor('int64', warmupEnc.attentionMask, [1, 64]),
        token_type_ids: new ort.Tensor('int64', warmupEnc.tokenTypeIds, [1, 64])
      };
      await session.run(warmupFeeds);

      logger.info('URLBERT v4 ONNX Model loaded and warmed up successfully.');
      isInitializing = false;
      return true;
    } catch (err) {
      logger.warn(`Failed to initialize URLBERT ONNX model: ${err.message}`);
      isInitializing = false;
      session = null;
      tokenizer = null;
      return false;
    }
  })();

  return initPromise;
}

// Automatically trigger model loading at server boot
initModel().catch(() => {});

/**
 * Generates explainability indicators correctly attributing AI model result.
 */
function generateIndicators(url, prob, confidence, prediction) {
  return [
    `URLBERT classified this URL as ${prediction} (${confidence}% phishing probability).`
  ];
}

// Known legitimate brand domains for token-bias calibration
const LEGITIMATE_BRAND_DOMAINS = [
  { sld: 'google', domain: 'google.com' },
  { sld: 'paypal', domain: 'paypal.com' },
  { sld: 'microsoft', domain: 'microsoft.com' },
  { sld: 'amazon', domain: 'amazon.com' },
  { sld: 'apple', domain: 'apple.com' },
  { sld: 'github', domain: 'github.com' },
  { sld: 'facebook', domain: 'facebook.com' },
  { sld: 'instagram', domain: 'instagram.com' },
  { sld: 'netflix', domain: 'netflix.com' },
  { sld: 'linkedin', domain: 'linkedin.com' },
  { sld: 'pinterest', domain: 'pinterest.com' },
  { sld: 'twitter', domain: 'twitter.com' },
  { sld: 'wikipedia', domain: 'wikipedia.org' },
  { sld: 'youtube', domain: 'youtube.com' },
  { sld: 'binance', domain: 'binance.com' },
  { sld: 'coinbase', domain: 'coinbase.com' },
  { sld: 'steampowered', domain: 'steampowered.com' },
  { sld: 'chase', domain: 'chase.com' },
  { sld: 'wellsfargo', domain: 'wellsfargo.com' }
];

/**
 * Checks if a target URL belongs to an authentic, officially recognized brand apex domain
 * without deceptive subdomains, IP hosts, or spoofing parameters.
 */
function isAuthenticBrandApexDomain(targetUrl) {
  try {
    const parsed = new URL(targetUrl);
    const host = parsed.hostname.toLowerCase();

    // Must not be an IP address or contain punycode
    if (/^[0-9.]+$/.test(host) || host.includes('xn--')) {
      return false;
    }

    for (const brand of LEGITIMATE_BRAND_DOMAINS) {
      const isExactOrSubdomain = (host === brand.domain) || host.endsWith('.' + brand.domain);
      if (isExactOrSubdomain) {
        // Ensure no impersonation subdomains (e.g. login.paypal.evil.com is NOT paypal.com)
        const hostParts = host.split('.');
        const domainParts = brand.domain.split('.');
        const isTrueSuffix = host.endsWith(brand.domain) && 
          (host.length === brand.domain.length || host.charAt(host.length - brand.domain.length - 1) === '.');

        if (isTrueSuffix) {
          // Check that there are no suspicious @ symbols or embedded authentication bypasses in the URL
          if (!targetUrl.includes('@')) {
            return true;
          }
        }
      }
    }
    return false;
  } catch {
    return false;
  }
}

/**
 * Predicts whether a URL is phishing using the local in-process URLBERT ONNX model.
 *
 * Contract:
 * {
 *   available: true,
 *   status: "ACTIVE",
 *   prediction: "PHISHING" | "SUSPICIOUS" | "BENIGN",
 *   probability: 0.98,
 *   confidence: 98,
 *   model_type: "URLBERT Tiny v4 Classifier",
 *   model_version: "4.0.0",
 *   aiModelResult: "URLBERT classified this URL as PHISHING (98% phishing probability).",
 *   importantFeatures: [...],
 *   latencyMs: 15
 * }
 */
exports.predictUrl = async (targetUrl) => {
  const startTime = Date.now();

  try {
    const isReady = await initModel();
    if (!isReady || !session || !tokenizer) {
      throw new Error('URLBERT model session is unavailable.');
    }

    logger.info(`Invoking URLBERT AI inference for: ${targetUrl}`);

    const encoded = tokenizer.encode(targetUrl);
    const feeds = {
      input_ids: new ort.Tensor('int64', encoded.inputIds, [1, 64]),
      attention_mask: new ort.Tensor('int64', encoded.attentionMask, [1, 64]),
      token_type_ids: new ort.Tensor('int64', encoded.tokenTypeIds, [1, 64])
    };

    const results = await session.run(feeds);
    const latencyMs = Date.now() - startTime;

    const logits = results.logits.data; // [logit_good, logit_fish]
    const z0 = logits[0];
    const z1 = logits[1];

    // Numerically stable Softmax calculation
    const maxZ = Math.max(z0, z1);
    const exp0 = Math.exp(z0 - maxZ);
    const exp1 = Math.exp(z1 - maxZ);
    const sumExp = exp0 + exp1;
    let pFish = exp1 / sumExp;

    // Apply domain-context calibration:
    // Pure sequence transformers experience token-bias false positives on legitimate brand names
    // (e.g. 'paypal', 'microsoft', 'amazon') because those brand tokens appear heavily in phishing corpora.
    // If the URL is verified as the authentic apex domain itself (and not a typosquat like paypa1.com),
    // calibrate the probability to reflect legitimate domain ownership.
    if (isAuthenticBrandApexDomain(targetUrl)) {
      pFish = Math.min(pFish * 0.05, 0.05); // Calibrated to benign baseline (<= 5%)
    }

    const prob = Math.round(pFish * 10000) / 10000;
    const confidence = Math.round(pFish * 100);

    // Prediction categorization
    let prediction = 'BENIGN';
    if (prob >= 0.70) {
      prediction = 'PHISHING';
    } else if (prob >= 0.40) {
      prediction = 'SUSPICIOUS';
    } else {
      prediction = 'BENIGN';
    }

    const aiModelResult = `URLBERT classified this URL as ${prediction} (${confidence}% phishing probability).`;
    const importantFeatures = [aiModelResult];

    logger.info(`URLBERT inference success (${latencyMs}ms): ${prediction} (${confidence}%)`);

    return {
      available: true,
      status: 'ACTIVE',
      prediction,
      probability: prob,
      confidence,
      model_type: 'URLBERT Tiny v4 Classifier',
      model_version: '4.0.0',
      aiModelResult,
      importantFeatures,
      latencyMs
    };

  } catch (error) {
    const latencyMs = Date.now() - startTime;
    logger.warn(`URLBERT inference failed or unavailable (${latencyMs}ms): ${error.message}`);

    return {
      available: false,
      status: 'TEMPORARILY UNAVAILABLE',
      error: error.message,
      prediction: 'UNAVAILABLE',
      probability: 0.0,
      confidence: 0,
      importantFeatures: [],
      model_type: 'URLBERT Tiny v4 Classifier',
      model_version: '4.0.0',
      latencyMs
    };
  }
};

