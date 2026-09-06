const express = require('express');
const router = express.Router();
const phishController = require('../controllers/phishController');
const previewController = require('../controllers/previewController');

// Define API routes for phishing analyzer & isolated preview
router.post('/analyze', phishController.analyzeUrl);
router.post('/preview', previewController.generatePreview);

module.exports = router;

