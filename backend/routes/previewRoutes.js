const express = require('express');
const router = express.Router();
const previewController = require('../controllers/previewController');

// POST /api/v1/preview
router.post('/', previewController.generatePreview);

module.exports = router;
