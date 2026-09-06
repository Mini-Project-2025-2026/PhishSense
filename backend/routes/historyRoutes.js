const express = require('express');
const router = express.Router();
const { optionalAuth } = require('../middleware/authMiddleware');
const historyController = require('../controllers/historyController');

// Apply optionalAuth so req.user is automatically populated from JWT when signed in
router.use(optionalAuth);

// GET /api/v1/history
router.get('/', historyController.getHistory);

// POST /api/v1/history
router.post('/', historyController.addScan);

// DELETE /api/v1/history/:id
router.delete('/:id', historyController.deleteScan);

// DELETE /api/v1/history
router.delete('/', historyController.clearHistory);

module.exports = router;
