const express = require('express');
const { protect, admin } = require('../middleware/auth');
const { logger } = require('../utils/logger');
const { makeSingleUploader, getFileUrl } = require('../middleware/upload');

const router = express.Router();

// POST /api/uploads/banner - upload a single banner image
router.post('/banner', protect, admin, makeSingleUploader('banners', 'image'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ success: false, message: 'No image file provided' });
    }
    const imageUrl = getFileUrl(req, req.file.filename, 'banners');
    logger.info(`Banner image uploaded: ${req.file.filename}`);
    res.json({ success: true, data: { imageUrl, filename: req.file.filename, size: req.file.size } });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message || 'Upload failed' });
  }
});

module.exports = router;


