const express = require('express');
const router = express.Router();
const mongoose = require('mongoose');
const Scan = require('../models/Scan');
const ThreatEngine = require('../services/ThreatEngine');
const { extractDomain, normalizeUrl } = require('../services/phishingAnalyzer');
const { saveInMemoryScan, getInMemoryHistory } = require('../services/inMemoryStore');

/**
 * POST /api/scan
 * Full phishing analysis pipeline using modular ThreatEngine
 */
router.post('/', async (req, res, next) => {
  try {
    let { url } = req.body;

    if (!url || typeof url !== 'string') {
      return res.status(400).json({ success: false, error: 'URL is required' });
    }

    url = url.trim();

    // Validate URL format
    const normalizedUrl = normalizeUrl(url);
    try {
      new URL(normalizedUrl);
    } catch (e) {
      return res.status(400).json({ success: false, error: 'Invalid URL format' });
    }

    const domain = extractDomain(normalizedUrl);

    console.log(`🔍 Deep Scan Initiated: ${normalizedUrl} (Domain: ${domain})`);

    // Use the new ThreatEngine for analysis
    const analysis = await ThreatEngine.analyze(normalizedUrl, domain);

    // Build full result (Ensuring compatibility with existing frontend JSON structure)
    const result = {
      url: normalizedUrl,
      domain,
      threatScore: analysis.threatScore,
      phishingProbability: analysis.phishingProbability,
      riskLevel: analysis.riskLevel,
      issues: analysis.issues,
      piracyStatus: analysis.piracyStatus,
      sslStatus: analysis.sslStatus,
      domainInfo: analysis.domainInfo,
      virusTotal: analysis.virusTotal,
      googleSafeBrowsing: analysis.googleSafeBrowsing,
      ipIntel: analysis.ipIntel,
      engineStatuses: analysis.engineStatuses
    };

    // Save scan result (MongoDB if available, otherwise in-memory)
    let savedScan;
    if (mongoose.connection.readyState === 1) {
      try {
        const scan = new Scan(result);
        await scan.save();
        savedScan = { ...result, _id: scan._id, createdAt: scan.createdAt };
      } catch (dbErr) {
        console.warn('⚠️ MongoDB save failed, saving to in-memory store:', dbErr.message);
        savedScan = saveInMemoryScan(result);
      }
    } else {
      savedScan = saveInMemoryScan(result);
    }

    console.log(`✅ Deep Scan Complete: ${domain} | Score: ${analysis.threatScore} | Risk: ${analysis.riskLevel}`);

    res.json({ success: true, data: savedScan });
  } catch (err) {
    console.error(`❌ Scan failed for ${req.body.url}:`, err.message);
    next(err);
  }
});

/**
 * GET /api/scan/history
 * Get scan history with pagination
 */
router.get('/history', async (req, res, next) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;

    let scans, total;
    if (mongoose.connection.readyState === 1) {
      try {
        [scans, total] = await Promise.all([
          Scan.find().sort({ createdAt: -1 }).skip(skip).limit(limit).lean(),
          Scan.countDocuments()
        ]);
      } catch (dbErr) {
        console.warn('⚠️ MongoDB history query failed, using in-memory store:', dbErr.message);
        const memData = getInMemoryHistory(skip, limit);
        scans = memData.scans;
        total = memData.total;
      }
    } else {
      const memData = getInMemoryHistory(skip, limit);
      scans = memData.scans;
      total = memData.total;
    }

    res.json({
      success: true,
      data: scans,
      pagination: {
        total,
        page,
        limit,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;

