const express = require('express');
const router = express.Router();
const mongoose = require('mongoose');
const Scan = require('../models/Scan');
const { getInMemoryDashboardStats } = require('../services/inMemoryStore');

/**
 * GET /api/dashboard
 * Aggregated statistics (from MongoDB or in-memory fallback)
 */
router.get('/', async (req, res, next) => {
  try {
    if (mongoose.connection.readyState !== 1) {
      return res.json({
        success: true,
        data: getInMemoryDashboardStats()
      });
    }

    const now = new Date();
    const startOfDay = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const last7Days = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    const last30Days = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);

    // Run all aggregations in parallel
    const [
      totalScans,
      scansToday,
      highRiskDetected,
      suspiciousDomains,
      safeDomains,
      recentScans,
      dailyActivity,
      threatDistribution
    ] = await Promise.all([
      Scan.countDocuments(),
      Scan.countDocuments({ createdAt: { $gte: startOfDay } }),
      Scan.countDocuments({ riskLevel: 'MALICIOUS' }),
      Scan.countDocuments({ riskLevel: 'SUSPICIOUS' }),
      Scan.countDocuments({ riskLevel: 'SAFE' }),
      Scan.find().sort({ createdAt: -1 }).limit(10).lean(),
      // Daily scan activity for last 7 days
      Scan.aggregate([
        { $match: { createdAt: { $gte: last7Days } } },
        {
          $group: {
            _id: {
              $dateToString: { format: '%Y-%m-%d', date: '$createdAt' }
            },
            count: { $sum: 1 },
            highRisk: {
              $sum: { $cond: [{ $eq: ['$riskLevel', 'MALICIOUS'] }, 1, 0] }
            }
          }
        },
        { $sort: { _id: 1 } }
      ]),
      // Threat distribution
      Scan.aggregate([
        { $match: { createdAt: { $gte: last30Days } } },
        {
          $group: {
            _id: '$riskLevel',
            count: { $sum: 1 }
          }
        }
      ])
    ]);

    // Format daily activity for chart
    const activityMap = {};
    const last7DaysLabels = [];
    for (let i = 6; i >= 0; i--) {
      const d = new Date(Date.now() - i * 24 * 60 * 60 * 1000);
      const key = d.toISOString().split('T')[0];
      last7DaysLabels.push(key);
      activityMap[key] = { count: 0, highRisk: 0 };
    }
    
    dailyActivity.forEach(item => {
      if (activityMap[item._id] !== undefined) {
        activityMap[item._id] = { count: item.count, highRisk: item.highRisk };
      }
    });

    const chartData = {
      labels: last7DaysLabels.map(d => {
        const date = new Date(d);
        return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
      }),
      scans: last7DaysLabels.map(d => activityMap[d].count),
      highRisk: last7DaysLabels.map(d => activityMap[d].highRisk)
    };

    // Format threat distribution
    const threatMap = { 'SAFE': 0, 'SUSPICIOUS': 0, 'MALICIOUS': 0 };
    threatDistribution.forEach(item => {
      if (threatMap[item._id] !== undefined) {
        threatMap[item._id] = item.count;
      }
    });

    res.json({
      success: true,
      data: {
        totalScans,
        scansToday,
        highRiskDetected,
        suspiciousDomains,
        safeDomains,
        recentScans,
        chartData,
        threatDistribution: threatMap
      }
    });
  } catch (err) {
    console.warn('⚠️ Dashboard query error, falling back to in-memory stats:', err.message);
    res.json({
      success: true,
      data: getInMemoryDashboardStats()
    });
  }
});

module.exports = router;
