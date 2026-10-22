/**
 * In-memory scan storage and analytics engine for standalone mode
 * Used when MongoDB is offline, disabled, or unconfigured.
 */

const inMemoryScans = [
  {
    _id: 'seed_scan_1',
    url: 'https://paypal-security-update-center.com/login',
    domain: 'paypal-security-update-center.com',
    threatScore: 92,
    phishingProbability: 'Critical',
    riskLevel: 'MALICIOUS',
    issues: [
      'Typosquatting detected targeting paypal.com',
      'Suspicious brand impersonation keywords in URL path',
      'Untrusted registrar detected'
    ],
    piracyStatus: 'No Piracy Signals',
    sslStatus: {
      valid: false,
      validFrom: null,
      validTo: null,
      daysRemaining: 0,
      status: 'NO SSL'
    },
    domainInfo: {
      age: 12,
      registrar: 'NameCheap Inc.',
      country: 'RU',
      creationDate: '2026-02-28T00:00:00.000Z',
      expirationDate: '2027-02-28T00:00:00.000Z',
      hostingProvider: 'Unknown Host',
      nameservers: ['ns1.parkingcrew.net', 'ns2.parkingcrew.net']
    },
    virusTotal: {
      malicious: 14,
      suspicious: 3,
      harmless: 2,
      undetected: 55,
      totalEngines: 74
    },
    googleSafeBrowsing: {
      isSafe: false,
      threats: ['SOCIAL_ENGINEERING']
    },
    createdAt: new Date(Date.now() - 3 * 3600 * 1000).toISOString()
  },
  {
    _id: 'seed_scan_2',
    url: 'https://free-crypto-giveaway-2026.net',
    domain: 'free-crypto-giveaway-2026.net',
    threatScore: 68,
    phishingProbability: 'High',
    riskLevel: 'SUSPICIOUS',
    issues: [
      'Newly registered domain (< 30 days old)',
      'High-risk cryptocurrency reward scheme patterns',
      'Self-signed SSL certificate'
    ],
    piracyStatus: 'No Piracy Signals',
    sslStatus: {
      valid: true,
      validFrom: '2026-03-01T00:00:00.000Z',
      validTo: '2026-06-01T00:00:00.000Z',
      daysRemaining: 81,
      status: 'SELF SIGNED'
    },
    domainInfo: {
      age: 10,
      registrar: 'Hostinger Operations, UAB',
      country: 'PA',
      creationDate: '2026-03-01T00:00:00.000Z',
      expirationDate: '2027-03-01T00:00:00.000Z',
      hostingProvider: 'Cloudflare, Inc.',
      nameservers: ['ns1.cloudflare.com', 'ns2.cloudflare.com']
    },
    virusTotal: {
      malicious: 4,
      suspicious: 2,
      harmless: 10,
      undetected: 58,
      totalEngines: 74
    },
    googleSafeBrowsing: {
      isSafe: true,
      threats: []
    },
    createdAt: new Date(Date.now() - 8 * 3600 * 1000).toISOString()
  },
  {
    _id: 'seed_scan_3',
    url: 'https://github.com',
    domain: 'github.com',
    threatScore: 0,
    phishingProbability: 'Low',
    riskLevel: 'SAFE',
    issues: [],
    piracyStatus: 'No Piracy Signals',
    sslStatus: {
      valid: true,
      validFrom: '2025-01-15T00:00:00.000Z',
      validTo: '2027-01-15T00:00:00.000Z',
      daysRemaining: 308,
      status: 'VALID'
    },
    domainInfo: {
      age: 5800,
      registrar: 'MarkMonitor Inc.',
      country: 'US',
      creationDate: '2007-10-09T00:00:00.000Z',
      expirationDate: '2028-10-09T00:00:00.000Z',
      hostingProvider: 'GitHub, Inc.',
      nameservers: ['dns1.p08.nsone.net', 'dns2.p08.nsone.net']
    },
    virusTotal: {
      malicious: 0,
      suspicious: 0,
      harmless: 72,
      undetected: 2,
      totalEngines: 74
    },
    googleSafeBrowsing: {
      isSafe: true,
      threats: []
    },
    createdAt: new Date(Date.now() - 20 * 3600 * 1000).toISOString()
  }
];

/**
 * Persist a scan result into in-memory store
 */
function saveInMemoryScan(scanData) {
  const record = {
    ...scanData,
    _id: 'mem_' + Date.now() + '_' + Math.random().toString(36).substring(2, 8),
    createdAt: new Date().toISOString()
  };
  inMemoryScans.unshift(record);
  return record;
}

/**
 * Retrieve paginated scan history from in-memory store
 */
function getInMemoryHistory(skip = 0, limit = 20) {
  const total = inMemoryScans.length;
  const scans = inMemoryScans.slice(skip, skip + limit);
  return { scans, total };
}

/**
 * Calculate dashboard aggregates directly from in-memory store
 */
function getInMemoryDashboardStats() {
  const now = new Date();
  const startOfDay = new Date(now.getFullYear(), now.getMonth(), now.getDate());

  const totalScans = inMemoryScans.length;
  const scansToday = inMemoryScans.filter(s => new Date(s.createdAt) >= startOfDay).length;
  const highRiskDetected = inMemoryScans.filter(s => s.riskLevel === 'MALICIOUS').length;
  const suspiciousDomains = inMemoryScans.filter(s => s.riskLevel === 'SUSPICIOUS').length;
  const safeDomains = inMemoryScans.filter(s => s.riskLevel === 'SAFE' || s.riskLevel === 'LOW RISK' || s.riskLevel === 'TRUSTED PLATFORM').length;
  const recentScans = inMemoryScans.slice(0, 10);

  // Generate 7-day timeline labels and stats for Chart.js
  const activityMap = {};
  const last7DaysLabels = [];
  for (let i = 6; i >= 0; i--) {
    const d = new Date(Date.now() - i * 24 * 60 * 60 * 1000);
    const key = d.toISOString().split('T')[0];
    last7DaysLabels.push(key);
    activityMap[key] = { count: 0, highRisk: 0 };
  }

  inMemoryScans.forEach(item => {
    const dateKey = new Date(item.createdAt).toISOString().split('T')[0];
    if (activityMap[dateKey]) {
      activityMap[dateKey].count++;
      if (item.riskLevel === 'MALICIOUS') {
        activityMap[dateKey].highRisk++;
      }
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

  const threatMap = {
    'SAFE': safeDomains,
    'SUSPICIOUS': suspiciousDomains,
    'MALICIOUS': highRiskDetected
  };

  return {
    totalScans,
    scansToday,
    highRiskDetected,
    suspiciousDomains,
    safeDomains,
    recentScans,
    chartData,
    threatDistribution: threatMap
  };
}

module.exports = {
  inMemoryScans,
  saveInMemoryScan,
  getInMemoryHistory,
  getInMemoryDashboardStats
};
