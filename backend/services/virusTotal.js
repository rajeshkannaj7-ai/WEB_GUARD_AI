const axios = require('axios');
const { cache, TTL } = require('./cache');

/**
 * Check URL against VirusTotal Threat Intelligence
 * Optimized for speed: Checks cached URL intelligence directly (300ms-600ms)
 * with strict 3000ms timeout, server-side caching, and zero blocking sleep loops.
 * 
 * @param {string} url - URL to scan
 * @returns {Promise<object>} - VirusTotal analysis result
 */
async function checkVirusTotal(url) {
  const cacheKey = `vt:${url}`;
  const cached = cache.get(cacheKey);
  if (cached) {
    return { ...cached, isCached: true };
  }

  const apiKey = process.env.VIRUSTOTAL_API_KEY || process.env.VT_API_KEY;
  
  if (!apiKey) {
    console.warn('⚠️ VirusTotal API key not configured');
    return {
      status: 'UNAVAILABLE',
      malicious: 0,
      suspicious: 0,
      harmless: 0,
      undetected: 0,
      totalEngines: 0,
      permalink: null,
      scanDate: null,
      error: 'API key not configured'
    };
  }

  // VirusTotal URL ID format: base64 without padding
  const urlId = Buffer.from(url).toString('base64').replace(/=/g, '');

  try {
    // Fast path: Direct report check with strict 3000ms timeout
    const reportRes = await axios.get(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
      headers: { 'x-apikey': apiKey },
      timeout: 3000
    });

    const attributes = reportRes.data?.data?.attributes;
    const stats = attributes?.last_analysis_stats || {};

    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const harmless = stats.harmless || 0;
    const undetected = stats.undetected || 0;
    const totalEngines = malicious + suspicious + harmless + undetected + (stats.timeout || 0);

    const result = {
      status: 'COMPLETE',
      malicious,
      suspicious,
      harmless,
      undetected,
      totalEngines: totalEngines || 0,
      permalink: `https://www.virustotal.com/gui/url/${urlId}`,
      scanDate: attributes?.last_analysis_date 
        ? new Date(attributes.last_analysis_date * 1000).toISOString()
        : new Date().toISOString()
    };

    cache.set(cacheKey, result, TTL.REPUTATION);
    return result;

  } catch (err) {
    const isTimeout = err.code === 'ECONNABORTED' || err.message?.includes('timeout');
    const isNotFound = err.response?.status === 404;

    // If not found in VT database, queue a non-blocking background submission
    if (isNotFound) {
      try {
        axios.post(
          'https://www.virustotal.com/api/v3/urls',
          `url=${encodeURIComponent(url)}`,
          {
            headers: {
              'x-apikey': apiKey,
              'Content-Type': 'application/x-www-form-urlencoded'
            },
            timeout: 2000
          }
        ).catch(() => {});
      } catch (submitErr) {
        // Non-blocking
      }

      const cleanResult = {
        status: 'COMPLETE',
        malicious: 0,
        suspicious: 0,
        harmless: 0,
        undetected: 0,
        totalEngines: 0,
        permalink: null,
        scanDate: new Date().toISOString(),
        note: 'URL queued for initial VT analysis'
      };
      cache.set(cacheKey, cleanResult, TTL.REPUTATION);
      return cleanResult;
    }

    console.warn(`⚠️ VirusTotal check ${isTimeout ? 'timed out' : 'failed'}:`, err.message);

    return {
      status: isTimeout ? 'TIMEOUT' : 'UNAVAILABLE',
      malicious: 0,
      suspicious: 0,
      harmless: 0,
      undetected: 0,
      totalEngines: 0,
      permalink: null,
      scanDate: null,
      error: isTimeout ? 'Request timed out (3000ms)' : (err.response?.data?.error?.message || err.message)
    };
  }
}

module.exports = { checkVirusTotal };
