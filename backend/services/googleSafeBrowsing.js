const axios = require('axios');
const { cache, TTL } = require('./cache');

/**
 * Query Google Safe Browsing API v4
 * Optimized with strict 2500ms timeout and server-side caching.
 * 
 * @param {string} url - URL to check
 * @returns {Promise<object>} - Safe Browsing result
 */
async function checkGoogleSafeBrowsing(url) {
  const cacheKey = `gsb:${url}`;
  const cached = cache.get(cacheKey);
  if (cached) {
    return { ...cached, isCached: true };
  }

  const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
  
  if (!apiKey) {
    return {
      status: 'UNAVAILABLE',
      isSafe: true,
      threats: [],
      error: 'API key not configured'
    };
  }

  try {
    const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`;
    
    const requestBody = {
      client: {
        clientId: 'phishguard-ai',
        clientVersion: '1.0.0'
      },
      threatInfo: {
        threatTypes: [
          'MALWARE',
          'SOCIAL_ENGINEERING',
          'UNWANTED_SOFTWARE',
          'POTENTIALLY_HARMFUL_APPLICATION'
        ],
        platformTypes: ['ANY_PLATFORM'],
        threatEntryTypes: ['URL'],
        threatEntries: [{ url }]
      }
    };

    const response = await axios.post(endpoint, requestBody, {
      timeout: 2500,
      headers: { 'Content-Type': 'application/json' }
    });

    const matches = response.data?.matches || [];
    const isSafe = matches.length === 0;
    const threats = matches.map(m => m.threatType);

    const result = {
      status: 'COMPLETE',
      isSafe,
      threats,
      raw: matches
    };

    cache.set(cacheKey, result, TTL.REPUTATION);
    return result;

  } catch (err) {
    const isTimeout = err.code === 'ECONNABORTED' || err.message?.includes('timeout');
    console.warn(`⚠️ Google Safe Browsing ${isTimeout ? 'timed out' : 'failed'}:`, err.message);

    return {
      status: isTimeout ? 'TIMEOUT' : 'UNAVAILABLE',
      isSafe: true,
      threats: [],
      error: isTimeout ? 'Request timed out (2500ms)' : err.message
    };
  }
}

module.exports = { checkGoogleSafeBrowsing };
