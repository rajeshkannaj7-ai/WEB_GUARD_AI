const dns = require('dns').promises;
const { cache, TTL } = require('./cache');

// Helper to enforce timeout on promises
function withTimeout(promise, ms, defaultValue) {
  return Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error('DNS query timeout')), ms))
  ]).catch(err => defaultValue);
}

class DNSAnalyzer {
  static async resolve(domain) {
    const cleanDomain = domain.split(':')[0].replace(/^www\./, '');
    const cacheKey = `dns:resolve:${cleanDomain}`;
    const cached = cache.get(cacheKey);
    if (cached) return cached;

    const results = {
      ipAddresses: [],
      nameservers: [],
      mxRecords: [],
      txtRecords: [],
      status: 'COMPLETE'
    };

    try {
      const [a, ns, mx, txt] = await Promise.allSettled([
        withTimeout(dns.resolve4(cleanDomain), 2500, []),
        withTimeout(dns.resolveNs(cleanDomain), 2500, []),
        withTimeout(dns.resolveMx(cleanDomain), 2500, []),
        withTimeout(dns.resolveTxt(cleanDomain), 2500, [])
      ]);

      if (a.status === 'fulfilled' && Array.isArray(a.value)) results.ipAddresses = a.value;
      if (ns.status === 'fulfilled' && Array.isArray(ns.value)) results.nameservers = ns.value;
      if (mx.status === 'fulfilled' && Array.isArray(mx.value)) results.mxRecords = mx.value;
      if (txt.status === 'fulfilled' && Array.isArray(txt.value)) results.txtRecords = txt.value;

      cache.set(cacheKey, results, TTL.DNS);
    } catch (err) {
      console.warn(`⚠️ DNS Analysis warning for ${cleanDomain}:`, err.message);
      results.status = 'UNAVAILABLE';
    }

    return results;
  }

  static async checkExistence(domain) {
    const cleanDomain = domain.split(':')[0].replace(/^www\./, '');
    const cacheKey = `dns:exists:${cleanDomain}`;
    const cached = cache.get(cacheKey);
    if (cached) return cached;

    try {
      await withTimeout(dns.lookup(cleanDomain), 2500, null);
      const res = { exists: true, status: 'COMPLETE' };
      cache.set(cacheKey, res, TTL.DNS);
      return res;
    } catch (err) {
      const isTimeout = err.message === 'DNS query timeout';
      const res = { 
        exists: false, 
        error: isTimeout ? 'ETIMEDOUT' : err.code || err.message,
        isNXDOMAIN: ['ENOTFOUND', 'EAI_AGAIN'].includes(err.code),
        status: isTimeout ? 'TIMEOUT' : 'COMPLETE'
      };
      cache.set(cacheKey, res, TTL.DNS);
      return res;
    }
  }

  static async resolveWithExistence(domain) {
    const [resolveData, existData] = await Promise.all([
      this.resolve(domain),
      this.checkExistence(domain)
    ]);
    return {
      ...resolveData,
      exists: existData.exists,
      dnsError: existData.error,
      isNXDOMAIN: existData.isNXDOMAIN
    };
  }
}

module.exports = DNSAnalyzer;
