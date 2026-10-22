const whois = require('whois-json');
const axios = require('axios');
const { cache, TTL } = require('./cache');

class WHOISAnalyzer {
  static async fetchWhoisXml(domain) {
    const apiKey = process.env.WHOIS_API_KEY;
    if (!apiKey) return null;
    try {
      const response = await axios.get('https://www.whoisxmlapi.com/whoisserver/WhoisService', {
        params: {
          apiKey,
          domainName: domain,
          outputFormat: 'JSON'
        },
        timeout: 3000 // Strict 3000ms timeout
      });
      return response.data?.WhoisRecord || null;
    } catch (err) {
      const isTimeout = err.code === 'ECONNABORTED' || err.message?.includes('timeout');
      console.warn(`⚠️ WhoisXML API ${isTimeout ? 'timed out (3000ms)' : 'failed'} for ${domain}:`, err.message);
      return null;
    }
  }

  static async analyze(domain, ipAddresses = []) {
    const cleanDomain = domain.split(':')[0].replace(/^www\./, '');
    const cacheKey = `whois:${cleanDomain}`;
    const cached = cache.get(cacheKey);
    if (cached) return { ...cached, isCached: true };

    let data = {};
    let registrar = null;
    let country = null;
    let creationDateRaw = null;
    let expirationDateRaw = null;
    let nsList = [];
    let status = 'COMPLETE';

    // Attempt WhoisXML API first with 3000ms timeout
    const xmlRecord = await this.fetchWhoisXml(cleanDomain);
    const hasValidRecord = xmlRecord && xmlRecord.dataError !== 'MISSING_WHOIS_DATA' && 
                           (xmlRecord.registrarName || xmlRecord.registryData || xmlRecord.createdDate);

    if (hasValidRecord) {
      registrar = xmlRecord.registrarName || xmlRecord.registryData?.registrarName || null;
      country = xmlRecord.registrant?.country || xmlRecord.registrant?.countryCode || 
                xmlRecord.registryData?.registrant?.country || xmlRecord.registryData?.registrant?.countryCode || null;
      creationDateRaw = xmlRecord.createdDate || xmlRecord.registryData?.createdDate || null;
      expirationDateRaw = xmlRecord.expiresDate || xmlRecord.registryData?.expiresDate || null;
      nsList = xmlRecord.nameServers?.hostNames || xmlRecord.registryData?.nameServers?.hostNames || [];
    } else {
      // Fallback to socket WHOIS lookup with short 3000ms timeout
      try {
        data = await whois(cleanDomain, { timeout: 3000 });
        registrar = this.extractField(data, ['registrar', 'Registrar', 'REGISTRAR', 'Registrar Name']);
        country = this.extractField(data, ['registrantCountry', 'country', 'Country', 'Registrant Country']);
        creationDateRaw = this.extractField(data, ['creationDate', 'created', 'Created Date', 'Creation Date', 'registered']);
        expirationDateRaw = this.extractField(data, ['registrarRegistrationExpirationDate', 'expiresDate', 'Expiry Date', 'Expiration Date']);
        nsList = data.nameServer || data.nameServers || [];
      } catch (err) {
        console.warn(`⚠️ WHOIS socket lookup failed for ${cleanDomain}:`, err.message);
        status = err.message?.includes('timeout') ? 'TIMEOUT' : 'DATA UNAVAILABLE';
      }
    }

    let age = null;
    let creationDate = null;
    if (creationDateRaw) {
      const parsed = new Date(creationDateRaw);
      if (!isNaN(parsed.getTime())) {
        creationDate = parsed.toISOString();
        const ageMs = Date.now() - parsed.getTime();
        age = Math.floor(ageMs / (1000 * 60 * 60 * 24));
      }
    }

    let hostingProvider = 'Unknown';
    let asn = 'Unknown';
    if (ipAddresses && ipAddresses.length > 0) {
      const hostData = await this.getHostingProvider(ipAddresses[0]);
      hostingProvider = hostData.name;
      asn = hostData.asn;
    }

    // Cloudflare detection
    if (hostingProvider.toLowerCase().includes('cloudflare') || 
        JSON.stringify(nsList).toLowerCase().includes('cloudflare')) {
      hostingProvider = 'Cloudflare CDN Protected';
    }

    const result = {
      status: (registrar || country || creationDate) ? 'COMPLETE' : status,
      registrar: registrar || 'Unknown',
      country: country || 'Unknown',
      creationDate,
      expirationDate: expirationDateRaw ? new Date(expirationDateRaw).toISOString() : null,
      age,
      hostingProvider,
      asn,
      isRecent: age !== null && age < 365,
      score: (age !== null && age < 365 ? 10 : 0) + (!registrar || registrar === 'Unknown' ? 10 : 0)
    };

    cache.set(cacheKey, result, TTL.WHOIS);
    return result;
  }

  static extractField(data, keys) {
    for (const key of keys) {
      if (data[key]) {
        const val = data[key];
        return Array.isArray(val) ? val[0] : typeof val === 'string' ? val.trim() : val;
      }
    }
    return null;
  }

  static async getHostingProvider(ip) {
    if (!ip) return { name: 'Unknown', asn: 'Unknown' };
    const cacheKey = `ip:host:${ip}`;
    const cached = cache.get(cacheKey);
    if (cached) return cached;

    const apis = [
      { url: `https://ipinfo.io/${ip}/json?token=${process.env.IPINFO_API_KEY}`, parse: d => ({ name: d.org, asn: d.asn || (d.org?.startsWith('AS') ? d.org.split(' ')[0] : 'Unknown') }) },
      { url: `https://ipapi.co/${ip}/json/`, parse: d => ({ name: d.org, asn: d.asn }) },
      { url: `https://ipwhois.app/json/${ip}`, parse: d => ({ name: d.org || d.isp, asn: d.asn }) }
    ];

    for (const api of apis) {
      try {
        const res = await axios.get(api.url, { timeout: 2000 });
        const provider = api.parse(res.data);
        if (provider.name) {
          cache.set(cacheKey, provider, TTL.IP);
          return provider;
        }
      } catch (e) {
        continue;
      }
    }
    const fallback = { name: 'Unknown', asn: 'Unknown' };
    cache.set(cacheKey, fallback, TTL.IP);
    return fallback;
  }

  static async checkRegistration(domain) {
    const cleanDomain = domain.split(':')[0].replace(/^www\./, '');
    const cacheKey = `whois:reg:${cleanDomain}`;
    const cached = cache.get(cacheKey);
    if (cached) return cached;

    // WhoisXML API check with 3000ms timeout
    const xmlRecord = await this.fetchWhoisXml(cleanDomain);
    if (xmlRecord) {
      const isUnregistered = xmlRecord.dataError === 'MISSING_WHOIS_DATA' ||
                             (xmlRecord.parseCode === 0 && !xmlRecord.registrarName);
      const res = {
        isRegistered: !isUnregistered,
        data: xmlRecord
      };
      cache.set(cacheKey, res, TTL.WHOIS);
      return res;
    }

    try {
      const data = await whois(cleanDomain, { timeout: 3000 });
      
      const statusStr = JSON.stringify(data).toLowerCase();
      const isUnregistered = 
        statusStr.includes("no match") || 
        statusStr.includes("not found") || 
        statusStr.includes("available") ||
        Object.keys(data).length <= 1;

      const res = {
        isRegistered: !isUnregistered,
        data: data
      };
      cache.set(cacheKey, res, TTL.WHOIS);
      return res;
    } catch (err) {
      return { isRegistered: false, error: err.message };
    }
  }
}

module.exports = WHOISAnalyzer;
