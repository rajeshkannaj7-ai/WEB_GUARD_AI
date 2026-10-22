const dns = require('dns').promises;
const whois = require('whois-json');
const axios = require('axios');
const { checkSSL } = require('./sslChecker');
const { cache, TTL } = require('./cache');

/**
 * Check if a domain is active via DNS, HTTP, or SSL
 */
async function checkDomainAvailability(domain) {
  const cleanDomain = domain.split(':')[0].replace(/^www\./, '');
  
  // 1. Check DNS resolution first with 2000ms timeout
  try {
    await Promise.race([
      dns.lookup(cleanDomain),
      new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 2000))
    ]);
    return true;
  } catch (dnsErr) {
    // DNS failed, continue to other checks
  }

  // 2. Check HTTP status (200-499) with 2000ms timeout
  try {
    await axios.get(`http://${cleanDomain}`, { 
      timeout: 2000,
      validateStatus: (status) => status >= 200 && status < 500,
      maxContentLength: 1,
      maxRedirects: 3
    });
    return true;
  } catch (httpErr) {
    try {
      await axios.get(`https://${cleanDomain}`, {
        timeout: 2000,
        validateStatus: (status) => status >= 200 && status < 500,
        maxContentLength: 1,
        maxRedirects: 3
      });
      return true;
    } catch (httpsErr) {
      // Continue to SSL check
    }
  }

  // 3. Check SSL Certificate (Port 443)
  try {
    const ssl = await checkSSL(cleanDomain);
    if (ssl && ssl.status !== 'NO SSL' && ssl.status !== 'UNKNOWN') {
      return true;
    }
  } catch (sslErr) {
    // Final failure
  }

  return false;
}

async function fetchWhoisXml(domain) {
  const apiKey = process.env.WHOIS_API_KEY;
  if (!apiKey) return null;
  try {
    const response = await axios.get('https://www.whoisxmlapi.com/whoisserver/WhoisService', {
      params: {
        apiKey,
        domainName: domain,
        outputFormat: 'JSON'
      },
      timeout: 3000
    });
    return response.data?.WhoisRecord || null;
  } catch (err) {
    return null;
  }
}

/**
 * Get WHOIS and DNS information for a domain
 */
async function getDomainIntel(domain) {
  const cleanDomain = domain.split(':')[0].replace(/^www\./, '');
  const cacheKey = `intel:${cleanDomain}`;
  const cached = cache.get(cacheKey);
  if (cached) return cached;

  const [isActive, addresses, nameservers, xmlRecord] = await Promise.all([
    checkDomainAvailability(cleanDomain).catch(() => false),
    dns.resolve4(cleanDomain).catch(() => []),
    dns.resolveNs(cleanDomain).catch(() => []),
    fetchWhoisXml(cleanDomain).catch(() => null)
  ]);

  let registrar = null;
  let country = null;
  let creationDateRaw = null;
  let expirationDateRaw = null;
  let nsArray = nameservers || [];

  if (xmlRecord && xmlRecord.dataError !== 'MISSING_WHOIS_DATA' && (xmlRecord.registrarName || xmlRecord.registryData || xmlRecord.createdDate)) {
    registrar = xmlRecord.registrarName || xmlRecord.registryData?.registrarName || null;
    country = xmlRecord.registrant?.country || xmlRecord.registrant?.countryCode || 
              xmlRecord.registryData?.registrant?.country || xmlRecord.registryData?.registrant?.countryCode || null;
    creationDateRaw = xmlRecord.createdDate || xmlRecord.registryData?.createdDate || null;
    expirationDateRaw = xmlRecord.expiresDate || xmlRecord.registryData?.expiresDate || null;
    if (xmlRecord.nameServers?.hostNames?.length > 0) {
      nsArray = xmlRecord.nameServers.hostNames;
    }
  } else {
    try {
      const whoisData = await whois(cleanDomain, { timeout: 3000 });
      registrar = extractWhoisField(whoisData, ['registrar', 'Registrar', 'REGISTRAR', 'Registrar Name']);
      country = extractWhoisField(whoisData, ['registrantCountry', 'country', 'Country', 'Registrant Country']);
      creationDateRaw = extractWhoisField(whoisData, ['creationDate', 'created', 'Created Date', 'Creation Date', 'registered']);
      expirationDateRaw = extractWhoisField(whoisData, ['registrarRegistrationExpirationDate', 'expiresDate', 'Expiry Date', 'Expiration Date']);
      if (!nsArray.length && (whoisData.nameServer || whoisData.nameServers)) {
        const ns = whoisData.nameServer || whoisData.nameServers;
        nsArray = Array.isArray(ns) ? ns : typeof ns === 'string' ? ns.split('\n').filter(Boolean) : [];
      }
    } catch (err) {
      // Ignore fallback failure
    }
  }

  let domainAge = null;
  let creationDate = null;
  if (creationDateRaw) {
    try {
      const parsed = new Date(creationDateRaw);
      if (!isNaN(parsed.getTime())) {
        creationDate = parsed.toISOString();
        const ageMs = Date.now() - parsed.getTime();
        domainAge = Math.floor(ageMs / (1000 * 60 * 60 * 24));
      }
    } catch (e) {}
  }

  let expirationDate = null;
  if (expirationDateRaw) {
    try {
      const parsed = new Date(expirationDateRaw);
      if (!isNaN(parsed.getTime())) {
        expirationDate = parsed.toISOString();
      }
    } catch (e) {}
  }

  let hostingProvider = null;
  if (addresses && addresses.length > 0) {
    hostingProvider = await getHostingProvider(addresses[0]);
  }

  const result = {
    isActive,
    age: domainAge,
    registrar: registrar || 'Unknown',
    country: country || 'Unknown',
    creationDate,
    expirationDate,
    nameservers: nsArray.slice(0, 4),
    hostingProvider: hostingProvider || 'Unknown',
    ipAddresses: addresses || []
  };

  cache.set(cacheKey, result, TTL.DNS);
  return result;
}

function extractWhoisField(data, keys) {
  for (const key of keys) {
    if (data[key]) {
      const val = data[key];
      if (Array.isArray(val)) return val[0];
      if (typeof val === 'string') return val.trim();
    }
  }
  return null;
}

/**
 * Get IP intelligence for a domain with fallbacks, 2000ms timeouts, and 15m caching
 * @param {string} domain 
 * @returns {Promise<object>}
 */
async function getIPIntelligence(domain) {
  const cleanDomain = domain.trim().replace(/^https?:\/\//, '').split('/')[0];
  const cacheKey = `ip:intel:${cleanDomain}`;
  const cached = cache.get(cacheKey);
  if (cached) return { ...cached, isCached: true };

  try {
    let ip = null;
    try {
      const lookup = await Promise.race([
        dns.lookup(cleanDomain),
        new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 2000))
      ]);
      ip = lookup.address;
    } catch (dnsErr) {
      const addresses = await dns.resolve4(cleanDomain).catch(() => []);
      if (addresses.length > 0) {
        ip = addresses[0];
      }
    }
    
    if (!ip) {
      return {
        status: 'UNAVAILABLE',
        ip: 'Unknown',
        country: 'Unknown',
        region: 'Unknown',
        city: 'Unknown',
        org: 'Unknown',
        asn: 'Unknown',
        error: 'Could not resolve domain to IP Address'
      };
    }
    
    // Attempt multiple APIs with 2000ms timeout
    const apis = [
      { url: `https://ipinfo.io/${ip}/json?token=${process.env.IPINFO_API_KEY}`, parse: d => ({ status: 'COMPLETE', ip: d.ip, country: d.country, region: d.region, city: d.city, org: d.org, asn: d.asn || (d.org?.startsWith('AS') ? d.org.split(' ')[0] : 'Unknown') }) },
      { url: `https://ipapi.co/${ip}/json/`, parse: d => ({ status: 'COMPLETE', ip: d.ip, country: d.country_code, region: d.region, city: d.city, org: d.org, asn: d.asn }) },
      { url: `https://ipwhois.app/json/${ip}`, parse: d => ({ status: 'COMPLETE', ip: d.ip, country: d.country_code, region: d.region, city: d.city, org: d.org || d.isp, asn: d.asn }) }
    ];

    for (const api of apis) {
      try {
        const res = await axios.get(api.url, { timeout: 2000 });
        if (res.data && (res.data.ip || res.data.success !== false)) {
          const parsed = api.parse(res.data);
          cache.set(cacheKey, parsed, TTL.IP);
          return parsed;
        }
      } catch (e) {
        continue;
      }
    }

    const fallback = {
      status: 'COMPLETE',
      ip,
      country: 'Unknown',
      region: 'Unknown',
      city: 'Unknown',
      org: 'Unknown',
      asn: 'Unknown'
    };
    cache.set(cacheKey, fallback, TTL.IP);
    return fallback;

  } catch (err) {
    return {
      status: 'UNAVAILABLE',
      ip: 'Unknown',
      country: 'Unknown',
      region: 'Unknown',
      city: 'Unknown',
      org: 'Unknown',
      asn: 'Unknown',
      error: err.message
    };
  }
}

async function getHostingProvider(ip) {
  if (!ip) return null;
  const cacheKey = `ip:org:${ip}`;
  const cached = cache.get(cacheKey);
  if (cached) return cached;

  try {
    const response = await axios.get(`https://ipinfo.io/${ip}/json?token=${process.env.IPINFO_API_KEY}`, { timeout: 2000 });
    const org = response.data.org || response.data.company?.name || null;
    if (org) cache.set(cacheKey, org, TTL.IP);
    return org;
  } catch (e) {
    return null;
  }
}

module.exports = { getDomainIntel, getIPIntelligence };
