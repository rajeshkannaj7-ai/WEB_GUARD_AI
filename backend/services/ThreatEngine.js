const ReputationScanner = require('./ReputationScanner');
const DNSAnalyzer = require('./DNSAnalyzer');
const SSLInspector = require('./SSLInspector');
const WHOISAnalyzer = require('./WHOISAnalyzer');
const PiracyDetector = require('./PiracyDetector');
const PhishingDetector = require('./PhishingDetector');
const { getIPIntelligence } = require('./domainIntel');
const { cache, TTL } = require('./cache');

class ThreatEngine {
  static async analyze(url, domain) {
    const cleanDomain = domain.split(':')[0].replace(/^www\./, '');
    const cacheKey = `scan:${url}:${cleanDomain}`;

    // Fast check for cached full scan result
    const cachedResult = cache.get(cacheKey);
    if (cachedResult) {
      console.log(`[Cache Hit] Returning cached scan verdict for ${cleanDomain}`);
      return { ...cachedResult, isCached: true };
    }

    console.log(`[ThreatEngine] Parallel scan initiated for: ${cleanDomain}`);

    // 1. Synchronous Heuristics (<1ms)
    const phishing = PhishingDetector.analyze(url, cleanDomain);
    const piracy = PiracyDetector.analyze(url, cleanDomain);

    // 2. Parallel concurrent execution of all external intelligence
    const [
      dnsSettled,
      sslSettled,
      whoisSettled,
      repSettled,
      ipIntelSettled
    ] = await Promise.allSettled([
      DNSAnalyzer.resolveWithExistence(cleanDomain),
      SSLInspector.analyze(cleanDomain),
      WHOISAnalyzer.analyze(cleanDomain),
      ReputationScanner.analyze(url),
      getIPIntelligence(cleanDomain)
    ]);

    // Extract settled results with safe fallbacks
    const dns = dnsSettled.status === 'fulfilled' ? dnsSettled.value : {
      exists: true,
      ipAddresses: [],
      nameservers: [],
      status: 'UNAVAILABLE'
    };

    const ssl = sslSettled.status === 'fulfilled' ? sslSettled.value : {
      valid: false,
      status: 'NO SSL',
      frontendStatus: '[ INSECURE ]',
      daysRemaining: 0,
      score: 15
    };

    const whois = whoisSettled.status === 'fulfilled' ? whoisSettled.value : {
      status: 'DATA UNAVAILABLE',
      registrar: 'Unknown',
      country: 'Unknown',
      creationDate: null,
      expirationDate: null,
      age: null,
      hostingProvider: 'Unknown',
      asn: 'Unknown',
      isRecent: false,
      score: 10
    };

    const rep = repSettled.status === 'fulfilled' ? repSettled.value : {
      googleSafeBrowsing: { isSafe: true, threats: [], status: 'UNAVAILABLE' },
      virusTotal: { malicious: 0, suspicious: 0, harmless: 0, undetected: 0, totalEngines: 0, status: 'UNAVAILABLE' },
      score: 0,
      flags: []
    };

    const ipIntel = ipIntelSettled.status === 'fulfilled' ? ipIntelSettled.value : {
      status: 'UNAVAILABLE',
      ip: dns.ipAddresses?.[0] || 'Unknown',
      country: 'Unknown',
      region: 'Unknown',
      city: 'Unknown',
      org: 'Unknown',
      asn: 'Unknown'
    };

    // Enrich hosting info if WHOIS had unknown but IPinfo resolved it
    if ((whois.hostingProvider === 'Unknown' || !whois.hostingProvider) && ipIntel.org && ipIntel.org !== 'Unknown') {
      whois.hostingProvider = ipIntel.org;
    }
    if ((whois.asn === 'Unknown' || !whois.asn) && ipIntel.asn && ipIntel.asn !== 'Unknown') {
      whois.asn = ipIntel.asn;
    }

    // Determine engine statuses for real SOC progress UI
    const engineStatuses = {
      urlValidation: 'COMPLETE',
      domainAnalysis: 'COMPLETE',
      heuristicAnalysis: 'COMPLETE',
      googleSafeBrowsing: rep.googleSafeBrowsing?.status || (rep.googleSafeBrowsing?.error ? 'UNAVAILABLE' : 'COMPLETE'),
      virusTotal: rep.virusTotal?.status || (rep.virusTotal?.error ? 'UNAVAILABLE' : 'COMPLETE'),
      ipIntelligence: ipIntel?.status || (ipIntel?.error ? 'UNAVAILABLE' : 'COMPLETE'),
      whois: whois?.status || (whois?.registrar !== 'Unknown' ? 'COMPLETE' : 'DATA UNAVAILABLE'),
      sslInspection: ssl?.status !== 'UNKNOWN' ? 'COMPLETE' : 'UNAVAILABLE'
    };

    // Special Check: Non-existent domain (NXDOMAIN / DNS Failure)
    if (!dns.exists) {
      const isRegistered = whois.registrar !== 'Unknown' || whois.age !== null;
      const result = {
        threatScore: isRegistered ? 90 : 95,
        riskLevel: "MALICIOUS",
        phishingProbability: "Critical",
        issues: [
          "⚠ Domain Not Found in Global DNS",
          "This domain does not exist or fails resolution.",
          "Possible typo, parked domain, or decommissioned phishing host.",
          `Detection: ${isRegistered ? "INVALID DOMAIN (DNS FAILURE)" : "UNREGISTERED DOMAIN"}`,
          `DNS Code: ${dns.dnsError || 'NXDOMAIN'}`,
          isRegistered ? "Domain is registered but inactive / dead" : "Domain is NOT registered (No WHOIS records)"
        ],
        piracyStatus: "No Piracy Signals",
        sslStatus: { valid: false, status: "[ INSECURE ]", actualStatus: "NO SSL", daysRemaining: 0 },
        domainInfo: {
          age: whois.age,
          registrar: isRegistered ? whois.registrar : "AVAILABLE FOR PURCHASE",
          country: whois.country,
          creationDate: whois.creationDate,
          expirationDate: whois.expirationDate,
          hostingProvider: "None (DNS Failure)",
          asn: "Unknown",
          nameservers: []
        },
        virusTotal: rep.virusTotal,
        googleSafeBrowsing: rep.googleSafeBrowsing,
        ipIntel,
        engineStatuses
      };

      cache.set(cacheKey, result, TTL.SCAN);
      return result;
    }

    // Threat Scoring Calculation
    let score = 0;
    const flags = [];

    // Phishing heuristics (+40)
    if (phishing.score >= 40) {
      score += 40;
      flags.push("Phishing indicators detected by Heuristic Engine");
    }

    // Malware domain / Blacklist (+70 or +30)
    if (rep.score >= 70) {
      score += 70;
      flags.push(...rep.flags);
    } else if (rep.score > 0) {
      score += 30;
      flags.push(...rep.flags);
    }

    // Piracy domain (+40)
    if (piracy.detected) {
      score += piracy.score;
      flags.push(piracy.type);
    }

    // Suspicious WHOIS (+10)
    if (whois.registrar === 'Unknown') {
      score += 10;
      flags.push("Suspicious WHOIS: Unknown or Hidden Registrar");
    }

    // Domain age < 1 year (+10)
    if (whois.isRecent) {
      score += 10;
      flags.push("Recently Registered Domain (< 1 year old)");
    }

    // SSL invalid or absent (+15)
    if (!ssl.valid) {
      score += 15;
      flags.push(`No valid SSL certificate (${ssl.status})`);
    }

    // Typosquatting (+20)
    if (phishing.hasTyposquatting) {
      score += 20;
      flags.push("Possible Typosquatting / Brand Impersonation Domain");
    }

    // Normalize final score between 0 and 100
    score = Math.min(100, Math.max(0, score));

    // Threat level classification
    let riskLevel = "SAFE";
    if (score > 50) riskLevel = "MALICIOUS";
    else if (score > 20) riskLevel = "SUSPICIOUS";

    const result = {
      threatScore: score,
      riskLevel,
      phishingProbability: score > 70 ? "Critical" : score > 50 ? "High" : score > 20 ? "Moderate" : "Low",
      issues: flags.length > 0 ? flags : ["No significant threats detected"],
      piracyStatus: piracy.detected ? piracy.type : "No Piracy Signals",
      sslStatus: {
        valid: ssl.valid,
        status: ssl.frontendStatus,
        actualStatus: ssl.status,
        daysRemaining: ssl.daysRemaining,
        validFrom: ssl.validFrom,
        validTo: ssl.validTo
      },
      domainInfo: {
        age: whois.age,
        registrar: whois.registrar,
        country: whois.country,
        creationDate: whois.creationDate,
        expirationDate: whois.expirationDate,
        hostingProvider: whois.hostingProvider,
        asn: whois.asn,
        nameservers: (dns.nameservers || []).slice(0, 4)
      },
      virusTotal: rep.virusTotal,
      googleSafeBrowsing: rep.googleSafeBrowsing,
      ipIntel,
      engineStatuses
    };

    cache.set(cacheKey, result, TTL.SCAN);
    return result;
  }
}

module.exports = ThreatEngine;
