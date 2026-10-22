/**
 * In-Memory TTL Cache for Threat Intelligence
 * Provides fast server-side caching for DNS, WHOIS, IP info, and Reputation lookups.
 */
class MemoryCache {
  constructor() {
    this.store = new Map();
  }

  get(key) {
    const entry = this.store.get(key);
    if (!entry) return null;
    if (Date.now() > entry.expiresAt) {
      this.store.delete(key);
      return null;
    }
    return entry.value;
  }

  set(key, value, ttlMs) {
    this.store.set(key, {
      value,
      expiresAt: Date.now() + (ttlMs || 60000)
    });
  }

  has(key) {
    return this.get(key) !== null;
  }

  delete(key) {
    this.store.delete(key);
  }

  clear() {
    this.store.clear();
  }
}

const cache = new MemoryCache();

const TTL = {
  WHOIS: 60 * 60 * 1000,       // 1 hour
  DNS: 5 * 60 * 1000,          // 5 minutes
  IP: 15 * 60 * 1000,          // 15 minutes
  REPUTATION: 15 * 60 * 1000,  // 15 minutes
  SCAN: 10 * 60 * 1000         // 10 minutes
};

module.exports = { cache, TTL };
