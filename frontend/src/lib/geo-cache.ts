// Geolocation cache utility for heatmap
import { enrichIndicator } from './api';
import type { EnrichedIndicator } from './api';

interface CacheEntry {
  data: EnrichedIndicator;
  timestamp: number;
  ttl: number;
}

export class GeoCache {
  private cache = new Map<string, CacheEntry>();
  private readonly TTL = 24 * 60 * 60 * 1000; // 24 hours in milliseconds

  /**
   * Get cached enrichment data for an IOC
   * Returns null if not cached or expired
   */
  get(ioc: string): EnrichedIndicator | null {
    const entry = this.cache.get(ioc);
    if (!entry) return null;

    // Check if entry has expired
    if (Date.now() - entry.timestamp > entry.ttl) {
      this.cache.delete(ioc);
      return null;
    }

    return entry.data;
  }

  /**
   * Store enrichment data in cache
   */
  set(ioc: string, data: EnrichedIndicator): void {
    this.cache.set(ioc, {
      data,
      timestamp: Date.now(),
      ttl: this.TTL
    });
  }

  /**
   * Check if an IOC is cached and not expired
   */
  has(ioc: string): boolean {
    return this.get(ioc) !== null;
  }

  /**
   * Clear all cached entries
   */
  clear(): void {
    this.cache.clear();
  }

  /**
   * Get cache statistics
   */
  getStats() {
    return {
      size: this.cache.size,
      entries: Array.from(this.cache.keys())
    };
  }

  /**
   * Batch enrich IP addresses with caching
   * @param ipAddresses - Array of IP addresses to enrich
   * @param maxConcurrent - Maximum concurrent API requests (default: 10)
   * @returns Map of IP addresses to enriched data
   */
  async batchEnrich(
    ipAddresses: string[],
    maxConcurrent = 10
  ): Promise<Map<string, EnrichedIndicator>> {
    const results = new Map<string, EnrichedIndicator>();

    // Deduplicate IPs
    const uniqueIps = [...new Set(ipAddresses)];

    // Check cache first
    const cached: string[] = [];
    const uncached: string[] = [];

    for (const ip of uniqueIps) {
      const cachedData = this.get(ip);
      if (cachedData) {
        results.set(ip, cachedData);
        cached.push(ip);
      } else {
        uncached.push(ip);
      }
    }

    console.log(`[GeoCache] Batch enrich IPs: ${cached.length} cached, ${uncached.length} to fetch`);

    // Batch enrich uncached IPs with concurrency limit
    if (uncached.length > 0) {
      const chunks = this.chunkArray(uncached, maxConcurrent);

      for (const chunk of chunks) {
        const promises = chunk.map(ip =>
          enrichIndicator(ip, 'ipv4')
            .then(response => {
              const enrichedData = response.enriched_indicators[0];
              if (enrichedData && enrichedData.geolocation) {
                this.set(ip, enrichedData);
                results.set(ip, enrichedData);
              }
              return { ip, success: true };
            })
            .catch(error => {
              console.warn(`[GeoCache] Failed to enrich ${ip}:`, error.message);
              return { ip, success: false };
            })
        );

        await Promise.all(promises);
      }
    }

    return results;
  }

  /**
   * Batch enrich domain names with caching (uses Shodan to resolve to IPs)
   * @param domains - Array of domain names to enrich
   * @param maxConcurrent - Maximum concurrent API requests (default: 5)
   * @returns Map of domain names to enriched data
   */
  async batchEnrichDomains(
    domains: string[],
    maxConcurrent = 5
  ): Promise<Map<string, EnrichedIndicator>> {
    const results = new Map<string, EnrichedIndicator>();

    // Deduplicate domains
    const uniqueDomains = [...new Set(domains)];

    // Check cache first
    const cached: string[] = [];
    const uncached: string[] = [];

    for (const domain of uniqueDomains) {
      const cachedData = this.get(domain);
      if (cachedData) {
        results.set(domain, cachedData);
        cached.push(domain);
      } else {
        uncached.push(domain);
      }
    }

    console.log(`[GeoCache] Batch enrich domains: ${cached.length} cached, ${uncached.length} to fetch`);

    // Batch enrich uncached domains with concurrency limit
    if (uncached.length > 0) {
      const chunks = this.chunkArray(uncached, maxConcurrent);

      for (const chunk of chunks) {
        const promises = chunk.map(domain =>
          enrichIndicator(domain, 'domain')
            .then(response => {
              const enrichedData = response.enriched_indicators[0];
              if (enrichedData) {
                // Cache the enriched domain data
                this.set(domain, enrichedData);
                results.set(domain, enrichedData);
              }
              return { domain, success: true };
            })
            .catch(error => {
              console.warn(`[GeoCache] Failed to enrich ${domain}:`, error.message);
              return { domain, success: false };
            })
        );

        await Promise.all(promises);
      }
    }

    return results;
  }

  /**
   * Split array into chunks for batch processing
   */
  private chunkArray<T>(array: T[], size: number): T[][] {
    const chunks: T[][] = [];
    for (let i = 0; i < array.length; i += size) {
      chunks.push(array.slice(i, i + size));
    }
    return chunks;
  }
}

// Export singleton instance
export const geoCache = new GeoCache();
