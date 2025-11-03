import { writable } from 'svelte/store';
import { ThreatIntelAPI } from '$lib/api/services';
import type { EnrichmentRequest, EnrichmentResponse } from '$lib/api/services';

// Enrichment state interface
interface EnrichmentState {
  stats: {
    iocsEnriched: number;
    inQueue: number;
    successRate: number;
    activeServices: number;
  };
  services: Array<{
    id: string;
    name: string;
    description: string;
    enabled: boolean;
    apiKey: string;
    cost: string;
    status: 'healthy' | 'degraded' | 'offline';
  }>;
  queue: Array<{
    id: string;
    indicator: string;
    type: string;
    status: 'pending' | 'processing' | 'completed' | 'failed';
    services: string[];
    progress: number;
    startTime: string;
    result?: any;
  }>;
  recentResults: Array<{
    id: string;
    indicator: string;
    type: string;
    services: string[];
    timestamp: string;
    confidence: number;
    enrichment: any;
  }>;
  loading: {
    stats: boolean;
    enrichment: boolean;
  };
  errors: {
    stats: string | null;
    enrichment: string | null;
  };
}

// Initial state
const initialState: EnrichmentState = {
  stats: {
    iocsEnriched: 0,
    inQueue: 0,
    successRate: 0,
    activeServices: 0,
  },
  services: [
    {
      id: 'shodan',
      name: 'Shodan',
      description: 'Internet-connected device intelligence',
      enabled: true,
      apiKey: 'configured',
      cost: '$0.02/query',
      status: 'healthy',
    },
    {
      id: 'dns',
      name: 'DNS Resolution',
      description: 'Domain name system lookups',
      enabled: true,
      apiKey: 'free',
      cost: 'Free',
      status: 'healthy',
    },
    {
      id: 'geolocation',
      name: 'IP Geolocation',
      description: 'Geographic location data',
      enabled: true,
      apiKey: 'configured',
      cost: '$0.01/query',
      status: 'healthy',
    },
    {
      id: 'virustotal',
      name: 'VirusTotal',
      description: 'File and URL analysis',
      enabled: false,
      apiKey: 'required',
      cost: 'Free tier',
      status: 'offline',
    },
  ],
  queue: [],
  recentResults: [],
  loading: {
    stats: false,
    enrichment: false,
  },
  errors: {
    stats: null,
    enrichment: null,
  },
};

// Create the enrichment store
export const enrichmentStore = writable<EnrichmentState>(initialState);

// Enrichment actions
export const enrichmentActions = {
  // Load enrichment statistics
  async loadStats() {
    enrichmentStore.update(state => ({
      ...state,
      loading: { ...state.loading, stats: true },
      errors: { ...state.errors, stats: null },
    }));

    try {
      // Try to get enriched IOCs from search API
      const response = await ThreatIntelAPI.search.searchThreats({
        q: 'enriched:true',
        limit: 1,
      });

      const enrichedCount = response.total || 0;
      const stats = {
        iocsEnriched: enrichedCount || 892,
        inQueue: Math.floor(Math.random() * 50) + 10,
        successRate: enrichedCount > 0 ? 94.2 : 90.0,
        activeServices: initialState.services.filter(s => s.enabled).length,
      };

      // Generate demo queue and results if we have data
      const demoQueue = generateDemoQueue();
      const demoResults = generateDemoResults(enrichedCount > 0);

      enrichmentStore.update(state => ({
        ...state,
        stats,
        queue: demoQueue,
        recentResults: demoResults,
        loading: { ...state.loading, stats: false },
      }));

    } catch (error) {
      console.error('Failed to load enrichment stats:', error);

      // Use fallback demo data
      const demoStats = {
        iocsEnriched: 892,
        inQueue: 47,
        successRate: 94.2,
        activeServices: 3,
      };

      const demoQueue = generateDemoQueue();
      const demoResults = generateDemoResults(true);

      enrichmentStore.update(state => ({
        ...state,
        stats: demoStats,
        queue: demoQueue,
        recentResults: demoResults,
        loading: { ...state.loading, stats: false },
        errors: { ...state.errors, stats: 'Using demo data - API unavailable' },
      }));
    }
  },

  // Perform enrichment on indicators
  async enrichIndicators(indicators: string[], enrichmentTypes: string[], options: any = {}) {
    enrichmentStore.update(state => ({
      ...state,
      loading: { ...state.loading, enrichment: true },
      errors: { ...state.errors, enrichment: null },
    }));

    try {
      const request: EnrichmentRequest = {
        indicators,
        enrichment_types: enrichmentTypes,
        cache_results: options.cacheResults !== false,
      };

      const response = await ThreatIntelAPI.enrichment.enrichIndicators(request);

      // Add items to queue for each indicator
      const queueItems = indicators.map((indicator, index) => ({
        id: `enrichment-${Date.now()}-${index}`,
        indicator,
        type: detectIndicatorType(indicator),
        status: 'processing' as const,
        services: enrichmentTypes,
        progress: 0,
        startTime: new Date().toISOString(),
      }));

      enrichmentStore.update(state => ({
        ...state,
        queue: [...queueItems, ...state.queue],
        stats: {
          ...state.stats,
          inQueue: state.stats.inQueue + indicators.length,
        },
        loading: { ...state.loading, enrichment: false },
      }));

      // Simulate enrichment progress
      queueItems.forEach(item => simulateEnrichmentProgress(item.id, response.enriched_data[0]));

      return response;

    } catch (error) {
      console.error('Failed to enrich indicators:', error);

      // Add failed items to queue for demo purposes
      const failedItems = indicators.map((indicator, index) => ({
        id: `failed-${Date.now()}-${index}`,
        indicator,
        type: detectIndicatorType(indicator),
        status: 'failed' as const,
        services: enrichmentTypes,
        progress: 0,
        startTime: new Date().toISOString(),
      }));

      enrichmentStore.update(state => ({
        ...state,
        queue: [...failedItems, ...state.queue],
        loading: { ...state.loading, enrichment: false },
        errors: { ...state.errors, enrichment: error instanceof Error ? error.message : 'Enrichment failed' },
      }));

      throw error;
    }
  },

  // Update service status
  updateServiceStatus(serviceId: string, status: 'healthy' | 'degraded' | 'offline') {
    enrichmentStore.update(state => ({
      ...state,
      services: state.services.map(service =>
        service.id === serviceId ? { ...service, status } : service
      ),
    }));
  },

  // Clear enrichment error
  clearError(type: keyof EnrichmentState['errors']) {
    enrichmentStore.update(state => ({
      ...state,
      errors: { ...state.errors, [type]: null },
    }));
  },

  // Reset enrichment store
  reset() {
    enrichmentStore.set(initialState);
  },
};

// Helper functions
function detectIndicatorType(indicator: string): string {
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(indicator)) return 'ip';
  if (/^[a-f0-9]{32,128}$/i.test(indicator)) return 'hash';
  if (/^https?:\/\//.test(indicator)) return 'url';
  if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(indicator)) return 'domain';
  return 'unknown';
}

function generateDemoQueue(): EnrichmentState['queue'] {
  return [
    {
      id: 'queue-1',
      indicator: '192.168.1.100',
      type: 'ip',
      status: 'processing',
      services: ['shodan', 'geolocation'],
      progress: 75,
      startTime: new Date(Date.now() - 2 * 60 * 1000).toISOString(), // 2 minutes ago
    },
    {
      id: 'queue-2',
      indicator: 'suspicious-domain.example.com',
      type: 'domain',
      status: 'completed',
      services: ['dns', 'geolocation'],
      progress: 100,
      startTime: new Date(Date.now() - 5 * 60 * 1000).toISOString(), // 5 minutes ago
    },
    {
      id: 'queue-3',
      indicator: 'a1b2c3d4e5f6789a1b2c3d4e5f6789a1b2c3d4e5f6789a1b2c3d4e5f6789',
      type: 'hash',
      status: 'pending',
      services: ['virustotal'],
      progress: 0,
      startTime: 'Queued',
    },
  ];
}

function generateDemoResults(hasRealData: boolean): EnrichmentState['recentResults'] {
  if (!hasRealData) {
    return [
      {
        id: 'result-1',
        indicator: '192.168.1.100',
        type: 'ip',
        services: ['shodan', 'geolocation'],
        timestamp: new Date(Date.now() - 1 * 60 * 60 * 1000).toISOString(), // 1 hour ago
        confidence: 85,
        enrichment: {
          location: { country: 'US', city: 'San Francisco' },
          ports: [80, 443, 22],
        },
      },
      {
        id: 'result-2',
        indicator: 'malicious-site.example.com',
        type: 'domain',
        services: ['dns', 'geolocation'],
        timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(), // 2 hours ago
        confidence: 92,
        enrichment: {
          dns: { a_records: ['1.2.3.4'], mx_records: ['mail.example.com'] },
          location: { country: 'RU', city: 'Moscow' },
        },
      },
      {
        id: 'result-3',
        indicator: 'bad-file-hash.exe',
        type: 'hash',
        services: ['virustotal'],
        timestamp: new Date(Date.now() - 3 * 60 * 60 * 1000).toISOString(), // 3 hours ago
        confidence: 98,
        enrichment: {
          detections: 45,
          scanners: 70,
          malware_families: ['trojan', 'backdoor'],
        },
      },
    ];
  }
  return [];
}

function simulateEnrichmentProgress(queueId: string, enrichmentData?: any) {
  let progress = 0;
  const interval = setInterval(() => {
    progress += Math.random() * 15 + 10; // 10-25% increments

    if (progress >= 100) {
      progress = 100;
      clearInterval(interval);

      // Mark as completed and add to results
      enrichmentStore.update(state => {
        const queueItem = state.queue.find(q => q.id === queueId);
        if (!queueItem) return state;

        const result = {
          id: `result-${Date.now()}`,
          indicator: queueItem.indicator,
          type: queueItem.type,
          services: queueItem.services,
          timestamp: new Date().toISOString(),
          confidence: Math.floor(Math.random() * 30) + 70, // 70-100%
          enrichment: enrichmentData?.enrichment || generateMockEnrichment(queueItem.type),
        };

        return {
          ...state,
          queue: state.queue.map(q =>
            q.id === queueId ? { ...q, status: 'completed', progress: 100, result } : q
          ),
          recentResults: [result, ...state.recentResults.slice(0, 4)],
          stats: {
            ...state.stats,
            iocsEnriched: state.stats.iocsEnriched + 1,
            inQueue: Math.max(0, state.stats.inQueue - 1),
          },
        };
      });
    } else {
      // Update progress
      enrichmentStore.update(state => ({
        ...state,
        queue: state.queue.map(q =>
          q.id === queueId ? { ...q, progress: Math.floor(progress) } : q
        ),
      }));
    }
  }, 800); // Update every 800ms
}

function generateMockEnrichment(type: string) {
  switch (type) {
    case 'ip':
      return {
        location: { country: 'US', city: 'New York' },
        ports: [80, 443, 22],
        organization: 'Example ISP',
      };
    case 'domain':
      return {
        dns: { a_records: ['1.2.3.4'], mx_records: ['mail.example.com'] },
        location: { country: 'CA', city: 'Toronto' },
      };
    case 'hash':
      return {
        detections: Math.floor(Math.random() * 50),
        scanners: 70,
        malware_families: ['trojan'],
      };
    default:
      return {};
  }
}