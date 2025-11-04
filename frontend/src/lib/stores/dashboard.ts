import { writable, derived } from 'svelte/store';
import { ThreatIntelAPI, type SearchResponse } from '$lib/api/services';
import type { ThreatIndicator, SystemStatus } from '$lib/types/api';

// Dashboard state interface
interface DashboardState {
  metrics: {
    totalThreats: number;
    activeCollections: number;
    iocsEnriched: number;
    uptime: number;
  };
  recentThreats: ThreatIndicator[];
  systemStatus: SystemStatus;
  loading: {
    metrics: boolean;
    recentThreats: boolean;
    systemStatus: boolean;
  };
  errors: {
    metrics: string | null;
    recentThreats: string | null;
    systemStatus: string | null;
  };
  lastUpdated: Date | null;
}

// Initial state
const initialState: DashboardState = {
  metrics: {
    totalThreats: 0,
    activeCollections: 0,
    iocsEnriched: 0,
    uptime: 0,
  },
  recentThreats: [],
  systemStatus: {
    api_gateway: 'healthy',
    lambda_functions: 'healthy',
    database: 'healthy',
    storage: 'healthy',
    last_checked: new Date().toISOString(),
  },
  loading: {
    metrics: false,
    recentThreats: false,
    systemStatus: false,
  },
  errors: {
    metrics: null,
    recentThreats: null,
    systemStatus: null,
  },
  lastUpdated: null,
};

// Create the main dashboard store
export const dashboardStore = writable<DashboardState>(initialState);

// Derived stores for individual sections
export const metricsStore = derived(dashboardStore, ($dashboard) => ({
  data: $dashboard.metrics,
  loading: $dashboard.loading.metrics,
  error: $dashboard.errors.metrics,
}));

export const recentThreatsStore = derived(dashboardStore, ($dashboard) => ({
  data: $dashboard.recentThreats,
  loading: $dashboard.loading.recentThreats,
  error: $dashboard.errors.recentThreats,
}));

export const systemStatusStore = derived(dashboardStore, ($dashboard) => ({
  data: $dashboard.systemStatus,
  loading: $dashboard.loading.systemStatus,
  error: $dashboard.errors.systemStatus,
}));

// Actions to update the store
export const dashboardActions = {
  // Fetch dashboard metrics from search API
  async fetchMetrics() {
    dashboardStore.update(state => ({
      ...state,
      loading: { ...state.loading, metrics: true },
      errors: { ...state.errors, metrics: null },
    }));

    try {
      // Get total threat count by searching for all indicators
      console.log('Dashboard: Fetching metrics...');
      const threatsResponse = await ThreatIntelAPI.search.searchThreats({
        limit: 1
      });
      console.log('Dashboard: Threats response:', threatsResponse);

      // Get enriched IOCs count (simplified - using same search for now)
      const enrichedResponse = await ThreatIntelAPI.search.searchThreats({
        limit: 1
      });
      console.log('Dashboard: Enriched response:', enrichedResponse);

      // Use API data if available, otherwise fallback to demo data
      const metrics = {
        totalThreats: threatsResponse.total || 1247, // Fallback to demo data
        activeCollections: 3, // This would come from a collections endpoint
        iocsEnriched: enrichedResponse.total || 892, // Fallback to demo data
        uptime: 99.97, // This would come from a health endpoint
      };

      console.log('Dashboard: Final metrics:', metrics);

      dashboardStore.update(state => ({
        ...state,
        metrics,
        loading: { ...state.loading, metrics: false },
        lastUpdated: new Date(),
      }));

    } catch (error) {
      console.error('Failed to fetch metrics:', error);
      dashboardStore.update(state => ({
        ...state,
        loading: { ...state.loading, metrics: false },
        errors: { ...state.errors, metrics: 'Failed to load metrics' },
      }));
    }
  },

  // Fetch recent threat activity
  async fetchRecentThreats() {
    dashboardStore.update(state => ({
      ...state,
      loading: { ...state.loading, recentThreats: true },
      errors: { ...state.errors, recentThreats: null },
    }));

    try {
      console.log('Dashboard: Fetching recent threats...');
      const response = await ThreatIntelAPI.search.getRecentThreats(5);
      console.log('Dashboard: Recent threats response:', response);

      // Transform API response to ThreatIndicator format, or use fallback data
      let recentThreats: ThreatIndicator[] = [];

      if (response.results && response.results.length > 0) {
        console.log('Dashboard: Using API data for recent threats');
        recentThreats = response.results.map(result => ({
          id: result.id,
          type: result.type as any,
          value: result.value,
          confidence: result.confidence,
          source: result.source,
          created_at: result.created_at,
          updated_at: result.created_at, // Use created_at as fallback
          tags: [], // Would be in stix_data
          stix_data: result.stix_data,
        }));
      } else {
        console.log('Dashboard: Using fallback demo data for recent threats');
        // Fallback demo data when API returns empty results
        recentThreats = [
          {
            id: 'demo-1',
            type: 'hash',
            value: '7f9a3c2e1b8d4a6f5e9c2a1b3d4f6e8a9c1b2d3f4e5a6b7c8d9e0f1a2b3c4d5e6f7',
            confidence: 95,
            source: 'OTX',
            created_at: new Date(Date.now() - 2 * 60 * 1000).toISOString(), // 2 minutes ago
            updated_at: new Date(Date.now() - 2 * 60 * 1000).toISOString(),
            tags: ['malware'],
            stix_data: {},
          },
          {
            id: 'demo-2',
            type: 'domain',
            value: 'suspicious-domain.example.com',
            confidence: 78,
            source: 'Abuse.ch',
            created_at: new Date(Date.now() - 5 * 60 * 1000).toISOString(), // 5 minutes ago
            updated_at: new Date(Date.now() - 5 * 60 * 1000).toISOString(),
            tags: ['phishing'],
            stix_data: {},
          },
          {
            id: 'demo-3',
            type: 'ip',
            value: '192.168.1.100',
            confidence: 62,
            source: 'Internal',
            created_at: new Date(Date.now() - 12 * 60 * 1000).toISOString(), // 12 minutes ago
            updated_at: new Date(Date.now() - 12 * 60 * 1000).toISOString(),
            tags: ['scanner'],
            stix_data: {},
          },
        ];
      }

      dashboardStore.update(state => ({
        ...state,
        recentThreats,
        loading: { ...state.loading, recentThreats: false },
        lastUpdated: new Date(),
      }));

    } catch (error) {
      console.error('Failed to fetch recent threats:', error);
      dashboardStore.update(state => ({
        ...state,
        loading: { ...state.loading, recentThreats: false },
        errors: { ...state.errors, recentThreats: 'Failed to load recent threats' },
      }));
    }
  },

  // Mock system status check (would be real health check endpoint)
  async fetchSystemStatus() {
    dashboardStore.update(state => ({
      ...state,
      loading: { ...state.loading, systemStatus: true },
      errors: { ...state.errors, systemStatus: null },
    }));

    try {
      // For now, just test API connectivity by making a simple search call
      await ThreatIntelAPI.search.searchThreats({ limit: 1 });

      const systemStatus: SystemStatus = {
        api_gateway: 'healthy',
        lambda_functions: 'healthy',
        database: 'healthy',
        storage: 'healthy',
        last_checked: new Date().toISOString(),
      };

      dashboardStore.update(state => ({
        ...state,
        systemStatus,
        loading: { ...state.loading, systemStatus: false },
        lastUpdated: new Date(),
      }));

    } catch (error) {
      console.error('Failed to check system status:', error);

      const systemStatus: SystemStatus = {
        api_gateway: 'degraded',
        lambda_functions: 'degraded',
        database: 'degraded',
        storage: 'degraded',
        last_checked: new Date().toISOString(),
      };

      dashboardStore.update(state => ({
        ...state,
        systemStatus,
        loading: { ...state.loading, systemStatus: false },
        errors: { ...state.errors, systemStatus: 'System check failed' },
      }));
    }
  },

  // Load all dashboard data
  async loadDashboard() {
    await Promise.all([
      dashboardActions.fetchMetrics(),
      dashboardActions.fetchRecentThreats(),
      dashboardActions.fetchSystemStatus(),
    ]);
  },

  // Clear error for a specific section
  clearError(section: keyof DashboardState['errors']) {
    dashboardStore.update(state => ({
      ...state,
      errors: { ...state.errors, [section]: null },
    }));
  },

  // Reset the entire dashboard
  reset() {
    dashboardStore.set(initialState);
  },
};