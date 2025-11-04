// API client for threat intelligence platform
import ky from 'ky';

const API_BASE = 'https://u88kzux168.execute-api.us-east-1.amazonaws.com/dev';
const API_KEY = import.meta.env.VITE_API_KEY || 'mhxJBeDRDP515dkUrivFZ2B9IWY1Khx3cQkUh7jf';

export const api = ky.create({
  prefixUrl: API_BASE,
  headers: { 'x-api-key': API_KEY },
  timeout: 30000
});

// Separate API client for collection endpoint with longer timeout
export const apiCollection = ky.create({
  prefixUrl: API_BASE,
  headers: { 'x-api-key': API_KEY },
  timeout: 60000  // 60 seconds for collection jobs
});

// Direct response types matching actual API specification
export interface ThreatIndicator {
  ioc_value: string;
  pulse_name: string;
  created_at: string;
  stix_data: {
    spec_version: string;
    created: string;
    confidence: number;
    pattern: string;
    modified: string;
    ioc_value: string;
    id: string;
    source: string;
    type: string;
    ioc_type: string;
    labels: string[];
  };
  threat_type: string;
  indicator_id: string;
  content_hash: string;
  object_type: string;
  confidence: number;
  ioc_type: string;
  source: string;
  object_id: string;
}

export interface ApiSearchResponse {
  action: string;
  results: {
    results: ThreatIndicator[];
    count: number;
    query: {
      q?: string;
      limit: number;
      type?: string;
      source?: string;
      confidence?: number;
    };
  };
  timestamp: string;
}

export interface CollectionResponse {
  message: string;
  indicators_collected: number;
  indicators_stored: number;
  collection_stats: {
    otx: number;
    abuse_ch: number;
  };
  timestamp: string;
}

export interface EnrichedIndicator {
  ioc_value: string;
  ioc_type: string;
  enriched_at: string;
  sources: string[];
  geolocation?: {
    country: string;
    country_code: string;
    region: string;
    city: string;
    latitude: number;
    longitude: number;
    isp: string;
    org: string;
    timezone: string;
    source: string;
  };
  shodan?: {
    ip: string;
    hostnames: string[];
    country_code: string;
    country_name: string;
    city: string;
    org: string;
    isp: string;
    ports: number[];
    vulns: string[];
    last_update: string;
    tags: string[];
    os: string | null;
    source: string;
    services: {
      port: number;
      protocol: string;
      product: string | null;
      version: string | null;
      banner: string;
    }[];
  };
}

export interface EnrichmentResponse {
  enriched_indicators: EnrichedIndicator[];
  total_processed: number;
  timestamp: string;
}

// API functions - matching actual API specification
export async function searchThreats(
  limit = 10,
  query?: string,
  type?: string,
  source?: string,
  confidence?: number
): Promise<ApiSearchResponse> {
  const params: Record<string, string> = { limit: limit.toString() };
  if (query) params.q = query;
  if (type) params.type = type;
  if (source) params.source = source;
  if (confidence) params.confidence = confidence.toString();

  return api.get('search', { searchParams: params }).json();
}

export async function collectThreats(
  sources: string[] = ['otx'],
  limit = 50,
  collectionType: 'automated' | 'manual' = 'automated',
  filters?: {
    ioc_types?: string[];
    confidence?: number;
  }
): Promise<CollectionResponse> {
  const requestBody: any = {
    sources,
    limit,
    collection_type: collectionType
  };

  if (filters) {
    requestBody.filters = filters;
  }

  return apiCollection.post('collect', { json: requestBody }).json();
}

export async function enrichIndicator(
  iocValue: string,
  iocType: 'ipv4' | 'domain' | 'hash' | 'url' = 'ipv4'
): Promise<EnrichmentResponse> {
  return api.post('enrich', {
    json: {
      ioc_value: iocValue,
      ioc_type: iocType
    }
  }).json();
}

// Helper function to auto-detect IOC type
export function detectIocType(value: string): 'ipv4' | 'domain' | 'hash' | 'url' {
  // IPv4 pattern
  if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(value)) {
    return 'ipv4';
  }

  // Hash patterns (MD5, SHA1, SHA256)
  if (/^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i.test(value)) {
    return 'hash';
  }

  // URL pattern
  if (/^https?:\/\//.test(value)) {
    return 'url';
  }

  // Default to domain
  return 'domain';
}