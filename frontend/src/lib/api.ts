// API client for threat intelligence platform
import ky from 'ky';

const API_BASE = 'https://u88kzux168.execute-api.us-east-1.amazonaws.com/dev';
const API_KEY = import.meta.env.VITE_API_KEY || 'mhxJBeDRDP515dkUrivFZ2B9IWY1Khx3cQkUh7jf';

export const api = ky.create({
  prefixUrl: API_BASE,
  headers: { 'x-api-key': API_KEY },
  timeout: 30000
});

// Direct response types matching actual API
export interface ThreatIndicator {
  indicator_id: string;
  ioc_value: string;
  ioc_type: string;
  confidence: number;
  source: string;
  created_at: string;
  stix_data: any;
}

export interface ApiSearchResponse {
  action: string;
  results: {
    results: ThreatIndicator[];
    count: number;
  };
  timestamp: string;
}

export interface CollectionResponse {
  action: string;
  results: {
    collected: number;
    stored: number;
    duplicates: number;
    errors: number;
  };
  timestamp: string;
}

export interface EnrichmentResponse {
  action: string;
  results: {
    indicator: string;
    enrichment_data: {
      shodan?: any;
      dns?: any;
      geolocation?: any;
    };
    risk_score: number;
  };
  timestamp: string;
}

// API functions - simple and direct
export async function searchThreats(limit = 10): Promise<ApiSearchResponse> {
  return api.get('search', { searchParams: { limit } }).json();
}

export async function collectThreats(sources: string[] = ['otx']): Promise<CollectionResponse> {
  return api.post('collect', {
    json: { sources, action: 'collect' }
  }).json();
}

export async function enrichIndicator(indicator: string): Promise<EnrichmentResponse> {
  return api.post('enrich', {
    json: { indicators: [indicator], enrichment_types: ['shodan', 'dns', 'geolocation'] }
  }).json();
}