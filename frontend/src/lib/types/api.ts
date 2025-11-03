// Threat Intelligence Platform API Type Definitions

export interface ThreatIndicator {
  id: string;
  type: 'ip' | 'domain' | 'url' | 'hash' | 'email';
  value: string;
  confidence: number;
  source: string;
  created_at: string;
  updated_at: string;
  tags: string[];
  stix_data: Record<string, unknown>;
}

export interface ThreatCollection {
  job_id: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  sources: string[];
  collection_type: string;
  progress: number;
  total_indicators: number;
  created_at: string;
  completed_at?: string;
  error_message?: string;
}

export interface EnrichmentResult {
  indicator: string;
  type: string;
  confidence: number;
  enrichment: {
    shodan?: {
      ports: number[];
      location: {
        country: string;
        city: string;
        coordinates: [number, number];
      };
      organization: string;
      last_scan: string;
    };
    dns?: {
      a_records: string[];
      mx_records: string[];
      ns_records: string[];
      txt_records: string[];
    };
    geolocation?: {
      country: string;
      region: string;
      city: string;
      coordinates: [number, number];
      timezone: string;
    };
  };
  cache_hit: boolean;
  enriched_at: string;
}

export interface APIResponse<T> {
  success: boolean;
  data: T;
  message?: string;
  errors?: string[];
}

export interface PaginatedResponse<T> {
  results: T[];
  total: number;
  page: number;
  per_page: number;
  has_next: boolean;
  has_prev: boolean;
}

export interface SystemStatus {
  api_gateway: 'healthy' | 'degraded' | 'down';
  lambda_functions: 'healthy' | 'degraded' | 'down';
  database: 'healthy' | 'degraded' | 'down';
  storage: 'healthy' | 'degraded' | 'down';
  last_checked: string;
}