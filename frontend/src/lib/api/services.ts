import type { AxiosResponse } from 'axios';
import { apiClient } from './client';

// Type definitions based on CLAUDE.md API specifications
export interface ThreatCollectionRequest {
  sources: string[];
  collection_type: string;
  filters?: Record<string, unknown>;
}

export interface ThreatCollectionResponse {
  job_id: string;
  status: string;
  collection_metadata: Record<string, unknown>;
}

export interface EnrichmentRequest {
  indicators: string[];
  enrichment_types: string[];
  cache_results?: boolean;
}

export interface EnrichmentResponse {
  enriched_data: Array<{
    indicator: string;
    type: string;
    confidence: number;
    enrichment: Record<string, unknown>;
  }>;
}

export interface SearchParams {
  q?: string;
  type?: string;
  limit?: number;
  confidence?: number;
}

export interface SearchResponse {
  results: Array<{
    id: string;
    type: string;
    value: string;
    confidence: number;
    source: string;
    created_at: string;
    stix_data: Record<string, unknown>;
  }>;
  total: number;
  page: number;
}

// Backend API response format (actual format from the API)
interface BackendSearchResponse {
  action: string;
  results: {
    results: Array<{
      indicator_id: string;
      ioc_type: string;
      ioc_value: string;
      confidence: number;
      source: string;
      created_at: string;
      stix_data: Record<string, unknown>;
    }>;
    count: number;
    query: Record<string, unknown>;
  };
  timestamp: string;
}

/**
 * Threat Collection Service
 * Handles POST /collect requests for automated threat intelligence collection
 */
export class ThreatCollectionService {
  static async collectThreats(request: ThreatCollectionRequest): Promise<ThreatCollectionResponse> {
    const response: AxiosResponse<ThreatCollectionResponse> = await apiClient.post('/collect', request);
    return response.data;
  }

  static async getCollectionStatus(jobId: string): Promise<{ status: string; progress: number }> {
    const response = await apiClient.get(`/collect/status/${jobId}`);
    return response.data;
  }
}

/**
 * OSINT Enrichment Service
 * Handles POST /enrich requests for IOC enrichment
 */
export class EnrichmentService {
  static async enrichIndicators(request: EnrichmentRequest): Promise<EnrichmentResponse> {
    const response: AxiosResponse<EnrichmentResponse> = await apiClient.post('/enrich', request);
    return response.data;
  }

  static async getSupportedEnrichmentTypes(): Promise<string[]> {
    const response = await apiClient.get('/enrich/types');
    return response.data.types;
  }
}

/**
 * Threat Intelligence Search Service
 * Handles GET /search requests for querying stored threat data
 */
export class SearchService {
  // Helper method to transform backend response to frontend format
  private static transformSearchResponse(backendResponse: BackendSearchResponse): SearchResponse {
    console.log('SearchService: Transforming backend response:', backendResponse);

    const transformed = {
      results: backendResponse.results.results.map(item => ({
        id: item.indicator_id,
        type: item.ioc_type,
        value: item.ioc_value,
        confidence: item.confidence,
        source: item.source,
        created_at: item.created_at,
        stix_data: item.stix_data,
      })),
      total: backendResponse.results.count,
      page: 1, // Backend doesn't provide pagination info currently
    };

    console.log('SearchService: Transformed response:', transformed);
    return transformed;
  }

  static async searchThreats(params: SearchParams): Promise<SearchResponse> {
    console.log('SearchService: Making request with params:', params);
    const response: AxiosResponse<BackendSearchResponse> = await apiClient.get('/search', { params });
    console.log('SearchService: Raw response:', response.data);
    return this.transformSearchResponse(response.data);
  }

  static async getRecentThreats(limit: number = 10): Promise<SearchResponse> {
    const response: AxiosResponse<BackendSearchResponse> = await apiClient.get('/search', {
      params: { limit, sort: 'created_at:desc' }
    });
    return this.transformSearchResponse(response.data);
  }

  static async getThreatByType(type: string, limit: number = 50): Promise<SearchResponse> {
    const response: AxiosResponse<BackendSearchResponse> = await apiClient.get('/search', {
      params: { type, limit }
    });
    return this.transformSearchResponse(response.data);
  }
}

/**
 * Combined API Service for convenience
 */
export const ThreatIntelAPI = {
  collection: ThreatCollectionService,
  enrichment: EnrichmentService,
  search: SearchService,
};