# API Reference Documentation

## Overview

The Threat Intelligence Platform provides a comprehensive REST API for threat intelligence collection, processing, enrichment, search, analytics, and export operations. All endpoints require API key authentication and follow RESTful conventions.

## Base Configuration

### API Gateway Details
- **Base URL**: `https://{api_id}.execute-api.{region}.amazonaws.com/dev`
- **Authentication**: API Key required in `x-api-key` header
- **Content-Type**: `application/json`
- **Rate Limits**: 100 req/s, 200 burst, 10K/month quota

### Common Response Format
```json
{
  "status": "success|error",
  "message": "Operation description",
  "data": {},
  "timestamp": "2024-01-01T00:00:00Z",
  "correlation_id": "uuid"
}
```

### HTTP Status Codes
- **200**: Success
- **400**: Bad Request (invalid parameters)
- **401**: Unauthorized (missing/invalid API key)
- **429**: Rate Limit Exceeded
- **500**: Internal Server Error

## Core Endpoints

### 1. Threat Intelligence Collection

#### POST /collect
Trigger threat intelligence collection from OSINT sources.

**Request:**
```bash
curl -X POST "https://API_ID.execute-api.REGION.amazonaws.com/dev/collect" \
  -H "x-api-key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "source": "otx|abuse_ch|shodan",
    "priority": "critical|high|standard|low",
    "filters": {
      "date_range": {
        "start": "2024-01-01T00:00:00Z",
        "end": "2024-01-02T00:00:00Z"
      },
      "indicator_types": ["ip", "domain", "url", "hash"],
      "confidence_threshold": 70
    },
    "options": {
      "enable_enrichment": true,
      "batch_size": 50,
      "max_indicators": 1000
    }
  }'
```

**Response:**
```json
{
  "status": "success",
  "message": "Collection job initiated",
  "data": {
    "job_id": "collect-20240101-uuid",
    "source": "otx",
    "priority": "high",
    "estimated_completion": "2024-01-01T00:05:00Z",
    "indicators_expected": 245,
    "correlation_id": "corr-uuid"
  },
  "timestamp": "2024-01-01T00:00:00Z"
}
```

**Parameters:**
- `source` (required): Data source identifier
- `priority` (optional): Processing priority level (default: "standard")
- `filters` (optional): Collection filters and constraints
- `options` (optional): Collection configuration options

**Supported Sources:**
- `otx`: AT&T Alien Labs Open Threat Exchange
- `abuse_ch`: Abuse.ch multi-feed (MalwareBazaar, URLhaus, ThreatFox, Feodo)
- `shodan`: Shodan infrastructure scanning (requires premium key)

---

### 2. OSINT Enrichment

#### POST /enrich
Enrich threat indicators with additional intelligence sources.

**Request:**
```bash
curl -X POST "https://API_ID.execute-api.REGION.amazonaws.com/dev/enrich" \
  -H "x-api-key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "indicators": [
      {
        "type": "ip",
        "value": "8.8.8.8"
      },
      {
        "type": "domain",
        "value": "example.com"
      }
    ],
    "enrichment_types": [
      "geolocation",
      "reputation",
      "dns_analysis",
      "whois",
      "shodan"
    ],
    "options": {
      "force_refresh": false,
      "include_raw_data": true,
      "confidence_threshold": 60
    }
  }'
```

**Response:**
```json
{
  "status": "success",
  "message": "Enrichment completed",
  "data": {
    "enriched_indicators": [
      {
        "indicator": {
          "type": "ip",
          "value": "8.8.8.8"
        },
        "enrichment": {
          "geolocation": {
            "country": "US",
            "region": "California",
            "city": "Mountain View",
            "latitude": 37.4056,
            "longitude": -122.0775,
            "confidence": 95
          },
          "reputation": {
            "risk_score": 15,
            "reputation_score": 85,
            "threat_level": "low",
            "sources_count": 12
          },
          "dns_analysis": {
            "reverse_dns": "dns.google",
            "ptr_records": ["dns.google."],
            "authoritative": true
          },
          "shodan": {
            "open_ports": [53, 443],
            "services": ["DNS", "HTTPS"],
            "last_scan": "2024-01-01T00:00:00Z",
            "vulns": []
          }
        },
        "cache_status": "hit",
        "processing_time_ms": 245
      }
    ],
    "summary": {
      "total_indicators": 2,
      "successful_enrichments": 2,
      "cache_hits": 1,
      "total_processing_time_ms": 450
    }
  },
  "timestamp": "2024-01-01T00:00:00Z"
}
```

**Enrichment Types:**
- `geolocation`: IP/domain geographic location
- `reputation`: Multi-source reputation scoring
- `dns_analysis`: DNS record analysis and validation
- `whois`: Domain registration information
- `shodan`: Infrastructure scanning and vulnerability data

---

### 3. Search & Query Engine

#### POST /search
Search threat intelligence data with advanced query capabilities.

**Request:**
```bash
curl -X POST "https://API_ID.execute-api.REGION.amazonaws.com/dev/search" \
  -H "x-api-key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "search",
    "query": {
      "ioc_value": "malicious.domain.com",
      "ioc_type": "domain",
      "threat_type": "malware",
      "date_range": {
        "start": "2024-01-01T00:00:00Z",
        "end": "2024-01-02T00:00:00Z"
      },
      "confidence_threshold": 70,
      "risk_score_range": {
        "min": 60,
        "max": 100
      },
      "sources": ["otx", "abuse_ch"],
      "fuzzy_match": true,
      "fuzzy_threshold": 0.8
    },
    "options": {
      "include_stix": true,
      "include_enrichment": true,
      "max_results": 100,
      "sort_by": "confidence",
      "sort_order": "desc"
    },
    "pagination": {
      "page": 1,
      "page_size": 50,
      "cursor": null
    }
  }'
```

**Response:**
```json
{
  "status": "success",
  "message": "Search completed",
  "data": {
    "results": [
      {
        "indicator_id": "ind-uuid",
        "ioc_value": "malicious.domain.com",
        "ioc_type": "domain",
        "threat_type": "malware",
        "confidence": 85,
        "risk_score": 75,
        "source": "otx",
        "first_seen": "2024-01-01T00:00:00Z",
        "last_seen": "2024-01-01T12:00:00Z",
        "stix_object": {
          "type": "indicator",
          "id": "indicator--uuid",
          "pattern": "[domain-name:value = 'malicious.domain.com']",
          "labels": ["malicious-activity"]
        },
        "enrichment": {
          "geolocation": {
            "country": "RU",
            "risk_level": "high"
          },
          "reputation": {
            "risk_score": 85,
            "threat_level": "high"
          }
        },
        "correlation_count": 5,
        "related_indicators": 12
      }
    ],
    "pagination": {
      "total_results": 245,
      "page": 1,
      "page_size": 50,
      "total_pages": 5,
      "next_cursor": "cursor-token",
      "has_more": true
    },
    "query_performance": {
      "execution_time_ms": 125,
      "strategy_used": "gsi_time_index",
      "cache_hit": false,
      "results_cached": true
    },
    "aggregations": {
      "by_source": {
        "otx": 150,
        "abuse_ch": 95
      },
      "by_threat_type": {
        "malware": 180,
        "phishing": 65
      },
      "by_confidence": {
        "high": 200,
        "medium": 45
      }
    }
  },
  "timestamp": "2024-01-01T00:00:00Z"
}
```

**Search Strategies:**
- `exact_ioc`: Direct IOC value match
- `pattern_search`: Pattern-based matching
- `fuzzy_search`: Similarity-based matching (70% threshold)
- `time_range`: Temporal query optimization
- `source_specific`: Source-filtered queries
- `correlation`: Related indicator discovery
- `risk_analysis`: Risk score-based filtering
- `geographic`: Location-based clustering
- `full_text`: Content-based search

---

### 4. Export Operations

#### POST /search (action: export)
Export threat intelligence data in multiple formats.

**Request:**
```bash
curl -X POST "https://API_ID.execute-api.REGION.amazonaws.com/dev/search" \
  -H "x-api-key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "export",
    "query": {
      "date_range": {
        "start": "2024-01-01T00:00:00Z",
        "end": "2024-01-02T00:00:00Z"
      },
      "sources": ["otx", "abuse_ch"],
      "confidence_threshold": 70
    },
    "export_options": {
      "format": "stix21",
      "compression": "gzip",
      "include_enrichment": true,
      "include_metadata": true,
      "max_file_size_mb": 100,
      "split_by_source": false
    },
    "delivery": {
      "method": "s3_presigned_url",
      "expires_in_hours": 24
    }
  }'
```

**Response:**
```json
{
  "status": "success",
  "message": "Export completed",
  "data": {
    "export_id": "export-20240101-uuid",
    "format": "stix21",
    "compression": "gzip",
    "file_info": {
      "filename": "threat_intel_export_20240101.stix2.gz",
      "size_bytes": 2048576,
      "compressed_size_bytes": 512144,
      "compression_ratio": 0.25,
      "record_count": 1250
    },
    "download": {
      "url": "https://s3.amazonaws.com/bucket/export.stix2.gz?X-Amz-SignedHeaders=...",
      "expires_at": "2024-01-02T00:00:00Z",
      "method": "GET"
    },
    "metadata": {
      "export_timestamp": "2024-01-01T00:00:00Z",
      "query_hash": "sha256-hash",
      "data_freshness": "2024-01-01T23:30:00Z"
    }
  },
  "timestamp": "2024-01-01T00:00:00Z"
}
```

**Export Formats:**
- `json`: Raw JSON format
- `csv`: Comma-separated values
- `stix21`: STIX 2.1 compliant format
- `xml`: Structured XML format

**Compression Options:**
- `none`: No compression
- `gzip`: GZIP compression (recommended)
- `zip`: ZIP archive format

---

## Analytics Endpoints

### 5. Trend Analysis

#### POST /search (action: trend_analysis)
Analyze threat intelligence trends and patterns.

**Request:**
```bash
curl -X POST "https://API_ID.execute-api.REGION.amazonaws.com/dev/search" \
  -H "x-api-key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "trend_analysis",
    "analysis_config": {
      "time_period": {
        "start": "2024-01-01T00:00:00Z",
        "end": "2024-01-07T00:00:00Z",
        "granularity": "daily"
      },
      "analysis_types": [
        "volume_trends",
        "threat_evolution",
        "source_analysis",
        "campaign_detection"
      ],
      "filters": {
        "threat_types": ["malware", "phishing"],
        "min_confidence": 70,
        "sources": ["otx", "abuse_ch"]
      }
    }
  }'
```

**Response:**
```json
{
  "status": "success",
  "message": "Trend analysis completed",
  "data": {
    "analysis_period": {
      "start": "2024-01-01T00:00:00Z",
      "end": "2024-01-07T00:00:00Z",
      "total_indicators": 15420
    },
    "volume_trends": {
      "daily_counts": [
        {"date": "2024-01-01", "count": 2100, "change_pct": 15.2},
        {"date": "2024-01-02", "count": 2350, "change_pct": 11.9}
      ],
      "peak_activity": {
        "timestamp": "2024-01-03T14:00:00Z",
        "indicator_count": 450,
        "dominant_threat": "malware"
      },
      "volatility_score": 0.23
    },
    "threat_evolution": {
      "emerging_threats": [
        {
          "threat_type": "ransomware",
          "growth_rate": 45.2,
          "indicator_count": 890,
          "confidence": 85
        }
      ],
      "declining_threats": [
        {
          "threat_type": "adware",
          "decline_rate": -12.5,
          "indicator_count": 120
        }
      ]
    },
    "campaign_detection": {
      "potential_campaigns": [
        {
          "campaign_id": "camp-uuid",
          "indicators_count": 245,
          "confidence": 78,
          "geographic_focus": ["US", "EU"],
          "timeframe": {
            "start": "2024-01-02T00:00:00Z",
            "peak": "2024-01-03T12:00:00Z"
          },
          "threat_type": "apt"
        }
      ]
    }
  },
  "timestamp": "2024-01-01T00:00:00Z"
}
```

### 6. Geographic Analysis

#### POST /search (action: geographic_analysis)
Analyze geographic distribution of threats.

**Request:**
```bash
curl -X POST "https://API_ID.execute-api.REGION.amazonaws.com/dev/search" \
  -H "x-api-key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "geographic_analysis",
    "analysis_config": {
      "clustering": {
        "enable": true,
        "radius_km": 100,
        "min_cluster_size": 5
      },
      "regions": ["US", "EU", "APAC"],
      "threat_types": ["malware", "phishing"],
      "time_period": {
        "start": "2024-01-01T00:00:00Z",
        "end": "2024-01-07T00:00:00Z"
      }
    }
  }'
```

### 7. Risk Scoring

#### POST /search (action: risk_scoring)
Generate comprehensive risk assessments.

**Request:**
```bash
curl -X POST "https://API_ID.execute-api.REGION.amazonaws.com/dev/search" \
  -H "x-api-key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "risk_scoring",
    "indicators": [
      {"type": "ip", "value": "192.168.1.1"},
      {"type": "domain", "value": "suspicious.com"}
    ],
    "scoring_config": {
      "weight_factors": {
        "source_reliability": 0.2,
        "temporal_relevance": 0.15,
        "geographic_risk": 0.1,
        "threat_severity": 0.25,
        "correlation_strength": 0.15,
        "consistency": 0.1,
        "urgency": 0.05
      },
      "business_context": {
        "industry": "finance",
        "geographic_focus": ["US"],
        "threat_tolerance": "low"
      }
    }
  }'
```

### 8. Correlation Analysis

#### POST /search (action: correlation_analysis)
Discover relationships between threat indicators.

**Request:**
```bash
curl -X POST "https://API_ID.execute-api.REGION.amazonaws.com/dev/search" \
  -H "x-api-key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "correlation_analysis",
    "seed_indicators": [
      {"type": "ip", "value": "192.168.1.1"},
      {"type": "domain", "value": "malicious.com"}
    ],
    "correlation_config": {
      "max_depth": 3,
      "min_correlation_score": 0.7,
      "correlation_types": [
        "infrastructure_overlap",
        "temporal_correlation",
        "behavioral_similarity",
        "attribution_links"
      ],
      "time_window_hours": 168
    }
  }'
```

## Administrative Endpoints

### 9. Cache Management

#### POST /search (action: cache_stats)
Get cache performance statistics.

**Request:**
```bash
curl -X POST "https://API_ID.execute-api.REGION.amazonaws.com/dev/search" \
  -H "x-api-key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "cache_stats",
    "time_period": {
      "start": "2024-01-01T00:00:00Z",
      "end": "2024-01-02T00:00:00Z"
    }
  }'
```

#### POST /search (action: invalidate_cache)
Invalidate cache entries.

**Request:**
```bash
curl -X POST "https://API_ID.execute-api.REGION.amazonaws.com/dev/search" \
  -H "x-api-key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "invalidate_cache",
    "invalidation_config": {
      "cache_types": ["query_results", "analytics"],
      "patterns": ["otx:*", "search:domain:*"],
      "force": false
    }
  }'
```

## Error Handling

### Error Response Format
```json
{
  "status": "error",
  "error": {
    "code": "INVALID_PARAMETERS",
    "message": "Missing required parameter: ioc_value",
    "details": {
      "parameter": "ioc_value",
      "expected_type": "string",
      "provided": null
    }
  },
  "timestamp": "2024-01-01T00:00:00Z",
  "correlation_id": "error-uuid"
}
```

### Common Error Codes
- `INVALID_API_KEY`: Authentication failed
- `RATE_LIMIT_EXCEEDED`: Request rate limit exceeded
- `INVALID_PARAMETERS`: Request validation failed
- `RESOURCE_NOT_FOUND`: Requested resource not found
- `PROCESSING_ERROR`: Internal processing error
- `EXTERNAL_API_ERROR`: External service unavailable
- `CACHE_ERROR`: Cache operation failed
- `EXPORT_TOO_LARGE`: Export exceeds size limits

## Rate Limiting

### Rate Limit Headers
All responses include rate limiting information:
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1609459200
X-RateLimit-Retry-After: 60
```

### Rate Limit Tiers
- **Free Tier**: 100 req/s, 1K req/day
- **Basic Tier**: 500 req/s, 10K req/day
- **Premium Tier**: 1K req/s, 100K req/day
- **Enterprise Tier**: 5K req/s, unlimited daily
- **Admin Tier**: Unlimited

## SDK Examples

### Python SDK
```python
import requests
import json

class ThreatIntelAPI:
    def __init__(self, api_key, base_url):
        self.api_key = api_key
        self.base_url = base_url
        self.headers = {
            'x-api-key': api_key,
            'Content-Type': 'application/json'
        }

    def search_indicators(self, query):
        payload = {
            'action': 'search',
            'query': query
        }
        response = requests.post(
            f"{self.base_url}/search",
            headers=self.headers,
            json=payload
        )
        return response.json()

    def enrich_indicator(self, indicator_type, indicator_value):
        payload = {
            'indicators': [{'type': indicator_type, 'value': indicator_value}],
            'enrichment_types': ['geolocation', 'reputation', 'dns_analysis']
        }
        response = requests.post(
            f"{self.base_url}/enrich",
            headers=self.headers,
            json=payload
        )
        return response.json()

# Usage
api = ThreatIntelAPI('your-api-key', 'https://api-id.execute-api.region.amazonaws.com/dev')
results = api.search_indicators({'ioc_value': 'malicious.com', 'ioc_type': 'domain'})
```

### JavaScript/Node.js SDK
```javascript
class ThreatIntelAPI {
    constructor(apiKey, baseUrl) {
        this.apiKey = apiKey;
        this.baseUrl = baseUrl;
    }

    async searchIndicators(query) {
        const response = await fetch(`${this.baseUrl}/search`, {
            method: 'POST',
            headers: {
                'x-api-key': this.apiKey,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                action: 'search',
                query: query
            })
        });
        return await response.json();
    }

    async enrichIndicator(type, value) {
        const response = await fetch(`${this.baseUrl}/enrich`, {
            method: 'POST',
            headers: {
                'x-api-key': this.apiKey,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                indicators: [{type, value}],
                enrichment_types: ['geolocation', 'reputation', 'dns_analysis']
            })
        });
        return await response.json();
    }
}

// Usage
const api = new ThreatIntelAPI('your-api-key', 'https://api-id.execute-api.region.amazonaws.com/dev');
const results = await api.searchIndicators({ioc_value: 'malicious.com', ioc_type: 'domain'});
```

## Testing & Development

### API Testing with curl
```bash
# Test API connectivity
curl -X GET "https://API_ID.execute-api.REGION.amazonaws.com/dev/collect" \
  -H "x-api-key: YOUR_API_KEY" \
  -w "\nHTTP Status: %{http_code}\nResponse Time: %{time_total}s\n"

# Test rate limiting
for i in {1..110}; do
  curl -s -o /dev/null -w "%{http_code} " \
    "https://API_ID.execute-api.REGION.amazonaws.com/dev/collect" \
    -H "x-api-key: YOUR_API_KEY"
done
```

### Postman Collection
Import the API collection for interactive testing:
```json
{
  "info": {
    "name": "Threat Intelligence Platform API",
    "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
  },
  "auth": {
    "type": "apikey",
    "apikey": [
      {"key": "key", "value": "x-api-key"},
      {"key": "value", "value": "{{API_KEY}}"}
    ]
  },
  "variable": [
    {"key": "BASE_URL", "value": "https://API_ID.execute-api.REGION.amazonaws.com/dev"}
  ]
}
```

---

For additional support or API questions, consult the TROUBLESHOOTING.md guide or check CloudWatch logs for detailed error analysis.