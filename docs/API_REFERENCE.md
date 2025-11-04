# Threat Intelligence Platform API Reference

**Version**: 1.0
**Base URL**: `https://u88kzux168.execute-api.us-east-1.amazonaws.com/dev`
**Last Updated**: November 4, 2025

## Overview

The Threat Intelligence Platform provides a RESTful API for automated threat intelligence collection, OSINT enrichment, and threat data search capabilities. The platform integrates with multiple threat intelligence sources and provides STIX 2.1 compliant data output.

## Authentication

All API endpoints require authentication using an API key passed in the request header.

### Header
```
x-api-key: mhxJBeDRDP515dkUrivFZ2B9IWY1Khx3cQkUh7jf
```

### CORS
CORS is enabled for web frontend integration with the following headers:
- `Access-Control-Allow-Origin: *`
- `Access-Control-Allow-Methods: GET, POST, OPTIONS`
- `Access-Control-Allow-Headers: Content-Type, x-api-key`

## Rate Limiting

- **Collection Endpoint**: Maximum 10 requests per minute per API key
- **Enrichment Endpoint**: Maximum 10 requests per minute per API key (Shodan API limits)
- **Search Endpoint**: Maximum 100 requests per minute per API key

## Endpoints

### 1. POST /collect

Triggers automated threat intelligence collection from configured OSINT sources.

**Status**:  **FULLY OPERATIONAL** (Completed Nov 4, 2025)

#### Request

```http
POST /collect
Content-Type: application/json
x-api-key: mhxJBeDRDP515dkUrivFZ2B9IWY1Khx3cQkUh7jf

{
  "sources": ["otx", "abuse_ch"],
  "limit": 50,
  "collection_type": "automated",
  "filters": {
    "ioc_types": ["domain", "ip", "hash"],
    "confidence": 70
  }
}
```

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `sources` | array | No | Data sources to collect from. Options: `["otx", "abuse_ch"]`. Default: `["otx", "abuse_ch"]` |
| `limit` | integer | No | Maximum indicators to collect. Range: 1-100. Default: 50 |
| `collection_type` | string | No | Collection mode. Options: `"automated"`, `"manual"`. Default: `"automated"` |
| `filters` | object | No | Collection filters |
| `filters.ioc_types` | array | No | IOC types to collect. Options: `["domain", "ip", "hash", "url"]` |
| `filters.confidence` | integer | No | Minimum confidence score (0-100). Default: 70 |

#### Response

**Success (200)**:
```json
{
  "message": "Collection completed successfully",
  "indicators_collected": 48,
  "indicators_stored": 45,
  "collection_stats": {
    "otx": 48,
    "abuse_ch": 0
  },
  "timestamp": "2025-11-04T14:29:17.602444+00:00"
}
```

**Error (400)**:
```json
{
  "error": "Invalid request parameters",
  "message": "Limit must be between 1 and 100",
  "timestamp": "2025-11-04T14:29:17.602444+00:00"
}
```

**Error (500)**:
```json
{
  "error": "Collection failed",
  "message": "Unable to connect to OTX API",
  "timestamp": "2025-11-04T14:29:17.602444+00:00"
}
```

#### Example Usage

```bash
curl -X POST "https://u88kzux168.execute-api.us-east-1.amazonaws.com/dev/collect" \
  -H "Content-Type: application/json" \
  -H "x-api-key: mhxJBeDRDP515dkUrivFZ2B9IWY1Khx3cQkUh7jf" \
  -d '{
    "sources": ["otx"],
    "limit": 25,
    "filters": {
      "ioc_types": ["domain", "ip"],
      "confidence": 80
    }
  }'
```

### 2. POST /enrich

Performs OSINT enrichment on provided indicators using Shodan, DNS resolution, and geolocation services.

**Status**:  **FULLY OPERATIONAL** (Completed Nov 4, 2025)

#### Request

```http
POST /enrich
Content-Type: application/json
x-api-key: mhxJBeDRDP515dkUrivFZ2B9IWY1Khx3cQkUh7jf

{
  "ioc_value": "8.8.8.8",
  "ioc_type": "ipv4"
}
```

**Alternative format for multiple indicators**:
```json
{
  "indicators": [
    {
      "ioc_value": "8.8.8.8",
      "ioc_type": "ipv4"
    },
    {
      "ioc_value": "example.com",
      "ioc_type": "domain"
    }
  ],
  "enrichment_types": ["shodan", "dns", "geolocation"],
  "cache_results": true
}
```

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `ioc_value` | string | Yes* | Single indicator value to enrich |
| `ioc_type` | string | Yes* | Type of indicator. Options: `"ipv4"`, `"domain"`, `"hash"`, `"url"` |
| `indicators` | array | Yes* | Array of indicator objects (alternative to single indicator) |
| `enrichment_types` | array | No | Enrichment sources. Options: `["shodan", "dns", "geolocation"]`. Default: all |
| `cache_results` | boolean | No | Cache enrichment results (7-day TTL). Default: `true` |

*Either `ioc_value`/`ioc_type` OR `indicators` is required.

#### Response

**Success (200)**:
```json
{
  "enriched_indicators": [
    {
      "ioc_value": "8.8.8.8",
      "ioc_type": "ipv4",
      "enriched_at": "2025-11-04T14:24:52.562118+00:00",
      "sources": ["geolocation", "shodan"],
      "geolocation": {
        "country": "United States",
        "country_code": "US",
        "region": "Virginia",
        "city": "Ashburn",
        "latitude": 39.03,
        "longitude": -77.5,
        "isp": "Google LLC",
        "org": "Google Public DNS",
        "timezone": "America/New_York",
        "source": "ip-api.com"
      },
      "shodan": {
        "ip": "8.8.8.8",
        "hostnames": ["dns.google"],
        "country_code": "US",
        "country_name": "United States",
        "city": "Mountain View",
        "org": "Google LLC",
        "isp": "Google LLC",
        "ports": [443, 53],
        "vulns": [],
        "last_update": "2025-11-04T09:54:36.177589",
        "tags": [],
        "os": null,
        "source": "shodan",
        "services": [
          {
            "port": 53,
            "protocol": "tcp",
            "product": null,
            "version": null,
            "banner": "\\nRecursion: enabled"
          },
          {
            "port": 443,
            "protocol": "tcp",
            "product": null,
            "version": null,
            "banner": "HTTP/1.1 200 OK..."
          }
        ]
      },
      "risk_score": 0
    }
  ],
  "total_processed": 1,
  "timestamp": "2025-11-04T14:24:52.718668+00:00"
}
```

**Error (400)**:
```json
{
  "error": "Enrichment failed",
  "message": "No indicators provided for enrichment",
  "timestamp": "2025-11-04T14:24:52.718668+00:00"
}
```

#### Risk Scoring

The `risk_score` field is calculated based on:
- **Vulnerabilities**: +20 points per CVE (max 60 points)
- **Sensitive Ports**: +10 points for ports 22, 23, 21, 3389, 1433, 3306, 5432, 27017
- **Geographic Risk**: +15 points for high-risk countries (CN, RU, KP, IR)
- **Maximum Score**: 100 points

#### Example Usage

```bash
curl -X POST "https://u88kzux168.execute-api.us-east-1.amazonaws.com/dev/enrich" \
  -H "Content-Type: application/json" \
  -H "x-api-key: mhxJBeDRDP515dkUrivFZ2B9IWY1Khx3cQkUh7jf" \
  -d '{
    "ioc_value": "1.1.1.1",
    "ioc_type": "ipv4"
  }'
```

### 3. GET /search

Searches stored threat intelligence data with optional filtering and pagination.

**Status**:  **FULLY OPERATIONAL** (Fixed Nov 3, 2025)

#### Request

```http
GET /search?q=malware&type=domain&source=otx&limit=10&confidence=80
x-api-key: mhxJBeDRDP515dkUrivFZ2B9IWY1Khx3cQkUh7jf
```

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `q` | string | No | Search query (searches across IOC values and pulse names) |
| `type` | string | No | Filter by IOC type. Options: `"domain"`, `"ip"`, `"hash"`, `"url"` |
| `source` | string | No | Filter by data source. Options: `"otx"`, `"abuse_ch"` |
| `limit` | integer | No | Number of results to return. Range: 1-100. Default: 20 |
| `confidence` | integer | No | Minimum confidence score (0-100) |
| `threat_type` | string | No | Filter by threat type |

#### Response

**Success (200)**:
```json
{
  "action": "search",
  "results": {
    "results": [
      {
        "ioc_value": "brokeragepacket.com",
        "pulse_name": "Remote access, real cargo: cybercriminals targeting trucking and logistics",
        "created_at": "2025-11-03T22:18:10.014408+00:00",
        "stix_data": {
          "spec_version": "2.1",
          "created": "2025-11-03T22:18:10.009829+00:00",
          "confidence": 75.0,
          "pattern": "[domain-name:value = 'brokeragepacket.com']",
          "modified": "2025-11-03T22:18:10.009832+00:00",
          "ioc_value": "brokeragepacket.com",
          "id": "indicator--5e05c3888cf52e0b25519cf828d0d831",
          "source": "otx",
          "type": "indicator",
          "ioc_type": "domain",
          "labels": ["malicious-activity"]
        },
        "threat_type": "unknown",
        "indicator_id": "indicator--5e05c3888cf52e0b25519cf828d0d831",
        "content_hash": "d79dfc8a1da7d44bc96f2fc637f8d504169d4a7ad6298f680aa4c8c9dd74e695",
        "object_type": "indicator",
        "confidence": 75.0,
        "ioc_type": "domain",
        "source": "otx",
        "object_id": "indicator--5e05c3888cf52e0b25519cf828d0d831"
      }
    ],
    "count": 1,
    "query": {
      "q": "brokeragepacket",
      "limit": 10
    }
  },
  "timestamp": "2025-11-04T14:29:46.154572+00:00"
}
```

**Empty Results (200)**:
```json
{
  "action": "search",
  "results": {
    "results": [],
    "count": 0,
    "query": {
      "q": "nonexistent",
      "limit": 20
    }
  },
  "timestamp": "2025-11-04T14:29:46.154572+00:00"
}
```

#### Search Methods

The search endpoint supports multiple search patterns:

1. **General Search**: Searches across IOC values and pulse names
2. **Type-based Search**: Filter by specific IOC types
3. **Source-based Search**: Filter by data source
4. **Confidence-based Search**: Filter by confidence threshold

#### Example Usage

```bash
# General search
curl -G "https://u88kzux168.execute-api.us-east-1.amazonaws.com/dev/search" \
  -H "x-api-key: mhxJBeDRDP515dkUrivFZ2B9IWY1Khx3cQkUh7jf" \
  -d "q=malware" \
  -d "limit=5"

# Domain-specific search
curl -G "https://u88kzux168.execute-api.us-east-1.amazonaws.com/dev/search" \
  -H "x-api-key: mhxJBeDRDP515dkUrivFZ2B9IWY1Khx3cQkUh7jf" \
  -d "type=domain" \
  -d "source=otx" \
  -d "limit=10"
```

## Data Models

### STIX 2.1 Compliance

All threat intelligence data follows STIX 2.1 specification:

```json
{
  "spec_version": "2.1",
  "type": "indicator",
  "id": "indicator--{uuid}",
  "created": "2025-11-04T14:29:17.602444+00:00",
  "modified": "2025-11-04T14:29:17.602444+00:00",
  "pattern": "[domain-name:value = 'example.com']",
  "labels": ["malicious-activity"],
  "confidence": 75,
  "ioc_value": "example.com",
  "ioc_type": "domain",
  "source": "otx"
}
```

### IOC Types

Supported Indicator of Compromise types:

| Type | Description | Pattern Example |
|------|-------------|-----------------|
| `domain` | Domain names | `[domain-name:value = 'example.com']` |
| `ipv4` | IPv4 addresses | `[ipv4-addr:value = '192.168.1.1']` |
| `hash` | File hashes (MD5, SHA1, SHA256) | `[file:hashes.MD5 = 'abc123...']` |
| `url` | URLs | `[url:value = 'https://example.com/path']` |

## Error Handling

### HTTP Status Codes

| Code | Meaning | Description |
|------|---------|-------------|
| 200 | Success | Request completed successfully |
| 400 | Bad Request | Invalid request parameters |
| 401 | Unauthorized | Invalid or missing API key |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Server Error | Server-side error occurred |

### Error Response Format

```json
{
  "error": "Error category",
  "message": "Detailed error description",
  "timestamp": "2025-11-04T14:29:17.602444+00:00",
  "details": {
    "parameter": "limit",
    "received": 150,
    "expected": "1-100"
  }
}
```

### Common Error Messages

#### Authentication Errors
- `"Invalid API key"` - API key is incorrect or revoked
- `"Missing API key"` - x-api-key header not provided

#### Rate Limiting Errors
- `"Rate limit exceeded"` - Too many requests in time window
- `"Quota exceeded"` - Daily/monthly quota reached

#### Validation Errors
- `"Invalid IOC type"` - Unsupported IOC type provided
- `"Invalid parameter format"` - Parameter format is incorrect
- `"Missing required parameters"` - Required fields not provided

## SDK Examples

### Python

```python
import requests

class ThreatIntelAPI:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://u88kzux168.execute-api.us-east-1.amazonaws.com/dev"
        self.headers = {
            "Content-Type": "application/json",
            "x-api-key": api_key
        }

    def collect_threats(self, sources=["otx"], limit=50):
        response = requests.post(
            f"{self.base_url}/collect",
            headers=self.headers,
            json={"sources": sources, "limit": limit}
        )
        return response.json()

    def enrich_ioc(self, ioc_value, ioc_type):
        response = requests.post(
            f"{self.base_url}/enrich",
            headers=self.headers,
            json={"ioc_value": ioc_value, "ioc_type": ioc_type}
        )
        return response.json()

    def search_threats(self, query=None, ioc_type=None, limit=20):
        params = {"limit": limit}
        if query:
            params["q"] = query
        if ioc_type:
            params["type"] = ioc_type

        response = requests.get(
            f"{self.base_url}/search",
            headers={"x-api-key": self.api_key},
            params=params
        )
        return response.json()

# Usage
api = ThreatIntelAPI("mhxJBeDRDP515dkUrivFZ2B9IWY1Khx3cQkUh7jf")
threats = api.collect_threats(sources=["otx"], limit=25)
enrichment = api.enrich_ioc("8.8.8.8", "ipv4")
search_results = api.search_threats(query="malware", limit=10)
```

### JavaScript

```javascript
class ThreatIntelAPI {
    constructor(apiKey) {
        this.apiKey = apiKey;
        this.baseUrl = "https://u88kzux168.execute-api.us-east-1.amazonaws.com/dev";
    }

    async collectThreats(sources = ["otx"], limit = 50) {
        const response = await fetch(`${this.baseUrl}/collect`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-api-key': this.apiKey
            },
            body: JSON.stringify({ sources, limit })
        });
        return response.json();
    }

    async enrichIOC(iocValue, iocType) {
        const response = await fetch(`${this.baseUrl}/enrich`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-api-key': this.apiKey
            },
            body: JSON.stringify({
                ioc_value: iocValue,
                ioc_type: iocType
            })
        });
        return response.json();
    }

    async searchThreats(query = null, iocType = null, limit = 20) {
        const params = new URLSearchParams({ limit });
        if (query) params.append('q', query);
        if (iocType) params.append('type', iocType);

        const response = await fetch(`${this.baseUrl}/search?${params}`, {
            headers: { 'x-api-key': this.apiKey }
        });
        return response.json();
    }
}

// Usage
const api = new ThreatIntelAPI("mhxJBeDRDP515dkUrivFZ2B9IWY1Khx3cQkUh7jf");
const threats = await api.collectThreats(["otx"], 25);
const enrichment = await api.enrichIOC("8.8.8.8", "ipv4");
const searchResults = await api.searchThreats("malware", null, 10);
```

## Changelog

### Version 1.0 (November 4, 2025)
-  **API Gateway Base64 Issue Resolution**: Fixed systematic JSON parsing errors across all POST endpoints
-  **Complete Endpoint Functionality**: All three endpoints (collect, enrich, search) fully operational
-  **Enhanced Documentation**: Comprehensive API reference with examples and SDK code
-  **Verified Integration**: End-to-end testing confirmed with live data collection and enrichment

### Previous Versions
- **November 3, 2025**: Initial deployment with search endpoint functionality
- **November 3, 2025**: OTX collection integration and DynamoDB storage
- **October 31, 2025**: Infrastructure deployment and Lambda function setup

## Support

For technical support, API questions, or to report issues:
- **Documentation**: [Project Repository](https://github.com/user/threat-intel-platform)
- **Status Page**: All endpoints monitored with 99.9% uptime target
- **Rate Limit Increases**: Contact support for higher rate limits

---

**Last Updated**: November 4, 2025
**API Version**: 1.0
**Status**:  All endpoints operational