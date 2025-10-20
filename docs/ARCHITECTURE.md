# System Architecture Documentation

## Overview

The Serverless Threat Intelligence Platform is a modular, enterprise-grade system built on AWS that automates threat intelligence collection, processing, enrichment, and analysis. The architecture follows microservices principles with event-driven automation and comprehensive monitoring.

## System Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            Frontend Layer                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│  CloudFront Distribution  │  S3 Frontend Bucket  │  SvelteKit Application   │
└─────────────────────────────────────────────────────────────────────────────┘
                                        │
┌─────────────────────────────────────────────────────────────────────────────┐
│                            API Gateway Layer                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│  REST API Gateway  │  Usage Plans  │  API Keys  │  Rate Limiting  │  CORS    │
│  /collect         │  /enrich      │  /search   │  Method Routing  │  Auth    │
└─────────────────────────────────────────────────────────────────────────────┘
                                        │
┌─────────────────────────────────────────────────────────────────────────────┐
│                            Compute Layer (Lambda)                            │
├─────────────────────────────────────────────────────────────────────────────┤
│ Core Functions:                    │ Advanced Functions:                      │
│ • collector.py (256MB)             │ • search_engine.py (512MB)              │
│ • processor.py (512MB)             │ • export_engine.py (512MB)              │
│ • enrichment.py (1024MB)           │ • analytics_engine.py (1024MB)          │
│                                    │ • event_orchestrator.py (512MB)         │
│                                    │ • query_optimizer.py (256MB)            │
│                                    │ • cache_manager.py (512MB)              │
│                                    │ • performance_metrics.py (256MB)        │
│                                    │ • rate_limiting_service.py (256MB)      │
│                                    │ • cache_invalidation.py (256MB)         │
└─────────────────────────────────────────────────────────────────────────────┘
                                        │
┌─────────────────────────────────────────────────────────────────────────────┐
│                            Event-Driven Architecture                          │
├─────────────────────────────────────────────────────────────────────────────┤
│  EventBridge Rules  │  DynamoDB Streams  │  SNS Topics  │  Workflow Engine   │
│  13 Event Types     │  Real-time Triggers │  Alerting   │  Orchestration     │
└─────────────────────────────────────────────────────────────────────────────┘
                                        │
┌─────────────────────────────────────────────────────────────────────────────┐
│                            Data Layer                                        │
├─────────────────────────────────────────────────────────────────────────────┤
│ DynamoDB Tables:                   │ S3 Buckets:                             │
│ • threat-intelligence (main)       │ • raw-data (archival)                  │
│ • threat-intel-dedup (TTL 30d)     │ • processed-data (analytics)           │
│ • osint-enrichment-cache (TTL 7d)  │ • frontend-hosting (static assets)     │
│                                    │                                         │
│ GSI Indices (9 total):             │ Lifecycle Policies:                     │
│ • time-index                       │ • 30d → IA                             │
│ • source-index                     │ • 90d → Glacier                        │
│ • pattern-hash-index               │ • 180d → Deep Archive                  │
│ • risk-analytics-index             │ • 365d → Delete                        │
│ • geographic-index                 │                                         │
│ • ioc-pattern-index                │                                         │
│ • temporal-correlation-index       │                                         │
└─────────────────────────────────────────────────────────────────────────────┘
                                        │
┌─────────────────────────────────────────────────────────────────────────────┐
│                            Caching Layer                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│  ElastiCache Redis Cluster  │  Multi-Layer Caching  │  Circuit Breakers     │
│  • Query Results (30min)    │  • Lambda Memory       │  • Failure Detection  │
│  • Analytics Cache (1hr)    │  • Redis Cluster       │  • Auto Recovery      │
│  • Enrichment Data (7d)     │  • DynamoDB            │  • Health Monitoring  │
└─────────────────────────────────────────────────────────────────────────────┘
                                        │
┌─────────────────────────────────────────────────────────────────────────────┐
│                            External Integrations                             │
├─────────────────────────────────────────────────────────────────────────────┤
│ OSINT Sources:                     │ Enrichment Services:                    │
│ • AT&T Alien Labs OTX              │ • Shodan API                           │
│ • Abuse.ch (4 feeds)               │ • Geolocation Services                 │
│ • MalwareBazaar                    │ • DNS Analysis                         │
│ • URLhaus                          │ • WHOIS Intelligence                   │
│ • ThreatFox                        │ • Reputation Analysis                  │
│ • Feodo Tracker                    │                                        │
└─────────────────────────────────────────────────────────────────────────────┘
                                        │
┌─────────────────────────────────────────────────────────────────────────────┐
│                            Monitoring & Security                             │
├─────────────────────────────────────────────────────────────────────────────┤
│ CloudWatch Dashboards (4):         │ Security:                              │
│ • System Overview                  │ • IAM Least Privilege                 │
│ • Threat Intelligence              │ • KMS Encryption                       │
│ • Cost & Performance               │ • Secrets Manager                      │
│ • Security & Compliance            │ • VPC Security Groups                  │
│                                    │ • API Authentication                   │
│ Alerting:                          │ • HTTPS/TLS                           │
│ • Cost Thresholds                  │ • CloudTrail Logging                   │
│ • Performance Anomalies            │                                        │
│ • Security Events                  │                                        │
│ • System Health                    │                                        │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Module Dependencies

### Dependency Flow
```
Security → Database → Storage → Compute → Networking → Caching → Monitoring
   ↓         ↓         ↓         ↓         ↓          ↓         ↓
  IAM     DynamoDB     S3     Lambda    API GW    Redis   CloudWatch
 Roles    Tables    Buckets  Functions  Endpoints Cluster Dashboards
Secrets     GSI    Lifecycle   Logs      CORS     Cache   Metrics
 KMS       TTL     Encryption  Memory   Auth     Circuit  Alarms
```

### Critical Dependencies
1. **Security → All Modules**: IAM roles required by all services
2. **Database → Compute**: Lambda functions need table names/ARNs
3. **Storage → Compute**: Lambda functions need bucket names
4. **Storage → Networking**: CloudFront needs frontend bucket
5. **Compute → Networking**: API Gateway needs Lambda function ARNs
6. **Security → Caching**: Redis needs security groups and subnet IDs
7. **All Modules → Monitoring**: CloudWatch monitors all resources

## Data Flow Architecture

### Collection Pipeline
```
OSINT Sources → collector.py → DynamoDB → processor.py → enrichment.py
     ↓              ↓             ↓           ↓             ↓
External APIs  Rate Limiting  Raw Storage  Processing   Enhanced Data
   OTX        Circuit Breaker   S3 Archive  STIX 2.1     Caching
  Abuse.ch    Error Handling   Dedup TTL   Correlation   Analytics
```

### Event-Driven Workflow
```
Collection Event → EventBridge → Processing Trigger → Enrichment Trigger
      ↓               ↓              ↓                    ↓
  Priority Queue  Workflow State  Batch Processing   Analytics Update
  Real-time      Correlation ID   4-Tier Priority    Cache Refresh
  Critical Path  Error Handling   Resource Optimization
```

### Search & Analytics Pipeline
```
API Request → search_engine.py → Query Optimizer → DynamoDB GSIs
     ↓             ↓                   ↓              ↓
Query Parser   Cache Check      Query Planning   Result Set
Fuzzy Match    Redis Lookup     Cost Analysis    Correlation
Multi-Criteria Performance       Index Selection  Export Ready
```

## Terraform Module Structure

### Module Organization
```
modules/
├── security/           # IAM, Secrets, KMS, CloudWatch logs
│   ├── main.tf        # 15 resources
│   ├── variables.tf   # 8 input variables
│   └── outputs.tf     # 12 output values
├── database/          # DynamoDB tables and GSIs
│   ├── main.tf        # 25 resources (3 tables + 9 GSIs)
│   ├── variables.tf   # 12 input variables
│   └── outputs.tf     # 9 output values
├── storage/           # S3 buckets and lifecycle policies
│   ├── main.tf        # 18 resources (3 buckets + policies)
│   ├── variables.tf   # 14 input variables
│   └── outputs.tf     # 12 output values
├── compute/           # Lambda functions and CloudWatch logs
│   ├── main.tf        # 32 resources (16 functions + logs)
│   ├── variables.tf   # 20 input variables
│   └── outputs.tf     # 8 output values
├── networking/        # API Gateway and CloudFront
│   ├── main.tf        # 22 resources
│   ├── variables.tf   # 16 input variables
│   └── outputs.tf     # 15 output values
├── caching/           # ElastiCache Redis cluster
│   ├── main.tf        # 8 resources
│   ├── variables.tf   # 12 input variables
│   └── outputs.tf     # 6 output values
└── monitoring/        # CloudWatch dashboards and alarms
    ├── main.tf        # 12 resources (4 dashboards + alarms)
    ├── variables.tf   # 8 input variables
    └── outputs.tf     # 8 output values
```

### Resource Count by Module
- **Security**: 15 resources (IAM roles, policies, secrets)
- **Database**: 25 resources (DynamoDB tables with 9 GSIs)
- **Storage**: 18 resources (S3 buckets with lifecycle policies)
- **Compute**: 32 resources (16 Lambda functions + logs)
- **Networking**: 22 resources (API Gateway + CloudFront)
- **Caching**: 8 resources (Redis cluster + monitoring)
- **Monitoring**: 12 resources (dashboards + alarms)
- **Total**: 132 AWS resources

## Lambda Function Architecture

### Function Categories and Memory Allocation

#### Core Processing Functions
- **collector.py** (256MB): Lightweight data collection from OSINT sources
- **processor.py** (512MB): STIX 2.1 processing and correlation analysis
- **enrichment.py** (1024MB): Container-heavy OSINT enrichment services

#### Advanced Analytics Functions
- **search_engine.py** (512MB): Multi-criteria search with fuzzy matching
- **export_engine.py** (512MB): Multi-format export with compression
- **analytics_engine.py** (1024MB): Statistical analysis and trend detection

#### Infrastructure Functions
- **event_orchestrator.py** (512MB): Workflow management and automation
- **query_optimizer.py** (256MB): DynamoDB query optimization
- **cache_manager.py** (512MB): Multi-layer cache management
- **performance_metrics_collector.py** (256MB): System performance monitoring
- **rate_limiting_service.py** (256MB): API rate limiting and throttling
- **cache_invalidation_service.py** (256MB): Event-driven cache invalidation

### Function Integration Patterns

#### Event-Driven Integration
```python
# Collection triggers processing
collector.py → EventBridge → processor.py

# Processing triggers enrichment
processor.py → EventBridge → enrichment.py

# Critical threats bypass queues
collector.py → SNS → real-time processing
```

#### API Integration
```python
# Search request routing
API Gateway → search_engine.py → query_optimizer.py → DynamoDB

# Export request handling
API Gateway → export_engine.py → S3 → presigned URL response

# Analytics request processing
API Gateway → analytics_engine.py → cache_manager.py → results
```

## Database Schema Design

### Primary Table: threat-intelligence
```json
{
  "partition_key": "indicator_id",
  "sort_key": "timestamp",
  "attributes": {
    "ioc_value": "string",
    "ioc_type": "string",
    "threat_type": "string",
    "source": "string",
    "confidence": "number",
    "risk_score": "number",
    "geographic_region": "string",
    "stix_object": "json",
    "last_modified": "timestamp",
    "created_at": "timestamp"
  }
}
```

### Global Secondary Indexes (9 total)
1. **time-index**: Query by timestamp (time-based analysis)
2. **source-index**: Query by data source (source-specific analysis)
3. **pattern-hash-index**: Query by pattern hash (deduplication)
4. **risk-analytics-index**: Query by risk score + threat type
5. **geographic-index**: Query by geographic region + timestamp
6. **ioc-pattern-index**: Query by IOC type + value pattern
7. **temporal-correlation-index**: Query by last_modified + confidence

### Deduplication Table: threat-intel-dedup
- **TTL**: 30 days automatic cleanup
- **Hash-based**: SHA-256 pattern hashing
- **Purpose**: Prevent duplicate indicator processing

### Enrichment Cache: osint-enrichment-cache
- **TTL**: 7 days automatic cleanup
- **Multi-source**: Aggregated enrichment data
- **Purpose**: Reduce external API calls and costs

## Security Architecture

### Defense in Depth Strategy

#### Network Security
- **VPC**: Isolated network environment for Lambda functions
- **Security Groups**: Restrictive ingress/egress rules
- **Private Subnets**: No direct internet access for compute resources
- **NAT Gateway**: Controlled outbound internet access

#### Identity & Access Management
```json
{
  "lambda_execution_role": {
    "principle": "lambda.amazonaws.com",
    "policies": [
      "DynamoDBReadWrite",
      "S3BucketAccess",
      "SecretsManagerRead",
      "CloudWatchLogs"
    ]
  },
  "api_gateway_role": {
    "principle": "apigateway.amazonaws.com",
    "policies": [
      "LambdaInvokeFunction",
      "CloudWatchLogs"
    ]
  }
}
```

#### Data Encryption
- **At Rest**: KMS encryption for DynamoDB, S3, EBS
- **In Transit**: TLS 1.2+ for all API communications
- **Secrets**: AWS Secrets Manager with automatic rotation
- **Logs**: CloudWatch logs encryption with KMS

#### API Security
- **Authentication**: API key required for all endpoints
- **Rate Limiting**: Multi-tier limits (100 req/s, 200 burst)
- **CORS**: Restricted to frontend domain only
- **Input Validation**: JSON schema validation for all requests

## Performance Optimization

### Caching Strategy

#### Multi-Layer Cache Architecture
```
Lambda Memory Cache (5min TTL)
        ↓
ElastiCache Redis (30min-7d TTL)
        ↓
DynamoDB (permanent storage)
```

#### Cache Patterns
- **Query Results**: 30-minute TTL for search results
- **Analytics Data**: 1-hour TTL for trend analysis
- **Enrichment Data**: 7-day TTL for OSINT enrichment
- **Configuration**: 24-hour TTL for system configuration

### Database Optimization

#### Query Optimization
- **GSI Selection**: Intelligent index selection based on query patterns
- **Batch Operations**: Group related operations for efficiency
- **Projection Types**: Minimize data transfer with targeted projections
- **Hot Partitions**: Distribute load across partition keys

#### Cost Optimization
- **Pay-per-Request**: No provisioned capacity charges
- **TTL**: Automatic data cleanup reduces storage costs
- **Compression**: GZIP compression for large objects
- **Lifecycle Policies**: Automatic S3 tier transitions

## Monitoring & Observability

### CloudWatch Dashboard Structure

#### System Overview Dashboard
- Infrastructure health across all modules
- Resource utilization and performance metrics
- Cost tracking and optimization recommendations
- Alert status and system availability

#### Threat Intelligence Dashboard
- Collection rates by source and time period
- Processing success rates and error analysis
- Enrichment performance and cache hit ratios
- STIX object validation and quality metrics

#### Cost & Performance Dashboard
- Resource costs by service and time period
- Lambda function performance and memory usage
- DynamoDB consumption and throttling metrics
- S3 storage costs and lifecycle effectiveness

#### Security & Compliance Dashboard
- Failed authentication attempts and patterns
- API usage patterns and rate limiting events
- Security group violations and network anomalies
- Compliance status and audit trail

### Alerting Strategy

#### Critical Alerts (Immediate Response)
- System outages or service unavailability
- Security breaches or unauthorized access
- Cost threshold breaches (>$50/month)
- Data corruption or processing failures

#### Warning Alerts (24-hour Response)
- Performance degradation trends
- Approaching rate limits or quotas
- Cache miss ratios exceeding thresholds
- Unusual usage patterns or anomalies

## Scalability Considerations

### Current Limitations
- **Lambda Concurrency**: 1,000 concurrent executions (AWS default)
- **API Gateway**: 10,000 requests per second (regional limit)
- **DynamoDB**: 40,000 read/write capacity units (soft limit)
- **ElastiCache**: 90 nodes per cluster (current configuration)

### Scaling Strategies
- **Horizontal Scaling**: Additional Lambda functions and API endpoints
- **Vertical Scaling**: Increase Lambda memory and timeout limits
- **Geographic Scaling**: Multi-region deployment for global access
- **Service Scaling**: Migrate to ECS/EKS for container-based workloads

### Future Enhancements
- **Machine Learning**: Threat classification and anomaly detection
- **Real-time Analytics**: Stream processing with Kinesis
- **Advanced Correlation**: Graph database integration with Neptune
- **External Integrations**: SIEM and SOAR platform connectors

---

This architecture provides a solid foundation for enterprise-grade threat intelligence operations while maintaining flexibility for future enhancements and scaling requirements.