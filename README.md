# senior-project
A cost-effective, serverless threat intelligence platform designed for small businesses, built as a capstone project demonstrating cloud-native security architecture.

# Problem Statement
Security analysts spend ~3 hours daily on manual alert review, processing 4,484 alerts daily with 83% false positives, leading to alert fatigue and extended breach recovery times (average 150+ days). Commercial threat intelligence platforms cost $50K-200K annually, making them inaccessible to small businesses who represent 99.9% of US firms but face 42% of cyberattacks.

# Proposed Solution
A serverless, cloud-native platform that:

Automates threat intelligence aggregation from multiple OSINT sources
Reduces manual analyst workload through real-time correlation and enrichment
Provides cost-effective alternative to enterprise solutions ($100-250 vs $50K+ annually)
Scales efficiently using AWS serverless architecture with pay-per-use pricing

# Key Features
Threat Intelligence Collection

Multiple Sources: AT&T Alien Labs OTX, Abuse.ch (MalwareBazaar, URLhaus)
STIX 2.1 Compliance: Industry-standard threat intelligence format
Automated De-duplication: Hash-based duplicate detection and removal
Manual Triggers: Cost-controlled data collection via API Gateway

OSINT Enrichment

Domain Intelligence: TheHarvester for subdomain discovery
Network Scanning: Shodan API integration for infrastructure analysis
Whois Lookup: Domain registration and ownership information
Containerized Tools: Docker containers for isolated OSINT execution

Cloud-Native Architecture

Serverless Computing: AWS Lambda for cost-effective processing
NoSQL Storage: DynamoDB with Global Secondary Indexes for fast queries
Object Storage: S3 with lifecycle policies for raw data archival
Infrastructure as Code: Terraform modules for reproducible deployments

# Tech Stack
Backend
* AWS Lambda: Serverless compute (Python 3.11)
* Amazon DynamoDB: NoSQL database with GSI
* Amazon S3: Object storage with lifecycle policies
* AWS Secrets Manager: Secure API key storage
* Terraform: Infrastructure as Code

Data Processing
* STIX 2.1: Threat intel standardization
* Python libraries: BOTO3, Requests, pandas, python-whois
* Containers: Docker for OSINT

Frontend
* Svelte.js: Web framework
* Chart.js: Data visualization
* D3.js: Threat relationship mapping

# Development Timeline
Phase 1: Infrastructure - Weeks 1-3
* Terraform infrastructure modules and components
* Lambda functions
* DynamoDB DB Schema design
* Basic API setup

Phase 2: Data Processing - Weeks 4-6
* Threat intel collectors
* STIX 2.1 data processing
* De-duplication
* OSINT tool integration

Phase 3: Frontend - Weeks 7-9
* Svelte.js frontend
* Search & filter
* Threat visualization