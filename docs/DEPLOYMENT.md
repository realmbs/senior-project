# Deployment Guide - Phase 9A Infrastructure Deployment

## Overview

This guide provides step-by-step procedures for deploying the serverless threat intelligence platform infrastructure. This represents the **first real deployment** of the system, transitioning from theoretical to production infrastructure.

## ⚠️ Critical Prerequisites

### AWS Account Setup
```bash
# Verify AWS CLI configuration
aws sts get-caller-identity
aws configure list

# Required AWS services access:
# - IAM (roles, policies)
# - DynamoDB (tables)
# - S3 (buckets)
# - Lambda (functions)
# - API Gateway (REST APIs)
# - ElastiCache (Redis)
# - CloudWatch (dashboards, logs)
# - Secrets Manager
# - CloudFront
```

### Cost Controls Setup
```bash
# Set up billing alerts BEFORE deployment
aws budgets create-budget --account-id $(aws sts get-caller-identity --query Account --output text) \
  --budget '{
    "BudgetName": "ThreatIntelPlatformBudget",
    "BudgetLimit": {"Amount": "50", "Unit": "USD"},
    "TimeUnit": "MONTHLY",
    "BudgetType": "COST"
  }'
```

## Phase 9A: Incremental Deployment Strategy

### Step 1: Environment Preparation

```bash
cd /Users/markblaha/senior-project/infrastructure/terraform/environments/dev

# Initialize Terraform
terraform init

# Validate configuration
terraform validate
# Expected: "Success! The configuration is valid."

# Preview resources (should show 100+ resources)
terraform plan
```

### Step 2: Security Module Deployment (CRITICAL FIRST)

```bash
# Deploy security infrastructure first
terraform apply -target=module.security -auto-approve

# Verify security resources
aws iam list-roles --query 'Roles[?contains(RoleName, `threat-intel`)]'
aws secretsmanager list-secrets --query 'SecretList[?contains(Name, `threat-intel`)]'
```

**Expected Resources:**
- IAM roles: lambda-execution-role, api-gateway-role
- Secrets Manager: API keys secret
- CloudWatch log groups: 7 log groups created

### Step 3: Database Module Deployment

```bash
# Deploy DynamoDB infrastructure
terraform apply -target=module.database -auto-approve

# Verify database resources
aws dynamodb list-tables --query 'TableNames[?contains(@, `threat-intel`)]'
aws dynamodb describe-table --table-name threat-intel-dev --query 'Table.TableStatus'
```

**Expected Resources:**
- 3 DynamoDB tables with GSIs
- Pay-per-request billing mode
- TTL configured for deduplication table

### Step 4: Storage Module Deployment

```bash
# Deploy S3 infrastructure
terraform apply -target=module.storage -auto-approve

# Verify storage resources
aws s3 ls | grep threat-intel
aws s3api get-bucket-encryption --bucket $(terraform output -raw raw_data_bucket_name)
```

**Expected Resources:**
- 3 S3 buckets with unique suffixes
- Lifecycle policies configured
- Encryption enabled

### Step 5: Compute Module Deployment (HIGH RISK)

```bash
# Package Lambda functions
cd ../../lambda_functions
zip -r lambda_deployment.zip . -x "__pycache__/*" "*.pyc" ".git/*"
cd ../environments/dev

# Deploy Lambda infrastructure
terraform apply -target=module.compute -auto-approve

# Verify Lambda functions
aws lambda list-functions --query 'Functions[?contains(FunctionName, `threat-intel`)]'
```

**Expected Resources:**
- 16 Lambda functions deployed
- CloudWatch log groups created
- IAM permissions configured

### Step 6: Networking Module Deployment

```bash
# Deploy API Gateway and CloudFront
terraform apply -target=module.networking -auto-approve

# Verify API Gateway
aws apigateway get-rest-apis --query 'items[?contains(name, `threat-intel`)]'
terraform output api_gateway_url
```

**Expected Resources:**
- REST API Gateway with 3 endpoints
- CloudFront distribution
- API keys and usage plans

### Step 7: Caching Module Deployment

```bash
# Deploy ElastiCache infrastructure
terraform apply -target=module.caching -auto-approve

# Verify Redis cluster
aws elasticache describe-cache-clusters --query 'CacheClusters[?contains(CacheClusterId, `threat-intel`)]'
```

### Step 8: Monitoring Module Deployment

```bash
# Deploy CloudWatch dashboards
terraform apply -target=module.monitoring -auto-approve

# Verify dashboards
aws cloudwatch list-dashboards --query 'DashboardEntries[?contains(DashboardName, `ThreatIntel`)]'
```

## Post-Deployment Validation

### Infrastructure Health Check

```bash
# Check all resources deployed successfully
terraform show | grep -c "resource\|data"
# Expected: 100+ resources

# Verify critical endpoints
curl -X GET "$(terraform output -raw api_gateway_url)/collect" \
  -H "x-api-key: $(terraform output -raw api_key_value)"
```

### Lambda Function Testing

```bash
cd ../../lambda_functions

# Test collector function
aws lambda invoke --function-name threat-intel-collector-dev \
  --payload '{"source": "test"}' \
  response.json && cat response.json

# Test processor function
aws lambda invoke --function-name threat-intel-processor-dev \
  --payload '{"action": "search", "query": {"ioc_value": "test"}}' \
  response.json && cat response.json
```

### Cost Monitoring Setup

```bash
# Monitor initial costs
aws ce get-cost-and-usage \
  --time-period Start=$(date -d '1 day ago' +%Y-%m-%d),End=$(date +%Y-%m-%d) \
  --granularity DAILY \
  --metrics BlendedCost \
  --group-by Type=DIMENSION,Key=SERVICE
```

## Emergency Rollback Procedures

### Module-Level Rollback
```bash
# Rollback specific module (safe)
terraform destroy -target=module.monitoring -auto-approve
terraform destroy -target=module.caching -auto-approve
terraform destroy -target=module.networking -auto-approve
terraform destroy -target=module.compute -auto-approve  # Lambda functions
```

### Complete Environment Rollback
```bash
# Nuclear option - destroy everything
terraform destroy -auto-approve

# Verify cleanup
aws resourcegroupstaggingapi get-resources \
  --tag-filters Key=Project,Values=threat-intel
```

## Common Deployment Issues

### Issue: Lambda Package Too Large
```bash
# Solution: Optimize package size
cd lambda_functions
pip install --target ./package -r requirements.txt
zip -r lambda_deployment.zip . -x "package/*" "__pycache__/*"
```

### Issue: DynamoDB Throttling
```bash
# Solution: Check provisioned capacity
aws dynamodb describe-table --table-name threat-intel-dev \
  --query 'Table.BillingModeSummary'
# Should show PAY_PER_REQUEST
```

### Issue: S3 Bucket Name Conflicts
```bash
# Solution: Check random suffix generation
terraform refresh
terraform plan  # Will show new random suffix
```

## Success Metrics

### Deployment Success Criteria
- [ ] All 7 modules deployed without errors
- [ ] API Gateway returns valid responses
- [ ] Lambda functions execute successfully
- [ ] DynamoDB tables accessible
- [ ] S3 buckets created with proper permissions
- [ ] ElastiCache cluster running
- [ ] CloudWatch dashboards populated
- [ ] Total deployment cost < $10 first month

### Performance Validation
- [ ] API response time < 3 seconds
- [ ] Lambda cold start < 5 seconds
- [ ] DynamoDB read/write latency < 100ms
- [ ] Redis cache hit ratio > 80%

## Phase 9B Preparation

Once Phase 9A deployment is successful:

1. **API Key Configuration**: Add real OTX, Shodan, Abuse.ch API keys to Secrets Manager
2. **End-to-End Testing**: Run full data pipeline tests
3. **Performance Tuning**: Optimize based on real usage patterns
4. **Security Hardening**: Review IAM permissions and access patterns

## Support and Troubleshooting

For issues during deployment:
1. Check CloudWatch logs for Lambda errors
2. Review Terraform state for resource conflicts
3. Verify AWS service limits and quotas
4. Consult TROUBLESHOOTING.md for common solutions
5. Monitor costs in AWS Billing dashboard

---

**⚠️ IMPORTANT**: This is the first real infrastructure deployment. Monitor costs closely and be prepared to rollback if issues arise. The theoretical system becomes reality in Phase 9A.