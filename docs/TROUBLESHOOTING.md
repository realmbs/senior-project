# Troubleshooting Guide

## Overview

This guide provides solutions for common issues encountered during deployment, operation, and maintenance of the serverless threat intelligence platform.

## Deployment Issues

### 1. Terraform Validation Errors

#### Issue: Missing Provider Requirements
```
Error: Required providers not specified
```

**Solution:**
```bash
# Check if versions.tf exists in all modules
find modules/ -name "versions.tf"

# Add missing versions.tf to module
cat > modules/[MODULE_NAME]/versions.tf << EOF
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.1"
    }
  }
}
EOF
```

#### Issue: Invalid Resource Types
```
Error: Unsupported resource type "aws_api_gateway_method_request"
```

**Solution:**
```bash
# Remove invalid resource types and integrate into method definition
# Check networking/main.tf for proper request/response models
terraform validate
```

#### Issue: Deprecated Attributes
```
Warning: Deprecated attribute "invoke_url"
```

**Solution:**
```bash
# Replace invoke_url with proper URL construction
# Use: "https://${aws_api_gateway_rest_api.name.id}.execute-api.${region}.amazonaws.com/${stage}"
terraform apply
```

### 2. S3 Bucket Issues

#### Issue: Bucket Name Already Exists
```
Error: BucketAlreadyExists: The requested bucket name is not available
```

**Solution:**
```bash
# Force new random suffix generation
terraform state rm module.storage.random_id.bucket_suffix
terraform apply

# Or manually refresh random values
terraform refresh
```

#### Issue: Lifecycle Configuration Warnings
```
Warning: Missing required filter block in lifecycle configuration
```

**Solution:**
```bash
# Add filter block to all lifecycle rules
resource "aws_s3_bucket_lifecycle_configuration" "example" {
  rule {
    filter {
      prefix = ""  # Empty prefix for all objects
    }
  }
}
```

### 3. Lambda Function Issues

#### Issue: Lambda Package Too Large
```
Error: InvalidParameterValueException: Unzipped size must be smaller than 262144000 bytes
```

**Solution:**
```bash
cd lambda_functions

# Option 1: Optimize package size
rm -rf __pycache__ *.pyc .git
zip -r lambda_deployment.zip . -x "__pycache__/*" "*.pyc" ".git/*"

# Option 2: Use Lambda layers for dependencies
pip install --target ./layer/python -r requirements.txt
zip -r layer.zip layer/

# Option 3: Use container image instead
# Convert to ECR container deployment if package > 250MB
```

#### Issue: Lambda Function Timeout
```
Error: Task timed out after 300.00 seconds
```

**Solution:**
```bash
# Increase timeout in variables.tf
variable "lambda_timeout" {
  default = 900  # Maximum 15 minutes
}

# Optimize function performance
# - Reduce memory allocation for I/O bound functions
# - Increase memory for CPU bound functions
# - Implement connection pooling
# - Use Lambda provisioned concurrency for predictable latency
```

#### Issue: Lambda Memory Errors
```
Error: Process exited before completing request (signal: SIGKILL)
```

**Solution:**
```bash
# Increase memory allocation
variable "enrichment_memory_size" {
  default = 2048  # Increase from 1024MB
}

# Monitor memory usage in CloudWatch
aws logs filter-log-events \
  --log-group-name "/aws/lambda/threat-intel-enrichment-dev" \
  --filter-pattern "REPORT" \
  --query 'events[*].message'
```

## Runtime Issues

### 4. DynamoDB Issues

#### Issue: DynamoDB Throttling
```
Error: ProvisionedThroughputExceededException
```

**Solution:**
```bash
# Check billing mode (should be PAY_PER_REQUEST)
aws dynamodb describe-table --table-name threat-intel-dev \
  --query 'Table.BillingModeSummary'

# If provisioned mode, convert to on-demand
aws dynamodb modify-table \
  --table-name threat-intel-dev \
  --billing-mode PAY_PER_REQUEST
```

#### Issue: GSI Query Errors
```
Error: ValidationException: One or more parameter values were invalid
```

**Solution:**
```bash
# Verify GSI exists and is active
aws dynamodb describe-table --table-name threat-intel-dev \
  --query 'Table.GlobalSecondaryIndexes[*].[IndexName,IndexStatus]'

# Check query parameters match GSI key schema
# Ensure partition key is always provided in GSI queries
```

#### Issue: TTL Not Working
```
Issue: TTL items not being deleted automatically
```

**Solution:**
```bash
# Verify TTL is enabled
aws dynamodb describe-time-to-live --table-name threat-intel-dedup-dev

# TTL takes up to 48 hours to process expired items
# Verify TTL attribute is number (Unix timestamp)
# Example: expires_at = int(time.time()) + 2592000  # 30 days
```

### 5. API Gateway Issues

#### Issue: API Key Authentication Failing
```
Error: Forbidden (403) - Invalid API Key
```

**Solution:**
```bash
# Get valid API key value
aws apigateway get-api-keys --include-values \
  --query 'items[?name==`threat-intel-api-key-dev`].value'

# Test API with correct key
curl -X GET "https://API_ID.execute-api.REGION.amazonaws.com/dev/collect" \
  -H "x-api-key: YOUR_API_KEY"

# Verify usage plan association
aws apigateway get-usage-plans \
  --query 'items[?name==`threat-intel-usage-plan-dev`]'
```

#### Issue: CORS Errors
```
Error: Access to fetch at 'API_URL' has been blocked by CORS policy
```

**Solution:**
```bash
# Verify CORS is enabled in API Gateway
aws apigateway get-method --rest-api-id API_ID \
  --resource-id RESOURCE_ID --http-method OPTIONS

# Check response headers include:
# Access-Control-Allow-Origin: *
# Access-Control-Allow-Methods: GET,POST,OPTIONS
# Access-Control-Allow-Headers: Content-Type,x-api-key
```

#### Issue: Lambda Integration Errors
```
Error: Internal server error (502)
```

**Solution:**
```bash
# Check Lambda function logs
aws logs tail /aws/lambda/threat-intel-collector-dev --follow

# Verify API Gateway has permission to invoke Lambda
aws lambda get-policy --function-name threat-intel-collector-dev

# Test Lambda function directly
aws lambda invoke --function-name threat-intel-collector-dev \
  --payload '{"test": "data"}' response.json
```

### 6. Caching Issues

#### Issue: Redis Connection Failures
```
Error: ConnectionError: Error connecting to Redis
```

**Solution:**
```bash
# Verify Redis cluster status
aws elasticache describe-cache-clusters \
  --cache-cluster-id threat-intel-cache-dev \
  --query 'CacheClusters[0].CacheClusterStatus'

# Check security group rules allow port 6379
aws ec2 describe-security-groups \
  --filters "Name=group-name,Values=threat-intel-redis-sg-dev"

# Test connectivity from Lambda subnet
# Ensure Lambda functions are in same VPC/subnet as Redis
```

#### Issue: Cache Miss Ratios Too High
```
Issue: Cache hit ratio below 80%
```

**Solution:**
```bash
# Monitor cache performance
aws cloudwatch get-metric-statistics \
  --namespace AWS/ElastiCache \
  --metric-name CacheHitRate \
  --dimensions Name=CacheClusterId,Value=threat-intel-cache-dev \
  --start-time 2024-01-01T00:00:00Z \
  --end-time 2024-01-02T00:00:00Z \
  --period 3600 \
  --statistics Average

# Optimize cache TTL values
# Increase memory allocation if evictions are high
# Review cache key strategies for better hit rates
```

### 7. External API Issues

#### Issue: OTX API Rate Limiting
```
Error: HTTP 429 - Rate limit exceeded
```

**Solution:**
```bash
# Implement exponential backoff in collector.py
# Verify rate limits: 900 requests/hour for OTX

# Check circuit breaker status
aws lambda invoke --function-name threat-intel-collector-dev \
  --payload '{"action": "circuit_breaker_status"}' response.json

# Monitor API usage in CloudWatch
```

#### Issue: Shodan API Key Invalid
```
Error: HTTP 401 - Unauthorized
```

**Solution:**
```bash
# Verify API key in Secrets Manager
aws secretsmanager get-secret-value \
  --secret-id threat-intel-api-keys-dev \
  --query 'SecretString'

# Test API key directly
curl -H "Authorization: Bearer YOUR_SHODAN_KEY" \
  "https://api.shodan.io/shodan/host/8.8.8.8"

# Update secret value if needed
aws secretsmanager update-secret \
  --secret-id threat-intel-api-keys-dev \
  --secret-string '{"shodan_api_key": "NEW_KEY"}'
```

## Performance Issues

### 8. Slow Query Performance

#### Issue: DynamoDB Queries Taking >3 Seconds
```
Issue: High query latency impacting user experience
```

**Solution:**
```bash
# Analyze query patterns in CloudWatch
aws logs filter-log-events \
  --log-group-name "/aws/lambda/threat-intel-processor-dev" \
  --filter-pattern "[timestamp, requestId, level=ERROR]"

# Use query optimizer recommendations
aws lambda invoke --function-name threat-intel-query-optimizer-dev \
  --payload '{"analyze_queries": true}' response.json

# Consider adding new GSI for frequent query patterns
# Enable DynamoDB Contributor Insights for hot partitions
```

#### Issue: Lambda Cold Starts >5 Seconds
```
Issue: High cold start latency affecting API response times
```

**Solution:**
```bash
# Enable provisioned concurrency for critical functions
aws lambda put-provisioned-concurrency-config \
  --function-name threat-intel-collector-dev \
  --provisioned-concurrency-config ProvisionedConcurrencyConfig=1

# Optimize function initialization
# - Reduce package size
# - Initialize connections outside handler
# - Use AWS SDK v3 for faster startup
# - Consider moving to container-based deployment
```

### 9. Cost Optimization Issues

#### Issue: Unexpected High Costs
```
Issue: Monthly AWS bill exceeding $50 budget
```

**Solution:**
```bash
# Analyze cost breakdown by service
aws ce get-cost-and-usage \
  --time-period Start=2024-01-01,End=2024-01-31 \
  --granularity MONTHLY \
  --metrics BlendedCost \
  --group-by Type=DIMENSION,Key=SERVICE

# Check for expensive operations:
# - DynamoDB on-demand charges
# - Lambda high memory usage
# - S3 request charges
# - Data transfer costs
# - CloudWatch log retention

# Optimize based on findings:
# - Implement better caching
# - Reduce Lambda memory for I/O operations
# - Optimize DynamoDB query patterns
# - Adjust S3 lifecycle policies
```

## Security Issues

### 10. IAM Permission Errors

#### Issue: Access Denied Errors
```
Error: AccessDenied: User/Role is not authorized to perform action
```

**Solution:**
```bash
# Check IAM role permissions
aws iam get-role-policy \
  --role-name threat-intel-lambda-execution-role-dev \
  --policy-name LambdaDynamoDBPolicy

# Verify resource ARNs in policies match actual resources
# Use AWS IAM Policy Simulator to test permissions
# Add missing permissions with least privilege principle

# Example: Add S3 access if missing
aws iam put-role-policy \
  --role-name threat-intel-lambda-execution-role-dev \
  --policy-name S3AccessPolicy \
  --policy-document file://s3-policy.json
```

#### Issue: Secrets Manager Access Denied
```
Error: AccessDenied: Unable to decrypt secret
```

**Solution:**
```bash
# Verify KMS key permissions
aws kms describe-key --key-id alias/threat-intel-secrets-key-dev

# Check Lambda execution role has secretsmanager:GetSecretValue
# Verify secret ARN in IAM policy matches actual secret

# Test secret access
aws secretsmanager get-secret-value \
  --secret-id threat-intel-api-keys-dev
```

## Monitoring and Alerting Issues

### 11. Missing Metrics or Logs

#### Issue: CloudWatch Logs Not Appearing
```
Issue: Lambda function logs not visible in CloudWatch
```

**Solution:**
```bash
# Verify log group exists
aws logs describe-log-groups \
  --log-group-name-prefix "/aws/lambda/threat-intel"

# Check IAM permissions for CloudWatch Logs
# Verify Lambda function has logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents

# Test logging in function
import logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.info("Test log message")
```

#### Issue: CloudWatch Alarms Not Triggering
```
Issue: No alerts received despite threshold breaches
```

**Solution:**
```bash
# Verify alarm configuration
aws cloudwatch describe-alarms \
  --alarm-names "threat-intel-high-error-rate-dev"

# Check SNS topic subscription
aws sns list-subscriptions-by-topic \
  --topic-arn arn:aws:sns:region:account:threat-intel-alerts-dev

# Test alarm manually
aws cloudwatch set-alarm-state \
  --alarm-name "threat-intel-high-error-rate-dev" \
  --state-value ALARM \
  --state-reason "Manual test"
```

## Data Quality Issues

### 12. STIX Object Validation Errors

#### Issue: Invalid STIX 2.1 Objects
```
Error: Invalid STIX object - missing required properties
```

**Solution:**
```bash
# Enable STIX validation in processor.py
# Check processor logs for validation errors
aws logs filter-log-events \
  --log-group-name "/aws/lambda/threat-intel-processor-dev" \
  --filter-pattern "STIX validation failed"

# Validate STIX objects manually
python -c "
import stix2
try:
    stix2.parse(stix_object_json)
    print('Valid STIX object')
except Exception as e:
    print(f'Invalid STIX: {e}')
"
```

## Emergency Procedures

### 13. System Outage Response

#### Complete System Failure
```bash
# 1. Check AWS Service Health Dashboard
# 2. Verify account limits and quotas
# 3. Check for security incidents

# Emergency rollback
cd infrastructure/terraform/environments/dev
terraform destroy -auto-approve

# Redeploy from known good state
git checkout last-known-good-commit
terraform apply -auto-approve
```

#### Partial Service Degradation
```bash
# Identify affected modules
terraform state list | grep -E "(error|failed)"

# Rollback specific module
terraform destroy -target=module.compute
terraform apply -target=module.compute
```

### 14. Security Incident Response

#### Suspected Compromise
```bash
# 1. Rotate all API keys immediately
aws secretsmanager update-secret \
  --secret-id threat-intel-api-keys-dev \
  --secret-string '{"rotated": "emergency"}'

# 2. Check CloudTrail for suspicious activity
aws logs filter-log-events \
  --log-group-name CloudTrail/ThreatIntelPlatform \
  --start-time $(date -d '1 hour ago' +%s)000

# 3. Disable API Gateway temporarily
aws apigateway update-stage \
  --rest-api-id API_ID \
  --stage-name dev \
  --patch-ops op=replace,path=/throttle/rateLimit,value=0
```

## Getting Help

### Log Analysis Commands
```bash
# Recent errors across all functions
aws logs filter-log-events \
  --log-group-name "/aws/lambda/threat-intel-*" \
  --filter-pattern "ERROR" \
  --start-time $(date -d '1 hour ago' +%s)000

# Performance metrics
aws logs filter-log-events \
  --log-group-name "/aws/lambda/threat-intel-*" \
  --filter-pattern "REPORT" \
  --start-time $(date -d '1 hour ago' +%s)000
```

### Health Check Commands
```bash
# Infrastructure health check
terraform plan  # Should show no changes
terraform validate  # Should show success

# API health check
curl -s -o /dev/null -w "%{http_code}" \
  "https://API_ID.execute-api.REGION.amazonaws.com/dev/collect" \
  -H "x-api-key: API_KEY"
```

### Support Resources
- AWS Support Cases: High-priority issues
- CloudWatch Logs: Detailed error analysis
- AWS X-Ray: Request tracing (if enabled)
- Cost Explorer: Unexpected billing analysis
- AWS Trusted Advisor: Best practice recommendations

---

**Remember**: Always test solutions in a development environment before applying to production. Keep this guide updated as new issues are discovered and resolved.