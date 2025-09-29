# =============================================================================
# Development Environment Configuration Values
# =============================================================================
# This file contains specific values for the development environment
# These values override the defaults in variables.tf

# Project Configuration
project_name = "threat-intel-platform"
environment  = "dev"
aws_region   = "us-east-1"

# Lambda Function Configuration
lambda_timeout         = 300  # 5 minutes
collector_memory_size  = 256  # Cost-optimized for collection
processor_memory_size  = 512  # Higher memory for data processing
enrichment_memory_size = 1024 # Highest memory for OSINT tools

# Development Environment Settings
enable_detailed_logging     = true
enable_api_gateway_logging  = true
retention_days             = 7    # Short retention for cost savings

# Cost Control
enable_cost_monitoring = true
monthly_budget_limit   = 50.00  # $50 monthly budget for dev

# Development Testing
enable_test_data_generation = false  # Disable to avoid unnecessary costs
test_data_retention_hours   = 24     # Clean up test data after 24 hours

# API Gateway Configuration
api_throttle_rate_limit   = 100    # 100 requests per second
api_throttle_burst_limit  = 200    # Allow burst up to 200 requests
api_usage_quota_limit     = 10000  # 10K requests per month limit
cloudfront_price_class    = "PriceClass_100"  # Most cost-effective
enable_cors              = true    # Enable for frontend development