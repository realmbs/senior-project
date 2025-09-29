# =============================================================================
# Networking Module Variables
# =============================================================================
# Input variables for API Gateway and CloudFront configuration

# -----------------------------------------------------------------------------
# Environment Configuration
# -----------------------------------------------------------------------------

variable "project_name" {
  description = "Name of the project for resource naming"
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]*[a-z0-9]$", var.project_name))
    error_message = "Project name must contain only lowercase letters, numbers, and hyphens, starting with a letter."
  }
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod."
  }
}

# -----------------------------------------------------------------------------
# Lambda Function Configuration
# -----------------------------------------------------------------------------

variable "lambda_function_names" {
  description = "Map of Lambda function names to integrate with API Gateway"
  type        = map(string)

  validation {
    condition     = contains(keys(var.lambda_function_names), "collector") && contains(keys(var.lambda_function_names), "processor") && contains(keys(var.lambda_function_names), "enrichment")
    error_message = "Lambda function names map must contain 'collector', 'processor', and 'enrichment' keys."
  }
}

variable "lambda_invoke_arns" {
  description = "Map of Lambda function invoke ARNs for API Gateway integration"
  type        = map(string)

  validation {
    condition     = contains(keys(var.lambda_invoke_arns), "collector") && contains(keys(var.lambda_invoke_arns), "processor") && contains(keys(var.lambda_invoke_arns), "enrichment")
    error_message = "Lambda invoke ARNs map must contain 'collector', 'processor', and 'enrichment' keys."
  }
}

# -----------------------------------------------------------------------------
# S3 Frontend Bucket Configuration
# -----------------------------------------------------------------------------

variable "frontend_bucket_name" {
  description = "Name of S3 bucket for frontend static hosting"
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]*[a-z0-9]$", var.frontend_bucket_name))
    error_message = "S3 bucket name must contain only lowercase letters, numbers, and hyphens."
  }
}

variable "frontend_bucket_domain_name" {
  description = "Domain name of the frontend S3 bucket for CloudFront origin"
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]*[a-z0-9]$", var.frontend_bucket_domain_name))
    error_message = "Frontend bucket domain name must be a valid S3 bucket domain name."
  }
}

# -----------------------------------------------------------------------------
# API Gateway Throttling Configuration
# -----------------------------------------------------------------------------

variable "api_throttle_rate_limit" {
  description = "API Gateway steady-state request rate limit (requests per second)"
  type        = number
  default     = 100

  validation {
    condition     = var.api_throttle_rate_limit > 0 && var.api_throttle_rate_limit <= 10000
    error_message = "API throttle rate limit must be between 1 and 10000 requests per second."
  }
}

variable "api_throttle_burst_limit" {
  description = "API Gateway burst limit for request spikes"
  type        = number
  default     = 200

  validation {
    condition     = var.api_throttle_burst_limit >= 100
    error_message = "API throttle burst limit must be at least 100 requests per second."
  }
}

# -----------------------------------------------------------------------------
# API Gateway Usage Plan Configuration
# -----------------------------------------------------------------------------

variable "api_usage_quota_limit" {
  description = "Monthly API usage quota (requests per month)"
  type        = number
  default     = 10000

  validation {
    condition     = var.api_usage_quota_limit > 0 && var.api_usage_quota_limit <= 1000000
    error_message = "API usage quota limit must be between 1 and 1,000,000 requests per month."
  }
}

# -----------------------------------------------------------------------------
# CloudFront Configuration
# -----------------------------------------------------------------------------

variable "cloudfront_price_class" {
  description = "CloudFront price class for cost optimization"
  type        = string
  default     = "PriceClass_100"

  validation {
    condition     = contains(["PriceClass_100", "PriceClass_200", "PriceClass_All"], var.cloudfront_price_class)
    error_message = "CloudFront price class must be one of: PriceClass_100, PriceClass_200, PriceClass_All."
  }
}

# -----------------------------------------------------------------------------
# Optional Features Configuration
# -----------------------------------------------------------------------------

variable "enable_cors" {
  description = "Enable CORS (Cross-Origin Resource Sharing) for API Gateway"
  type        = bool
  default     = true
}

variable "enable_api_gateway_logging" {
  description = "Enable API Gateway request/response logging to CloudWatch"
  type        = bool
  default     = false

  # Note: Enabling this will incur additional CloudWatch costs
}

# -----------------------------------------------------------------------------
# Security Configuration
# -----------------------------------------------------------------------------

variable "api_key_required" {
  description = "Require API key for all endpoints (recommended for production)"
  type        = bool
  default     = true
}

# -----------------------------------------------------------------------------
# Development and Testing Configuration
# -----------------------------------------------------------------------------

variable "enable_xray_tracing" {
  description = "Enable AWS X-Ray tracing for API Gateway (useful for debugging)"
  type        = bool
  default     = false
}

variable "cache_ttl_seconds" {
  description = "Default cache TTL in seconds for CloudFront static content"
  type        = number
  default     = 3600  # 1 hour

  validation {
    condition     = var.cache_ttl_seconds >= 0 && var.cache_ttl_seconds <= 86400
    error_message = "Cache TTL must be between 0 and 86400 seconds (24 hours)."
  }
}