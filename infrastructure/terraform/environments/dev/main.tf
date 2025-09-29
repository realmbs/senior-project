# =============================================================================
# Development Environment - Main Configuration
# =============================================================================
# This file orchestrates all infrastructure modules for the dev environment
# Implements the complete serverless threat intelligence platform

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }
}

# AWS Provider Configuration
provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "terraform"
      Owner       = "capstone-project"
    }
  }
}

# =============================================================================
# Data Sources
# =============================================================================

# Get current AWS account ID and region
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# =============================================================================
# Security Module
# =============================================================================
# Creates IAM roles, policies, Secrets Manager, and CloudWatch log groups

module "security" {
  source = "../../modules/security"

  project_name = var.project_name
  environment  = var.environment

  # API Keys for threat intelligence sources
  otx_api_key      = var.otx_api_key
  shodan_api_key   = var.shodan_api_key
  abuse_ch_api_key = var.abuse_ch_api_key
}

# =============================================================================
# Database Module
# =============================================================================
# Creates DynamoDB tables for threat intelligence storage and deduplication

module "database" {
  source = "../../modules/database"

  project_name = var.project_name
  environment  = var.environment
}

# =============================================================================
# Storage Module
# =============================================================================
# Creates S3 buckets for raw data archival and processed data

module "storage" {
  source = "../../modules/storage"

  project_name = var.project_name
  environment  = var.environment
}

# =============================================================================
# Compute Module
# =============================================================================
# Creates Lambda functions for threat intelligence collection and processing

module "compute" {
  source = "../../modules/compute"

  project_name = var.project_name
  environment  = var.environment

  # Dependencies from security module
  lambda_execution_role_arn = module.security.lambda_role_arn
  api_keys_secret_arn      = module.security.api_keys_secret_arn

  # Dependencies from database module
  threat_intel_table_name      = module.database.threat_intel_table_name
  dedup_table_name            = module.database.dedup_table_name
  enrichment_cache_table_name = module.database.enrichment_cache_table_name

  # Dependencies from storage module
  raw_data_bucket_name       = module.storage.raw_data_bucket_name
  processed_data_bucket_name = module.storage.processed_data_bucket_name

  # Lambda configuration
  lambda_timeout          = var.lambda_timeout
  collector_memory_size   = var.collector_memory_size
  processor_memory_size   = var.processor_memory_size
  enrichment_memory_size  = var.enrichment_memory_size
}

# =============================================================================
# Networking Module
# =============================================================================
# Creates API Gateway endpoints and CloudFront distribution for frontend

module "networking" {
  source = "../../modules/networking"

  project_name = var.project_name
  environment  = var.environment

  # Dependencies from compute module
  lambda_function_names = module.compute.lambda_function_names
  lambda_invoke_arns    = module.compute.lambda_invoke_arns

  # Dependencies from storage module
  frontend_bucket_name        = module.storage.frontend_bucket_name
  frontend_bucket_domain_name = module.storage.frontend_bucket_domain_name

  # API Gateway configuration
  api_throttle_rate_limit   = var.api_throttle_rate_limit
  api_throttle_burst_limit  = var.api_throttle_burst_limit
  api_usage_quota_limit     = var.api_usage_quota_limit
  cloudfront_price_class    = var.cloudfront_price_class

  # Development environment specific settings
  enable_cors               = var.enable_cors
  enable_api_gateway_logging = var.enable_api_gateway_logging
}

# =============================================================================
# Local Values for Resource References
# =============================================================================

locals {
  # Account and region information
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name

  # Common resource naming
  resource_prefix = "${var.project_name}-${var.environment}"

  # Common tags
  common_tags = {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "terraform"
    Owner       = "capstone-project"
    CreatedBy   = "terraform-dev-environment"
  }
}