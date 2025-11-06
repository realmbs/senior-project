# =============================================================================
# Compute Module Variables
# =============================================================================
# Input variables for Lambda function configuration and resource dependencies

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
# IAM and Security Configuration
# -----------------------------------------------------------------------------
variable "lambda_execution_role_arn" {
  description = "ARN of Lambda execution role with required permissions"
  type        = string

  validation {
    condition     = can(regex("^arn:aws:iam::", var.lambda_execution_role_arn))
    error_message = "Lambda execution role ARN must be a valid AWS IAM role ARN."
  }
}

variable "api_keys_secret_arn" {
  description = "ARN of Secrets Manager secret containing API keys (OTX, Shodan, Abuse.ch)"
  type        = string

  validation {
    condition     = can(regex("^arn:aws:secretsmanager:", var.api_keys_secret_arn))
    error_message = "API keys secret ARN must be a valid AWS Secrets Manager ARN."
  }
}

variable "cloudwatch_kms_key_arn" {
  description = "ARN of KMS key for CloudWatch log encryption (optional)"
  type        = string
  default     = null

  validation {
    condition     = var.cloudwatch_kms_key_arn == null || can(regex("^arn:aws:kms:", var.cloudwatch_kms_key_arn))
    error_message = "CloudWatch KMS key ARN must be a valid AWS KMS key ARN or null."
  }
}

# -----------------------------------------------------------------------------
# Database Table Names
# -----------------------------------------------------------------------------
variable "threat_intel_table_name" {
  description = "Name of threat intelligence DynamoDB table"
  type        = string

  validation {
    condition     = length(var.threat_intel_table_name) > 0
    error_message = "Threat intelligence table name cannot be empty."
  }
}

variable "dedup_table_name" {
  description = "Name of deduplication DynamoDB table with TTL"
  type        = string

  validation {
    condition     = length(var.dedup_table_name) > 0
    error_message = "Deduplication table name cannot be empty."
  }
}

variable "enrichment_cache_table_name" {
  description = "Name of OSINT enrichment cache DynamoDB table"
  type        = string

  validation {
    condition     = length(var.enrichment_cache_table_name) > 0
    error_message = "Enrichment cache table name cannot be empty."
  }
}

# -----------------------------------------------------------------------------
# S3 Bucket Names
# -----------------------------------------------------------------------------
variable "raw_data_bucket_name" {
  description = "Name of S3 bucket for raw threat intelligence data archival"
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]*[a-z0-9]$", var.raw_data_bucket_name))
    error_message = "S3 bucket name must contain only lowercase letters, numbers, and hyphens."
  }
}

variable "processed_data_bucket_name" {
  description = "Name of S3 bucket for processed threat intelligence data"
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]*[a-z0-9]$", var.processed_data_bucket_name))
    error_message = "S3 bucket name must contain only lowercase letters, numbers, and hyphens."
  }
}

# -----------------------------------------------------------------------------
# Lambda Function Configuration
# -----------------------------------------------------------------------------
variable "lambda_timeout" {
  description = "Lambda function timeout in seconds (max 900 seconds / 15 minutes)"
  type        = number
  default     = 600

  validation {
    condition     = var.lambda_timeout >= 1 && var.lambda_timeout <= 900
    error_message = "Lambda timeout must be between 1 and 900 seconds."
  }
}

variable "collector_memory_size" {
  description = "Memory size for threat collector Lambda function in MB (cost optimized)"
  type        = number
  default     = 256

  validation {
    condition     = var.collector_memory_size >= 128 && var.collector_memory_size <= 10240
    error_message = "Lambda memory size must be between 128MB and 10240MB."
  }
}

variable "processor_memory_size" {
  description = "Memory size for data processor Lambda function in MB (higher for processing)"
  type        = number
  default     = 512

  validation {
    condition     = var.processor_memory_size >= 128 && var.processor_memory_size <= 10240
    error_message = "Lambda memory size must be between 128MB and 10240MB."
  }
}

variable "enrichment_memory_size" {
  description = "Memory size for OSINT enrichment Lambda function in MB (highest for containers)"
  type        = number
  default     = 1024

  validation {
    condition     = var.enrichment_memory_size >= 128 && var.enrichment_memory_size <= 10240
    error_message = "Lambda memory size must be between 128MB and 10240MB."
  }
}

# -----------------------------------------------------------------------------
# Optional VPC Configuration
# -----------------------------------------------------------------------------
variable "subnet_ids" {
  description = "List of subnet IDs for Lambda VPC configuration (optional)"
  type        = list(string)
  default     = []
}

variable "security_group_ids" {
  description = "List of security group IDs for Lambda VPC configuration (optional)"
  type        = list(string)
  default     = []
}

