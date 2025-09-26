# =============================================================================
# Database Module Variables
# =============================================================================
# Input variables for the database module
# These variables configure DynamoDB tables, TTL settings, and billing

# -----------------------------------------------------------------------------
# Environment Configuration
# -----------------------------------------------------------------------------

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod."
  }
}

variable "project_name" {
  description = "Project name for table naming and resource tagging"
  type        = string
  default     = "threat-intel"
  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.project_name))
    error_message = "Project name must contain only lowercase letters, numbers, and hyphens."
  }
}

# -----------------------------------------------------------------------------
# DynamoDB Configuration
# -----------------------------------------------------------------------------

variable "billing_mode" {
  description = "DynamoDB billing mode (PAY_PER_REQUEST or PROVISIONED)"
  type        = string
  default     = "PAY_PER_REQUEST"
  validation {
    condition     = contains(["PAY_PER_REQUEST", "PROVISIONED"], var.billing_mode)
    error_message = "Billing mode must be either PAY_PER_REQUEST or PROVISIONED."
  }
}

variable "enable_point_in_time_recovery" {
  description = "Enable DynamoDB point-in-time recovery for data protection"
  type        = bool
  default     = true
}

# -----------------------------------------------------------------------------
# TTL Configuration
# -----------------------------------------------------------------------------
# Time-to-live settings for automatic data cleanup and cost optimization

variable "dedup_ttl_days" {
  description = "TTL for deduplication table in days (automatic cleanup of duplicate hashes)"
  type        = number
  default     = 30
  validation {
    condition     = var.dedup_ttl_days >= 1 && var.dedup_ttl_days <= 365
    error_message = "Deduplication TTL must be between 1 and 365 days."
  }
}

variable "enrichment_cache_ttl_days" {
  description = "TTL for enrichment cache in days (automatic cleanup of OSINT data)"
  type        = number
  default     = 7
  validation {
    condition     = var.enrichment_cache_ttl_days >= 1 && var.enrichment_cache_ttl_days <= 90
    error_message = "Enrichment cache TTL must be between 1 and 90 days."
  }
}

# -----------------------------------------------------------------------------
# Provisioned Throughput (for PROVISIONED billing mode)
# -----------------------------------------------------------------------------
# These variables are only used when billing_mode is set to PROVISIONED

variable "read_capacity" {
  description = "Read capacity units for main table (only used with PROVISIONED billing)"
  type        = number
  default     = 5
  validation {
    condition     = var.read_capacity >= 1 && var.read_capacity <= 40000
    error_message = "Read capacity must be between 1 and 40000."
  }
}

variable "write_capacity" {
  description = "Write capacity units for main table (only used with PROVISIONED billing)"
  type        = number
  default     = 5
  validation {
    condition     = var.write_capacity >= 1 && var.write_capacity <= 40000
    error_message = "Write capacity must be between 1 and 40000."
  }
}

# -----------------------------------------------------------------------------
# Tagging
# -----------------------------------------------------------------------------

variable "tags" {
  description = "Common tags to apply to all database resources"
  type        = map(string)
  default     = {}
}

# -----------------------------------------------------------------------------
# Monitoring Configuration
# -----------------------------------------------------------------------------

variable "enable_cloudwatch_alarms" {
  description = "Enable CloudWatch alarms for DynamoDB monitoring"
  type        = bool
  default     = true
}

variable "alarm_sns_topic_arn" {
  description = "SNS topic ARN for CloudWatch alarm notifications (optional)"
  type        = string
  default     = ""
}