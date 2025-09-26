# =============================================================================
# Storage Module Variables
# =============================================================================
# Input variables for the storage module
# These variables configure S3 buckets, lifecycle policies, and encryption

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
  description = "Project name for bucket naming and resource tagging"
  type        = string
  default     = "threat-intel"
  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.project_name))
    error_message = "Project name must contain only lowercase letters, numbers, and hyphens."
  }
}

# -----------------------------------------------------------------------------
# S3 Lifecycle Configuration
# -----------------------------------------------------------------------------
# Cost optimization through intelligent data tiering

variable "s3_lifecycle_ia_days" {
  description = "Days before transitioning to Infrequent Access storage class"
  type        = number
  default     = 30
  validation {
    condition     = var.s3_lifecycle_ia_days >= 1 && var.s3_lifecycle_ia_days <= 365
    error_message = "IA transition days must be between 1 and 365."
  }
}

variable "s3_lifecycle_glacier_days" {
  description = "Days before transitioning to Glacier storage class"
  type        = number
  default     = 90
  validation {
    condition     = var.s3_lifecycle_glacier_days >= 1 && var.s3_lifecycle_glacier_days <= 365
    error_message = "Glacier transition days must be between 1 and 365."
  }
}

variable "s3_lifecycle_deep_archive_days" {
  description = "Days before transitioning to Glacier Deep Archive storage class"
  type        = number
  default     = 180
  validation {
    condition     = var.s3_lifecycle_deep_archive_days >= 90 && var.s3_lifecycle_deep_archive_days <= 365
    error_message = "Deep Archive transition days must be between 90 and 365."
  }
}

variable "s3_lifecycle_delete_days" {
  description = "Days before permanent deletion of objects"
  type        = number
  default     = 365
  validation {
    condition     = var.s3_lifecycle_delete_days >= 90 && var.s3_lifecycle_delete_days <= 2555  # ~7 years
    error_message = "Deletion days must be between 90 and 2555 (7 years)."
  }
}

# -----------------------------------------------------------------------------
# Security Configuration
# -----------------------------------------------------------------------------

variable "enable_versioning" {
  description = "Enable S3 bucket versioning for data protection"
  type        = bool
  default     = true
}

variable "kms_key_id" {
  description = "KMS key ID for S3 server-side encryption"
  type        = string
  default     = "alias/aws/s3"
  validation {
    condition = can(regex("^(alias/[a-zA-Z0-9/_-]+|arn:aws:kms:.+|[a-f0-9-]{36})$", var.kms_key_id))
    error_message = "KMS key ID must be a valid alias, ARN, or key ID format."
  }
}

variable "force_destroy" {
  description = "Allow Terraform to destroy buckets with objects (use with caution)"
  type        = bool
  default     = false
}

# -----------------------------------------------------------------------------
# Access Control Configuration
# -----------------------------------------------------------------------------

variable "allowed_ips" {
  description = "List of IP addresses allowed to access buckets (for development)"
  type        = list(string)
  default     = []
  validation {
    condition = alltrue([
      for ip in var.allowed_ips : can(cidrhost(ip, 0))
    ])
    error_message = "All IP addresses must be valid CIDR blocks."
  }
}

variable "cors_allowed_origins" {
  description = "CORS allowed origins for frontend bucket"
  type        = list(string)
  default     = []
}

# -----------------------------------------------------------------------------
# Monitoring Configuration
# -----------------------------------------------------------------------------

variable "enable_monitoring" {
  description = "Enable CloudWatch monitoring for S3 buckets"
  type        = bool
  default     = true
}

variable "storage_cost_threshold_gb" {
  description = "Storage cost alarm threshold in GB"
  type        = number
  default     = 10
  validation {
    condition     = var.storage_cost_threshold_gb >= 1 && var.storage_cost_threshold_gb <= 1000
    error_message = "Storage cost threshold must be between 1 and 1000 GB."
  }
}

variable "alarm_sns_topic_arn" {
  description = "SNS topic ARN for CloudWatch alarm notifications (optional)"
  type        = string
  default     = ""
}

# -----------------------------------------------------------------------------
# Tagging
# -----------------------------------------------------------------------------

variable "tags" {
  description = "Common tags to apply to all storage resources"
  type        = map(string)
  default     = {}
}

# -----------------------------------------------------------------------------
# Advanced Configuration
# -----------------------------------------------------------------------------

variable "enable_access_logging" {
  description = "Enable S3 access logging for security monitoring"
  type        = bool
  default     = false
}

variable "notification_configurations" {
  description = "S3 bucket notification configurations"
  type = map(object({
    lambda_function_arn = string
    events             = list(string)
    filter_prefix      = string
    filter_suffix      = string
  }))
  default = {}
}

variable "replication_configuration" {
  description = "Cross-region replication configuration for disaster recovery"
  type = object({
    enabled                = bool
    destination_bucket_arn = string
    destination_region     = string
    replica_kms_key_id     = string
  })
  default = {
    enabled                = false
    destination_bucket_arn = ""
    destination_region     = ""
    replica_kms_key_id     = ""
  }
}