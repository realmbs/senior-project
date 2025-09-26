# =============================================================================
# Security Module Variables
# =============================================================================
# Input variables for the security module
# These variables configure IAM roles, secrets, and logging settings

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
  description = "Project name for resource naming and tagging"
  type        = string
  default     = "threat-intel"
  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.project_name))
    error_message = "Project name must contain only lowercase letters, numbers, and hyphens."
  }
}

# -----------------------------------------------------------------------------
# API Keys (Sensitive)
# -----------------------------------------------------------------------------
# Third-party API keys for threat intelligence sources
# These are stored securely in AWS Secrets Manager

variable "otx_api_key" {
  description = "API key for AT&T Alien Labs OTX threat intelligence feed"
  type        = string
  sensitive   = true
  validation {
    condition     = length(var.otx_api_key) > 0
    error_message = "OTX API key cannot be empty."
  }
}

variable "shodan_api_key" {
  description = "API key for Shodan infrastructure scanning and enrichment"
  type        = string
  sensitive   = true
  validation {
    condition     = length(var.shodan_api_key) > 0
    error_message = "Shodan API key cannot be empty."
  }
}

variable "abuse_ch_api_key" {
  description = "API key for Abuse.ch malware and threat intelligence feeds"
  type        = string
  sensitive   = true
  validation {
    condition     = length(var.abuse_ch_api_key) > 0
    error_message = "Abuse.ch API key cannot be empty."
  }
}

# -----------------------------------------------------------------------------
# Security Configuration
# -----------------------------------------------------------------------------

variable "kms_key_deletion_window" {
  description = "KMS key deletion window in days (7-30)"
  type        = number
  default     = 7
  validation {
    condition     = var.kms_key_deletion_window >= 7 && var.kms_key_deletion_window <= 30
    error_message = "KMS key deletion window must be between 7 and 30 days."
  }
}

# -----------------------------------------------------------------------------
# Logging Configuration
# -----------------------------------------------------------------------------

variable "log_retention_days" {
  description = "CloudWatch log retention period in days for cost optimization"
  type        = number
  default     = 7
  validation {
    condition = contains([
      1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653
    ], var.log_retention_days)
    error_message = "Log retention days must be a valid CloudWatch retention period."
  }
}