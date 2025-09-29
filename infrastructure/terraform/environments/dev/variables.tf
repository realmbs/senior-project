# =============================================================================
# Development Environment Variables
# =============================================================================
# Input variables for the development environment configuration

# -----------------------------------------------------------------------------
# Environment Configuration
# -----------------------------------------------------------------------------

variable "project_name" {
  description = "Name of the project for resource naming"
  type        = string
  default     = "threat-intel-platform"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]*[a-z0-9]$", var.project_name))
    error_message = "Project name must contain only lowercase letters, numbers, and hyphens, starting with a letter."
  }
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod."
  }
}

variable "aws_region" {
  description = "AWS region for resource deployment"
  type        = string
  default     = "us-east-1"

  validation {
    condition     = can(regex("^[a-z]{2}-[a-z]+-[0-9]$", var.aws_region))
    error_message = "AWS region must be in the format 'us-east-1'."
  }
}

# -----------------------------------------------------------------------------
# Lambda Function Configuration
# -----------------------------------------------------------------------------

variable "lambda_timeout" {
  description = "Lambda function timeout in seconds (max 900 seconds / 15 minutes)"
  type        = number
  default     = 300

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
# Development Environment Specific Settings
# -----------------------------------------------------------------------------

variable "enable_detailed_logging" {
  description = "Enable detailed logging for development debugging"
  type        = bool
  default     = true
}

variable "enable_api_gateway_logging" {
  description = "Enable API Gateway request/response logging (dev only)"
  type        = bool
  default     = true
}

variable "retention_days" {
  description = "CloudWatch log retention in days for development environment"
  type        = number
  default     = 7

  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653], var.retention_days)
    error_message = "Retention days must be a valid CloudWatch log retention period."
  }
}

# -----------------------------------------------------------------------------
# Cost Control Settings
# -----------------------------------------------------------------------------

variable "enable_cost_monitoring" {
  description = "Enable cost monitoring and alerts for development environment"
  type        = bool
  default     = true
}

variable "monthly_budget_limit" {
  description = "Monthly budget limit in USD for cost alerts"
  type        = number
  default     = 50.00

  validation {
    condition     = var.monthly_budget_limit > 0
    error_message = "Monthly budget limit must be greater than 0."
  }
}

# -----------------------------------------------------------------------------
# Development Testing Configuration
# -----------------------------------------------------------------------------

variable "enable_test_data_generation" {
  description = "Enable automatic test data generation for development"
  type        = bool
  default     = false
}

variable "test_data_retention_hours" {
  description = "Hours to retain test data before automatic cleanup"
  type        = number
  default     = 24

  validation {
    condition     = var.test_data_retention_hours >= 1 && var.test_data_retention_hours <= 168
    error_message = "Test data retention must be between 1 and 168 hours (1 week)."
  }
}

# -----------------------------------------------------------------------------
# API Keys for Threat Intelligence Sources (Development)
# -----------------------------------------------------------------------------
# Note: In production, these should be managed through a secure secrets management system

variable "otx_api_key" {
  description = "API key for AT&T Alien Labs OTX threat intelligence feed"
  type        = string
  sensitive   = true
  default     = "dev-placeholder-otx-key"

  validation {
    condition     = length(var.otx_api_key) > 0
    error_message = "OTX API key cannot be empty."
  }
}

variable "shodan_api_key" {
  description = "API key for Shodan infrastructure scanning and enrichment"
  type        = string
  sensitive   = true
  default     = "dev-placeholder-shodan-key"

  validation {
    condition     = length(var.shodan_api_key) > 0
    error_message = "Shodan API key cannot be empty."
  }
}

variable "abuse_ch_api_key" {
  description = "API key for Abuse.ch malware and threat intelligence feeds"
  type        = string
  sensitive   = true
  default     = "dev-placeholder-abuse-ch-key"

  validation {
    condition     = length(var.abuse_ch_api_key) > 0
    error_message = "Abuse.ch API key cannot be empty."
  }
}