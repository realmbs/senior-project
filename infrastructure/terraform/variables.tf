variable "environment" {
  description = "Environment (dev, staging, prod)"
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
    condition = can(regex("^[a-z]{2}-[a-z]+-[0-9]$", var.aws_region))
    error_message = "AWS region must be in valid format (e.g., us-east-1)."
  }
}

variable "project_name" {
  description = "Name of the threat intelligence project"
  type        = string
  default     = "threat-intel-platform"

  validation {
    condition     = can(regex("^[a-zA-Z0-9-]+$", var.project_name))
    error_message = "Project name must contain only alphanumeric characters and hyphens."
  }
}

variable "otx_api_key" {
  description = "AlienVault OTX API key"
  type        = string
  sensitive   = true

  validation {
    condition     = length(var.otx_api_key) > 0
    error_message = "OTX API key cannot be empty."
  }
}

variable "shodan_api_key" {
  description = "Shodan API key for network scanning"
  type        = string
  sensitive   = true

  validation {
    condition     = length(var.shodan_api_key) > 0
    error_message = "Shodan API key cannot be empty."
  }
}

variable "abuse_ch_api_key" {
  description = "Abuse.ch API key for malware feeds"
  type        = string
  sensitive   = true

  validation {
    condition     = length(var.abuse_ch_api_key) > 0
    error_message = "Abuse.ch API key cannot be empty."
  }
}

variable "cost_optimization_enabled" {
  description = "Enable cost optimization features"
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "CloudWatch log retention period in days"
  type        = number
  default     = 7

  validation {
    condition = contains([
      1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653
    ], var.log_retention_days)
    error_message = "Log retention days must be a valid CloudWatch log retention value."
  }
}