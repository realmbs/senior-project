# =============================================================================
# Monitoring Module Variables
# =============================================================================

# -----------------------------------------------------------------------------
# Basic Configuration
# -----------------------------------------------------------------------------
variable "project_name" {
  description = "Name of the project"
  type        = string
  validation {
    condition     = length(var.project_name) > 0 && length(var.project_name) <= 30
    error_message = "Project name must be between 1 and 30 characters."
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

variable "aws_region" {
  description = "AWS region for monitoring resources"
  type        = string
  default     = "us-east-1"
}

variable "tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default     = {}
}

# -----------------------------------------------------------------------------
# Lambda Function Names
# -----------------------------------------------------------------------------
variable "collector_function_name" {
  description = "Name of the threat intelligence collector Lambda function"
  type        = string
}

variable "processor_function_name" {
  description = "Name of the threat intelligence processor Lambda function"
  type        = string
}

variable "enrichment_function_name" {
  description = "Name of the OSINT enrichment Lambda function"
  type        = string
}

variable "search_function_name" {
  description = "Name of the search engine Lambda function"
  type        = string
  default     = ""
}

variable "analytics_function_name" {
  description = "Name of the analytics engine Lambda function"
  type        = string
  default     = ""
}

variable "cache_manager_function_name" {
  description = "Name of the cache manager Lambda function"
  type        = string
  default     = ""
}

variable "query_optimizer_function_name" {
  description = "Name of the query optimizer Lambda function"
  type        = string
  default     = ""
}

# -----------------------------------------------------------------------------
# Infrastructure Resource Names
# -----------------------------------------------------------------------------
variable "threat_intel_table_name" {
  description = "Name of the main threat intelligence DynamoDB table"
  type        = string
}

variable "enrichment_cache_table_name" {
  description = "Name of the enrichment cache DynamoDB table"
  type        = string
  default     = ""
}

variable "dedup_table_name" {
  description = "Name of the deduplication DynamoDB table"
  type        = string
  default     = ""
}

variable "api_gateway_name" {
  description = "Name of the API Gateway"
  type        = string
}

variable "redis_cluster_id" {
  description = "ElastiCache Redis cluster ID"
  type        = string
  default     = ""
}

variable "s3_bucket_names" {
  description = "List of S3 bucket names to monitor"
  type        = list(string)
  default     = []
}

# -----------------------------------------------------------------------------
# Logging Configuration
# -----------------------------------------------------------------------------
variable "log_retention_days" {
  description = "CloudWatch log retention period in days"
  type        = number
  default     = 7
  validation {
    condition = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653], var.log_retention_days)
    error_message = "Log retention days must be a valid CloudWatch retention period."
  }
}

variable "security_log_retention_days" {
  description = "Security log retention period in days"
  type        = number
  default     = 30
  validation {
    condition = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653], var.security_log_retention_days)
    error_message = "Security log retention days must be a valid CloudWatch retention period."
  }
}

variable "audit_log_retention_days" {
  description = "Audit log retention period in days"
  type        = number
  default     = 90
  validation {
    condition = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653], var.audit_log_retention_days)
    error_message = "Audit log retention days must be a valid CloudWatch retention period."
  }
}

# -----------------------------------------------------------------------------
# Alerting Configuration
# -----------------------------------------------------------------------------
variable "enable_cloudwatch_alarms" {
  description = "Enable CloudWatch alarms"
  type        = bool
  default     = true
}

variable "alarm_notification_arns" {
  description = "List of SNS topic ARNs for alarm notifications"
  type        = list(string)
  default     = []
}

variable "create_sns_topic" {
  description = "Create SNS topic for critical alerts"
  type        = bool
  default     = true
}

variable "alert_email_addresses" {
  description = "List of email addresses for critical alerts"
  type        = list(string)
  default     = []
  validation {
    condition = alltrue([
      for email in var.alert_email_addresses : can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", email))
    ])
    error_message = "All email addresses must be valid email format."
  }
}

# -----------------------------------------------------------------------------
# Alarm Thresholds
# -----------------------------------------------------------------------------
variable "error_rate_threshold" {
  description = "Error rate threshold for alarms (errors per 5 minutes)"
  type        = number
  default     = 10
  validation {
    condition     = var.error_rate_threshold >= 1 && var.error_rate_threshold <= 1000
    error_message = "Error rate threshold must be between 1 and 1000."
  }
}

variable "lambda_duration_threshold" {
  description = "Lambda function duration threshold in milliseconds"
  type        = number
  default     = 30000
  validation {
    condition     = var.lambda_duration_threshold >= 1000 && var.lambda_duration_threshold <= 900000
    error_message = "Lambda duration threshold must be between 1000ms and 900000ms."
  }
}

variable "cache_hit_ratio_threshold" {
  description = "Minimum cache hit ratio threshold (percentage)"
  type        = number
  default     = 80
  validation {
    condition     = var.cache_hit_ratio_threshold >= 10 && var.cache_hit_ratio_threshold <= 100
    error_message = "Cache hit ratio threshold must be between 10 and 100 percent."
  }
}

variable "security_events_threshold" {
  description = "Security events threshold for alarms (events per 5 minutes)"
  type        = number
  default     = 5
  validation {
    condition     = var.security_events_threshold >= 1 && var.security_events_threshold <= 100
    error_message = "Security events threshold must be between 1 and 100."
  }
}

variable "api_error_rate_threshold" {
  description = "API Gateway error rate threshold (percentage)"
  type        = number
  default     = 5
  validation {
    condition     = var.api_error_rate_threshold >= 1 && var.api_error_rate_threshold <= 50
    error_message = "API error rate threshold must be between 1 and 50 percent."
  }
}

variable "api_latency_threshold" {
  description = "API Gateway latency threshold in milliseconds"
  type        = number
  default     = 5000
  validation {
    condition     = var.api_latency_threshold >= 100 && var.api_latency_threshold <= 30000
    error_message = "API latency threshold must be between 100ms and 30000ms."
  }
}

# -----------------------------------------------------------------------------
# DynamoDB Monitoring Configuration
# -----------------------------------------------------------------------------
variable "dynamodb_read_throttle_threshold" {
  description = "DynamoDB read throttle threshold"
  type        = number
  default     = 0
}

variable "dynamodb_write_throttle_threshold" {
  description = "DynamoDB write throttle threshold"
  type        = number
  default     = 0
}

variable "dynamodb_consumed_read_capacity_threshold" {
  description = "DynamoDB consumed read capacity threshold"
  type        = number
  default     = 80
  validation {
    condition     = var.dynamodb_consumed_read_capacity_threshold >= 10 && var.dynamodb_consumed_read_capacity_threshold <= 100
    error_message = "DynamoDB read capacity threshold must be between 10 and 100 percent."
  }
}

variable "dynamodb_consumed_write_capacity_threshold" {
  description = "DynamoDB consumed write capacity threshold"
  type        = number
  default     = 80
  validation {
    condition     = var.dynamodb_consumed_write_capacity_threshold >= 10 && var.dynamodb_consumed_write_capacity_threshold <= 100
    error_message = "DynamoDB write capacity threshold must be between 10 and 100 percent."
  }
}

# -----------------------------------------------------------------------------
# Cache Monitoring Configuration
# -----------------------------------------------------------------------------
variable "redis_cpu_threshold" {
  description = "Redis CPU utilization threshold (percentage)"
  type        = number
  default     = 80
  validation {
    condition     = var.redis_cpu_threshold >= 10 && var.redis_cpu_threshold <= 100
    error_message = "Redis CPU threshold must be between 10 and 100 percent."
  }
}

variable "redis_memory_threshold" {
  description = "Redis memory utilization threshold (percentage)"
  type        = number
  default     = 85
  validation {
    condition     = var.redis_memory_threshold >= 10 && var.redis_memory_threshold <= 100
    error_message = "Redis memory threshold must be between 10 and 100 percent."
  }
}

variable "redis_connection_threshold" {
  description = "Redis connection count threshold"
  type        = number
  default     = 1000
  validation {
    condition     = var.redis_connection_threshold >= 10 && var.redis_connection_threshold <= 10000
    error_message = "Redis connection threshold must be between 10 and 10000."
  }
}

# -----------------------------------------------------------------------------
# Custom Metrics Configuration
# -----------------------------------------------------------------------------
variable "custom_metrics_enabled" {
  description = "Enable custom application metrics"
  type        = bool
  default     = true
}

variable "custom_metric_namespaces" {
  description = "List of custom metric namespaces to monitor"
  type        = list(string)
  default = [
    "ThreatIntel/Collection",
    "ThreatIntel/Processing",
    "ThreatIntel/Enrichment",
    "ThreatIntel/Search",
    "ThreatIntel/Analytics",
    "ThreatIntel/Cache",
    "ThreatIntel/Security"
  ]
}

# -----------------------------------------------------------------------------
# Synthetics Monitoring Configuration
# -----------------------------------------------------------------------------
variable "enable_synthetics" {
  description = "Enable CloudWatch Synthetics for API monitoring"
  type        = bool
  default     = false
}

variable "synthetics_bucket_name" {
  description = "S3 bucket name for synthetics artifacts"
  type        = string
  default     = ""
}

variable "synthetics_execution_role_arn" {
  description = "IAM role ARN for synthetics execution"
  type        = string
  default     = ""
}

variable "synthetics_schedule" {
  description = "Schedule expression for synthetics canary"
  type        = string
  default     = "rate(5 minutes)"
  validation {
    condition = can(regex("^(rate\\([0-9]+ (minute|minutes|hour|hours|day|days)\\)|cron\\(.+\\))$", var.synthetics_schedule))
    error_message = "Synthetics schedule must be a valid rate or cron expression."
  }
}

variable "api_endpoint_url" {
  description = "API endpoint URL for synthetics monitoring"
  type        = string
  default     = ""
}

# -----------------------------------------------------------------------------
# Dashboard Configuration
# -----------------------------------------------------------------------------
variable "dashboard_time_range" {
  description = "Default time range for dashboards"
  type        = string
  default     = "-PT3H"
  validation {
    condition = can(regex("^-P(T)?([0-9]+[SMHD])+$", var.dashboard_time_range))
    error_message = "Dashboard time range must be a valid ISO 8601 duration (e.g., -PT3H for 3 hours)."
  }
}

variable "dashboard_refresh_interval" {
  description = "Dashboard auto-refresh interval in seconds"
  type        = number
  default     = 300
  validation {
    condition     = var.dashboard_refresh_interval >= 60 && var.dashboard_refresh_interval <= 3600
    error_message = "Dashboard refresh interval must be between 60 and 3600 seconds."
  }
}

# -----------------------------------------------------------------------------
# Cost Monitoring Configuration
# -----------------------------------------------------------------------------
variable "enable_cost_monitoring" {
  description = "Enable cost monitoring dashboards"
  type        = bool
  default     = true
}

variable "cost_budget_threshold" {
  description = "Monthly cost budget threshold in USD"
  type        = number
  default     = 100
  validation {
    condition     = var.cost_budget_threshold >= 1 && var.cost_budget_threshold <= 10000
    error_message = "Cost budget threshold must be between $1 and $10000."
  }
}

variable "cost_alert_thresholds" {
  description = "Cost alert thresholds as percentages of budget"
  type        = list(number)
  default     = [50, 80, 100]
  validation {
    condition = alltrue([
      for threshold in var.cost_alert_thresholds : threshold >= 10 && threshold <= 100
    ])
    error_message = "All cost alert thresholds must be between 10 and 100 percent."
  }
}

# -----------------------------------------------------------------------------
# Performance Monitoring Configuration
# -----------------------------------------------------------------------------
variable "performance_baseline_days" {
  description = "Number of days to use for performance baseline calculation"
  type        = number
  default     = 7
  validation {
    condition     = var.performance_baseline_days >= 1 && var.performance_baseline_days <= 30
    error_message = "Performance baseline days must be between 1 and 30."
  }
}

variable "anomaly_detection_enabled" {
  description = "Enable CloudWatch anomaly detection"
  type        = bool
  default     = true
}

variable "anomaly_detection_threshold" {
  description = "Anomaly detection threshold (standard deviations)"
  type        = number
  default     = 2.0
  validation {
    condition     = var.anomaly_detection_threshold >= 1.0 && var.anomaly_detection_threshold <= 5.0
    error_message = "Anomaly detection threshold must be between 1.0 and 5.0 standard deviations."
  }
}