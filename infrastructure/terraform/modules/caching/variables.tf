# =============================================================================
# Caching Module Variables
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

variable "tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default     = {}
}

# -----------------------------------------------------------------------------
# Network Configuration
# -----------------------------------------------------------------------------
variable "vpc_id" {
  description = "VPC ID where the Redis cluster will be created"
  type        = string
}

variable "private_subnet_ids" {
  description = "List of private subnet IDs for the Redis cluster"
  type        = list(string)
  validation {
    condition     = length(var.private_subnet_ids) >= 2
    error_message = "At least 2 private subnets are required for high availability."
  }
}

variable "lambda_security_group_ids" {
  description = "List of Lambda function security group IDs that need Redis access"
  type        = list(string)
  default     = []
}

# -----------------------------------------------------------------------------
# Redis Cluster Configuration
# -----------------------------------------------------------------------------
variable "node_type" {
  description = "ElastiCache node type"
  type        = string
  default     = "cache.t3.micro"
  validation {
    condition = can(regex("^cache\\.", var.node_type))
    error_message = "Node type must be a valid ElastiCache instance type starting with 'cache.'."
  }
}

variable "redis_port" {
  description = "Port for Redis cluster"
  type        = number
  default     = 6379
  validation {
    condition     = var.redis_port > 1024 && var.redis_port < 65536
    error_message = "Redis port must be between 1024 and 65535."
  }
}

variable "redis_family" {
  description = "Redis parameter group family"
  type        = string
  default     = "redis7.x"
  validation {
    condition = can(regex("^redis[0-9]\\.", var.redis_family))
    error_message = "Redis family must be in format 'redisX.x' (e.g., 'redis7.x')."
  }
}

variable "num_cache_nodes" {
  description = "Number of cache nodes in the Redis cluster"
  type        = number
  default     = 2
  validation {
    condition     = var.num_cache_nodes >= 1 && var.num_cache_nodes <= 6
    error_message = "Number of cache nodes must be between 1 and 6."
  }
}

variable "automatic_failover_enabled" {
  description = "Enable automatic failover for Redis cluster"
  type        = bool
  default     = true
}

variable "multi_az_enabled" {
  description = "Enable Multi-AZ for Redis cluster"
  type        = bool
  default     = true
}

# -----------------------------------------------------------------------------
# Redis Parameter Configuration
# -----------------------------------------------------------------------------
variable "maxmemory_policy" {
  description = "Redis maxmemory policy"
  type        = string
  default     = "allkeys-lru"
  validation {
    condition = contains([
      "volatile-lru", "allkeys-lru", "volatile-lfu", "allkeys-lfu",
      "volatile-random", "allkeys-random", "volatile-ttl", "noeviction"
    ], var.maxmemory_policy)
    error_message = "Invalid maxmemory policy. Must be one of the supported Redis policies."
  }
}

variable "connection_timeout" {
  description = "Redis connection timeout in seconds"
  type        = number
  default     = 300
  validation {
    condition     = var.connection_timeout >= 60 && var.connection_timeout <= 3600
    error_message = "Connection timeout must be between 60 and 3600 seconds."
  }
}

variable "tcp_keepalive" {
  description = "Redis TCP keepalive time in seconds"
  type        = number
  default     = 300
  validation {
    condition     = var.tcp_keepalive >= 60 && var.tcp_keepalive <= 7200
    error_message = "TCP keepalive must be between 60 and 7200 seconds."
  }
}

# -----------------------------------------------------------------------------
# Backup and Maintenance Configuration
# -----------------------------------------------------------------------------
variable "snapshot_retention_limit" {
  description = "Number of days to retain automatic backups"
  type        = number
  default     = 5
  validation {
    condition     = var.snapshot_retention_limit >= 0 && var.snapshot_retention_limit <= 35
    error_message = "Snapshot retention limit must be between 0 and 35 days."
  }
}

variable "snapshot_window" {
  description = "Daily time range for automatic snapshots (UTC)"
  type        = string
  default     = "03:00-05:00"
  validation {
    condition = can(regex("^([0-1]?[0-9]|2[0-3]):[0-5][0-9]-([0-1]?[0-9]|2[0-3]):[0-5][0-9]$", var.snapshot_window))
    error_message = "Snapshot window must be in format 'HH:MM-HH:MM' (24-hour UTC)."
  }
}

variable "maintenance_window" {
  description = "Weekly time range for system maintenance (UTC)"
  type        = string
  default     = "sun:05:00-sun:07:00"
  validation {
    condition = can(regex("^(sun|mon|tue|wed|thu|fri|sat):[0-2][0-9]:[0-5][0-9]-(sun|mon|tue|wed|thu|fri|sat):[0-2][0-9]:[0-5][0-9]$", var.maintenance_window))
    error_message = "Maintenance window must be in format 'ddd:HH:MM-ddd:HH:MM' (UTC)."
  }
}

variable "auto_minor_version_upgrade" {
  description = "Enable automatic minor version upgrades"
  type        = bool
  default     = true
}

# -----------------------------------------------------------------------------
# Security Configuration
# -----------------------------------------------------------------------------
variable "encryption_at_rest_enabled" {
  description = "Enable encryption at rest for Redis cluster"
  type        = bool
  default     = true
}

variable "encryption_in_transit_enabled" {
  description = "Enable encryption in transit for Redis cluster"
  type        = bool
  default     = true
}

variable "auth_token_enabled" {
  description = "Enable Redis AUTH token for additional security"
  type        = bool
  default     = true
}

variable "secret_recovery_window_days" {
  description = "Recovery window for deleted secrets (0 to delete immediately)"
  type        = number
  default     = 7
  validation {
    condition     = var.secret_recovery_window_days >= 0 && var.secret_recovery_window_days <= 30
    error_message = "Secret recovery window must be between 0 and 30 days."
  }
}

# -----------------------------------------------------------------------------
# Monitoring and Alerting Configuration
# -----------------------------------------------------------------------------
variable "enable_cloudwatch_alarms" {
  description = "Enable CloudWatch alarms for Redis monitoring"
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "CloudWatch log retention period in days"
  type        = number
  default     = 7
  validation {
    condition = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653], var.log_retention_days)
    error_message = "Log retention days must be a valid CloudWatch retention period."
  }
}

variable "alarm_notification_arns" {
  description = "List of SNS topic ARNs for alarm notifications"
  type        = list(string)
  default     = []
}

variable "cpu_alarm_threshold" {
  description = "CPU utilization threshold for alarms (percentage)"
  type        = number
  default     = 80
  validation {
    condition     = var.cpu_alarm_threshold >= 10 && var.cpu_alarm_threshold <= 100
    error_message = "CPU alarm threshold must be between 10 and 100 percent."
  }
}

variable "memory_alarm_threshold" {
  description = "Memory utilization threshold for alarms (percentage)"
  type        = number
  default     = 85
  validation {
    condition     = var.memory_alarm_threshold >= 10 && var.memory_alarm_threshold <= 100
    error_message = "Memory alarm threshold must be between 10 and 100 percent."
  }
}

variable "cache_hit_ratio_threshold" {
  description = "Minimum cache hit ratio threshold for alarms (percentage)"
  type        = number
  default     = 80
  validation {
    condition     = var.cache_hit_ratio_threshold >= 10 && var.cache_hit_ratio_threshold <= 100
    error_message = "Cache hit ratio threshold must be between 10 and 100 percent."
  }
}

variable "connection_alarm_threshold" {
  description = "Maximum connections threshold for alarms"
  type        = number
  default     = 1000
  validation {
    condition     = var.connection_alarm_threshold >= 10 && var.connection_alarm_threshold <= 10000
    error_message = "Connection alarm threshold must be between 10 and 10000."
  }
}

# -----------------------------------------------------------------------------
# Auto Scaling Configuration
# -----------------------------------------------------------------------------
variable "enable_auto_scaling" {
  description = "Enable auto scaling for Redis cluster"
  type        = bool
  default     = false
}

variable "min_cache_nodes" {
  description = "Minimum number of cache nodes for auto scaling"
  type        = number
  default     = 1
  validation {
    condition     = var.min_cache_nodes >= 1 && var.min_cache_nodes <= 20
    error_message = "Minimum cache nodes must be between 1 and 20."
  }
}

variable "max_cache_nodes" {
  description = "Maximum number of cache nodes for auto scaling"
  type        = number
  default     = 6
  validation {
    condition     = var.max_cache_nodes >= 1 && var.max_cache_nodes <= 20
    error_message = "Maximum cache nodes must be between 1 and 20."
  }
}

variable "auto_scaling_cpu_target" {
  description = "Target CPU utilization for auto scaling (percentage)"
  type        = number
  default     = 70
  validation {
    condition     = var.auto_scaling_cpu_target >= 20 && var.auto_scaling_cpu_target <= 90
    error_message = "Auto scaling CPU target must be between 20 and 90 percent."
  }
}

variable "scale_in_cooldown" {
  description = "Cooldown period for scale-in operations (seconds)"
  type        = number
  default     = 300
  validation {
    condition     = var.scale_in_cooldown >= 60 && var.scale_in_cooldown <= 3600
    error_message = "Scale-in cooldown must be between 60 and 3600 seconds."
  }
}

variable "scale_out_cooldown" {
  description = "Cooldown period for scale-out operations (seconds)"
  type        = number
  default     = 300
  validation {
    condition     = var.scale_out_cooldown >= 60 && var.scale_out_cooldown <= 3600
    error_message = "Scale-out cooldown must be between 60 and 3600 seconds."
  }
}