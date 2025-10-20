# =============================================================================
# Caching Module - ElastiCache Redis for Threat Intelligence Platform
# =============================================================================
# This module creates the caching infrastructure for Phase 8D enhancements:
# - ElastiCache Redis cluster for Lambda function caching
# - Subnet groups and parameter groups for optimal configuration
# - Security groups for controlled access
# - CloudWatch monitoring and alarms
# - Auto-scaling and backup configuration

# -----------------------------------------------------------------------------
# ElastiCache Subnet Group
# -----------------------------------------------------------------------------
# Subnet group for ElastiCache cluster placement
resource "aws_elasticache_subnet_group" "redis_subnet_group" {
  name       = "${var.project_name}-redis-subnet-group-${var.environment}"
  subnet_ids = var.private_subnet_ids

  tags = merge(var.tags, {
    Name        = "${var.project_name}-redis-subnet-group"
    Environment = var.environment
    Purpose     = "ElastiCache Redis subnet group"
  })
}

# -----------------------------------------------------------------------------
# ElastiCache Parameter Group
# -----------------------------------------------------------------------------
# Custom parameter group for Redis optimization
resource "aws_elasticache_parameter_group" "redis_params" {
  family      = var.redis_family
  name        = "${var.project_name}-redis-params-${var.environment}"
  description = "Custom Redis parameter group for threat intelligence caching"

  # Optimize for Lambda function caching patterns
  parameter {
    name  = "maxmemory-policy"
    value = var.maxmemory_policy
  }

  parameter {
    name  = "timeout"
    value = var.connection_timeout
  }

  parameter {
    name  = "tcp-keepalive"
    value = var.tcp_keepalive
  }

  # Enable keyspace notifications for cache invalidation
  parameter {
    name  = "notify-keyspace-events"
    value = "Ex"  # Notify on key expiration events
  }

  tags = merge(var.tags, {
    Name        = "${var.project_name}-redis-parameters"
    Environment = var.environment
  })
}

# -----------------------------------------------------------------------------
# Security Group for Redis Cluster
# -----------------------------------------------------------------------------
resource "aws_security_group" "redis_sg" {
  name_prefix = "${var.project_name}-redis-${var.environment}-"
  vpc_id      = var.vpc_id
  description = "Security group for ElastiCache Redis cluster"

  # Allow inbound Redis traffic from Lambda functions
  ingress {
    from_port       = var.redis_port
    to_port         = var.redis_port
    protocol        = "tcp"
    security_groups = var.lambda_security_group_ids
    description     = "Redis access from Lambda functions"
  }

  # Allow all outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound traffic"
  }

  tags = merge(var.tags, {
    Name        = "${var.project_name}-redis-security-group"
    Environment = var.environment
    Purpose     = "ElastiCache Redis access control"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# -----------------------------------------------------------------------------
# ElastiCache Replication Group (Redis Cluster)
# -----------------------------------------------------------------------------
resource "aws_elasticache_replication_group" "redis_cluster" {
  replication_group_id       = "${var.project_name}-redis-${var.environment}"
  description                = "Redis cluster for threat intelligence caching"

  # Node configuration
  node_type                  = var.node_type
  port                       = var.redis_port
  parameter_group_name       = aws_elasticache_parameter_group.redis_params.name

  # Cluster configuration
  num_cache_clusters         = var.num_cache_nodes
  automatic_failover_enabled = var.automatic_failover_enabled
  multi_az_enabled          = var.multi_az_enabled

  # Network and security
  subnet_group_name  = aws_elasticache_subnet_group.redis_subnet_group.name
  security_group_ids = [aws_security_group.redis_sg.id]

  # Backup and maintenance
  snapshot_retention_limit = var.snapshot_retention_limit
  snapshot_window         = var.snapshot_window
  maintenance_window      = var.maintenance_window

  # Encryption
  at_rest_encryption_enabled = var.encryption_at_rest_enabled
  transit_encryption_enabled = var.encryption_in_transit_enabled
  auth_token                = var.auth_token_enabled ? random_password.redis_auth_token[0].result : null

  # Auto scaling
  auto_minor_version_upgrade = var.auto_minor_version_upgrade

  # Logging
  log_delivery_configuration {
    destination      = aws_cloudwatch_log_group.redis_logs.name
    destination_type = "cloudwatch-logs"
    log_format       = "text"
    log_type         = "slow-log"
  }

  tags = merge(var.tags, {
    Name        = "${var.project_name}-redis-cluster"
    Environment = var.environment
    Purpose     = "Threat intelligence caching layer"
    CacheType   = "Redis"
  })
}

# -----------------------------------------------------------------------------
# Random Password for Redis Auth Token
# -----------------------------------------------------------------------------
resource "random_password" "redis_auth_token" {
  count   = var.auth_token_enabled ? 1 : 0
  length  = 32
  special = false  # Redis auth tokens don't support special characters
}

# -----------------------------------------------------------------------------
# Store Auth Token in Secrets Manager
# -----------------------------------------------------------------------------
resource "aws_secretsmanager_secret" "redis_auth_token" {
  count                   = var.auth_token_enabled ? 1 : 0
  name                    = "${var.project_name}/redis-auth-token/${var.environment}"
  description             = "Redis authentication token for threat intelligence cache"
  recovery_window_in_days = var.secret_recovery_window_days

  tags = merge(var.tags, {
    Name        = "${var.project_name}-redis-auth-secret"
    Environment = var.environment
    Purpose     = "Redis authentication"
  })
}

resource "aws_secretsmanager_secret_version" "redis_auth_token" {
  count     = var.auth_token_enabled ? 1 : 0
  secret_id = aws_secretsmanager_secret.redis_auth_token[0].id
  secret_string = jsonencode({
    auth_token = random_password.redis_auth_token[0].result
    endpoint   = aws_elasticache_replication_group.redis_cluster.configuration_endpoint_address
    port       = var.redis_port
  })
}

# -----------------------------------------------------------------------------
# CloudWatch Log Group for Redis Logs
# -----------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "redis_logs" {
  name              = "/aws/elasticache/redis/${var.project_name}-${var.environment}"
  retention_in_days = var.log_retention_days

  tags = merge(var.tags, {
    Name        = "${var.project_name}-redis-logs"
    Environment = var.environment
    Purpose     = "ElastiCache Redis logging"
  })
}

# -----------------------------------------------------------------------------
# CloudWatch Alarms for Redis Monitoring
# -----------------------------------------------------------------------------

# CPU Utilization Alarm
resource "aws_cloudwatch_metric_alarm" "redis_cpu_high" {
  count = var.enable_cloudwatch_alarms ? 1 : 0

  alarm_name          = "${var.project_name}-redis-cpu-high-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/ElastiCache"
  period              = "300"
  statistic           = "Average"
  threshold           = var.cpu_alarm_threshold
  alarm_description   = "This metric monitors Redis CPU utilization"
  alarm_actions       = var.alarm_notification_arns

  dimensions = {
    CacheClusterId = aws_elasticache_replication_group.redis_cluster.id
  }

  tags = merge(var.tags, {
    Name        = "${var.project_name}-redis-cpu-alarm"
    Environment = var.environment
  })
}

# Memory Utilization Alarm
resource "aws_cloudwatch_metric_alarm" "redis_memory_high" {
  count = var.enable_cloudwatch_alarms ? 1 : 0

  alarm_name          = "${var.project_name}-redis-memory-high-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "DatabaseMemoryUsagePercentage"
  namespace           = "AWS/ElastiCache"
  period              = "300"
  statistic           = "Average"
  threshold           = var.memory_alarm_threshold
  alarm_description   = "This metric monitors Redis memory utilization"
  alarm_actions       = var.alarm_notification_arns

  dimensions = {
    CacheClusterId = aws_elasticache_replication_group.redis_cluster.id
  }

  tags = merge(var.tags, {
    Name        = "${var.project_name}-redis-memory-alarm"
    Environment = var.environment
  })
}

# Cache Hit Ratio Alarm
resource "aws_cloudwatch_metric_alarm" "redis_cache_hit_ratio_low" {
  count = var.enable_cloudwatch_alarms ? 1 : 0

  alarm_name          = "${var.project_name}-redis-cache-hit-ratio-low-${var.environment}"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = "3"
  metric_name         = "CacheHitRate"
  namespace           = "AWS/ElastiCache"
  period              = "300"
  statistic           = "Average"
  threshold           = var.cache_hit_ratio_threshold
  alarm_description   = "This metric monitors Redis cache hit ratio"
  alarm_actions       = var.alarm_notification_arns

  dimensions = {
    CacheClusterId = aws_elasticache_replication_group.redis_cluster.id
  }

  tags = merge(var.tags, {
    Name        = "${var.project_name}-redis-hit-ratio-alarm"
    Environment = var.environment
  })
}

# Connection Count Alarm
resource "aws_cloudwatch_metric_alarm" "redis_connections_high" {
  count = var.enable_cloudwatch_alarms ? 1 : 0

  alarm_name          = "${var.project_name}-redis-connections-high-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CurrConnections"
  namespace           = "AWS/ElastiCache"
  period              = "300"
  statistic           = "Average"
  threshold           = var.connection_alarm_threshold
  alarm_description   = "This metric monitors Redis connection count"
  alarm_actions       = var.alarm_notification_arns

  dimensions = {
    CacheClusterId = aws_elasticache_replication_group.redis_cluster.id
  }

  tags = merge(var.tags, {
    Name        = "${var.project_name}-redis-connections-alarm"
    Environment = var.environment
  })
}

# -----------------------------------------------------------------------------
# Auto Scaling for Redis Cluster (if supported by node type)
# -----------------------------------------------------------------------------
resource "aws_appautoscaling_target" "redis_target" {
  count = var.enable_auto_scaling ? 1 : 0

  max_capacity       = var.max_cache_nodes
  min_capacity       = var.min_cache_nodes
  resource_id        = "replication-group/${aws_elasticache_replication_group.redis_cluster.replication_group_id}"
  scalable_dimension = "elasticache:replication-group:Replicas"
  service_namespace  = "elasticache"

  tags = merge(var.tags, {
    Name        = "${var.project_name}-redis-autoscaling-target"
    Environment = var.environment
  })
}

resource "aws_appautoscaling_policy" "redis_scale_up" {
  count = var.enable_auto_scaling ? 1 : 0

  name               = "${var.project_name}-redis-scale-up-${var.environment}"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.redis_target[0].resource_id
  scalable_dimension = aws_appautoscaling_target.redis_target[0].scalable_dimension
  service_namespace  = aws_appautoscaling_target.redis_target[0].service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ElastiCachePrimaryEngineCPUUtilization"
    }
    target_value       = var.auto_scaling_cpu_target
    scale_in_cooldown  = var.scale_in_cooldown
    scale_out_cooldown = var.scale_out_cooldown
  }
}

# -----------------------------------------------------------------------------
# SSM Parameters for Lambda Integration
# -----------------------------------------------------------------------------
resource "aws_ssm_parameter" "redis_endpoint" {
  name        = "/${var.project_name}/${var.environment}/redis/endpoint"
  description = "Redis cluster endpoint for Lambda functions"
  type        = "String"
  value       = aws_elasticache_replication_group.redis_cluster.configuration_endpoint_address

  tags = merge(var.tags, {
    Name        = "${var.project_name}-redis-endpoint-param"
    Environment = var.environment
  })
}

resource "aws_ssm_parameter" "redis_port" {
  name        = "/${var.project_name}/${var.environment}/redis/port"
  description = "Redis cluster port for Lambda functions"
  type        = "String"
  value       = tostring(var.redis_port)

  tags = merge(var.tags, {
    Name        = "${var.project_name}-redis-port-param"
    Environment = var.environment
  })
}