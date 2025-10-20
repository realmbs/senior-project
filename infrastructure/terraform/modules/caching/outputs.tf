# =============================================================================
# Caching Module Outputs
# =============================================================================

# -----------------------------------------------------------------------------
# Redis Cluster Information
# -----------------------------------------------------------------------------
output "redis_cluster_id" {
  description = "The ID of the ElastiCache Redis replication group"
  value       = aws_elasticache_replication_group.redis_cluster.id
}

output "redis_cluster_arn" {
  description = "The ARN of the ElastiCache Redis replication group"
  value       = aws_elasticache_replication_group.redis_cluster.arn
}

output "redis_primary_endpoint" {
  description = "The primary endpoint of the Redis cluster"
  value       = aws_elasticache_replication_group.redis_cluster.primary_endpoint_address
  sensitive   = false
}

output "redis_configuration_endpoint" {
  description = "The configuration endpoint of the Redis cluster (for cluster mode)"
  value       = aws_elasticache_replication_group.redis_cluster.configuration_endpoint_address
  sensitive   = false
}

output "redis_port" {
  description = "The port of the Redis cluster"
  value       = var.redis_port
}

output "redis_member_clusters" {
  description = "List of member cluster IDs"
  value       = aws_elasticache_replication_group.redis_cluster.member_clusters
}

# -----------------------------------------------------------------------------
# Security Group Information
# -----------------------------------------------------------------------------
output "redis_security_group_id" {
  description = "The ID of the Redis security group"
  value       = aws_security_group.redis_sg.id
}

output "redis_security_group_arn" {
  description = "The ARN of the Redis security group"
  value       = aws_security_group.redis_sg.arn
}

# -----------------------------------------------------------------------------
# Authentication Information
# -----------------------------------------------------------------------------
output "redis_auth_token_secret_arn" {
  description = "The ARN of the Secrets Manager secret containing the Redis auth token"
  value       = var.auth_token_enabled ? aws_secretsmanager_secret.redis_auth_token[0].arn : null
  sensitive   = false
}

output "redis_auth_token_secret_name" {
  description = "The name of the Secrets Manager secret containing the Redis auth token"
  value       = var.auth_token_enabled ? aws_secretsmanager_secret.redis_auth_token[0].name : null
  sensitive   = false
}

# -----------------------------------------------------------------------------
# Parameter Group Information
# -----------------------------------------------------------------------------
output "redis_parameter_group_id" {
  description = "The ID of the Redis parameter group"
  value       = aws_elasticache_parameter_group.redis_params.id
}

output "redis_parameter_group_name" {
  description = "The name of the Redis parameter group"
  value       = aws_elasticache_parameter_group.redis_params.name
}

# -----------------------------------------------------------------------------
# Subnet Group Information
# -----------------------------------------------------------------------------
output "redis_subnet_group_name" {
  description = "The name of the Redis subnet group"
  value       = aws_elasticache_subnet_group.redis_subnet_group.name
}

# -----------------------------------------------------------------------------
# CloudWatch Resources
# -----------------------------------------------------------------------------
output "redis_log_group_name" {
  description = "The name of the CloudWatch log group for Redis logs"
  value       = aws_cloudwatch_log_group.redis_logs.name
}

output "redis_log_group_arn" {
  description = "The ARN of the CloudWatch log group for Redis logs"
  value       = aws_cloudwatch_log_group.redis_logs.arn
}

# -----------------------------------------------------------------------------
# Alarm Information
# -----------------------------------------------------------------------------
output "redis_cpu_alarm_arn" {
  description = "The ARN of the Redis CPU utilization alarm"
  value       = var.enable_cloudwatch_alarms ? aws_cloudwatch_metric_alarm.redis_cpu_high[0].arn : null
}

output "redis_memory_alarm_arn" {
  description = "The ARN of the Redis memory utilization alarm"
  value       = var.enable_cloudwatch_alarms ? aws_cloudwatch_metric_alarm.redis_memory_high[0].arn : null
}

output "redis_cache_hit_ratio_alarm_arn" {
  description = "The ARN of the Redis cache hit ratio alarm"
  value       = var.enable_cloudwatch_alarms ? aws_cloudwatch_metric_alarm.redis_cache_hit_ratio_low[0].arn : null
}

output "redis_connections_alarm_arn" {
  description = "The ARN of the Redis connections alarm"
  value       = var.enable_cloudwatch_alarms ? aws_cloudwatch_metric_alarm.redis_connections_high[0].arn : null
}

# -----------------------------------------------------------------------------
# Auto Scaling Information
# -----------------------------------------------------------------------------
output "redis_autoscaling_target_arn" {
  description = "The ARN of the Redis auto scaling target"
  value       = var.enable_auto_scaling ? aws_appautoscaling_target.redis_target[0].arn : null
}

output "redis_autoscaling_policy_arn" {
  description = "The ARN of the Redis auto scaling policy"
  value       = var.enable_auto_scaling ? aws_appautoscaling_policy.redis_scale_up[0].arn : null
}

# -----------------------------------------------------------------------------
# SSM Parameter Information
# -----------------------------------------------------------------------------
output "redis_endpoint_ssm_parameter_name" {
  description = "The name of the SSM parameter containing the Redis endpoint"
  value       = aws_ssm_parameter.redis_endpoint.name
}

output "redis_port_ssm_parameter_name" {
  description = "The name of the SSM parameter containing the Redis port"
  value       = aws_ssm_parameter.redis_port.name
}

# -----------------------------------------------------------------------------
# Connection Information for Lambda Functions
# -----------------------------------------------------------------------------
output "redis_connection_info" {
  description = "Complete Redis connection information for Lambda functions"
  value = {
    endpoint                  = aws_elasticache_replication_group.redis_cluster.configuration_endpoint_address
    primary_endpoint         = aws_elasticache_replication_group.redis_cluster.primary_endpoint_address
    port                     = var.redis_port
    auth_token_secret_arn    = var.auth_token_enabled ? aws_secretsmanager_secret.redis_auth_token[0].arn : null
    security_group_id        = aws_security_group.redis_sg.id
    parameter_group_name     = aws_elasticache_parameter_group.redis_params.name
    encryption_at_rest       = var.encryption_at_rest_enabled
    encryption_in_transit    = var.encryption_in_transit_enabled
    multi_az                 = var.multi_az_enabled
    automatic_failover       = var.automatic_failover_enabled
  }
  sensitive = false
}

# -----------------------------------------------------------------------------
# Cache Configuration for Environment Variables
# -----------------------------------------------------------------------------
output "lambda_environment_variables" {
  description = "Environment variables for Lambda functions to use Redis caching"
  value = {
    REDIS_CLUSTER_ENDPOINT          = aws_elasticache_replication_group.redis_cluster.configuration_endpoint_address
    REDIS_PRIMARY_ENDPOINT          = aws_elasticache_replication_group.redis_cluster.primary_endpoint_address
    REDIS_PORT                      = tostring(var.redis_port)
    REDIS_AUTH_TOKEN_SECRET_ARN     = var.auth_token_enabled ? aws_secretsmanager_secret.redis_auth_token[0].arn : ""
    ENABLE_CACHE_COMPRESSION        = "true"
    CACHE_KEY_PREFIX               = "${var.project_name}-${var.environment}"
    REDIS_ENCRYPTION_IN_TRANSIT    = tostring(var.encryption_in_transit_enabled)
  }
  sensitive = false
}

# -----------------------------------------------------------------------------
# Monitoring and Metrics Information
# -----------------------------------------------------------------------------
output "cache_monitoring_info" {
  description = "Information for cache monitoring and metrics"
  value = {
    cluster_id              = aws_elasticache_replication_group.redis_cluster.id
    log_group_name          = aws_cloudwatch_log_group.redis_logs.name
    parameter_group_name    = aws_elasticache_parameter_group.redis_params.name
    subnet_group_name       = aws_elasticache_subnet_group.redis_subnet_group.name
    security_group_id       = aws_security_group.redis_sg.id
    alarms_enabled          = var.enable_cloudwatch_alarms
    auto_scaling_enabled    = var.enable_auto_scaling
  }
  sensitive = false
}

# -----------------------------------------------------------------------------
# Cost Optimization Information
# -----------------------------------------------------------------------------
output "cost_optimization_info" {
  description = "Information for cost optimization and monitoring"
  value = {
    node_type                    = var.node_type
    num_cache_nodes             = var.num_cache_nodes
    snapshot_retention_limit    = var.snapshot_retention_limit
    log_retention_days          = var.log_retention_days
    auto_minor_version_upgrade  = var.auto_minor_version_upgrade
    encryption_enabled          = var.encryption_at_rest_enabled && var.encryption_in_transit_enabled
    multi_az_enabled           = var.multi_az_enabled
  }
  sensitive = false
}