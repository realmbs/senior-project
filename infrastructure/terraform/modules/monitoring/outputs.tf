# =============================================================================
# Monitoring Module Outputs
# =============================================================================

# -----------------------------------------------------------------------------
# Dashboard Information
# -----------------------------------------------------------------------------
output "system_overview_dashboard_url" {
  description = "URL to the system overview CloudWatch dashboard"
  value       = "https://${var.aws_region}.console.aws.amazon.com/cloudwatch/home?region=${var.aws_region}#dashboards:name=${aws_cloudwatch_dashboard.system_overview.dashboard_name}"
}

output "threat_intelligence_dashboard_url" {
  description = "URL to the threat intelligence CloudWatch dashboard"
  value       = "https://${var.aws_region}.console.aws.amazon.com/cloudwatch/home?region=${var.aws_region}#dashboards:name=${aws_cloudwatch_dashboard.threat_intelligence.dashboard_name}"
}

output "cost_performance_dashboard_url" {
  description = "URL to the cost and performance CloudWatch dashboard"
  value       = "https://${var.aws_region}.console.aws.amazon.com/cloudwatch/home?region=${var.aws_region}#dashboards:name=${aws_cloudwatch_dashboard.cost_performance.dashboard_name}"
}

output "security_compliance_dashboard_url" {
  description = "URL to the security and compliance CloudWatch dashboard"
  value       = "https://${var.aws_region}.console.aws.amazon.com/cloudwatch/home?region=${var.aws_region}#dashboards:name=${aws_cloudwatch_dashboard.security_compliance.dashboard_name}"
}

output "dashboard_names" {
  description = "List of all dashboard names created"
  value = [
    aws_cloudwatch_dashboard.system_overview.dashboard_name,
    aws_cloudwatch_dashboard.threat_intelligence.dashboard_name,
    aws_cloudwatch_dashboard.cost_performance.dashboard_name,
    aws_cloudwatch_dashboard.security_compliance.dashboard_name
  ]
}

# -----------------------------------------------------------------------------
# Log Group Information
# -----------------------------------------------------------------------------
output "application_log_group_name" {
  description = "Name of the application log group"
  value       = aws_cloudwatch_log_group.application_logs.name
}

output "application_log_group_arn" {
  description = "ARN of the application log group"
  value       = aws_cloudwatch_log_group.application_logs.arn
}

output "security_log_group_name" {
  description = "Name of the security log group"
  value       = aws_cloudwatch_log_group.security_logs.name
}

output "security_log_group_arn" {
  description = "ARN of the security log group"
  value       = aws_cloudwatch_log_group.security_logs.arn
}

output "audit_log_group_name" {
  description = "Name of the audit log group"
  value       = aws_cloudwatch_log_group.audit_logs.name
}

output "audit_log_group_arn" {
  description = "ARN of the audit log group"
  value       = aws_cloudwatch_log_group.audit_logs.arn
}

output "log_group_names" {
  description = "List of all log group names created"
  value = [
    aws_cloudwatch_log_group.application_logs.name,
    aws_cloudwatch_log_group.security_logs.name,
    aws_cloudwatch_log_group.audit_logs.name
  ]
}

# -----------------------------------------------------------------------------
# Alarm Information
# -----------------------------------------------------------------------------
output "high_error_rate_alarm_arn" {
  description = "ARN of the high error rate alarm"
  value       = var.enable_cloudwatch_alarms ? aws_cloudwatch_metric_alarm.high_error_rate[0].arn : null
}

output "lambda_duration_alarm_arn" {
  description = "ARN of the Lambda duration alarm"
  value       = var.enable_cloudwatch_alarms ? aws_cloudwatch_metric_alarm.lambda_duration_high[0].arn : null
}

output "dynamodb_throttle_alarm_arn" {
  description = "ARN of the DynamoDB throttle alarm"
  value       = var.enable_cloudwatch_alarms ? aws_cloudwatch_metric_alarm.dynamodb_throttle[0].arn : null
}

output "cache_hit_ratio_alarm_arn" {
  description = "ARN of the cache hit ratio alarm"
  value       = var.enable_cloudwatch_alarms ? aws_cloudwatch_metric_alarm.cache_hit_ratio_low[0].arn : null
}

output "security_events_alarm_arn" {
  description = "ARN of the security events alarm"
  value       = var.enable_cloudwatch_alarms ? aws_cloudwatch_metric_alarm.security_events_high[0].arn : null
}

output "alarm_arns" {
  description = "List of all alarm ARNs created"
  value = var.enable_cloudwatch_alarms ? compact([
    aws_cloudwatch_metric_alarm.high_error_rate[0].arn,
    aws_cloudwatch_metric_alarm.lambda_duration_high[0].arn,
    aws_cloudwatch_metric_alarm.dynamodb_throttle[0].arn,
    aws_cloudwatch_metric_alarm.cache_hit_ratio_low[0].arn,
    aws_cloudwatch_metric_alarm.security_events_high[0].arn
  ]) : []
}

# -----------------------------------------------------------------------------
# SNS Topic Information
# -----------------------------------------------------------------------------
output "critical_alerts_topic_arn" {
  description = "ARN of the critical alerts SNS topic"
  value       = var.create_sns_topic ? aws_sns_topic.critical_alerts[0].arn : null
}

output "critical_alerts_topic_name" {
  description = "Name of the critical alerts SNS topic"
  value       = var.create_sns_topic ? aws_sns_topic.critical_alerts[0].name : null
}

# -----------------------------------------------------------------------------
# Metric Filter Information
# -----------------------------------------------------------------------------
output "error_rate_metric_filter_name" {
  description = "Name of the error rate metric filter"
  value       = aws_cloudwatch_log_metric_filter.error_rate.name
}

output "security_events_metric_filter_name" {
  description = "Name of the security events metric filter"
  value       = aws_cloudwatch_log_metric_filter.security_events.name
}

output "threat_intel_processed_metric_filter_name" {
  description = "Name of the threat intelligence processed metric filter"
  value       = aws_cloudwatch_log_metric_filter.threat_intel_processed.name
}

output "metric_filter_names" {
  description = "List of all metric filter names created"
  value = [
    aws_cloudwatch_log_metric_filter.error_rate.name,
    aws_cloudwatch_log_metric_filter.security_events.name,
    aws_cloudwatch_log_metric_filter.threat_intel_processed.name
  ]
}

# -----------------------------------------------------------------------------
# Synthetics Information
# -----------------------------------------------------------------------------
output "api_health_check_canary_name" {
  description = "Name of the API health check canary"
  value       = var.enable_synthetics ? aws_synthetics_canary.api_health_check[0].name : null
}

output "api_health_check_canary_arn" {
  description = "ARN of the API health check canary"
  value       = var.enable_synthetics ? aws_synthetics_canary.api_health_check[0].arn : null
}

# -----------------------------------------------------------------------------
# Monitoring Configuration Summary
# -----------------------------------------------------------------------------
output "monitoring_configuration" {
  description = "Summary of monitoring configuration"
  value = {
    dashboards_created          = length(aws_cloudwatch_dashboard.system_overview.dashboard_name) > 0 ? 4 : 0
    log_groups_created         = 3
    alarms_enabled             = var.enable_cloudwatch_alarms
    alarms_created             = var.enable_cloudwatch_alarms ? 5 : 0
    synthetics_enabled         = var.enable_synthetics
    sns_topic_created          = var.create_sns_topic
    custom_metrics_enabled     = var.custom_metrics_enabled
    anomaly_detection_enabled  = var.anomaly_detection_enabled
    cost_monitoring_enabled    = var.enable_cost_monitoring
  }
}

# -----------------------------------------------------------------------------
# Environment Variables for Lambda Functions
# -----------------------------------------------------------------------------
output "lambda_environment_variables" {
  description = "Environment variables for Lambda functions to use monitoring"
  value = {
    APPLICATION_LOG_GROUP      = aws_cloudwatch_log_group.application_logs.name
    SECURITY_LOG_GROUP        = aws_cloudwatch_log_group.security_logs.name
    AUDIT_LOG_GROUP           = aws_cloudwatch_log_group.audit_logs.name
    MONITORING_ENABLED        = "true"
    CUSTOM_METRICS_ENABLED    = tostring(var.custom_metrics_enabled)
    ALERT_TOPIC_ARN           = var.create_sns_topic ? aws_sns_topic.critical_alerts[0].arn : ""
    ENVIRONMENT               = var.environment
    PROJECT_NAME              = var.project_name
  }
}

# -----------------------------------------------------------------------------
# Metric Namespaces
# -----------------------------------------------------------------------------
output "custom_metric_namespaces" {
  description = "List of custom metric namespaces configured"
  value       = var.custom_metric_namespaces
}

# -----------------------------------------------------------------------------
# Dashboard Configuration for External Access
# -----------------------------------------------------------------------------
output "dashboard_configuration" {
  description = "Dashboard configuration details"
  value = {
    system_overview = {
      name = aws_cloudwatch_dashboard.system_overview.dashboard_name
      url  = "https://${var.aws_region}.console.aws.amazon.com/cloudwatch/home?region=${var.aws_region}#dashboards:name=${aws_cloudwatch_dashboard.system_overview.dashboard_name}"
    }
    threat_intelligence = {
      name = aws_cloudwatch_dashboard.threat_intelligence.dashboard_name
      url  = "https://${var.aws_region}.console.aws.amazon.com/cloudwatch/home?region=${var.aws_region}#dashboards:name=${aws_cloudwatch_dashboard.threat_intelligence.dashboard_name}"
    }
    cost_performance = {
      name = aws_cloudwatch_dashboard.cost_performance.dashboard_name
      url  = "https://${var.aws_region}.console.aws.amazon.com/cloudwatch/home?region=${var.aws_region}#dashboards:name=${aws_cloudwatch_dashboard.cost_performance.dashboard_name}"
    }
    security_compliance = {
      name = aws_cloudwatch_dashboard.security_compliance.dashboard_name
      url  = "https://${var.aws_region}.console.aws.amazon.com/cloudwatch/home?region=${var.aws_region}#dashboards:name=${aws_cloudwatch_dashboard.security_compliance.dashboard_name}"
    }
  }
}

# -----------------------------------------------------------------------------
# Alerting Configuration
# -----------------------------------------------------------------------------
output "alerting_configuration" {
  description = "Alerting configuration summary"
  value = {
    alarms_enabled           = var.enable_cloudwatch_alarms
    sns_topic_arn           = var.create_sns_topic ? aws_sns_topic.critical_alerts[0].arn : null
    email_subscriptions     = length(var.alert_email_addresses)
    error_rate_threshold    = var.error_rate_threshold
    lambda_duration_threshold = var.lambda_duration_threshold
    cache_hit_ratio_threshold = var.cache_hit_ratio_threshold
    security_events_threshold = var.security_events_threshold
  }
}

# -----------------------------------------------------------------------------
# Log Analysis Configuration
# -----------------------------------------------------------------------------
output "log_analysis_configuration" {
  description = "Log analysis and retention configuration"
  value = {
    application_log_retention = var.log_retention_days
    security_log_retention   = var.security_log_retention_days
    audit_log_retention     = var.audit_log_retention_days
    metric_filters_count    = 3
    log_groups_count        = 3
  }
}