# =============================================================================
# Monitoring Module - CloudWatch Dashboards and Alarms
# =============================================================================
# This module creates comprehensive monitoring infrastructure for Phase 8D:
# - Multi-layer CloudWatch dashboards for all system components
# - Performance metrics and cost tracking dashboards
# - Custom metrics for threat intelligence analytics
# - Automated alerting and notification systems
# - Log aggregation and analysis

# -----------------------------------------------------------------------------
# CloudWatch Dashboard: System Overview
# -----------------------------------------------------------------------------
resource "aws_cloudwatch_dashboard" "system_overview" {
  dashboard_name = "${var.project_name}-system-overview-${var.environment}"

  dashboard_body = jsonencode({
    widgets = [
      # Lambda Functions Overview
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/Lambda", "Invocations", "FunctionName", var.collector_function_name],
            [".", "Duration", ".", "."],
            [".", "Errors", ".", "."],
            ["AWS/Lambda", "Invocations", "FunctionName", var.processor_function_name],
            [".", "Duration", ".", "."],
            [".", "Errors", ".", "."],
            ["AWS/Lambda", "Invocations", "FunctionName", var.enrichment_function_name],
            [".", "Duration", ".", "."],
            [".", "Errors", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.aws_region
          title   = "Lambda Functions Performance"
          period  = 300
        }
      },

      # DynamoDB Performance
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/DynamoDB", "ConsumedReadCapacityUnits", "TableName", var.threat_intel_table_name],
            [".", "ConsumedWriteCapacityUnits", ".", "."],
            [".", "ItemCount", ".", "."],
            [".", "TableSizeBytes", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.aws_region
          title   = "DynamoDB Performance"
          period  = 300
        }
      },

      # API Gateway Metrics
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/ApiGateway", "Count", "ApiName", var.api_gateway_name],
            [".", "Latency", ".", "."],
            [".", "4XXError", ".", "."],
            [".", "5XXError", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.aws_region
          title   = "API Gateway Performance"
          period  = 300
        }
      },

      # Cache Performance
      {
        type   = "metric"
        x      = 12
        y      = 6
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["ThreatIntel/Cache", "CacheHitRatio", "Environment", var.environment],
            [".", "CacheResponseTime", ".", "."],
            [".", "CacheMemoryUsage", ".", "."],
            [".", "CacheErrors", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.aws_region
          title   = "Cache Performance"
          period  = 300
        }
      }
    ]
  })

}

# -----------------------------------------------------------------------------
# CloudWatch Dashboard: Threat Intelligence Analytics
# -----------------------------------------------------------------------------
resource "aws_cloudwatch_dashboard" "threat_intelligence" {
  dashboard_name = "${var.project_name}-threat-intelligence-${var.environment}"

  dashboard_body = jsonencode({
    widgets = [
      # Threat Collection Metrics
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 8
        height = 6

        properties = {
          metrics = [
            ["ThreatIntel/Collection", "ThreatsCollected", "Source", "OTX"],
            [".", ".", "Source", "AbuseDB"],
            [".", ".", "Source", "Shodan"],
            [".", "ProcessingLatency", "Environment", var.environment],
            [".", "CollectionErrors", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.aws_region
          title   = "Threat Collection"
          period  = 300
        }
      },

      # Processing Pipeline
      {
        type   = "metric"
        x      = 8
        y      = 0
        width  = 8
        height = 6

        properties = {
          metrics = [
            ["ThreatIntel/Processing", "IndicatorsProcessed", "Environment", var.environment],
            [".", "ProcessingTime", ".", "."],
            [".", "QualityScore", ".", "."],
            [".", "DeduplicationRate", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.aws_region
          title   = "Processing Pipeline"
          period  = 300
        }
      },

      # Enrichment Analytics
      {
        type   = "metric"
        x      = 16
        y      = 0
        width  = 8
        height = 6

        properties = {
          metrics = [
            ["ThreatIntel/Enrichment", "EnrichmentRequests", "Environment", var.environment],
            [".", "EnrichmentLatency", ".", "."],
            [".", "EnrichmentSuccessRate", ".", "."],
            [".", "APICallsOptimized", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.aws_region
          title   = "OSINT Enrichment"
          period  = 300
        }
      },

      # Search Analytics
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["ThreatIntel/Search", "SearchQueries", "Environment", var.environment],
            [".", "SearchLatency", ".", "."],
            [".", "SearchResultCount", ".", "."],
            [".", "FuzzyMatchSuccessRate", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.aws_region
          title   = "Search Performance"
          period  = 300
        }
      },

      # Analytics Engine
      {
        type   = "metric"
        x      = 12
        y      = 6
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["ThreatIntel/Analytics", "TrendAnalysisRequests", "Environment", var.environment],
            [".", "GeographicAnalysisRequests", ".", "."],
            [".", "RiskScoringRequests", ".", "."],
            [".", "CorrelationAnalysisRequests", ".", "."],
            [".", "BehavioralAnalysisRequests", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.aws_region
          title   = "Analytics Engine"
          period  = 300
        }
      }
    ]
  })

}

# -----------------------------------------------------------------------------
# CloudWatch Dashboard: Cost and Performance Optimization
# -----------------------------------------------------------------------------
resource "aws_cloudwatch_dashboard" "cost_performance" {
  dashboard_name = "${var.project_name}-cost-performance-${var.environment}"

  dashboard_body = jsonencode({
    widgets = [
      # DynamoDB Cost Optimization
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["ThreatIntel/DynamoDB", "QueryCost", "TableName", var.threat_intel_table_name],
            [".", "QueryExecutionTime", ".", "."],
            [".", "ConsumedReadCapacity", ".", "."],
            [".", "ScanEfficiency", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.aws_region
          title   = "DynamoDB Cost Optimization"
          period  = 300
        }
      },

      # Lambda Cost Analysis
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/Lambda", "Duration", "FunctionName", var.collector_function_name],
            [".", ".", "FunctionName", var.processor_function_name],
            [".", ".", "FunctionName", var.enrichment_function_name],
            [".", "BilledDuration", "FunctionName", var.collector_function_name],
            [".", ".", "FunctionName", var.processor_function_name],
            [".", ".", "FunctionName", var.enrichment_function_name]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.aws_region
          title   = "Lambda Cost Analysis"
          period  = 300
        }
      },

      # Cache Efficiency
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 8
        height = 6

        properties = {
          metrics = [
            ["ThreatIntel/Cache", "CacheHitRatio", "Environment", var.environment],
            ["ThreatIntel/CacheInvalidation", "CacheInvalidations", ".", "."],
            [".", "CacheKeysInvalidated", ".", "."],
            ["ThreatIntel/Cache", "CacheMemoryUsage", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.aws_region
          title   = "Cache Efficiency"
          period  = 300
        }
      },

      # Query Optimization
      {
        type   = "metric"
        x      = 8
        y      = 6
        width  = 8
        height = 6

        properties = {
          metrics = [
            ["ThreatIntel/QueryOptimization", "OptimizationRecommendations", "Environment", var.environment],
            [".", "QueryPerformanceImprovement", ".", "."],
            [".", "CostReduction", ".", "."],
            [".", "QueryPatternAnalysis", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.aws_region
          title   = "Query Optimization"
          period  = 300
        }
      },

      # Resource Utilization
      {
        type   = "metric"
        x      = 16
        y      = 6
        width  = 8
        height = 6

        properties = {
          metrics = [
            ["AWS/Lambda", "MemoryUtilization", "FunctionName", var.collector_function_name],
            [".", ".", "FunctionName", var.processor_function_name],
            [".", ".", "FunctionName", var.enrichment_function_name],
            ["AWS/ElastiCache", "CPUUtilization", "CacheClusterId", var.redis_cluster_id],
            [".", "DatabaseMemoryUsagePercentage", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.aws_region
          title   = "Resource Utilization"
          period  = 300
        }
      }
    ]
  })

}

# -----------------------------------------------------------------------------
# CloudWatch Dashboard: Security and Compliance
# -----------------------------------------------------------------------------
resource "aws_cloudwatch_dashboard" "security_compliance" {
  dashboard_name = "${var.project_name}-security-compliance-${var.environment}"

  dashboard_body = jsonencode({
    widgets = [
      # API Gateway Security
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/ApiGateway", "4XXError", "ApiName", var.api_gateway_name],
            [".", "5XXError", ".", "."],
            ["ThreatIntel/Security", "AuthenticationFailures", "Environment", var.environment],
            [".", "RateLimitExceeded", ".", "."],
            [".", "SuspiciousActivity", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.aws_region
          title   = "API Security Metrics"
          period  = 300
        }
      },

      # Data Access Patterns
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["ThreatIntel/Security", "DataAccess", "Operation", "Read"],
            [".", ".", "Operation", "Write"],
            [".", ".", "Operation", "Delete"],
            [".", "UnauthorizedAccess", "Environment", var.environment],
            [".", "DataExfiltrationAttempts", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.aws_region
          title   = "Data Access Patterns"
          period  = 300
        }
      },

      # Compliance Metrics
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["ThreatIntel/Compliance", "DataRetentionCompliance", "Environment", var.environment],
            [".", "EncryptionCompliance", ".", "."],
            [".", "AuditLogCompleteness", ".", "."],
            [".", "AccessControlCompliance", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.aws_region
          title   = "Compliance Metrics"
          period  = 300
        }
      },

      # Threat Detection
      {
        type   = "metric"
        x      = 12
        y      = 6
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["ThreatIntel/ThreatDetection", "AnomalousPatterns", "Environment", var.environment],
            [".", "HighRiskIndicators", ".", "."],
            [".", "CriticalThreatAlerts", ".", "."],
            [".", "FalsePositiveRate", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.aws_region
          title   = "Threat Detection"
          period  = 300
        }
      }
    ]
  })

}

# -----------------------------------------------------------------------------
# CloudWatch Log Groups for Centralized Logging
# -----------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "application_logs" {
  name              = "/aws/lambda/${var.project_name}-application-${var.environment}"
  retention_in_days = var.log_retention_days

  tags = merge(var.tags, {
    Name        = "${var.project_name}-application-logs"
    Environment = var.environment
    Purpose     = "Centralized application logging"
  })
}

resource "aws_cloudwatch_log_group" "security_logs" {
  name              = "/aws/security/${var.project_name}-${var.environment}"
  retention_in_days = var.security_log_retention_days

  tags = merge(var.tags, {
    Name        = "${var.project_name}-security-logs"
    Environment = var.environment
    Purpose     = "Security event logging"
  })
}

resource "aws_cloudwatch_log_group" "audit_logs" {
  name              = "/aws/audit/${var.project_name}-${var.environment}"
  retention_in_days = var.audit_log_retention_days

  tags = merge(var.tags, {
    Name        = "${var.project_name}-audit-logs"
    Environment = var.environment
    Purpose     = "Audit trail logging"
  })
}

# -----------------------------------------------------------------------------
# CloudWatch Metric Filters for Custom Metrics
# -----------------------------------------------------------------------------
resource "aws_cloudwatch_log_metric_filter" "error_rate" {
  name           = "${var.project_name}-error-rate-${var.environment}"
  log_group_name = aws_cloudwatch_log_group.application_logs.name
  pattern        = "[timestamp, request_id, ERROR, ...]"

  metric_transformation {
    name      = "ErrorRate"
    namespace = "ThreatIntel/Application"
    value     = "1"
  }
}

resource "aws_cloudwatch_log_metric_filter" "security_events" {
  name           = "${var.project_name}-security-events-${var.environment}"
  log_group_name = aws_cloudwatch_log_group.security_logs.name
  pattern        = "[timestamp, event_type=\"SECURITY\", ...]"

  metric_transformation {
    name      = "SecurityEvents"
    namespace = "ThreatIntel/Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_log_metric_filter" "threat_intel_processed" {
  name           = "${var.project_name}-threat-intel-processed-${var.environment}"
  log_group_name = aws_cloudwatch_log_group.application_logs.name
  pattern        = "[timestamp, request_id, INFO, message=\"Threat intelligence processed\", count]"

  metric_transformation {
    name      = "ThreatsProcessed"
    namespace = "ThreatIntel/Processing"
    value     = "$count"
  }
}

# -----------------------------------------------------------------------------
# CloudWatch Alarms for Critical Metrics
# -----------------------------------------------------------------------------

# High Error Rate Alarm
resource "aws_cloudwatch_metric_alarm" "high_error_rate" {
  count = var.enable_cloudwatch_alarms ? 1 : 0

  alarm_name          = "${var.project_name}-high-error-rate-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "ErrorRate"
  namespace           = "ThreatIntel/Application"
  period              = "300"
  statistic           = "Sum"
  threshold           = var.error_rate_threshold
  alarm_description   = "This metric monitors application error rate"
  alarm_actions       = var.alarm_notification_arns
  ok_actions          = var.alarm_notification_arns

  tags = merge(var.tags, {
    Name        = "${var.project_name}-high-error-rate-alarm"
    Environment = var.environment
    Severity    = "critical"
  })
}

# Lambda Duration Alarm
resource "aws_cloudwatch_metric_alarm" "lambda_duration_high" {
  count = var.enable_cloudwatch_alarms ? 1 : 0

  alarm_name          = "${var.project_name}-lambda-duration-high-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "Duration"
  namespace           = "AWS/Lambda"
  period              = "300"
  statistic           = "Average"
  threshold           = var.lambda_duration_threshold
  alarm_description   = "This metric monitors Lambda function duration"
  alarm_actions       = var.alarm_notification_arns

  dimensions = {
    FunctionName = var.processor_function_name
  }

  tags = merge(var.tags, {
    Name        = "${var.project_name}-lambda-duration-alarm"
    Environment = var.environment
    Severity    = "warning"
  })
}

# DynamoDB Throttling Alarm
resource "aws_cloudwatch_metric_alarm" "dynamodb_throttle" {
  count = var.enable_cloudwatch_alarms ? 1 : 0

  alarm_name          = "${var.project_name}-dynamodb-throttle-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "UserErrors"
  namespace           = "AWS/DynamoDB"
  period              = "300"
  statistic           = "Sum"
  threshold           = "0"
  alarm_description   = "This metric monitors DynamoDB throttling"
  alarm_actions       = var.alarm_notification_arns

  dimensions = {
    TableName = var.threat_intel_table_name
  }

  tags = merge(var.tags, {
    Name        = "${var.project_name}-dynamodb-throttle-alarm"
    Environment = var.environment
    Severity    = "critical"
  })
}

# Cache Hit Ratio Low Alarm
resource "aws_cloudwatch_metric_alarm" "cache_hit_ratio_low" {
  count = var.enable_cloudwatch_alarms ? 1 : 0

  alarm_name          = "${var.project_name}-cache-hit-ratio-low-${var.environment}"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = "3"
  metric_name         = "CacheHitRatio"
  namespace           = "ThreatIntel/Cache"
  period              = "300"
  statistic           = "Average"
  threshold           = var.cache_hit_ratio_threshold
  alarm_description   = "This metric monitors cache hit ratio"
  alarm_actions       = var.alarm_notification_arns

  dimensions = {
    Environment = var.environment
  }

  tags = merge(var.tags, {
    Name        = "${var.project_name}-cache-hit-ratio-alarm"
    Environment = var.environment
    Severity    = "warning"
  })
}

# Security Event Alarm
resource "aws_cloudwatch_metric_alarm" "security_events_high" {
  count = var.enable_cloudwatch_alarms ? 1 : 0

  alarm_name          = "${var.project_name}-security-events-high-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "SecurityEvents"
  namespace           = "ThreatIntel/Security"
  period              = "300"
  statistic           = "Sum"
  threshold           = var.security_events_threshold
  alarm_description   = "This metric monitors security events"
  alarm_actions       = var.alarm_notification_arns
  treat_missing_data  = "notBreaching"

  tags = merge(var.tags, {
    Name        = "${var.project_name}-security-events-alarm"
    Environment = var.environment
    Severity    = "critical"
  })
}

# -----------------------------------------------------------------------------
# SNS Topic for Critical Alerts (if not provided)
# -----------------------------------------------------------------------------
resource "aws_sns_topic" "critical_alerts" {
  count = var.create_sns_topic ? 1 : 0
  name  = "${var.project_name}-critical-alerts-${var.environment}"

  tags = merge(var.tags, {
    Name        = "${var.project_name}-critical-alerts"
    Environment = var.environment
    Purpose     = "Critical system alerts"
  })
}

resource "aws_sns_topic_subscription" "email_alerts" {
  count     = var.create_sns_topic && length(var.alert_email_addresses) > 0 ? length(var.alert_email_addresses) : 0
  topic_arn = aws_sns_topic.critical_alerts[0].arn
  protocol  = "email"
  endpoint  = var.alert_email_addresses[count.index]
}

# -----------------------------------------------------------------------------
# CloudWatch Synthetics for API Monitoring
# -----------------------------------------------------------------------------
resource "aws_synthetics_canary" "api_health_check" {
  count                = var.enable_synthetics ? 1 : 0
  name                 = "${var.project_name}-api-health-${var.environment}"
  artifact_s3_location = "s3://${var.synthetics_bucket_name}/canary-artifacts/"
  execution_role_arn   = var.synthetics_execution_role_arn
  handler              = "apiCanaryBlueprint.handler"
  zip_file             = "apicanary.zip"
  runtime_version      = "syn-nodejs-puppeteer-3.9"

  schedule {
    expression = var.synthetics_schedule
  }

  run_config {
    timeout_in_seconds = 60
  }

  tags = merge(var.tags, {
    Name        = "${var.project_name}-api-health-canary"
    Environment = var.environment
    Purpose     = "API health monitoring"
  })
}