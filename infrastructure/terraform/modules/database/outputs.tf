# =============================================================================
# Database Module Outputs
# =============================================================================
# Output values from the database module
# These are used by other modules for cross-module dependencies

# -----------------------------------------------------------------------------
# Main Threat Intelligence Table Outputs
# -----------------------------------------------------------------------------

output "threat_intel_table_name" {
  description = "Name of the main threat intelligence DynamoDB table"
  value       = aws_dynamodb_table.threat_intelligence.name
  sensitive   = false
}

output "threat_intel_table_arn" {
  description = "ARN of the main threat intelligence DynamoDB table"
  value       = aws_dynamodb_table.threat_intelligence.arn
  sensitive   = false
}

output "threat_intel_table_id" {
  description = "ID of the main threat intelligence DynamoDB table"
  value       = aws_dynamodb_table.threat_intelligence.id
  sensitive   = false
}

# -----------------------------------------------------------------------------
# Deduplication Table Outputs
# -----------------------------------------------------------------------------

output "dedup_table_name" {
  description = "Name of the deduplication DynamoDB table"
  value       = aws_dynamodb_table.deduplication.name
  sensitive   = false
}

output "dedup_table_arn" {
  description = "ARN of the deduplication DynamoDB table"
  value       = aws_dynamodb_table.deduplication.arn
  sensitive   = false
}

output "dedup_table_id" {
  description = "ID of the deduplication DynamoDB table"
  value       = aws_dynamodb_table.deduplication.id
  sensitive   = false
}

# -----------------------------------------------------------------------------
# Enrichment Cache Table Outputs
# -----------------------------------------------------------------------------

output "enrichment_cache_table_name" {
  description = "Name of the OSINT enrichment cache DynamoDB table"
  value       = aws_dynamodb_table.enrichment_cache.name
  sensitive   = false
}

output "enrichment_cache_table_arn" {
  description = "ARN of the OSINT enrichment cache DynamoDB table"
  value       = aws_dynamodb_table.enrichment_cache.arn
  sensitive   = false
}

output "enrichment_cache_table_id" {
  description = "ID of the OSINT enrichment cache DynamoDB table"
  value       = aws_dynamodb_table.enrichment_cache.id
  sensitive   = false
}

# -----------------------------------------------------------------------------
# Global Secondary Index Information
# -----------------------------------------------------------------------------

output "global_secondary_indexes" {
  description = "Information about Global Secondary Indexes on the main table"
  value = {
    time_index = {
      name      = "time-index"
      hash_key  = "object_type"
      range_key = "created_date"
    }
    source_index = {
      name      = "source-index"
      hash_key  = "source_name"
      range_key = "confidence"
    }
    pattern_hash_index = {
      name     = "pattern-hash-index"
      hash_key = "pattern_hash"
    }
  }
  sensitive = false
}

# -----------------------------------------------------------------------------
# Consolidated Table Information
# -----------------------------------------------------------------------------

output "table_names" {
  description = "Map of all DynamoDB table names for easy reference"
  value = {
    threat_intel     = aws_dynamodb_table.threat_intelligence.name
    deduplication    = aws_dynamodb_table.deduplication.name
    enrichment_cache = aws_dynamodb_table.enrichment_cache.name
  }
  sensitive = false
}

output "table_arns" {
  description = "Map of all DynamoDB table ARNs for IAM policy references"
  value = {
    threat_intel     = aws_dynamodb_table.threat_intelligence.arn
    deduplication    = aws_dynamodb_table.deduplication.arn
    enrichment_cache = aws_dynamodb_table.enrichment_cache.arn
  }
  sensitive = false
}

# -----------------------------------------------------------------------------
# Configuration Information
# -----------------------------------------------------------------------------

output "billing_mode" {
  description = "Billing mode used for all tables"
  value       = var.billing_mode
  sensitive   = false
}

output "ttl_configuration" {
  description = "TTL configuration for tables with automatic cleanup"
  value = {
    deduplication_ttl_days    = var.dedup_ttl_days
    enrichment_cache_ttl_days = var.enrichment_cache_ttl_days
  }
  sensitive = false
}

# -----------------------------------------------------------------------------
# CloudWatch Alarm Outputs
# -----------------------------------------------------------------------------

output "cloudwatch_alarms" {
  description = "CloudWatch alarm information for monitoring"
  value = var.enable_cloudwatch_alarms ? {
    read_throttle_alarm = {
      name = aws_cloudwatch_metric_alarm.threat_intel_read_throttle[0].alarm_name
      arn  = aws_cloudwatch_metric_alarm.threat_intel_read_throttle[0].arn
    }
    write_throttle_alarm = {
      name = aws_cloudwatch_metric_alarm.threat_intel_write_throttle[0].alarm_name
      arn  = aws_cloudwatch_metric_alarm.threat_intel_write_throttle[0].arn
    }
  } : {}
  sensitive = false
}