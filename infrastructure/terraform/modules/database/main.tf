# =============================================================================
# Database Module - DynamoDB Tables for Threat Intelligence Platform
# =============================================================================
# This module creates the data layer for the threat intelligence platform:
# - Main threat intelligence table with GSIs for efficient querying
# - Deduplication table with TTL for hash-based duplicate detection
# - OSINT enrichment cache with TTL for performance optimization
# - Pay-per-request billing for cost optimization

# -----------------------------------------------------------------------------
# Main Threat Intelligence Table
# -----------------------------------------------------------------------------
# Primary table storing STIX 2.1 threat intelligence objects
# Supports queries by time, source, and pattern hash via GSIs
resource "aws_dynamodb_table" "threat_intelligence" {
  name           = "${var.project_name}-threat-intelligence-${var.environment}"
  billing_mode   = var.billing_mode
  hash_key       = "object_id"
  range_key      = "object_type"

  # Primary key attributes
  attribute {
    name = "object_id"
    type = "S"  # String - STIX object ID (UUIDv4)
  }

  attribute {
    name = "object_type"
    type = "S"  # String - STIX object type (indicator, observable, etc.)
  }

  # GSI attributes for efficient querying
  attribute {
    name = "created_date"
    type = "S"  # String - ISO 8601 timestamp for time-based queries
  }

  attribute {
    name = "source_name"
    type = "S"  # String - Source identifier (OTX, Shodan, Abuse.ch)
  }

  attribute {
    name = "confidence"
    type = "N"  # Number - Confidence score (0-100)
  }

  attribute {
    name = "pattern_hash"
    type = "S"  # String - SHA-256 hash of threat pattern for deduplication
  }

  # -----------------------------------------------------------------------------
  # Global Secondary Index: Time-based queries
  # -----------------------------------------------------------------------------
  # Enables efficient queries by object type and creation time
  # Use case: "Get all indicators created in the last 24 hours"
  global_secondary_index {
    name     = "time-index"
    hash_key = "object_type"
    range_key = "created_date"
    projection_type = "ALL"  # Include all attributes for complete data access
  }

  # -----------------------------------------------------------------------------
  # Global Secondary Index: Source-based queries
  # -----------------------------------------------------------------------------
  # Enables efficient queries by source and confidence level
  # Use case: "Get high-confidence indicators from OTX source"
  global_secondary_index {
    name     = "source-index"
    hash_key = "source_name"
    range_key = "confidence"
    projection_type = "ALL"  # Include all attributes for analytics
  }

  # -----------------------------------------------------------------------------
  # Global Secondary Index: Pattern hash queries
  # -----------------------------------------------------------------------------
  # Enables efficient deduplication checks by pattern hash
  # Use case: "Check if this threat pattern already exists"
  global_secondary_index {
    name     = "pattern-hash-index"
    hash_key = "pattern_hash"
    projection_type = "KEYS_ONLY"  # Minimal projection for dedup checks
  }

  # Security and backup configuration
  point_in_time_recovery {
    enabled = var.enable_point_in_time_recovery
  }

  server_side_encryption {
    enabled = true  # Encrypt data at rest using AWS managed keys
  }

  # Cost optimization: Use default autoscaling for pay-per-request
  # No need to configure read/write capacity units

  tags = merge(var.tags, {
    Name        = "${var.project_name}-threat-intelligence"
    Environment = var.environment
    Purpose     = "Main threat intelligence data storage"
    DataType    = "STIX2.1"
  })
}

# -----------------------------------------------------------------------------
# Deduplication Table
# -----------------------------------------------------------------------------
# Hash-based deduplication using content hashes with TTL
# Prevents duplicate threat intelligence from being stored
resource "aws_dynamodb_table" "deduplication" {
  name         = "${var.project_name}-threat-intel-dedup-${var.environment}"
  billing_mode = var.billing_mode
  hash_key     = "content_hash"

  # Primary key: content hash of threat intelligence data
  attribute {
    name = "content_hash"
    type = "S"  # String - SHA-256 hash of normalized content
  }

  # TTL configuration for automatic cleanup
  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  # Security configuration
  point_in_time_recovery {
    enabled = var.enable_point_in_time_recovery
  }

  server_side_encryption {
    enabled = true
  }

  tags = merge(var.tags, {
    Name        = "${var.project_name}-deduplication"
    Environment = var.environment
    Purpose     = "Hash-based deduplication with TTL"
    TTLDays     = tostring(var.dedup_ttl_days)
  })
}

# -----------------------------------------------------------------------------
# OSINT Enrichment Cache Table
# -----------------------------------------------------------------------------
# Cache for OSINT enrichment data (Shodan, TheHarvester results)
# Reduces API calls and improves response times
resource "aws_dynamodb_table" "enrichment_cache" {
  name         = "${var.project_name}-osint-enrichment-cache-${var.environment}"
  billing_mode = var.billing_mode
  hash_key     = "observable_value"
  range_key    = "enrichment_type"

  # Composite primary key for different enrichment types per observable
  attribute {
    name = "observable_value"
    type = "S"  # String - IP, domain, URL, file hash, etc.
  }

  attribute {
    name = "enrichment_type"
    type = "S"  # String - shodan, theharvester, whois, etc.
  }

  # TTL configuration for cache expiration
  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  # Security configuration
  point_in_time_recovery {
    enabled = var.enable_point_in_time_recovery
  }

  server_side_encryption {
    enabled = true
  }

  tags = merge(var.tags, {
    Name        = "${var.project_name}-enrichment-cache"
    Environment = var.environment
    Purpose     = "OSINT enrichment data cache with TTL"
    TTLDays     = tostring(var.enrichment_cache_ttl_days)
  })
}

# -----------------------------------------------------------------------------
# CloudWatch Alarms for Monitoring
# -----------------------------------------------------------------------------
# Monitor table performance and costs

# Alarm for high read throttling on main table
resource "aws_cloudwatch_metric_alarm" "threat_intel_read_throttle" {
  count = var.enable_cloudwatch_alarms ? 1 : 0
  alarm_name          = "${var.project_name}-threat-intel-read-throttle-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "UserErrors"
  namespace           = "AWS/DynamoDB"
  period              = "120"
  statistic           = "Sum"
  threshold           = "0"
  alarm_description   = "This metric monitors read throttling on threat intelligence table"
  alarm_actions       = []  # Add SNS topic ARN for notifications if needed

  dimensions = {
    TableName = aws_dynamodb_table.threat_intelligence.name
  }

  tags = merge(var.tags, {
    Name        = "${var.project_name}-read-throttle-alarm"
    Environment = var.environment
  })
}

# Alarm for high write throttling on main table
resource "aws_cloudwatch_metric_alarm" "threat_intel_write_throttle" {
  count = var.enable_cloudwatch_alarms ? 1 : 0
  alarm_name          = "${var.project_name}-threat-intel-write-throttle-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "UserErrors"
  namespace           = "AWS/DynamoDB"
  period              = "120"
  statistic           = "Sum"
  threshold           = "0"
  alarm_description   = "This metric monitors write throttling on threat intelligence table"
  alarm_actions       = []

  dimensions = {
    TableName = aws_dynamodb_table.threat_intelligence.name
  }

  tags = merge(var.tags, {
    Name        = "${var.project_name}-write-throttle-alarm"
    Environment = var.environment
  })
}