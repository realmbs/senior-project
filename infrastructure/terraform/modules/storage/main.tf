# =============================================================================
# Storage Module - S3 Buckets for Threat Intelligence Platform
# =============================================================================
# This module creates the storage layer for the threat intelligence platform:
# - Raw data archival bucket with intelligent lifecycle policies
# - Frontend static hosting bucket for CloudFront distribution
# - Processed data bucket for analytics and reporting
# - Security configurations with encryption and access controls

# -----------------------------------------------------------------------------
# Raw Threat Intelligence Data Bucket
# -----------------------------------------------------------------------------
# Primary storage for raw threat intelligence data from OSINT sources
# Includes lifecycle policies for cost optimization
resource "aws_s3_bucket" "raw_threat_data" {
  bucket = "${var.project_name}-raw-data-${var.environment}-${random_id.bucket_suffix.hex}"

  tags = merge(var.tags, {
    Name        = "${var.project_name}-raw-data"
    Environment = var.environment
    Purpose     = "Raw threat intelligence data storage"
    DataType    = "OSINT-Raw"
  })
}

# Generate random suffix to ensure bucket name uniqueness
resource "random_id" "bucket_suffix" {
  byte_length = 4
}

# Configure versioning for raw data bucket
resource "aws_s3_bucket_versioning" "raw_threat_data" {
  bucket = aws_s3_bucket.raw_threat_data.id
  versioning_configuration {
    status = var.enable_versioning ? "Enabled" : "Suspended"
  }
}

# Server-side encryption configuration for raw data bucket
resource "aws_s3_bucket_server_side_encryption_configuration" "raw_threat_data" {
  bucket = aws_s3_bucket.raw_threat_data.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = var.kms_key_id
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true  # Reduce KMS costs
  }
}

# Block all public access for security
resource "aws_s3_bucket_public_access_block" "raw_threat_data" {
  bucket = aws_s3_bucket.raw_threat_data.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Lifecycle configuration for cost optimization
resource "aws_s3_bucket_lifecycle_configuration" "raw_threat_data" {
  bucket = aws_s3_bucket.raw_threat_data.id

  rule {
    id     = "threat_intel_lifecycle"
    status = "Enabled"

    filter {
      prefix = ""
    }

    # Transition to Infrequent Access after configured days
    transition {
      days          = var.s3_lifecycle_ia_days
      storage_class = "STANDARD_IA"
    }

    # Transition to Glacier after configured days
    transition {
      days          = var.s3_lifecycle_glacier_days
      storage_class = "GLACIER"
    }

    # Transition to Glacier Deep Archive for long-term retention
    transition {
      days          = var.s3_lifecycle_deep_archive_days
      storage_class = "DEEP_ARCHIVE"
    }

    # Delete objects after configured retention period
    expiration {
      days = var.s3_lifecycle_delete_days
    }

    # Clean up incomplete multipart uploads
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    # Handle versioned objects
    noncurrent_version_transition {
      noncurrent_days = 30
      storage_class   = "STANDARD_IA"
    }

    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }
}

# -----------------------------------------------------------------------------
# Processed Threat Intelligence Data Bucket
# -----------------------------------------------------------------------------
# Storage for processed and normalized threat intelligence data
resource "aws_s3_bucket" "processed_threat_data" {
  bucket = "${var.project_name}-processed-data-${var.environment}-${random_id.bucket_suffix.hex}"

  tags = merge(var.tags, {
    Name        = "${var.project_name}-processed-data"
    Environment = var.environment
    Purpose     = "Processed threat intelligence data storage"
    DataType    = "STIX2.1-Processed"
  })
}

# Configure versioning for processed data bucket
resource "aws_s3_bucket_versioning" "processed_threat_data" {
  bucket = aws_s3_bucket.processed_threat_data.id
  versioning_configuration {
    status = var.enable_versioning ? "Enabled" : "Suspended"
  }
}

# Server-side encryption for processed data bucket
resource "aws_s3_bucket_server_side_encryption_configuration" "processed_threat_data" {
  bucket = aws_s3_bucket.processed_threat_data.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = var.kms_key_id
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

# Block public access for processed data bucket
resource "aws_s3_bucket_public_access_block" "processed_threat_data" {
  bucket = aws_s3_bucket.processed_threat_data.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Shorter lifecycle for processed data (already optimized)
resource "aws_s3_bucket_lifecycle_configuration" "processed_threat_data" {
  bucket = aws_s3_bucket.processed_threat_data.id

  rule {
    id     = "processed_data_lifecycle"
    status = "Enabled"

    filter {
      prefix = ""
    }

    transition {
      days          = var.s3_lifecycle_ia_days
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = var.s3_lifecycle_glacier_days
      storage_class = "GLACIER"
    }

    expiration {
      days = var.s3_lifecycle_delete_days
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# -----------------------------------------------------------------------------
# Frontend Static Hosting Bucket
# -----------------------------------------------------------------------------
# Storage for static frontend assets served via CloudFront
resource "aws_s3_bucket" "frontend_hosting" {
  bucket = "${var.project_name}-frontend-${var.environment}-${random_id.bucket_suffix.hex}"

  tags = merge(var.tags, {
    Name        = "${var.project_name}-frontend"
    Environment = var.environment
    Purpose     = "Static frontend hosting for CloudFront"
    DataType    = "Static-Assets"
  })
}

# Configure versioning for frontend bucket (useful for rollbacks)
resource "aws_s3_bucket_versioning" "frontend_hosting" {
  bucket = aws_s3_bucket.frontend_hosting.id
  versioning_configuration {
    status = "Enabled"  # Always enable for frontend assets
  }
}

# Server-side encryption for frontend bucket
resource "aws_s3_bucket_server_side_encryption_configuration" "frontend_hosting" {
  bucket = aws_s3_bucket.frontend_hosting.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"  # Use AES256 for static assets (cost-effective)
    }
  }
}

# Block public access (CloudFront will access via OAC)
resource "aws_s3_bucket_public_access_block" "frontend_hosting" {
  bucket = aws_s3_bucket.frontend_hosting.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Lifecycle configuration for frontend assets
resource "aws_s3_bucket_lifecycle_configuration" "frontend_hosting" {
  bucket = aws_s3_bucket.frontend_hosting.id

  rule {
    id     = "frontend_lifecycle"
    status = "Enabled"

    filter {
      prefix = ""
    }

    # Keep current versions in Standard storage
    # Clean up old versions after 30 days
    noncurrent_version_expiration {
      noncurrent_days = 30
    }

    # Clean up incomplete uploads quickly
    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}

# -----------------------------------------------------------------------------
# CloudWatch Metrics and Monitoring
# -----------------------------------------------------------------------------
# Monitor S3 bucket usage and costs

# CloudWatch metric filter for large object uploads
resource "aws_cloudwatch_log_metric_filter" "large_s3_uploads" {
  count = var.enable_monitoring ? 1 : 0

  name           = "${var.project_name}-large-s3-uploads-${var.environment}"
  log_group_name = "/aws/s3/${aws_s3_bucket.raw_threat_data.bucket}"
  pattern        = "[timestamp, request_id, remote_ip, requester, operation=\"REST.PUT.OBJECT\", key, request_uri, http_status, error_code, bytes_sent > 10485760]"

  metric_transformation {
    name      = "LargeS3Uploads"
    namespace = "ThreatIntel/Storage"
    value     = "1"
  }
}

# Alarm for excessive storage costs
resource "aws_cloudwatch_metric_alarm" "storage_costs" {
  count = var.enable_monitoring ? 1 : 0

  alarm_name          = "${var.project_name}-storage-costs-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "BucketSizeBytes"
  namespace           = "AWS/S3"
  period              = "86400"  # Daily
  statistic           = "Average"
  threshold           = "10737418240"  # 10GB threshold
  alarm_description   = "Storage costs are getting high - review lifecycle policies"
  alarm_actions       = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []

  dimensions = {
    BucketName  = aws_s3_bucket.raw_threat_data.bucket
    StorageType = "StandardStorage"
  }

  tags = merge(var.tags, {
    Name        = "${var.project_name}-storage-cost-alarm"
    Environment = var.environment
  })
}