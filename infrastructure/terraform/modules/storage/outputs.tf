# =============================================================================
# Storage Module Outputs
# =============================================================================
# Output values from the storage module
# These are used by other modules for cross-module dependencies

# -----------------------------------------------------------------------------
# Raw Threat Intelligence Data Bucket Outputs
# -----------------------------------------------------------------------------

output "raw_data_bucket_name" {
  description = "Name of the S3 bucket for raw threat intelligence data storage"
  value       = aws_s3_bucket.raw_threat_data.bucket
  sensitive   = false
}

output "raw_data_bucket_arn" {
  description = "ARN of the raw threat intelligence data bucket"
  value       = aws_s3_bucket.raw_threat_data.arn
  sensitive   = false
}

output "raw_data_bucket_id" {
  description = "ID of the raw threat intelligence data bucket"
  value       = aws_s3_bucket.raw_threat_data.id
  sensitive   = false
}

output "raw_data_bucket_domain_name" {
  description = "Domain name of the raw data bucket"
  value       = aws_s3_bucket.raw_threat_data.bucket_domain_name
  sensitive   = false
}

# -----------------------------------------------------------------------------
# Processed Threat Intelligence Data Bucket Outputs
# -----------------------------------------------------------------------------

output "processed_data_bucket_name" {
  description = "Name of the S3 bucket for processed threat intelligence data"
  value       = aws_s3_bucket.processed_threat_data.bucket
  sensitive   = false
}

output "processed_data_bucket_arn" {
  description = "ARN of the processed threat intelligence data bucket"
  value       = aws_s3_bucket.processed_threat_data.arn
  sensitive   = false
}

output "processed_data_bucket_id" {
  description = "ID of the processed threat intelligence data bucket"
  value       = aws_s3_bucket.processed_threat_data.id
  sensitive   = false
}

# -----------------------------------------------------------------------------
# Frontend Hosting Bucket Outputs
# -----------------------------------------------------------------------------

output "frontend_bucket_name" {
  description = "Name of the S3 bucket for frontend static hosting"
  value       = aws_s3_bucket.frontend_hosting.bucket
  sensitive   = false
}

output "frontend_bucket_arn" {
  description = "ARN of the frontend hosting bucket"
  value       = aws_s3_bucket.frontend_hosting.arn
  sensitive   = false
}

output "frontend_bucket_id" {
  description = "ID of the frontend hosting bucket"
  value       = aws_s3_bucket.frontend_hosting.id
  sensitive   = false
}

output "frontend_bucket_domain_name" {
  description = "Domain name of the frontend bucket for CloudFront origin"
  value       = aws_s3_bucket.frontend_hosting.bucket_domain_name
  sensitive   = false
}

output "frontend_bucket_regional_domain_name" {
  description = "Regional domain name of the frontend bucket"
  value       = aws_s3_bucket.frontend_hosting.bucket_regional_domain_name
  sensitive   = false
}

# -----------------------------------------------------------------------------
# Consolidated Bucket Information
# -----------------------------------------------------------------------------

output "bucket_names" {
  description = "Map of all S3 bucket names for easy reference"
  value = {
    raw_data       = aws_s3_bucket.raw_threat_data.bucket
    processed_data = aws_s3_bucket.processed_threat_data.bucket
    frontend       = aws_s3_bucket.frontend_hosting.bucket
  }
  sensitive = false
}

output "bucket_arns" {
  description = "Map of all S3 bucket ARNs for IAM policy references"
  value = {
    raw_data       = aws_s3_bucket.raw_threat_data.arn
    processed_data = aws_s3_bucket.processed_threat_data.arn
    frontend       = aws_s3_bucket.frontend_hosting.arn
  }
  sensitive = false
}

output "bucket_domain_names" {
  description = "Map of all bucket domain names for CloudFront and application configuration"
  value = {
    raw_data       = aws_s3_bucket.raw_threat_data.bucket_domain_name
    processed_data = aws_s3_bucket.processed_threat_data.bucket_domain_name
    frontend       = aws_s3_bucket.frontend_hosting.bucket_domain_name
  }
  sensitive = false
}

# -----------------------------------------------------------------------------
# Lifecycle Configuration Information
# -----------------------------------------------------------------------------

output "lifecycle_configuration" {
  description = "S3 lifecycle configuration details for cost optimization tracking"
  value = {
    ia_transition_days         = var.s3_lifecycle_ia_days
    glacier_transition_days    = var.s3_lifecycle_glacier_days
    deep_archive_transition_days = var.s3_lifecycle_deep_archive_days
    deletion_days             = var.s3_lifecycle_delete_days
  }
  sensitive = false
}

# -----------------------------------------------------------------------------
# Security Configuration Information
# -----------------------------------------------------------------------------

output "encryption_configuration" {
  description = "Encryption configuration details for security compliance"
  value = {
    kms_key_id       = var.kms_key_id
    versioning_enabled = var.enable_versioning
  }
  sensitive = false
}

output "public_access_block_configuration" {
  description = "Public access block configuration for security validation"
  value = {
    block_public_acls       = true
    block_public_policy     = true
    ignore_public_acls      = true
    restrict_public_buckets = true
  }
  sensitive = false
}

# -----------------------------------------------------------------------------
# Monitoring Information
# -----------------------------------------------------------------------------

output "monitoring_configuration" {
  description = "CloudWatch monitoring configuration details"
  value = var.enable_monitoring ? {
    enabled = true
    storage_cost_alarm = {
      enabled    = true
      threshold_gb = var.storage_cost_threshold_gb
      alarm_name = "${var.project_name}-storage-costs-${var.environment}"
    }
    large_upload_metric = {
      enabled = true
      metric_name = "LargeS3Uploads"
      namespace   = "ThreatIntel/Storage"
    }
  } : {
    enabled = false
    storage_cost_alarm = {
      enabled    = false
      threshold_gb = 0
      alarm_name = ""
    }
    large_upload_metric = {
      enabled = false
      metric_name = ""
      namespace   = ""
    }
  }
  sensitive = false
}

# -----------------------------------------------------------------------------
# CloudWatch Alarm Outputs
# -----------------------------------------------------------------------------

output "cloudwatch_alarms" {
  description = "CloudWatch alarm information for storage monitoring"
  value = var.enable_monitoring ? {
    storage_cost_alarm = {
      name = aws_cloudwatch_metric_alarm.storage_costs[0].alarm_name
      arn  = aws_cloudwatch_metric_alarm.storage_costs[0].arn
    }
  } : {}
  sensitive = false
}

# -----------------------------------------------------------------------------
# Utility Outputs for Other Modules
# -----------------------------------------------------------------------------

output "bucket_suffix" {
  description = "Random suffix used for bucket names (for reference)"
  value       = random_id.bucket_suffix.hex
  sensitive   = false
}

output "s3_bucket_policies" {
  description = "S3 bucket policy information for IAM integration"
  value = {
    raw_data_bucket_policy_required       = true
    processed_data_bucket_policy_required = true
    frontend_bucket_policy_required       = true
  }
  sensitive = false
}