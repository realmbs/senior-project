# =============================================================================
# Security Module Outputs
# =============================================================================
# Output values from the security module
# These are used by other modules for cross-module dependencies

# -----------------------------------------------------------------------------
# IAM Role Outputs
# -----------------------------------------------------------------------------
# Lambda execution role information for compute module

output "lambda_role_arn" {
  description = "ARN of the Lambda execution role for threat intelligence functions"
  value       = aws_iam_role.lambda_execution_role.arn
  sensitive   = false
}

output "lambda_role_name" {
  description = "Name of the Lambda execution role"
  value       = aws_iam_role.lambda_execution_role.name
  sensitive   = false
}

# -----------------------------------------------------------------------------
# Secrets Manager Outputs
# -----------------------------------------------------------------------------
# API keys secret information for compute module

output "api_keys_secret_arn" {
  description = "ARN of the Secrets Manager secret containing API keys"
  value       = aws_secretsmanager_secret.api_keys.arn
  sensitive   = false
}

output "api_keys_secret_name" {
  description = "Name of the Secrets Manager secret for Lambda environment variables"
  value       = aws_secretsmanager_secret.api_keys.name
  sensitive   = false
}

# Backward compatibility alias for existing code
output "secrets_arn" {
  description = "Secrets Manager ARN (alias for backward compatibility)"
  value       = aws_secretsmanager_secret.api_keys.arn
  sensitive   = false
}

# -----------------------------------------------------------------------------
# API Gateway Outputs
# -----------------------------------------------------------------------------
# API key information for networking module

output "api_gateway_api_key_id" {
  description = "ID of the API Gateway API key for usage plan association"
  value       = aws_api_gateway_api_key.threat_intel_key.id
  sensitive   = false
}

output "api_gateway_api_key_value" {
  description = "Value of the API Gateway API key for client authentication"
  value       = aws_api_gateway_api_key.threat_intel_key.value
  sensitive   = true
}

# -----------------------------------------------------------------------------
# CloudWatch Logs Outputs
# -----------------------------------------------------------------------------
# Log group information for compute module Lambda function configuration

output "cloudwatch_log_groups" {
  description = "CloudWatch log group names and ARNs for Lambda functions"
  value = {
    collector = {
      name = aws_cloudwatch_log_group.collector_logs.name
      arn  = aws_cloudwatch_log_group.collector_logs.arn
    }
    processor = {
      name = aws_cloudwatch_log_group.processor_logs.name
      arn  = aws_cloudwatch_log_group.processor_logs.arn
    }
    enrichment = {
      name = aws_cloudwatch_log_group.enrichment_logs.name
      arn  = aws_cloudwatch_log_group.enrichment_logs.arn
    }
  }
  sensitive = false
}

# Individual log group outputs for easier reference
output "collector_log_group_name" {
  description = "Name of the collector Lambda function log group"
  value       = aws_cloudwatch_log_group.collector_logs.name
  sensitive   = false
}

output "processor_log_group_name" {
  description = "Name of the processor Lambda function log group"
  value       = aws_cloudwatch_log_group.processor_logs.name
  sensitive   = false
}

output "enrichment_log_group_name" {
  description = "Name of the enrichment Lambda function log group"
  value       = aws_cloudwatch_log_group.enrichment_logs.name
  sensitive   = false
}