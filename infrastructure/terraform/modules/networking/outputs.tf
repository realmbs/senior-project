# =============================================================================
# Networking Module Outputs
# =============================================================================
# Output values from the networking module
# These provide API endpoints and CloudFront configuration for other modules

# -----------------------------------------------------------------------------
# API Gateway Outputs
# -----------------------------------------------------------------------------

output "api_gateway_url" {
  description = "Base URL of the deployed API Gateway"
  value       = "https://${aws_api_gateway_rest_api.threat_intel_api.id}.execute-api.${data.aws_region.current.name}.amazonaws.com/${aws_api_gateway_stage.main.stage_name}"
  sensitive   = false
}

output "api_gateway_id" {
  description = "ID of the API Gateway REST API"
  value       = aws_api_gateway_rest_api.threat_intel_api.id
  sensitive   = false
}

output "api_gateway_execution_arn" {
  description = "Execution ARN of the API Gateway for Lambda permissions"
  value       = aws_api_gateway_rest_api.threat_intel_api.execution_arn
  sensitive   = false
}

output "api_stage_name" {
  description = "Name of the deployed API Gateway stage"
  value       = aws_api_gateway_stage.main.stage_name
  sensitive   = false
}

# -----------------------------------------------------------------------------
# API Endpoint URLs
# -----------------------------------------------------------------------------

output "api_endpoints" {
  description = "Map of available API endpoints for threat intelligence operations"
  value = {
    base    = "https://${aws_api_gateway_rest_api.threat_intel_api.id}.execute-api.${data.aws_region.current.name}.amazonaws.com/${aws_api_gateway_stage.main.stage_name}"
    collect = "https://${aws_api_gateway_rest_api.threat_intel_api.id}.execute-api.${data.aws_region.current.name}.amazonaws.com/${aws_api_gateway_stage.main.stage_name}/collect"
    enrich  = "https://${aws_api_gateway_rest_api.threat_intel_api.id}.execute-api.${data.aws_region.current.name}.amazonaws.com/${aws_api_gateway_stage.main.stage_name}/enrich"
    search  = "https://${aws_api_gateway_rest_api.threat_intel_api.id}.execute-api.${data.aws_region.current.name}.amazonaws.com/${aws_api_gateway_stage.main.stage_name}/search"
  }
  sensitive = false
}

# -----------------------------------------------------------------------------
# API Gateway Configuration
# -----------------------------------------------------------------------------

output "api_usage_plan_id" {
  description = "ID of the API Gateway usage plan for rate limiting"
  value       = aws_api_gateway_usage_plan.main.id
  sensitive   = false
}

output "api_key_id" {
  description = "ID of the API key for authentication"
  value       = aws_api_gateway_api_key.main.id
  sensitive   = false
}

output "api_key_value" {
  description = "Value of the API key for client authentication"
  value       = aws_api_gateway_api_key.main.value
  sensitive   = true
}

# -----------------------------------------------------------------------------
# CloudFront Distribution Outputs
# -----------------------------------------------------------------------------

output "cloudfront_domain_name" {
  description = "Domain name of the CloudFront distribution"
  value       = aws_cloudfront_distribution.frontend.domain_name
  sensitive   = false
}

output "cloudfront_distribution_id" {
  description = "ID of the CloudFront distribution"
  value       = aws_cloudfront_distribution.frontend.id
  sensitive   = false
}

output "cloudfront_distribution_arn" {
  description = "ARN of the CloudFront distribution"
  value       = aws_cloudfront_distribution.frontend.arn
  sensitive   = false
}

output "cloudfront_hosted_zone_id" {
  description = "Hosted zone ID of the CloudFront distribution for DNS"
  value       = aws_cloudfront_distribution.frontend.hosted_zone_id
  sensitive   = false
}

# -----------------------------------------------------------------------------
# Security Configuration
# -----------------------------------------------------------------------------

output "origin_access_control_id" {
  description = "ID of the CloudFront Origin Access Control for S3"
  value       = aws_cloudfront_origin_access_control.frontend.id
  sensitive   = false
}

# -----------------------------------------------------------------------------
# Frontend URLs
# -----------------------------------------------------------------------------

output "frontend_urls" {
  description = "URLs for accessing the threat intelligence platform"
  value = {
    cloudfront = "https://${aws_cloudfront_distribution.frontend.domain_name}"
    api_base   = "https://${aws_api_gateway_rest_api.threat_intel_api.id}.execute-api.${data.aws_region.current.name}.amazonaws.com/${aws_api_gateway_stage.main.stage_name}"
  }
  sensitive = false
}

# -----------------------------------------------------------------------------
# Monitoring and Debugging
# -----------------------------------------------------------------------------

output "api_gateway_log_group" {
  description = "CloudWatch log group for API Gateway (if logging enabled)"
  value       = var.enable_api_gateway_logging ? "API_GW_Execution_Logs_${aws_api_gateway_rest_api.threat_intel_api.id}/${var.environment}" : null
  sensitive   = false
}

# -----------------------------------------------------------------------------
# Configuration Summary
# -----------------------------------------------------------------------------

output "networking_configuration" {
  description = "Summary of networking module configuration"
  value = {
    api_throttle_rate   = var.api_throttle_rate_limit
    api_throttle_burst  = var.api_throttle_burst_limit
    api_quota_monthly   = var.api_usage_quota_limit
    cloudfront_price_class = var.cloudfront_price_class
    cors_enabled        = var.enable_cors
    api_key_required    = var.api_key_required
    logging_enabled     = var.enable_api_gateway_logging
  }
  sensitive = false
}

# -----------------------------------------------------------------------------
# Utility Outputs for Integration
# -----------------------------------------------------------------------------

output "lambda_permissions_configured" {
  description = "Confirmation that Lambda permissions are configured for API Gateway"
  value = {
    collector_permission  = aws_lambda_permission.allow_api_gateway_collect.statement_id
    enrichment_permission = aws_lambda_permission.allow_api_gateway_enrich.statement_id
    processor_permission  = aws_lambda_permission.allow_api_gateway_search.statement_id
  }
  sensitive = false
}