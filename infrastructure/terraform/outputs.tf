output "api_gateway_url" {
  description = "URL of the API Gateway for threat intelligence platform"
  value       = module.networking.api_gateway_url
  sensitive   = false
}

output "cloudfront_distribution_domain" {
  description = "CloudFront distribution domain for frontend"
  value       = module.networking.cloudfront_domain_name
  sensitive   = false
}

output "dynamodb_table_names" {
  description = "Names of all DynamoDB tables"
  value = {
    threat_intel      = module.database.threat_intel_table_name
    deduplication     = module.database.dedup_table_name
    enrichment_cache  = module.database.enrichment_cache_table_name
  }
  sensitive = false
}

output "s3_bucket_names" {
  description = "Names of all S3 buckets"
  value       = module.storage.bucket_names
  sensitive   = false
}

output "lambda_function_names" {
  description = "Names of all Lambda functions"
  value       = module.compute.lambda_function_names
  sensitive = false
}

output "secrets_manager_arn" {
  description = "ARN of Secrets Manager secret for API keys"
  value       = module.security.api_keys_secret_arn
  sensitive   = true
}

output "deployment_info" {
  description = "Key deployment information"
  value = {
    environment = var.environment
    region      = var.aws_region
    project     = var.project_name
    deployed_at = timestamp()
  }
  sensitive = false
}