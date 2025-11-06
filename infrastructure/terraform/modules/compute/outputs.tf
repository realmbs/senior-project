# =============================================================================
# Compute Module Outputs
# =============================================================================
# Output values for Lambda functions and related resources

# -----------------------------------------------------------------------------
# Lambda Function Names
# -----------------------------------------------------------------------------
output "lambda_function_names" {
  description = "Map of Lambda function names for reference by other modules"
  value = {
    collector   = aws_lambda_function.threat_collector.function_name
    processor   = aws_lambda_function.data_processor.function_name
    enrichment  = aws_lambda_function.osint_enrichment.function_name
  }
}

# -----------------------------------------------------------------------------
# Lambda Function ARNs
# -----------------------------------------------------------------------------
output "lambda_function_arns" {
  description = "Map of Lambda function ARNs for IAM policy references"
  value = {
    collector   = aws_lambda_function.threat_collector.arn
    processor   = aws_lambda_function.data_processor.arn
    enrichment  = aws_lambda_function.osint_enrichment.arn
  }
}

# -----------------------------------------------------------------------------
# Lambda Invoke ARNs for API Gateway
# -----------------------------------------------------------------------------
output "lambda_invoke_arns" {
  description = "Map of Lambda invoke ARNs for API Gateway integration"
  value = {
    collector   = aws_lambda_function.threat_collector.invoke_arn
    processor   = aws_lambda_function.data_processor.invoke_arn
    enrichment  = aws_lambda_function.osint_enrichment.invoke_arn
  }
}

# -----------------------------------------------------------------------------
# Function Names List
# -----------------------------------------------------------------------------
output "function_names" {
  description = "List of all Lambda function names for API Gateway configuration"
  value = [
    aws_lambda_function.threat_collector.function_name,
    aws_lambda_function.data_processor.function_name,
    aws_lambda_function.osint_enrichment.function_name
  ]
}

# -----------------------------------------------------------------------------
# CloudWatch Log Group Names
# -----------------------------------------------------------------------------
output "cloudwatch_log_group_names" {
  description = "Map of CloudWatch log group names for monitoring configuration"
  value = {
    collector   = aws_cloudwatch_log_group.threat_collector_logs.name
    processor   = aws_cloudwatch_log_group.data_processor_logs.name
    enrichment  = aws_cloudwatch_log_group.osint_enrichment_logs.name
  }
}

# -----------------------------------------------------------------------------
# Dead Letter Queue Details
# -----------------------------------------------------------------------------
output "lambda_dlq_arn" {
  description = "ARN of the Lambda dead letter queue for monitoring"
  value       = aws_sqs_queue.lambda_dlq.arn
}

output "lambda_dlq_url" {
  description = "URL of the Lambda dead letter queue for message processing"
  value       = aws_sqs_queue.lambda_dlq.url
}

# -----------------------------------------------------------------------------
# Lambda Deployment Package Info
# -----------------------------------------------------------------------------
output "lambda_deployment_package" {
  description = "Information about the Lambda deployment package"
  value = {
    filename     = "${path.module}/lambda_deployment_fixed.zip"
    source_hash  = filebase64sha256("${path.module}/lambda_deployment_fixed.zip")
    source_dir   = "../../lambda_functions"
  }
}