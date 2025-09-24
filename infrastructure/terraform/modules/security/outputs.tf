# DEFINE security_outputs():
#     OUTPUT lambda_role_arn WITH:
#         - description: "ARN of Lambda execution role"
#         - value: aws_iam_role.lambda_execution_role.arn
    
#     OUTPUT lambda_role_name WITH:
#         - description: "Name of Lambda execution role"
#         - value: aws_iam_role.lambda_execution_role.name
    
#     OUTPUT api_keys_secret_arn WITH:
#         - description: "ARN of API keys secret in Secrets Manager"
#         - value: aws_secretsmanager_secret.api_keys.arn
    
#     OUTPUT api_keys_secret_name WITH:
#         - description: "Name of API keys secret"
#         - value: aws_secretsmanager_secret.api_keys.name
    
#     OUTPUT api_gateway_api_key_id WITH:
#         - description: "ID of API Gateway API key"
#         - value: aws_api_gateway_api_key.threat_intel_key.id
    
#     OUTPUT cloudwatch_log_groups WITH:
#         - description: "CloudWatch log group names"
#         - value: {
#             collector: aws_cloudwatch_log_group.collector_logs.name,
#             processor: aws_cloudwatch_log_group.processor_logs.name,
#             enrichment: aws_cloudwatch_log_group.enrichment_logs.name
#         }
    
#     OUTPUT secrets_arn WITH:
#         - description: "Secrets Manager ARN (alias for backward compatibility)"
#         - value: aws_secretsmanager_secret.api_keys.arn