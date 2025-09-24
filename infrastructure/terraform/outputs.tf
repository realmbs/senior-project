# DEFINE root_level_outputs():
#     OUTPUT api_gateway_url WITH:
#         - description: "URL of the API Gateway for threat intelligence platform"
#         - value: module.networking.api_gateway_url
#         - sensitive: false
    
#     OUTPUT cloudfront_distribution_domain WITH:
#         - description: "CloudFront distribution domain for frontend"
#         - value: module.networking.cloudfront_domain
#         - sensitive: false
    
#     OUTPUT dynamodb_table_names WITH:
#         - description: "Names of all DynamoDB tables"
#         - value: {
#             threat_intel: module.database.threat_intel_table_name,
#             deduplication: module.database.dedup_table_name,
#             enrichment_cache: module.database.enrichment_cache_table_name
#         }
    
#     OUTPUT s3_bucket_names WITH:
#         - description: "Names of all S3 buckets"
#         - value: module.storage.bucket_names
    
#     OUTPUT lambda_function_names WITH:
#         - description: "Names of all Lambda functions"
#         - value: module.compute.lambda_function_names
    
#     OUTPUT secrets_manager_arn WITH:
#         - description: "ARN of Secrets Manager secret for API keys"
#         - value: module.security.api_keys_secret_arn
#         - sensitive: true
    
#     OUTPUT deployment_info WITH:
#         - description: "Key deployment information"
#         - value: {
#             environment: var.environment,
#             region: var.aws_region,
#             project: var.project_name,
#             deployed_at: timestamp()
#         }