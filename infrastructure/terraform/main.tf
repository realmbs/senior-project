# FUNCTION deploy_complete_infrastructure():
#     MODULE security_module WITH:
#         - source: "./modules/security"
#         - environment: var.environment
#         - otx_api_key: var.otx_api_key
#         - shodan_api_key: var.shodan_api_key
#         - abuse_ch_api_key: var.abuse_ch_api_key
    
#     MODULE database_module WITH:
#         - source: "./modules/database"
#         - environment: var.environment
    
#     MODULE storage_module WITH:
#         - source: "./modules/storage"
#         - environment: var.environment
    
#     MODULE compute_module WITH:
#         - source: "./modules/compute"
#         - environment: var.environment
#         - lambda_execution_role_arn: security_module.lambda_role_arn
#         - api_keys_secret_arn: security_module.secrets_arn
#         - threat_intel_table_name: database_module.threat_intel_table_name
#         - dedup_table_name: database_module.dedup_table_name
#         - raw_data_bucket_name: storage_module.raw_data_bucket_name
    
#     MODULE networking_module WITH:
#         - source: "./modules/networking"
#         - environment: var.environment
#         - lambda_function_names: compute_module.function_names
#         - lambda_invoke_arns: compute_module.invoke_arns
#         - frontend_bucket_name: storage_module.frontend_bucket_name
    
#     OUTPUT api_gateway_url FROM networking_module.api_url
#     OUTPUT cloudfront_domain FROM networking_module.cloudfront_domain
#     OUTPUT s3_bucket_names FROM storage_module.bucket_names
#     OUTPUT dynamodb_table_names FROM database_module.table_names