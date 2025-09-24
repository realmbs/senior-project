# DEFINE compute_variables():
#     VARIABLE environment WITH:
#         - description: "Environment name"
#         - type: string
    
#     VARIABLE lambda_execution_role_arn WITH:
#         - description: "ARN of Lambda execution role"
#         - type: string
    
#     VARIABLE api_keys_secret_arn WITH:
#         - description: "ARN of Secrets Manager secret with API keys"
#         - type: string
    
#     VARIABLE threat_intel_table_name WITH:
#         - description: "Name of threat intelligence DynamoDB table"
#         - type: string
    
#     VARIABLE dedup_table_name WITH:
#         - description: "Name of deduplication DynamoDB table"
#         - type: string
    
#     VARIABLE raw_data_bucket_name WITH:
#         - description: "Name of S3 bucket for raw data"
#         - type: string
    
#     VARIABLE lambda_timeout WITH:
#         - description: "Lambda function timeout in seconds"
#         - type: number
#         - default: 300
    
#     VARIABLE collector_memory_size WITH:
#         - description: "Memory size for collector Lambda"
#         - type: number
#         - default: 256
    
#     VARIABLE processor_memory_size WITH:
#         - description: "Memory size for processor Lambda"
#         - type: number
#         - default: 512
    
#     VARIABLE enrichment_memory_size WITH:
#         - description: "Memory size for enrichment Lambda"
#         - type: number
#         - default: 1024