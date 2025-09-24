# DEFINE database_variables():
#     VARIABLE environment WITH:
#         - description: "Environment name"
#         - type: string
    
#     VARIABLE project_name WITH:
#         - description: "Project name for table naming"
#         - type: string
#         - default: "threat-intel"
    
#     VARIABLE enable_point_in_time_recovery WITH:
#         - description: "Enable DynamoDB point-in-time recovery"
#         - type: bool
#         - default: true
    
#     VARIABLE dedup_ttl_days WITH:
#         - description: "TTL for deduplication table in days"
#         - type: number
#         - default: 30
    
#     VARIABLE enrichment_cache_ttl_days WITH:
#         - description: "TTL for enrichment cache in days"
#         - type: number
#         - default: 7
    
#     VARIABLE billing_mode WITH:
#         - description: "DynamoDB billing mode"
#         - type: string
#         - default: "PAY_PER_REQUEST"
#         - validation: must be "PAY_PER_REQUEST" or "PROVISIONED"
    
#     VARIABLE tags WITH:
#         - description: "Common tags for all database resources"
#         - type: map(string)
#         - default: {}