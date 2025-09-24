# DEFINE database_outputs():
#     OUTPUT threat_intel_table_name WITH:
#         - description: "Name of main threat intelligence table"
#         - value: aws_dynamodb_table.threat_intelligence.name
    
#     OUTPUT threat_intel_table_arn WITH:
#         - description: "ARN of main threat intelligence table"
#         - value: aws_dynamodb_table.threat_intelligence.arn
    
#     OUTPUT dedup_table_name WITH:
#         - description: "Name of deduplication table"
#         - value: aws_dynamodb_table.deduplication.name
    
#     OUTPUT dedup_table_arn WITH:
#         - description: "ARN of deduplication table"
#         - value: aws_dynamodb_table.deduplication.arn
    
#     OUTPUT enrichment_cache_table_name WITH:
#         - description: "Name of enrichment cache table"
#         - value: aws_dynamodb_table.enrichment_cache.name
    
#     OUTPUT enrichment_cache_table_arn WITH:
#         - description: "ARN of enrichment cache table"
#         - value: aws_dynamodb_table.enrichment_cache.arn
    
#     OUTPUT global_secondary_indexes WITH:
#         - description: "Information about GSIs"
#         - value: {
#             time_index: "time-index",
#             source_index: "source-index",
#             pattern_hash_index: "pattern-hash-index"
#         }
    
#     OUTPUT table_names WITH:
#         - description: "Map of all table names"
#         - value: {
#             threat_intel: aws_dynamodb_table.threat_intelligence.name,
#             deduplication: aws_dynamodb_table.deduplication.name,
#             enrichment_cache: aws_dynamodb_table.enrichment_cache.name
#         }