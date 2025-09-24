# FUNCTION deploy_database_infrastructure():
#     CREATE DynamoDB_threat_intel_table WITH:
#         - table_name: "threat-intelligence"
#         - hash_key: "object_id" (String)
#         - range_key: "object_type" (String)
#         - billing_mode: PAY_PER_REQUEST
#         - point_in_time_recovery: enabled
#         - server_side_encryption: enabled
    
#     CREATE GSI_time_index WITH:
#         - index_name: "time-index"
#         - hash_key: "object_type"
#         - range_key: "created_date"
#         - projection_type: ALL
    
#     CREATE GSI_source_index WITH:
#         - index_name: "source-index"
#         - hash_key: "source_name"
#         - range_key: "confidence"
#         - projection_type: ALL
    
#     CREATE GSI_pattern_index WITH:
#         - index_name: "pattern-hash-index"
#         - hash_key: "pattern_hash"
#         - projection_type: KEYS_ONLY
    
#     CREATE DynamoDB_deduplication_table WITH:
#         - table_name: "threat-intel-dedup"
#         - hash_key: "content_hash"
#         - TTL_attribute: "expires_at"
#         - TTL_enabled: true (30 days)
#         - billing_mode: PAY_PER_REQUEST
    
#     CREATE DynamoDB_enrichment_cache WITH:
#         - table_name: "osint-enrichment-cache"
#         - hash_key: "observable_value"
#         - range_key: "enrichment_type"
#         - TTL_attribute: "expires_at"
#         - TTL_enabled: true (7 days)
    
#     RETURN table_names_and_arns