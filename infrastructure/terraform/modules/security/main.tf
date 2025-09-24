# FUNCTION deploy_security_infrastructure():
#     CREATE IAM_lambda_execution_role WITH:
#         - name: "threat-intel-lambda-role"
#         - assume_role_policy: lambda.amazonaws.com
    
#     ATTACH IAM_policy_lambda_basic_execution TO lambda_execution_role
    
#     CREATE IAM_policy_dynamodb_access WITH:
#         - name: "threat-intel-dynamodb-policy"
#         - actions: ["dynamodb:PutItem", "dynamodb:GetItem", "dynamodb:Query", "dynamodb:Scan", "dynamodb:UpdateItem"]
#         - resources: [threat_intel_table_arn, dedup_table_arn, enrichment_cache_arn]
    
#     CREATE IAM_policy_s3_access WITH:
#         - name: "threat-intel-s3-policy"
#         - actions: ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
#         - resources: [raw_data_bucket_arn]
    
#     CREATE IAM_policy_secrets_manager_access WITH:
#         - name: "threat-intel-secrets-policy"
#         - actions: ["secretsmanager:GetSecretValue"]
#         - resources: [api_keys_secret_arn]
    
#     ATTACH all_policies TO lambda_execution_role
    
#     CREATE Secrets_Manager_secret_api_keys WITH:
#         - name: "threat-intel/api-keys"
#         - description: "API keys for threat intelligence sources"
#         - kms_key_id: "alias/aws/secretsmanager"
    
#     CREATE Secrets_Manager_secret_version WITH:
#         - secret_json: {
#             "otx_api_key": var.otx_api_key,
#             "shodan_api_key": var.shodan_api_key,
#             "abuse_ch_api_key": var.abuse_ch_api_key
#         }
    
#     CREATE API_Gateway_api_key WITH:
#         - name: "threat-intel-api-key"
#         - description: "API key for threat intelligence platform"
    
#     CREATE CloudWatch_log_group_collectors WITH:
#         - name: "/aws/lambda/threat-intel-collector"
#         - retention_days: 7 (cost optimization)
    
#     CREATE CloudWatch_log_group_processors WITH:
#         - name: "/aws/lambda/threat-intel-processor"
#         - retention_days: 7
    
#     CREATE CloudWatch_log_group_enrichment WITH:
#         - name: "/aws/lambda/osint-enrichment"
#         - retention_days: 7
    
#     RETURN iam_role_arn_and_secret_arn_and_api_key