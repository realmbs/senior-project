# DEFINE security_variables():
#     VARIABLE environment WITH:
#         - description: "Environment name"
#         - type: string
    
#     VARIABLE project_name WITH:
#         - description: "Project name for resource naming"
#         - type: string
#         - default: "threat-intel"
    
#     VARIABLE otx_api_key WITH:
#         - description: "OTX API key"
#         - type: string
#         - sensitive: true
    
#     VARIABLE shodan_api_key WITH:
#         - description: "Shodan API key"
#         - type: string
#         - sensitive: true
    
#     VARIABLE abuse_ch_api_key WITH:
#         - description: "Abuse.ch API key"
#         - type: string
#         - sensitive: true
    
#     VARIABLE kms_key_deletion_window WITH:
#         - description: "KMS key deletion window in days"
#         - type: number
#         - default: 7
    
#     VARIABLE log_retention_days WITH:
#         - description: "CloudWatch log retention in days"
#         - type: number
#         - default: 7