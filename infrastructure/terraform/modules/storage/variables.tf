# DEFINE storage_variables():
#     VARIABLE environment WITH:
#         - description: "Environment name"
#         - type: string
    
#     VARIABLE project_name WITH:
#         - description: "Project name for resource naming"
#         - type: string
#         - default: "threat-intel"
    
#     VARIABLE s3_lifecycle_ia_days WITH:
#         - description: "Days before transitioning to IA storage"
#         - type: number
#         - default: 30
    
#     VARIABLE s3_lifecycle_glacier_days WITH:
#         - description: "Days before transitioning to Glacier"
#         - type: number
#         - default: 90
    
#     VARIABLE s3_lifecycle_delete_days WITH:
#         - description: "Days before deletion"
#         - type: number
#         - default: 365
    
#     VARIABLE enable_versioning WITH:
#         - description: "Enable S3 bucket versioning"
#         - type: bool
#         - default: true
    
#     VARIABLE kms_key_id WITH:
#         - description: "KMS key ID for S3 encryption"
#         - type: string
#         - default: "alias/aws/s3"