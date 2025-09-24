# DEFINE storage_outputs():
#     OUTPUT raw_data_bucket_name WITH:
#         - description: "Name of S3 bucket for raw threat intelligence data"
#         - value: aws_s3_bucket.raw_threat_data.bucket
    
#     OUTPUT raw_data_bucket_arn WITH:
#         - description: "ARN of raw threat data bucket"
#         - value: aws_s3_bucket.raw_threat_data.arn
    
#     OUTPUT frontend_bucket_name WITH:
#         - description: "Name of S3 bucket for frontend hosting"
#         - value: aws_s3_bucket.frontend_hosting.bucket
    
#     OUTPUT frontend_bucket_arn WITH:
#         - description: "ARN of frontend hosting bucket"
#         - value: aws_s3_bucket.frontend_hosting.arn
    
#     OUTPUT bucket_names WITH:
#         - description: "Map of all bucket names"
#         - value: {
#             raw_data: aws_s3_bucket.raw_threat_data.bucket,
#             frontend: aws_s3_bucket.frontend_hosting.bucket,
#             processed_data: aws_s3_bucket.processed_threat_data.bucket
#         }
    
#     OUTPUT lifecycle_configuration WITH:
#         - description: "S3 lifecycle configuration details"
#         - value: {
#             ia_transition_days: var.s3_lifecycle_ia_days,
#             glacier_transition_days: var.s3_lifecycle_glacier_days,
#             deletion_days: var.s3_lifecycle_delete_days
#         }