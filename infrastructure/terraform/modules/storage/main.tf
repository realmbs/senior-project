# # s3 bucket => raw threat intelligence data

# FUNCTION deploy_storage_infrastructure():
#     CREATE S3_bucket WITH:
#         - versioning enabled
#         - lifecycle policies (30→IA, 90→Glacier, 365→delete)
#         - encryption AES256
#         - public access blocked
#     CREATE CloudWatch_log_groups WITH:
#         - retention: 7 days (cost optimization)
    
#     RETURN resource_ARNs_and_names