# DEFINE networking_variables():
#     VARIABLE environment WITH:
#         - description: "Environment name"
#         - type: string
    
#     VARIABLE lambda_function_names WITH:
#         - description: "Names of Lambda functions to integrate"
#         - type: map(string)
    
#     VARIABLE lambda_invoke_arns WITH:
#         - description: "Invoke ARNs of Lambda functions"
#         - type: map(string)
    
#     VARIABLE frontend_bucket_name WITH:
#         - description: "S3 bucket name for frontend hosting"
#         - type: string
    
#     VARIABLE api_throttle_rate_limit WITH:
#         - description: "API Gateway throttle rate limit"
#         - type: number
#         - default: 100
    
#     VARIABLE api_throttle_burst_limit WITH:
#         - description: "API Gateway throttle burst limit"
#         - type: number
#         - default: 200
    
#     VARIABLE api_usage_quota_limit WITH:
#         - description: "Monthly API usage quota"
#         - type: number
#         - default: 10000
    
#     VARIABLE cloudfront_price_class WITH:
#         - description: "CloudFront price class for cost optimization"
#         - type: string
#         - default: "PriceClass_100"
    
#     VARIABLE enable_cors WITH:
#         - description: "Enable CORS for API Gateway"
#         - type: bool
#         - default: true