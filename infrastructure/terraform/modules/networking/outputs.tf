# DEFINE networking_outputs():
#     OUTPUT api_gateway_url WITH:
#         - description: "URL of the deployed API Gateway"
#         - value: aws_api_gateway_deployment.main.invoke_url
    
#     OUTPUT api_gateway_id WITH:
#         - description: "ID of the API Gateway"
#         - value: aws_api_gateway_rest_api.threat_intel_api.id
    
#     OUTPUT cloudfront_domain WITH:
#         - description: "CloudFront distribution domain name"
#         - value: aws_cloudfront_distribution.frontend.domain_name
    
#     OUTPUT cloudfront_distribution_id WITH:
#         - description: "CloudFront distribution ID"
#         - value: aws_cloudfront_distribution.frontend.id
    
#     OUTPUT api_endpoints WITH:
#         - description: "Available API endpoints"
#         - value: {
#             collect: "${aws_api_gateway_deployment.main.invoke_url}/collect",
#             enrich: "${aws_api_gateway_deployment.main.invoke_url}/enrich",
#             search: "${aws_api_gateway_deployment.main.invoke_url}/search"
#         }
    
#     OUTPUT api_usage_plan_id WITH:
#         - description: "API Gateway usage plan ID"
#         - value: aws_api_gateway_usage_plan.main.id
    
#     OUTPUT api_url WITH:
#         - description: "API URL (alias for backward compatibility)"
#         - value: aws_api_gateway_deployment.main.invoke_url