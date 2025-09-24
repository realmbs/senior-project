# DEFINE compute_outputs():
#     OUTPUT lambda_function_names WITH:
#         - description: "Names of all Lambda functions"
#         - value: {
#             collector: aws_lambda_function.threat_collector.function_name,
#             processor: aws_lambda_function.data_processor.function_name,
#             enrichment: aws_lambda_function.osint_enrichment.function_name
#         }
    
#     OUTPUT lambda_function_arns WITH:
#         - description: "ARNs of all Lambda functions"
#         - value: {
#             collector: aws_lambda_function.threat_collector.arn,
#             processor: aws_lambda_function.data_processor.arn,
#             enrichment: aws_lambda_function.osint_enrichment.arn
#         }
    
#     OUTPUT lambda_invoke_arns WITH:
#         - description: "Invoke ARNs for API Gateway integration"
#         - value: {
#             collector: aws_lambda_function.threat_collector.invoke_arn,
#             processor: aws_lambda_function.data_processor.invoke_arn,
#             enrichment: aws_lambda_function.osint_enrichment.invoke_arn
#         }
    
#     OUTPUT function_names WITH:
#         - description: "List of function names for API Gateway"
#         - value: [
#             aws_lambda_function.threat_collector.function_name,
#             aws_lambda_function.data_processor.function_name,
#             aws_lambda_function.osint_enrichment.function_name
#         ]