# DEFINE root_level_variables():
#     VARIABLE environment WITH:
#         - description: "Environment (dev, staging, prod)"
#         - type: string
#         - default: "dev"
#         - validation: must be one of ["dev", "staging", "prod"]
    
#     VARIABLE aws_region WITH:
#         - description: "AWS region for resource deployment"
#         - type: string
#         - default: "us-east-1"
    
#     VARIABLE project_name WITH:
#         - description: "Name of the threat intelligence project"
#         - type: string
#         - default: "threat-intel-platform"
    
#     VARIABLE otx_api_key WITH:
#         - description: "AlienVault OTX API key"
#         - type: string
#         - sensitive: true
    
#     VARIABLE shodan_api_key WITH:
#         - description: "Shodan API key for network scanning"
#         - type: string
#         - sensitive: true
    
#     VARIABLE abuse_ch_api_key WITH:
#         - description: "Abuse.ch API key for malware feeds"
#         - type: string
#         - sensitive: true
    
#     VARIABLE cost_optimization_enabled WITH:
#         - description: "Enable cost optimization features"
#         - type: bool
#         - default: true
    
#     VARIABLE log_retention_days WITH:
#         - description: "CloudWatch log retention period"
#         - type: number
#         - default: 7