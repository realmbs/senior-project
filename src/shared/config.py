# CLASS Config:
#     FUNCTION __init__():
#         IF running_in_AWS():
#             self.environment = "production"
#         ELSE:
#             self.environment = "development"
#             load_env_file(".env")
    
#     FUNCTION get_api_keys():
#         IF self.environment == "production":
#             RETURN get_secrets_from_aws_secrets_manager()
#         ELSE:
#             RETURN {
#                 "otx_api_key": os.getenv("OTX_API_KEY"),
#                 "shodan_api_key": os.getenv("SHODAN_API_KEY")
#             }
    
#     FUNCTION validate_configuration():
#         api_keys = get_api_keys()
#         required_keys = ["otx_api_key", "shodan_api_key"]
#         FOR each key in required_keys:
#             IF key not in api_keys OR api_keys[key] is empty:
#                 RETURN false
#         RETURN true