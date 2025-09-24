# CLASS STIXIndicator:
#     ATTRIBUTES:
#         - type: "indicator"
#         - pattern: "[domain-name:value = 'evil.com']"
#         - labels: ["malicious-activity"]
#         - confidence: 0-100
#         - source_name: "OTX"
#         - pattern_hash: MD5(pattern) // for deduplication
    
#     FUNCTION to_dynamodb_item():
#         item = convert_to_dict()
#         item.object_id = self.id
#         item.object_type = "indicator" 
#         item.created_date = self.created.isoformat()
#         item.pattern_hash = self.pattern_hash
#         RETURN item

# CLASS STIXObservable:
#     FUNCTION create_domain_observable(domain, source):
#         RETURN STIXObservable WITH:
#             objects: {"0": {"type": "domain-name", "value": domain}}
#             observable_type: "domain"
#             observable_value: domain
#             source_name: source