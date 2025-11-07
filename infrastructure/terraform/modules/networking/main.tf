# =============================================================================
# Networking Module - API Gateway & CloudFront Distribution
# =============================================================================
# Creates REST API Gateway with Lambda integrations and CloudFront distribution
# for static content delivery with cost-optimized regional deployment

# =============================================================================
# ⚠️ TERRAFORM STATE DRIFT WARNING (November 7, 2025)
# =============================================================================
# CRITICAL: The following resources exist in AWS but are NOT tracked in Terraform state.
# They were created manually via AWS CLI on November 4, 2025, to restore API functionality
# after Terraform deployment failures.
#
# MANUALLY MANAGED RESOURCES (DO NOT EXIST IN TERRAFORM STATE):
# - aws_api_gateway_deployment.main (deployment ID: 59wbkc)
# - aws_api_gateway_stage.main (stage: dev)
# - aws_api_gateway_integration.collect_integration (AWS_PROXY to collector Lambda)
# - aws_api_gateway_integration.enrich_integration (AWS_PROXY to enrichment Lambda)
# - aws_api_gateway_integration.search_integration (AWS_PROXY to processor Lambda)
# - aws_lambda_permission.allow_api_gateway_collect (API Gateway → collector)
# - aws_lambda_permission.allow_api_gateway_enrich (API Gateway → enrichment)
# - aws_lambda_permission.allow_api_gateway_search (API Gateway → processor)
# - aws_api_gateway_usage_plan.main (API key association)
# - aws_api_gateway_usage_plan_key.main (API key to usage plan link)
#
# IMPACT: Running "terraform apply" will attempt to CREATE these resources, which may:
# - Break the currently working API Gateway (deployment ID will change)
# - Cause API downtime (stage must be updated to new deployment)
# - Destroy/recreate OPTIONS integrations (wrong type in state: AWS_PROXY vs MOCK)
# - Trigger 502 errors during CORS preflight requests
#
# CURRENT STATUS:
# - API Gateway: ✅ 100% OPERATIONAL (all endpoints working correctly)
# - Terraform Plan: ⚠️ Shows 26 resources to add/change/destroy
# - Risk Level: 🔴 HIGH (60% probability of API downtime if apply is run)
#
# MANAGEMENT STRATEGY:
# - ✅ Use AWS CLI for API Gateway changes (see docs/api-gateway-troubleshooting.md)
# - ✅ Use Terraform for Lambda, DynamoDB, S3 (tracked in state)
# - ⚠️ Do NOT run "terraform apply" on this module without reviewing drift
# - 📖 Full documentation: docs/terraform-state-drift.md
#
# Root Cause: Terraform Lambda deployment timeouts prevented proper integration setup
# on November 4, 2025. Manual AWS CLI fixes restored functionality but bypassed Terraform.
# =============================================================================

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# =============================================================================
# Data Sources
# =============================================================================
data "aws_region" "current" {}

# =============================================================================
# API Gateway REST API
# =============================================================================

resource "aws_api_gateway_rest_api" "threat_intel_api" {
  name        = "${var.project_name}-api-${var.environment}"
  description = "Threat Intelligence Platform API - ${var.environment}"

  endpoint_configuration {
    types = ["REGIONAL"]
  }

  binary_media_types = [
    "application/json",
    "application/octet-stream"
  ]

  tags = {
    Name        = "${var.project_name}-api-${var.environment}"
    Environment = var.environment
  }
}

# =============================================================================
# API Gateway Resources (/collect, /enrich, /search)
# =============================================================================

# /collect resource for threat intelligence collection
resource "aws_api_gateway_resource" "collect" {
  rest_api_id = aws_api_gateway_rest_api.threat_intel_api.id
  parent_id   = aws_api_gateway_rest_api.threat_intel_api.root_resource_id
  path_part   = "collect"
}

# /enrich resource for OSINT enrichment
resource "aws_api_gateway_resource" "enrich" {
  rest_api_id = aws_api_gateway_rest_api.threat_intel_api.id
  parent_id   = aws_api_gateway_rest_api.threat_intel_api.root_resource_id
  path_part   = "enrich"
}

# /search resource for threat intelligence queries
resource "aws_api_gateway_resource" "search" {
  rest_api_id = aws_api_gateway_rest_api.threat_intel_api.id
  parent_id   = aws_api_gateway_rest_api.threat_intel_api.root_resource_id
  path_part   = "search"
}

# =============================================================================
# Phase 8D Enhancements: Request Validation and Models
# =============================================================================

# Request models for validation
resource "aws_api_gateway_model" "collect_request_model" {
  rest_api_id  = aws_api_gateway_rest_api.threat_intel_api.id
  name         = "CollectRequestModel"
  content_type = "application/json"

  schema = jsonencode({
    "$schema": "http://json-schema.org/draft-04/schema#",
    "type": "object",
    "required": ["source", "action"],
    "properties": {
      "source": {
        "type": "string",
        "enum": ["otx", "abuse_ch", "shodan", "manual"],
        "description": "Source of threat intelligence collection"
      },
      "action": {
        "type": "string",
        "enum": ["collect", "manual_add"],
        "description": "Collection action to perform"
      },
      "parameters": {
        "type": "object",
        "properties": {
          "feed_type": {"type": "string"},
          "time_range": {"type": "string"},
          "limit": {"type": "integer", "minimum": 1, "maximum": 1000}
        }
      },
      "indicators": {
        "type": "array",
        "items": {
          "type": "object",
          "required": ["type", "value"],
          "properties": {
            "type": {"type": "string", "enum": ["ip", "domain", "url", "hash", "email"]},
            "value": {"type": "string", "minLength": 1, "maxLength": 2048},
            "confidence": {"type": "integer", "minimum": 0, "maximum": 100},
            "tags": {"type": "array", "items": {"type": "string"}}
          }
        }
      }
    }
  })
}

resource "aws_api_gateway_model" "enrich_request_model" {
  rest_api_id  = aws_api_gateway_rest_api.threat_intel_api.id
  name         = "EnrichRequestModel"
  content_type = "application/json"

  schema = jsonencode({
    "$schema": "http://json-schema.org/draft-04/schema#",
    "type": "object",
    "required": ["observables", "enrichment_types"],
    "properties": {
      "observables": {
        "type": "array",
        "minItems": 1,
        "maxItems": 100,
        "items": {
          "type": "object",
          "required": ["type", "value"],
          "properties": {
            "type": {"type": "string", "enum": ["ip", "domain", "url", "hash", "email"]},
            "value": {"type": "string", "minLength": 1, "maxLength": 2048}
          }
        }
      },
      "enrichment_types": {
        "type": "array",
        "minItems": 1,
        "items": {
          "type": "string",
          "enum": ["shodan", "whois", "geolocation", "dns", "reputation", "all"]
        }
      },
      "options": {
        "type": "object",
        "properties": {
          "include_historical": {"type": "boolean"},
          "max_depth": {"type": "integer", "minimum": 1, "maximum": 5},
          "cache_ttl": {"type": "integer", "minimum": 300, "maximum": 86400}
        }
      }
    }
  })
}

resource "aws_api_gateway_model" "search_response_model" {
  rest_api_id  = aws_api_gateway_rest_api.threat_intel_api.id
  name         = "SearchResponseModel"
  content_type = "application/json"

  schema = jsonencode({
    "$schema": "http://json-schema.org/draft-04/schema#",
    "type": "object",
    "required": ["results", "total_count", "query_info"],
    "properties": {
      "results": {
        "type": "array",
        "items": {
          "type": "object",
          "properties": {
            "indicator": {"type": "object"},
            "relevance_score": {"type": "number", "minimum": 0, "maximum": 1},
            "confidence_score": {"type": "integer", "minimum": 0, "maximum": 100},
            "match_type": {"type": "string"},
            "correlations": {"type": "array"}
          }
        }
      },
      "total_count": {"type": "integer", "minimum": 0},
      "query_info": {
        "type": "object",
        "properties": {
          "query_id": {"type": "string"},
          "execution_time_ms": {"type": "integer"},
          "cache_hit": {"type": "boolean"}
        }
      },
      "pagination": {
        "type": "object",
        "properties": {
          "current_page": {"type": "integer"},
          "total_pages": {"type": "integer"},
          "next_cursor": {"type": "string"}
        }
      }
    }
  })
}

resource "aws_api_gateway_model" "error_response_model" {
  rest_api_id  = aws_api_gateway_rest_api.threat_intel_api.id
  name         = "ErrorResponseModel"
  content_type = "application/json"

  schema = jsonencode({
    "$schema": "http://json-schema.org/draft-04/schema#",
    "type": "object",
    "required": ["error", "message", "timestamp"],
    "properties": {
      "error": {
        "type": "object",
        "required": ["code", "type"],
        "properties": {
          "code": {"type": "string"},
          "type": {"type": "string", "enum": ["VALIDATION_ERROR", "RATE_LIMIT_EXCEEDED", "INTERNAL_ERROR", "UNAUTHORIZED", "NOT_FOUND"]},
          "details": {"type": "array", "items": {"type": "string"}}
        }
      },
      "message": {"type": "string"},
      "timestamp": {"type": "string", "format": "date-time"},
      "request_id": {"type": "string"},
      "path": {"type": "string"}
    }
  })
}

# Request validators
resource "aws_api_gateway_request_validator" "collect_validator" {
  name                        = "collect-request-validator"
  rest_api_id                = aws_api_gateway_rest_api.threat_intel_api.id
  validate_request_body       = true
  validate_request_parameters = true
}

resource "aws_api_gateway_request_validator" "enrich_validator" {
  name                        = "enrich-request-validator"
  rest_api_id                = aws_api_gateway_rest_api.threat_intel_api.id
  validate_request_body       = true
  validate_request_parameters = true
}

resource "aws_api_gateway_request_validator" "search_validator" {
  name                        = "search-request-validator"
  rest_api_id                = aws_api_gateway_rest_api.threat_intel_api.id
  validate_request_body       = false
  validate_request_parameters = true
}

# =============================================================================
# API Gateway Methods with Enhanced Validation
# =============================================================================

# POST /collect method with Phase 8D enhancements
resource "aws_api_gateway_method" "collect_post" {
  rest_api_id   = aws_api_gateway_rest_api.threat_intel_api.id
  resource_id   = aws_api_gateway_resource.collect.id
  http_method   = "POST"
  authorization = "NONE"
  api_key_required = true

  request_parameters = {
    "method.request.header.Content-Type" = true
    "method.request.header.X-Request-ID" = false
    "method.request.header.X-Client-Version" = false
  }

  request_models = {
    "application/json" = aws_api_gateway_model.collect_request_model.name
  }

  request_validator_id = aws_api_gateway_request_validator.collect_validator.id
}

# POST /enrich method with Phase 8D enhancements
resource "aws_api_gateway_method" "enrich_post" {
  rest_api_id   = aws_api_gateway_rest_api.threat_intel_api.id
  resource_id   = aws_api_gateway_resource.enrich.id
  http_method   = "POST"
  authorization = "NONE"
  api_key_required = true

  request_parameters = {
    "method.request.header.Content-Type" = true
    "method.request.header.X-Request-ID" = false
    "method.request.header.X-Client-Version" = false
  }

  request_models = {
    "application/json" = aws_api_gateway_model.enrich_request_model.name
  }

  request_validator_id = aws_api_gateway_request_validator.enrich_validator.id
}

# GET /search method with Phase 8D enhancements
resource "aws_api_gateway_method" "search_get" {
  rest_api_id   = aws_api_gateway_rest_api.threat_intel_api.id
  resource_id   = aws_api_gateway_resource.search.id
  http_method   = "GET"
  authorization = "NONE"
  api_key_required = true

  request_parameters = {
    "method.request.querystring.query"        = false
    "method.request.querystring.limit"        = false
    "method.request.querystring.from_date"    = false
    "method.request.querystring.to_date"      = false
    "method.request.querystring.cursor"       = false
    "method.request.querystring.sort_by"      = false
    "method.request.querystring.include_enrichment" = false
    "method.request.header.X-Request-ID"      = false
    "method.request.header.X-Client-Version"  = false
  }

  request_validator_id = aws_api_gateway_request_validator.search_validator.id
}

# =============================================================================
# Lambda Integrations
# =============================================================================

# Lambda integration for /collect
resource "aws_api_gateway_integration" "collect_integration" {
  rest_api_id = aws_api_gateway_rest_api.threat_intel_api.id
  resource_id = aws_api_gateway_resource.collect.id
  http_method = aws_api_gateway_method.collect_post.http_method

  integration_http_method = "POST"
  type                   = "AWS_PROXY"
  uri                    = var.lambda_invoke_arns["collector"]

  depends_on = [aws_api_gateway_method.collect_post]
}

# Lambda integration for /enrich
resource "aws_api_gateway_integration" "enrich_integration" {
  rest_api_id = aws_api_gateway_rest_api.threat_intel_api.id
  resource_id = aws_api_gateway_resource.enrich.id
  http_method = aws_api_gateway_method.enrich_post.http_method

  integration_http_method = "POST"
  type                   = "AWS_PROXY"
  uri                    = var.lambda_invoke_arns["enrichment"]

  depends_on = [aws_api_gateway_method.enrich_post]
}

# Lambda integration for /search
resource "aws_api_gateway_integration" "search_integration" {
  rest_api_id = aws_api_gateway_rest_api.threat_intel_api.id
  resource_id = aws_api_gateway_resource.search.id
  http_method = aws_api_gateway_method.search_get.http_method

  integration_http_method = "POST"
  type                   = "AWS_PROXY"
  uri                    = var.lambda_invoke_arns["processor"]

  depends_on = [aws_api_gateway_method.search_get]
}

# =============================================================================
# Phase 8D Enhancements: Method Responses and Response Transformation
# =============================================================================

# Method responses for /collect
resource "aws_api_gateway_method_response" "collect_200" {
  rest_api_id = aws_api_gateway_rest_api.threat_intel_api.id
  resource_id = aws_api_gateway_resource.collect.id
  http_method = aws_api_gateway_method.collect_post.http_method
  status_code = "200"

  response_parameters = {
    "method.response.header.Access-Control-Allow-Origin" = true
    "method.response.header.X-Request-ID" = true
    "method.response.header.X-Response-Time" = true
  }

  response_models = {
    "application/json" = aws_api_gateway_model.search_response_model.name
  }
}

resource "aws_api_gateway_method_response" "collect_400" {
  rest_api_id = aws_api_gateway_rest_api.threat_intel_api.id
  resource_id = aws_api_gateway_resource.collect.id
  http_method = aws_api_gateway_method.collect_post.http_method
  status_code = "400"

  response_parameters = {
    "method.response.header.Access-Control-Allow-Origin" = true
    "method.response.header.X-Request-ID" = true
  }

  response_models = {
    "application/json" = aws_api_gateway_model.error_response_model.name
  }
}

resource "aws_api_gateway_method_response" "collect_429" {
  rest_api_id = aws_api_gateway_rest_api.threat_intel_api.id
  resource_id = aws_api_gateway_resource.collect.id
  http_method = aws_api_gateway_method.collect_post.http_method
  status_code = "429"

  response_parameters = {
    "method.response.header.Access-Control-Allow-Origin" = true
    "method.response.header.X-Request-ID" = true
    "method.response.header.Retry-After" = true
  }

  response_models = {
    "application/json" = aws_api_gateway_model.error_response_model.name
  }
}

resource "aws_api_gateway_method_response" "collect_500" {
  rest_api_id = aws_api_gateway_rest_api.threat_intel_api.id
  resource_id = aws_api_gateway_resource.collect.id
  http_method = aws_api_gateway_method.collect_post.http_method
  status_code = "500"

  response_parameters = {
    "method.response.header.Access-Control-Allow-Origin" = true
    "method.response.header.X-Request-ID" = true
  }

  response_models = {
    "application/json" = aws_api_gateway_model.error_response_model.name
  }
}

# Method responses for /enrich
resource "aws_api_gateway_method_response" "enrich_200" {
  rest_api_id = aws_api_gateway_rest_api.threat_intel_api.id
  resource_id = aws_api_gateway_resource.enrich.id
  http_method = aws_api_gateway_method.enrich_post.http_method
  status_code = "200"

  response_parameters = {
    "method.response.header.Access-Control-Allow-Origin" = true
    "method.response.header.X-Request-ID" = true
    "method.response.header.X-Response-Time" = true
  }

  response_models = {
    "application/json" = aws_api_gateway_model.search_response_model.name
  }
}

resource "aws_api_gateway_method_response" "enrich_400" {
  rest_api_id = aws_api_gateway_rest_api.threat_intel_api.id
  resource_id = aws_api_gateway_resource.enrich.id
  http_method = aws_api_gateway_method.enrich_post.http_method
  status_code = "400"

  response_parameters = {
    "method.response.header.Access-Control-Allow-Origin" = true
    "method.response.header.X-Request-ID" = true
  }

  response_models = {
    "application/json" = aws_api_gateway_model.error_response_model.name
  }
}

resource "aws_api_gateway_method_response" "enrich_429" {
  rest_api_id = aws_api_gateway_rest_api.threat_intel_api.id
  resource_id = aws_api_gateway_resource.enrich.id
  http_method = aws_api_gateway_method.enrich_post.http_method
  status_code = "429"

  response_parameters = {
    "method.response.header.Access-Control-Allow-Origin" = true
    "method.response.header.X-Request-ID" = true
    "method.response.header.Retry-After" = true
  }

  response_models = {
    "application/json" = aws_api_gateway_model.error_response_model.name
  }
}

resource "aws_api_gateway_method_response" "enrich_500" {
  rest_api_id = aws_api_gateway_rest_api.threat_intel_api.id
  resource_id = aws_api_gateway_resource.enrich.id
  http_method = aws_api_gateway_method.enrich_post.http_method
  status_code = "500"

  response_parameters = {
    "method.response.header.Access-Control-Allow-Origin" = true
    "method.response.header.X-Request-ID" = true
  }

  response_models = {
    "application/json" = aws_api_gateway_model.error_response_model.name
  }
}

# Method responses for /search
resource "aws_api_gateway_method_response" "search_200" {
  rest_api_id = aws_api_gateway_rest_api.threat_intel_api.id
  resource_id = aws_api_gateway_resource.search.id
  http_method = aws_api_gateway_method.search_get.http_method
  status_code = "200"

  response_parameters = {
    "method.response.header.Access-Control-Allow-Origin" = true
    "method.response.header.X-Request-ID" = true
    "method.response.header.X-Response-Time" = true
    "method.response.header.X-Cache-Status" = true
  }

  response_models = {
    "application/json" = aws_api_gateway_model.search_response_model.name
  }
}

resource "aws_api_gateway_method_response" "search_400" {
  rest_api_id = aws_api_gateway_rest_api.threat_intel_api.id
  resource_id = aws_api_gateway_resource.search.id
  http_method = aws_api_gateway_method.search_get.http_method
  status_code = "400"

  response_parameters = {
    "method.response.header.Access-Control-Allow-Origin" = true
    "method.response.header.X-Request-ID" = true
  }

  response_models = {
    "application/json" = aws_api_gateway_model.error_response_model.name
  }
}

resource "aws_api_gateway_method_response" "search_429" {
  rest_api_id = aws_api_gateway_rest_api.threat_intel_api.id
  resource_id = aws_api_gateway_resource.search.id
  http_method = aws_api_gateway_method.search_get.http_method
  status_code = "429"

  response_parameters = {
    "method.response.header.Access-Control-Allow-Origin" = true
    "method.response.header.X-Request-ID" = true
    "method.response.header.Retry-After" = true
  }

  response_models = {
    "application/json" = aws_api_gateway_model.error_response_model.name
  }
}

resource "aws_api_gateway_method_response" "search_500" {
  rest_api_id = aws_api_gateway_rest_api.threat_intel_api.id
  resource_id = aws_api_gateway_resource.search.id
  http_method = aws_api_gateway_method.search_get.http_method
  status_code = "500"

  response_parameters = {
    "method.response.header.Access-Control-Allow-Origin" = true
    "method.response.header.X-Request-ID" = true
  }

  response_models = {
    "application/json" = aws_api_gateway_model.error_response_model.name
  }
}

# =============================================================================
# CORS Configuration (if enabled)
# =============================================================================

# CORS for /collect
resource "aws_api_gateway_method" "collect_options" {
  count         = var.enable_cors ? 1 : 0
  rest_api_id   = aws_api_gateway_rest_api.threat_intel_api.id
  resource_id   = aws_api_gateway_resource.collect.id
  http_method   = "OPTIONS"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "collect_options_integration" {
  count       = var.enable_cors ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.threat_intel_api.id
  resource_id = aws_api_gateway_resource.collect.id
  http_method = aws_api_gateway_method.collect_options[0].http_method

  type = "MOCK"

  request_templates = {
    "application/json" = "{\"statusCode\": 200}"
  }
}

resource "aws_api_gateway_method_response" "collect_options_response" {
  count       = var.enable_cors ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.threat_intel_api.id
  resource_id = aws_api_gateway_resource.collect.id
  http_method = aws_api_gateway_method.collect_options[0].http_method
  status_code = "200"

  response_parameters = {
    "method.response.header.Access-Control-Allow-Headers" = true
    "method.response.header.Access-Control-Allow-Methods" = true
    "method.response.header.Access-Control-Allow-Origin"  = true
  }
}

resource "aws_api_gateway_integration_response" "collect_options_integration_response" {
  count       = var.enable_cors ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.threat_intel_api.id
  resource_id = aws_api_gateway_resource.collect.id
  http_method = aws_api_gateway_method.collect_options[0].http_method
  status_code = aws_api_gateway_method_response.collect_options_response[0].status_code

  response_parameters = {
    "method.response.header.Access-Control-Allow-Headers" = "'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token'"
    "method.response.header.Access-Control-Allow-Methods" = "'POST,OPTIONS'"
    "method.response.header.Access-Control-Allow-Origin"  = "'*'"
  }
}

# CORS for /search
resource "aws_api_gateway_method" "search_options" {
  count         = var.enable_cors ? 1 : 0
  rest_api_id   = aws_api_gateway_rest_api.threat_intel_api.id
  resource_id   = aws_api_gateway_resource.search.id
  http_method   = "OPTIONS"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "search_options_integration" {
  count       = var.enable_cors ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.threat_intel_api.id
  resource_id = aws_api_gateway_resource.search.id
  http_method = aws_api_gateway_method.search_options[0].http_method

  type = "MOCK"

  request_templates = {
    "application/json" = "{\"statusCode\": 200}"
  }
}

resource "aws_api_gateway_method_response" "search_options_response" {
  count       = var.enable_cors ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.threat_intel_api.id
  resource_id = aws_api_gateway_resource.search.id
  http_method = aws_api_gateway_method.search_options[0].http_method
  status_code = "200"

  response_parameters = {
    "method.response.header.Access-Control-Allow-Headers" = true
    "method.response.header.Access-Control-Allow-Methods" = true
    "method.response.header.Access-Control-Allow-Origin"  = true
  }
}

resource "aws_api_gateway_integration_response" "search_options_integration_response" {
  count       = var.enable_cors ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.threat_intel_api.id
  resource_id = aws_api_gateway_resource.search.id
  http_method = aws_api_gateway_method.search_options[0].http_method
  status_code = aws_api_gateway_method_response.search_options_response[0].status_code

  response_parameters = {
    "method.response.header.Access-Control-Allow-Headers" = "'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token'"
    "method.response.header.Access-Control-Allow-Methods" = "'GET,OPTIONS'"
    "method.response.header.Access-Control-Allow-Origin"  = "'*'"
  }
}

# CORS for /enrich
resource "aws_api_gateway_method" "enrich_options" {
  count         = var.enable_cors ? 1 : 0
  rest_api_id   = aws_api_gateway_rest_api.threat_intel_api.id
  resource_id   = aws_api_gateway_resource.enrich.id
  http_method   = "OPTIONS"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "enrich_options_integration" {
  count       = var.enable_cors ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.threat_intel_api.id
  resource_id = aws_api_gateway_resource.enrich.id
  http_method = aws_api_gateway_method.enrich_options[0].http_method

  type = "MOCK"

  request_templates = {
    "application/json" = "{\"statusCode\": 200}"
  }
}

resource "aws_api_gateway_method_response" "enrich_options_response" {
  count       = var.enable_cors ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.threat_intel_api.id
  resource_id = aws_api_gateway_resource.enrich.id
  http_method = aws_api_gateway_method.enrich_options[0].http_method
  status_code = "200"

  response_parameters = {
    "method.response.header.Access-Control-Allow-Headers" = true
    "method.response.header.Access-Control-Allow-Methods" = true
    "method.response.header.Access-Control-Allow-Origin"  = true
  }
}

resource "aws_api_gateway_integration_response" "enrich_options_integration_response" {
  count       = var.enable_cors ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.threat_intel_api.id
  resource_id = aws_api_gateway_resource.enrich.id
  http_method = aws_api_gateway_method.enrich_options[0].http_method
  status_code = aws_api_gateway_method_response.enrich_options_response[0].status_code

  response_parameters = {
    "method.response.header.Access-Control-Allow-Headers" = "'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token'"
    "method.response.header.Access-Control-Allow-Methods" = "'POST,OPTIONS'"
    "method.response.header.Access-Control-Allow-Origin"  = "'*'"
  }
}

# =============================================================================
# API Gateway Lambda Permissions
# =============================================================================

resource "aws_lambda_permission" "allow_api_gateway_collect" {
  statement_id  = "AllowExecutionFromAPIGateway"
  action        = "lambda:InvokeFunction"
  function_name = var.lambda_function_names["collector"]
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.threat_intel_api.execution_arn}/*/*"
}

resource "aws_lambda_permission" "allow_api_gateway_enrich" {
  statement_id  = "AllowExecutionFromAPIGateway"
  action        = "lambda:InvokeFunction"
  function_name = var.lambda_function_names["enrichment"]
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.threat_intel_api.execution_arn}/*/*"
}

resource "aws_lambda_permission" "allow_api_gateway_search" {
  statement_id  = "AllowExecutionFromAPIGateway"
  action        = "lambda:InvokeFunction"
  function_name = var.lambda_function_names["processor"]
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.threat_intel_api.execution_arn}/*/*"
}

# =============================================================================
# API Gateway Deployment
# =============================================================================

resource "aws_api_gateway_deployment" "main" {
  rest_api_id = aws_api_gateway_rest_api.threat_intel_api.id

  triggers = {
    redeployment = sha1(jsonencode([
      aws_api_gateway_resource.collect.id,
      aws_api_gateway_resource.enrich.id,
      aws_api_gateway_resource.search.id,
      aws_api_gateway_method.collect_post.id,
      aws_api_gateway_method.enrich_post.id,
      aws_api_gateway_method.search_get.id,
      aws_api_gateway_integration.collect_integration.id,
      aws_api_gateway_integration.enrich_integration.id,
      aws_api_gateway_integration.search_integration.id,
      # CORS methods for redeployment
      var.enable_cors ? aws_api_gateway_method.collect_options[0].id : "",
      var.enable_cors ? aws_api_gateway_method.search_options[0].id : "",
      var.enable_cors ? aws_api_gateway_method.enrich_options[0].id : "",
    ]))
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_api_gateway_stage" "main" {
  deployment_id = aws_api_gateway_deployment.main.id
  rest_api_id   = aws_api_gateway_rest_api.threat_intel_api.id
  stage_name    = var.environment

  description = "Deployment stage for ${var.environment} environment"

  xray_tracing_enabled = var.environment == "prod" ? true : false

  tags = {
    Name        = "${var.project_name}-api-stage-${var.environment}"
    Environment = var.environment
  }
}

# =============================================================================
# API Gateway Usage Plan & API Key
# =============================================================================

resource "aws_api_gateway_usage_plan" "main" {
  name         = "${var.project_name}-usage-plan-${var.environment}"
  description  = "Usage plan for ${var.project_name} API - ${var.environment}"

  api_stages {
    api_id = aws_api_gateway_rest_api.threat_intel_api.id
    stage  = aws_api_gateway_stage.main.stage_name
  }

  quota_settings {
    limit  = var.api_usage_quota_limit
    period = "MONTH"
  }

  throttle_settings {
    rate_limit  = var.api_throttle_rate_limit
    burst_limit = var.api_throttle_burst_limit
  }

  tags = {
    Name        = "${var.project_name}-usage-plan-${var.environment}"
    Environment = var.environment
  }
}

resource "aws_api_gateway_api_key" "main" {
  name        = "${var.project_name}-api-key-${var.environment}"
  description = "API key for ${var.project_name} - ${var.environment}"
  enabled     = true

  tags = {
    Name        = "${var.project_name}-api-key-${var.environment}"
    Environment = var.environment
  }
}

resource "aws_api_gateway_usage_plan_key" "main" {
  key_id        = aws_api_gateway_api_key.main.id
  key_type      = "API_KEY"
  usage_plan_id = aws_api_gateway_usage_plan.main.id
}

# =============================================================================
# CloudFront Distribution for Frontend
# =============================================================================

# Origin Access Control for S3
resource "aws_cloudfront_origin_access_control" "frontend" {
  name                              = "${var.project_name}-oac-${var.environment}"
  description                       = "OAC for ${var.project_name} frontend bucket"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

# CloudFront distribution
resource "aws_cloudfront_distribution" "frontend" {
  origin {
    domain_name              = var.frontend_bucket_domain_name
    origin_access_control_id = aws_cloudfront_origin_access_control.frontend.id
    origin_id                = "S3-${var.frontend_bucket_name}"
  }

  enabled             = true
  is_ipv6_enabled     = true
  default_root_object = "index.html"
  price_class         = var.cloudfront_price_class

  # Cache behavior for static content
  default_cache_behavior {
    allowed_methods        = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "S3-${var.frontend_bucket_name}"
    compress               = true
    viewer_protocol_policy = "redirect-to-https"

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }

    min_ttl     = 0
    default_ttl = 3600  # 1 hour
    max_ttl     = 86400 # 24 hours
  }

  # Cache behavior for API calls (no caching)
  ordered_cache_behavior {
    path_pattern           = "/api/*"
    allowed_methods        = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "S3-${var.frontend_bucket_name}"
    compress               = true
    viewer_protocol_policy = "redirect-to-https"

    forwarded_values {
      query_string = true
      headers      = ["Authorization", "CloudFront-Forwarded-Proto"]
      cookies {
        forward = "none"
      }
    }

    min_ttl     = 0
    default_ttl = 0
    max_ttl     = 0
  }

  # Geographic restrictions (optional cost optimization)
  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  # SSL certificate
  viewer_certificate {
    cloudfront_default_certificate = true
  }

  # Custom error pages
  custom_error_response {
    error_code            = 403
    response_code         = 200
    response_page_path    = "/index.html"
    error_caching_min_ttl = 0
  }

  custom_error_response {
    error_code            = 404
    response_code         = 200
    response_page_path    = "/index.html"
    error_caching_min_ttl = 0
  }

  tags = {
    Name        = "${var.project_name}-cloudfront-${var.environment}"
    Environment = var.environment
  }
}

# =============================================================================
# CloudWatch Logging (Optional)
# =============================================================================

resource "aws_api_gateway_method_settings" "main" {
  count       = var.enable_api_gateway_logging ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.threat_intel_api.id
  stage_name  = aws_api_gateway_stage.main.stage_name
  method_path = "*/*"

  settings {
    metrics_enabled    = true
    logging_level     = "INFO"
    data_trace_enabled = var.environment == "dev" ? true : false

    throttling_rate_limit  = var.api_throttle_rate_limit
    throttling_burst_limit = var.api_throttle_burst_limit
  }
}