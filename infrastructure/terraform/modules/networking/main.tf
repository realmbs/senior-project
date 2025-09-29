# =============================================================================
# Networking Module - API Gateway & CloudFront Distribution
# =============================================================================
# Creates REST API Gateway with Lambda integrations and CloudFront distribution
# for static content delivery with cost-optimized regional deployment

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

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
# API Gateway Methods
# =============================================================================

# POST /collect method
resource "aws_api_gateway_method" "collect_post" {
  rest_api_id   = aws_api_gateway_rest_api.threat_intel_api.id
  resource_id   = aws_api_gateway_resource.collect.id
  http_method   = "POST"
  authorization = "NONE"
  api_key_required = true

  request_parameters = {
    "method.request.header.Content-Type" = true
  }
}

# POST /enrich method
resource "aws_api_gateway_method" "enrich_post" {
  rest_api_id   = aws_api_gateway_rest_api.threat_intel_api.id
  resource_id   = aws_api_gateway_resource.enrich.id
  http_method   = "POST"
  authorization = "NONE"
  api_key_required = true

  request_parameters = {
    "method.request.header.Content-Type" = true
  }
}

# GET /search method
resource "aws_api_gateway_method" "search_get" {
  rest_api_id   = aws_api_gateway_rest_api.threat_intel_api.id
  resource_id   = aws_api_gateway_resource.search.id
  http_method   = "GET"
  authorization = "NONE"
  api_key_required = true

  request_parameters = {
    "method.request.querystring.query"     = false
    "method.request.querystring.limit"     = false
    "method.request.querystring.from_date" = false
    "method.request.querystring.to_date"   = false
  }
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