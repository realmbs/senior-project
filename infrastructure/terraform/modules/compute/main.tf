# =============================================================================
# Compute Module - MVP Lambda Functions for Threat Intelligence Processing
# =============================================================================
# This module creates the MVP compute layer for the threat intelligence platform:
# - Threat intelligence collector Lambda (256MB, 5min timeout) - Basic OTX/Abuse.ch collection
# - OSINT processor Lambda (512MB) - Core STIX 2.1 processing with basic search/export
# - OSINT enrichment Lambda (1024MB) - Basic Shodan/DNS/IP geolocation enrichment
# - Lambda deployment packages with minimal Python dependencies (94% size reduction)

# -----------------------------------------------------------------------------
# Data Archive for Lambda Deployment Package - DISABLED
# -----------------------------------------------------------------------------
# Using pre-built optimized lambda_deployment.zip (640KB) instead of dynamic archive
# This avoids the data source rebuilding a larger package from lambda_functions directory
#
# data "archive_file" "lambda_zip" {
#   type        = "zip"
#   source_dir  = "${path.module}/../../lambda_functions"
#   output_path = "${path.module}/lambda_deployment.zip"
#
#   # Exclude common non-essential files from deployment package
#   excludes = [
#     "__pycache__",
#     "*.pyc",
#     "*.pyo",
#     ".git*",
#     "tests/",
#     "*.md"
#   ]
# }

# -----------------------------------------------------------------------------
# Threat Intelligence Collector Lambda Function
# -----------------------------------------------------------------------------
# Collects threat intelligence from OSINT sources (OTX, Abuse.ch)
# Optimized for cost with 256MB memory and 5-minute timeout
resource "aws_lambda_function" "threat_collector" {
  filename         = "${path.module}/lambda_deployment.zip"
  function_name    = "${var.project_name}-threat-collector-${var.environment}"
  role            = var.lambda_execution_role_arn
  handler         = "build_correct.collector.lambda_handler"
  runtime         = "python3.11"
  timeout         = var.lambda_timeout
  memory_size     = var.collector_memory_size
  source_code_hash = filebase64sha256("${path.module}/lambda_deployment.zip")

  # Environment variables for threat intelligence collection
  environment {
    variables = {
      ENVIRONMENT               = var.environment
      SECRETS_MANAGER_ARN      = var.api_keys_secret_arn
      THREAT_INTEL_TABLE       = var.threat_intel_table_name
      DEDUP_TABLE             = var.dedup_table_name
      RAW_DATA_BUCKET         = var.raw_data_bucket_name
      ENABLE_DETAILED_LOGGING = "true"
      STIX_VERSION           = "2.1"
    }
  }

  # Dead letter queue for failed invocations
  dead_letter_config {
    target_arn = aws_sqs_queue.lambda_dlq.arn
  }

  # VPC configuration for secure network access (optional)
  # vpc_config {
  #   subnet_ids         = var.subnet_ids
  #   security_group_ids = var.security_group_ids
  # }

  tags = {
    Name        = "${var.project_name}-threat-collector"
    Environment = var.environment
    Purpose     = "Threat intelligence collection from OSINT sources"
    Runtime     = "python3.11"
    MemorySize  = var.collector_memory_size
  }
}

# -----------------------------------------------------------------------------
# OSINT Data Processor Lambda Function
# -----------------------------------------------------------------------------
# Processes collected threat intelligence data and performs STIX 2.1 compliance
# Higher memory allocation (512MB) for intensive data processing operations
resource "aws_lambda_function" "data_processor" {
  filename         = "${path.module}/lambda_deployment.zip"
  function_name    = "${var.project_name}-data-processor-${var.environment}"
  role            = var.lambda_execution_role_arn
  handler         = "build_correct.processor.lambda_handler"
  runtime         = "python3.11"
  timeout         = var.lambda_timeout
  memory_size     = var.processor_memory_size
  source_code_hash = filebase64sha256("${path.module}/lambda_deployment.zip")

  # Environment variables for data processing
  environment {
    variables = {
      ENVIRONMENT               = var.environment
      SECRETS_MANAGER_ARN      = var.api_keys_secret_arn
      THREAT_INTEL_TABLE       = var.threat_intel_table_name
      DEDUP_TABLE             = var.dedup_table_name
      RAW_DATA_BUCKET         = var.raw_data_bucket_name
      PROCESSED_DATA_BUCKET   = var.processed_data_bucket_name
      ENABLE_DETAILED_LOGGING = "true"
      STIX_VERSION           = "2.1"
      MAX_BATCH_SIZE         = "100"
    }
  }

  # Dead letter queue for failed invocations
  dead_letter_config {
    target_arn = aws_sqs_queue.lambda_dlq.arn
  }

  tags = {
    Name        = "${var.project_name}-data-processor"
    Environment = var.environment
    Purpose     = "STIX 2.1 compliant threat intelligence processing"
    Runtime     = "python3.11"
    MemorySize  = var.processor_memory_size
  }
}

# -----------------------------------------------------------------------------
# OSINT Enrichment Lambda Function
# -----------------------------------------------------------------------------
# Performs basic OSINT enrichment using Shodan API, IP geolocation, and DNS analysis
# Higher memory allocation (1024MB) for network requests and data processing
resource "aws_lambda_function" "osint_enrichment" {
  filename         = "${path.module}/lambda_deployment.zip"
  function_name    = "${var.project_name}-osint-enrichment-${var.environment}"
  role            = var.lambda_execution_role_arn
  handler         = "build_correct.enrichment.lambda_handler"
  runtime         = "python3.11"
  timeout         = var.lambda_timeout
  memory_size     = var.enrichment_memory_size
  source_code_hash = filebase64sha256("${path.module}/lambda_deployment.zip")

  # Environment variables for OSINT enrichment
  environment {
    variables = {
      ENVIRONMENT               = var.environment
      SECRETS_MANAGER_ARN      = var.api_keys_secret_arn
      ENRICHMENT_CACHE_TABLE   = var.enrichment_cache_table_name
      RAW_DATA_BUCKET         = var.raw_data_bucket_name
      ENABLE_DETAILED_LOGGING = "true"
      ENRICHMENT_TTL_DAYS     = "7"
      MAX_CONCURRENT_REQUESTS = "5"
    }
  }

  # Dead letter queue for failed invocations
  dead_letter_config {
    target_arn = aws_sqs_queue.lambda_dlq.arn
  }

  tags = {
    Name        = "${var.project_name}-osint-enrichment"
    Environment = var.environment
    Purpose     = "OSINT enrichment using containerized tools"
    Runtime     = "python3.11"
    MemorySize  = var.enrichment_memory_size
  }
}


# -----------------------------------------------------------------------------
# Lambda Dead Letter Queue
# -----------------------------------------------------------------------------
# SQS queue for capturing failed Lambda invocations
# Enables debugging and retry mechanisms for failed threat intelligence processing
resource "aws_sqs_queue" "lambda_dlq" {
  name                      = "${var.project_name}-lambda-dlq-${var.environment}"
  message_retention_seconds = 1209600  # 14 days
  visibility_timeout_seconds = 300      # 5 minutes

  # Enable server-side encryption
  kms_master_key_id = "alias/aws/sqs"

  tags = {
    Name        = "${var.project_name}-lambda-dlq"
    Environment = var.environment
    Purpose     = "Dead letter queue for failed Lambda invocations"
  }
}

# -----------------------------------------------------------------------------
# CloudWatch Log Groups for Lambda Functions
# -----------------------------------------------------------------------------
# Dedicated log groups with cost-optimized 7-day retention
# Provides centralized logging for debugging and monitoring

resource "aws_cloudwatch_log_group" "threat_collector_logs" {
  name              = "/aws/lambda/${aws_lambda_function.threat_collector.function_name}"
  retention_in_days = 7
  kms_key_id       = var.cloudwatch_kms_key_arn

  tags = {
    Name        = "${var.project_name}-threat-collector-logs"
    Environment = var.environment
    Purpose     = "CloudWatch logs for threat collector Lambda"
  }
}

resource "aws_cloudwatch_log_group" "data_processor_logs" {
  name              = "/aws/lambda/${aws_lambda_function.data_processor.function_name}"
  retention_in_days = 7
  kms_key_id       = var.cloudwatch_kms_key_arn

  tags = {
    Name        = "${var.project_name}-data-processor-logs"
    Environment = var.environment
    Purpose     = "CloudWatch logs for data processor Lambda"
  }
}

resource "aws_cloudwatch_log_group" "osint_enrichment_logs" {
  name              = "/aws/lambda/${aws_lambda_function.osint_enrichment.function_name}"
  retention_in_days = 7
  kms_key_id       = var.cloudwatch_kms_key_arn

  tags = {
    Name        = "${var.project_name}-osint-enrichment-logs"
    Environment = var.environment
    Purpose     = "CloudWatch logs for OSINT enrichment Lambda"
  }
}

