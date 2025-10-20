# =============================================================================
# Compute Module - Lambda Functions for Threat Intelligence Processing
# =============================================================================
# This module creates the compute layer for the threat intelligence platform:
# - Threat intelligence collector Lambda (256MB, 5min timeout)
# - OSINT processor Lambda (512MB for Docker containers)
# - STIX 2.1 compliance handlers
# - Lambda deployment packages with Python dependencies

# -----------------------------------------------------------------------------
# Data Archive for Lambda Deployment Package
# -----------------------------------------------------------------------------
# Creates ZIP archive containing Lambda function code and dependencies
# Automatically detects changes and rebuilds when source code is modified
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../../lambda_functions"
  output_path = "${path.module}/lambda_deployment.zip"

  # Exclude common non-essential files from deployment package
  excludes = [
    "__pycache__",
    "*.pyc",
    "*.pyo",
    ".git*",
    "tests/",
    "*.md"
  ]
}

# -----------------------------------------------------------------------------
# Threat Intelligence Collector Lambda Function
# -----------------------------------------------------------------------------
# Collects threat intelligence from OSINT sources (OTX, Abuse.ch)
# Optimized for cost with 256MB memory and 5-minute timeout
resource "aws_lambda_function" "threat_collector" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "${var.project_name}-threat-collector-${var.environment}"
  role            = var.lambda_execution_role_arn
  handler         = "collector.lambda_handler"
  runtime         = "python3.11"
  timeout         = var.lambda_timeout
  memory_size     = var.collector_memory_size
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

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
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "${var.project_name}-data-processor-${var.environment}"
  role            = var.lambda_execution_role_arn
  handler         = "processor.lambda_handler"
  runtime         = "python3.11"
  timeout         = var.lambda_timeout
  memory_size     = var.processor_memory_size
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

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
# Performs OSINT enrichment using containerized tools (TheHarvester, Shodan)
# Highest memory allocation (1024MB) for Docker container execution
resource "aws_lambda_function" "osint_enrichment" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "${var.project_name}-osint-enrichment-${var.environment}"
  role            = var.lambda_execution_role_arn
  handler         = "enrichment.lambda_handler"
  runtime         = "python3.11"
  timeout         = var.lambda_timeout
  memory_size     = var.enrichment_memory_size
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

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

# =============================================================================
# Phase 8D Enhanced Lambda Functions
# =============================================================================

# -----------------------------------------------------------------------------
# Search Engine Lambda Function
# -----------------------------------------------------------------------------
resource "aws_lambda_function" "search_engine" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "${var.project_name}-search-engine-${var.environment}"
  role            = var.lambda_execution_role_arn
  handler         = "search_engine.lambda_handler"
  runtime         = "python3.11"
  timeout         = var.lambda_timeout
  memory_size     = var.search_memory_size
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      ENVIRONMENT            = var.environment
      THREAT_INTEL_TABLE    = var.threat_intel_table_name
      ENRICHMENT_CACHE_TABLE = var.enrichment_cache_table_name
      DEDUP_TABLE           = var.dedup_table_name
      REDIS_CLUSTER_ENDPOINT = var.redis_cluster_endpoint
      REDIS_PORT            = var.redis_port
      ENABLE_CACHE_COMPRESSION = "true"
      CACHE_KEY_PREFIX      = "${var.project_name}-${var.environment}"
    }
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.lambda_dlq.arn
  }

  tags = {
    Name        = "${var.project_name}-search-engine"
    Environment = var.environment
    Purpose     = "Advanced search engine with fuzzy matching and correlation"
    Runtime     = "python3.11"
    MemorySize  = var.search_memory_size
  }
}

# -----------------------------------------------------------------------------
# Analytics Engine Lambda Function
# -----------------------------------------------------------------------------
resource "aws_lambda_function" "analytics_engine" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "${var.project_name}-analytics-engine-${var.environment}"
  role            = var.lambda_execution_role_arn
  handler         = "analytics_engine.lambda_handler"
  runtime         = "python3.11"
  timeout         = var.analytics_timeout
  memory_size     = var.analytics_memory_size
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      ENVIRONMENT            = var.environment
      THREAT_INTEL_TABLE    = var.threat_intel_table_name
      ENRICHMENT_CACHE_TABLE = var.enrichment_cache_table_name
      PROCESSED_DATA_BUCKET = var.processed_data_bucket_name
      ANALYTICS_CACHE_TABLE = "${var.project_name}-analytics-cache-${var.environment}"
      ENABLE_ANALYTICS_CACHE = "true"
      CACHE_COMPRESSION_ENABLED = "true"
    }
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.lambda_dlq.arn
  }

  tags = {
    Name        = "${var.project_name}-analytics-engine"
    Environment = var.environment
    Purpose     = "Comprehensive threat intelligence analytics and trend analysis"
    Runtime     = "python3.11"
    MemorySize  = var.analytics_memory_size
  }
}

# -----------------------------------------------------------------------------
# Cache Manager Lambda Function
# -----------------------------------------------------------------------------
resource "aws_lambda_function" "cache_manager" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "${var.project_name}-cache-manager-${var.environment}"
  role            = var.lambda_execution_role_arn
  handler         = "cache_manager.lambda_handler"
  runtime         = "python3.11"
  timeout         = 30
  memory_size     = 256
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      ENVIRONMENT              = var.environment
      REDIS_CLUSTER_ENDPOINT   = var.redis_cluster_endpoint
      REDIS_PORT              = var.redis_port
      ENABLE_CACHE_COMPRESSION = "true"
      CACHE_KEY_PREFIX        = "${var.project_name}-${var.environment}"
      REDIS_ENCRYPTION_IN_TRANSIT = "true"
    }
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.lambda_dlq.arn
  }

  tags = {
    Name        = "${var.project_name}-cache-manager"
    Environment = var.environment
    Purpose     = "Intelligent cache management with Redis integration"
    Runtime     = "python3.11"
    MemorySize  = "256"
  }
}

# -----------------------------------------------------------------------------
# Cache Invalidation Service Lambda Function
# -----------------------------------------------------------------------------
resource "aws_lambda_function" "cache_invalidation" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "${var.project_name}-cache-invalidation-${var.environment}"
  role            = var.lambda_execution_role_arn
  handler         = "cache_invalidation_service.lambda_handler"
  runtime         = "python3.11"
  timeout         = 60
  memory_size     = 512
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      ENVIRONMENT         = var.environment
      PROJECT_NAME       = var.project_name
      REDIS_CLUSTER_ENDPOINT = var.redis_cluster_endpoint
      REDIS_PORT         = var.redis_port
      CACHE_KEY_PREFIX   = "${var.project_name}-${var.environment}"
    }
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.lambda_dlq.arn
  }

  tags = {
    Name        = "${var.project_name}-cache-invalidation"
    Environment = var.environment
    Purpose     = "Intelligent cache invalidation with dependency tracking"
    Runtime     = "python3.11"
    MemorySize  = "512"
  }
}

# -----------------------------------------------------------------------------
# Query Optimizer Lambda Function
# -----------------------------------------------------------------------------
resource "aws_lambda_function" "query_optimizer" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "${var.project_name}-query-optimizer-${var.environment}"
  role            = var.lambda_execution_role_arn
  handler         = "query_optimizer.lambda_handler"
  runtime         = "python3.11"
  timeout         = 60
  memory_size     = 512
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      ENVIRONMENT         = var.environment
      THREAT_INTEL_TABLE = var.threat_intel_table_name
      QUERY_METRICS_TABLE = "${var.project_name}-query-metrics-${var.environment}"
    }
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.lambda_dlq.arn
  }

  tags = {
    Name        = "${var.project_name}-query-optimizer"
    Environment = var.environment
    Purpose     = "DynamoDB query optimization and cost analysis"
    Runtime     = "python3.11"
    MemorySize  = "512"
  }
}

# -----------------------------------------------------------------------------
# Performance Metrics Collector Lambda Function
# -----------------------------------------------------------------------------
resource "aws_lambda_function" "performance_metrics" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "${var.project_name}-performance-metrics-${var.environment}"
  role            = var.lambda_execution_role_arn
  handler         = "performance_metrics_collector.lambda_handler"
  runtime         = "python3.11"
  timeout         = 300
  memory_size     = 512
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      ENVIRONMENT         = var.environment
      PROJECT_NAME       = var.project_name
      METRICS_TABLE_NAME = "${var.project_name}-metrics-${var.environment}"
      ALERT_TOPIC_ARN    = var.alert_topic_arn
    }
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.lambda_dlq.arn
  }

  tags = {
    Name        = "${var.project_name}-performance-metrics"
    Environment = var.environment
    Purpose     = "Performance metrics collection and alerting"
    Runtime     = "python3.11"
    MemorySize  = "512"
  }
}

# -----------------------------------------------------------------------------
# Rate Limiting Service Lambda Function
# -----------------------------------------------------------------------------
resource "aws_lambda_function" "rate_limiting" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "${var.project_name}-rate-limiting-${var.environment}"
  role            = var.lambda_execution_role_arn
  handler         = "rate_limiting_service.lambda_handler"
  runtime         = "python3.11"
  timeout         = 30
  memory_size     = 256
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      ENVIRONMENT           = var.environment
      PROJECT_NAME         = var.project_name
      REDIS_CLUSTER_ENDPOINT = var.redis_cluster_endpoint
      REDIS_PORT           = var.redis_port
    }
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.lambda_dlq.arn
  }

  tags = {
    Name        = "${var.project_name}-rate-limiting"
    Environment = var.environment
    Purpose     = "Advanced rate limiting and error handling"
    Runtime     = "python3.11"
    MemorySize  = "256"
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

# Phase 8D Enhanced Lambda Log Groups
resource "aws_cloudwatch_log_group" "search_engine_logs" {
  name              = "/aws/lambda/${aws_lambda_function.search_engine.function_name}"
  retention_in_days = 7
  kms_key_id       = var.cloudwatch_kms_key_arn

  tags = {
    Name        = "${var.project_name}-search-engine-logs"
    Environment = var.environment
    Purpose     = "CloudWatch logs for search engine Lambda"
  }
}

resource "aws_cloudwatch_log_group" "analytics_engine_logs" {
  name              = "/aws/lambda/${aws_lambda_function.analytics_engine.function_name}"
  retention_in_days = 7
  kms_key_id       = var.cloudwatch_kms_key_arn

  tags = {
    Name        = "${var.project_name}-analytics-engine-logs"
    Environment = var.environment
    Purpose     = "CloudWatch logs for analytics engine Lambda"
  }
}

resource "aws_cloudwatch_log_group" "cache_manager_logs" {
  name              = "/aws/lambda/${aws_lambda_function.cache_manager.function_name}"
  retention_in_days = 7
  kms_key_id       = var.cloudwatch_kms_key_arn

  tags = {
    Name        = "${var.project_name}-cache-manager-logs"
    Environment = var.environment
    Purpose     = "CloudWatch logs for cache manager Lambda"
  }
}

resource "aws_cloudwatch_log_group" "cache_invalidation_logs" {
  name              = "/aws/lambda/${aws_lambda_function.cache_invalidation.function_name}"
  retention_in_days = 7
  kms_key_id       = var.cloudwatch_kms_key_arn

  tags = {
    Name        = "${var.project_name}-cache-invalidation-logs"
    Environment = var.environment
    Purpose     = "CloudWatch logs for cache invalidation Lambda"
  }
}

resource "aws_cloudwatch_log_group" "query_optimizer_logs" {
  name              = "/aws/lambda/${aws_lambda_function.query_optimizer.function_name}"
  retention_in_days = 7
  kms_key_id       = var.cloudwatch_kms_key_arn

  tags = {
    Name        = "${var.project_name}-query-optimizer-logs"
    Environment = var.environment
    Purpose     = "CloudWatch logs for query optimizer Lambda"
  }
}

resource "aws_cloudwatch_log_group" "performance_metrics_logs" {
  name              = "/aws/lambda/${aws_lambda_function.performance_metrics.function_name}"
  retention_in_days = 7
  kms_key_id       = var.cloudwatch_kms_key_arn

  tags = {
    Name        = "${var.project_name}-performance-metrics-logs"
    Environment = var.environment
    Purpose     = "CloudWatch logs for performance metrics Lambda"
  }
}

resource "aws_cloudwatch_log_group" "rate_limiting_logs" {
  name              = "/aws/lambda/${aws_lambda_function.rate_limiting.function_name}"
  retention_in_days = 7
  kms_key_id       = var.cloudwatch_kms_key_arn

  tags = {
    Name        = "${var.project_name}-rate-limiting-logs"
    Environment = var.environment
    Purpose     = "CloudWatch logs for rate limiting Lambda"
  }
}