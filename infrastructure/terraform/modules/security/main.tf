# =============================================================================
# Security Module - IAM Roles, Policies, Secrets Manager, and CloudWatch Logs
# =============================================================================
# This module creates the security foundation for the threat intelligence platform:
# - Lambda execution role with least-privilege IAM policies
# - Secrets Manager for secure API key storage
# - CloudWatch log groups with cost-optimized retention
# - API Gateway API key for access control

# -----------------------------------------------------------------------------
# Lambda Execution Role
# -----------------------------------------------------------------------------
# Primary IAM role that Lambda functions assume for execution
# Grants minimal permissions required for threat intelligence operations
resource "aws_iam_role" "lambda_execution_role" {
  name = "${var.project_name}-lambda-role-${var.environment}"

  # Trust policy allowing Lambda service to assume this role
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name        = "${var.project_name}-lambda-role"
    Environment = var.environment
    Purpose     = "Lambda execution role for threat intelligence platform"
  }
}

# -----------------------------------------------------------------------------
# Lambda Basic Execution Policy Attachment
# -----------------------------------------------------------------------------
# AWS managed policy providing basic Lambda execution permissions
# Includes CloudWatch Logs write access and VPC network interface management
resource "aws_iam_role_policy_attachment" "lambda_basic_execution" {
  role       = aws_iam_role.lambda_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# -----------------------------------------------------------------------------
# DynamoDB Access Policy
# -----------------------------------------------------------------------------
# Custom policy granting Lambda functions access to DynamoDB tables
# Scoped to threat intelligence, deduplication, and enrichment cache tables
resource "aws_iam_policy" "dynamodb_access" {
  name        = "${var.project_name}-dynamodb-policy-${var.environment}"
  description = "DynamoDB access policy for threat intelligence Lambda functions"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:Query",
          "dynamodb:Scan",
          "dynamodb:UpdateItem",
          "dynamodb:DeleteItem",
          "dynamodb:BatchGetItem",
          "dynamodb:BatchWriteItem"
        ]
        # Note: Table ARNs will be passed from database module
        # Using wildcard for now, will be restricted in production
        Resource = [
          "arn:aws:dynamodb:*:*:table/${var.project_name}-*",
          "arn:aws:dynamodb:*:*:table/${var.project_name}-*/index/*"
        ]
      }
    ]
  })

  tags = {
    Name        = "${var.project_name}-dynamodb-policy"
    Environment = var.environment
  }
}

# Attach DynamoDB policy to Lambda execution role
resource "aws_iam_role_policy_attachment" "lambda_dynamodb_access" {
  role       = aws_iam_role.lambda_execution_role.name
  policy_arn = aws_iam_policy.dynamodb_access.arn
}

# -----------------------------------------------------------------------------
# S3 Access Policy
# -----------------------------------------------------------------------------
# Policy granting Lambda functions access to S3 buckets for raw data storage
# Allows read/write operations on threat intelligence data archives
resource "aws_iam_policy" "s3_access" {
  name        = "${var.project_name}-s3-policy-${var.environment}"
  description = "S3 access policy for threat intelligence data storage"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket"
        ]
        # Note: Bucket ARNs will be passed from storage module
        # Using project-specific naming pattern for security
        Resource = [
          "arn:aws:s3:::${var.project_name}-*",
          "arn:aws:s3:::${var.project_name}-*/*"
        ]
      }
    ]
  })

  tags = {
    Name        = "${var.project_name}-s3-policy"
    Environment = var.environment
  }
}

# Attach S3 policy to Lambda execution role
resource "aws_iam_role_policy_attachment" "lambda_s3_access" {
  role       = aws_iam_role.lambda_execution_role.name
  policy_arn = aws_iam_policy.s3_access.arn
}

# -----------------------------------------------------------------------------
# Secrets Manager Access Policy
# -----------------------------------------------------------------------------
# Policy allowing Lambda functions to retrieve API keys from Secrets Manager
# Restricted to the specific secret containing threat intelligence API keys
resource "aws_iam_policy" "secrets_manager_access" {
  name        = "${var.project_name}-secrets-policy-${var.environment}"
  description = "Secrets Manager access policy for API key retrieval"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Resource = aws_secretsmanager_secret.api_keys.arn
      }
    ]
  })

  tags = {
    Name        = "${var.project_name}-secrets-policy"
    Environment = var.environment
  }
}

# Attach Secrets Manager policy to Lambda execution role
resource "aws_iam_role_policy_attachment" "lambda_secrets_access" {
  role       = aws_iam_role.lambda_execution_role.name
  policy_arn = aws_iam_policy.secrets_manager_access.arn
}

# -----------------------------------------------------------------------------
# Secrets Manager Secret for API Keys
# -----------------------------------------------------------------------------
# Secure storage for third-party API keys (OTX, Shodan, Abuse.ch)
# Encrypted using AWS managed KMS key for Secrets Manager
resource "aws_secretsmanager_secret" "api_keys" {
  name        = "${var.project_name}/api-keys/${var.environment}"
  description = "API keys for threat intelligence sources (OTX, Shodan, Abuse.ch)"

  # Use AWS managed KMS key for Secrets Manager (cost-effective)
  kms_key_id = "alias/aws/secretsmanager"

  # Automatic rotation disabled for external API keys
  # Manual rotation should be performed when keys are compromised

  tags = {
    Name        = "${var.project_name}-api-keys"
    Environment = var.environment
    Purpose     = "Threat intelligence source API keys"
  }
}

# -----------------------------------------------------------------------------
# Secrets Manager Secret Version
# -----------------------------------------------------------------------------
# Stores the actual API key values in JSON format
# Values are passed as sensitive variables from the calling module
resource "aws_secretsmanager_secret_version" "api_keys" {
  secret_id = aws_secretsmanager_secret.api_keys.id

  # JSON structure for API keys - Lambda functions parse this format
  secret_string = jsonencode({
    otx_api_key      = var.otx_api_key
    shodan_api_key   = var.shodan_api_key
    abuse_ch_api_key = var.abuse_ch_api_key
  })

  # Lifecycle rule to prevent accidental destruction of secret values
  lifecycle {
    ignore_changes = [secret_string]
  }
}

# -----------------------------------------------------------------------------
# API Gateway API Key
# -----------------------------------------------------------------------------
# API key for controlling access to API Gateway endpoints
# Used in conjunction with usage plans for rate limiting and quotas
resource "aws_api_gateway_api_key" "threat_intel_key" {
  name        = "${var.project_name}-api-key-${var.environment}"
  description = "API key for threat intelligence platform access"
  enabled     = true

  tags = {
    Name        = "${var.project_name}-api-key"
    Environment = var.environment
    Purpose     = "API Gateway access control"
  }
}

# -----------------------------------------------------------------------------
# CloudWatch Log Groups
# -----------------------------------------------------------------------------
# Centralized logging for Lambda functions with cost-optimized retention
# Separate log groups for different function types enable granular monitoring

# Log group for threat intelligence collector functions
resource "aws_cloudwatch_log_group" "collector_logs" {
  name              = "/aws/lambda/${var.project_name}-collector-${var.environment}"
  retention_in_days = var.log_retention_days

  tags = {
    Name         = "${var.project_name}-collector-logs"
    Environment  = var.environment
    FunctionType = "collector"
  }
}

# Log group for threat intelligence processor functions
resource "aws_cloudwatch_log_group" "processor_logs" {
  name              = "/aws/lambda/${var.project_name}-processor-${var.environment}"
  retention_in_days = var.log_retention_days

  tags = {
    Name         = "${var.project_name}-processor-logs"
    Environment  = var.environment
    FunctionType = "processor"
  }
}

# Log group for OSINT enrichment functions
resource "aws_cloudwatch_log_group" "enrichment_logs" {
  name              = "/aws/lambda/${var.project_name}-enrichment-${var.environment}"
  retention_in_days = var.log_retention_days

  tags = {
    Name         = "${var.project_name}-enrichment-logs"
    Environment  = var.environment
    FunctionType = "enrichment"
  }
}