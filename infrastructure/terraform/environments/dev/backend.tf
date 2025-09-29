# =============================================================================
# Terraform Backend Configuration for Development Environment
# =============================================================================
# This file configures where Terraform stores its state file
# For development, we use local backend for simplicity and cost savings

# Local Backend Configuration (Development Only)
# In production environments, use S3 backend with DynamoDB locking
terraform {
  backend "local" {
    path = "terraform.tfstate"
  }
}

# =============================================================================
# Alternative S3 Backend Configuration (Commented for Future Use)
# =============================================================================
# Uncomment and configure for shared team development or production use
#
# terraform {
#   backend "s3" {
#     bucket         = "threat-intel-platform-terraform-state-dev"
#     key            = "environments/dev/terraform.tfstate"
#     region         = "us-east-1"
#     dynamodb_table = "threat-intel-platform-terraform-locks"
#     encrypt        = true
#   }
# }
#
# Prerequisites for S3 backend:
# 1. Create S3 bucket for state storage
# 2. Create DynamoDB table for state locking
# 3. Configure appropriate IAM permissions
#
# Benefits of S3 backend:
# - Shared state for team collaboration
# - State locking to prevent concurrent modifications
# - Versioning and backup capabilities
# - Remote state for CI/CD pipelines