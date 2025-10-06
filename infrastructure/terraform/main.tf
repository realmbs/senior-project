terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}

module "security" {
  source = "./modules/security"

  environment       = var.environment
  project_name      = var.project_name
  otx_api_key      = var.otx_api_key
  shodan_api_key   = var.shodan_api_key
  abuse_ch_api_key = var.abuse_ch_api_key

  log_retention_days = var.log_retention_days
}

module "database" {
  source = "./modules/database"

  environment  = var.environment
  project_name = var.project_name
}

module "storage" {
  source = "./modules/storage"

  environment  = var.environment
  project_name = var.project_name
}

module "compute" {
  source = "./modules/compute"

  environment  = var.environment
  project_name = var.project_name

  lambda_execution_role_arn = module.security.lambda_role_arn
  api_keys_secret_arn      = module.security.api_keys_secret_arn

  threat_intel_table_name = module.database.threat_intel_table_name
  dedup_table_name       = module.database.dedup_table_name
  enrichment_cache_table_name = module.database.enrichment_cache_table_name

  raw_data_bucket_name = module.storage.raw_data_bucket_name
  processed_data_bucket_name = module.storage.processed_data_bucket_name

  depends_on = [module.security, module.database, module.storage]
}

module "networking" {
  source = "./modules/networking"

  environment  = var.environment
  project_name = var.project_name

  lambda_function_names = module.compute.lambda_function_names
  lambda_invoke_arns    = module.compute.lambda_invoke_arns

  frontend_bucket_name        = module.storage.frontend_bucket_name
  frontend_bucket_domain_name = module.storage.frontend_bucket_domain_name

  depends_on = [module.compute]
}