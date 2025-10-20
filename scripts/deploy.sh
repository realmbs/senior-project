#!/bin/bash

# =============================================================================
# Threat Intelligence Platform Deployment Script
# =============================================================================
# Automated deployment script for Phase 9A infrastructure deployment
# Implements incremental module deployment with validation and rollback

set -euo pipefail  # Exit on any error, undefined variables, or pipe failures

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TERRAFORM_DIR="$PROJECT_ROOT/infrastructure/terraform/environments/dev"
LOG_FILE="$SCRIPT_DIR/deployment_$(date +%Y%m%d_%H%M%S).log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    case $level in
        "INFO")  echo -e "${GREEN}[INFO]${NC} $message" | tee -a "$LOG_FILE" ;;
        "WARN")  echo -e "${YELLOW}[WARN]${NC} $message" | tee -a "$LOG_FILE" ;;
        "ERROR") echo -e "${RED}[ERROR]${NC} $message" | tee -a "$LOG_FILE" ;;
        "DEBUG") echo -e "${BLUE}[DEBUG]${NC} $message" | tee -a "$LOG_FILE" ;;
    esac
}

# Error handling
cleanup() {
    local exit_code=$?
    if [ $exit_code -ne 0 ]; then
        log "ERROR" "Deployment failed with exit code $exit_code"
        log "ERROR" "Check $LOG_FILE for details"
        log "ERROR" "To rollback, run: $0 --rollback"
    fi
    exit $exit_code
}
trap cleanup EXIT

# Help function
show_help() {
    cat << EOF
Threat Intelligence Platform Deployment Script

USAGE:
    $0 [OPTIONS]

OPTIONS:
    --help              Show this help message
    --validate-only     Run validation checks only (no deployment)
    --rollback          Rollback entire deployment
    --rollback-module   Rollback specific module (requires --module)
    --module MODULE     Specify module for partial operations
    --skip-validation   Skip pre-deployment validation
    --force             Force deployment even with warnings
    --dry-run          Show what would be deployed without applying

MODULES:
    security, database, storage, compute, networking, caching, monitoring

EXAMPLES:
    $0                          # Full deployment
    $0 --validate-only          # Validation only
    $0 --module security        # Deploy security module only
    $0 --rollback              # Complete rollback
    $0 --rollback-module --module compute  # Rollback compute module

LOGS:
    Deployment logs: $LOG_FILE

EOF
}

# Parse command line arguments
VALIDATE_ONLY=false
ROLLBACK=false
ROLLBACK_MODULE=false
MODULE=""
SKIP_VALIDATION=false
FORCE=false
DRY_RUN=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --help)
            show_help
            exit 0
            ;;
        --validate-only)
            VALIDATE_ONLY=true
            shift
            ;;
        --rollback)
            ROLLBACK=true
            shift
            ;;
        --rollback-module)
            ROLLBACK_MODULE=true
            shift
            ;;
        --module)
            MODULE="$2"
            shift 2
            ;;
        --skip-validation)
            SKIP_VALIDATION=true
            shift
            ;;
        --force)
            FORCE=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        *)
            log "ERROR" "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Validate module name if specified
VALID_MODULES=("security" "database" "storage" "compute" "networking" "caching" "monitoring")
if [[ -n "$MODULE" ]]; then
    if [[ ! " ${VALID_MODULES[@]} " =~ " ${MODULE} " ]]; then
        log "ERROR" "Invalid module: $MODULE"
        log "ERROR" "Valid modules: ${VALID_MODULES[*]}"
        exit 1
    fi
fi

# Prerequisites check
check_prerequisites() {
    log "INFO" "Checking prerequisites..."

    # Check if terraform is installed
    if ! command -v terraform &> /dev/null; then
        log "ERROR" "Terraform is not installed"
        exit 1
    fi

    # Check if AWS CLI is installed and configured
    if ! command -v aws &> /dev/null; then
        log "ERROR" "AWS CLI is not installed"
        exit 1
    fi

    # Verify AWS credentials
    if ! aws sts get-caller-identity &> /dev/null; then
        log "ERROR" "AWS credentials not configured or invalid"
        exit 1
    fi

    # Check if we're in the right directory
    if [[ ! -f "$TERRAFORM_DIR/main.tf" ]]; then
        log "ERROR" "Terraform configuration not found at $TERRAFORM_DIR"
        exit 1
    fi

    log "INFO" "Prerequisites check passed"
}

# Cost protection check
check_billing_alerts() {
    log "INFO" "Checking billing alerts..."

    local account_id=$(aws sts get-caller-identity --query Account --output text)

    # Check if billing alerts exist
    if ! aws budgets describe-budgets --account-id "$account_id" --query 'Budgets[?BudgetName==`ThreatIntelPlatformBudget`]' --output text | grep -q "ThreatIntelPlatformBudget"; then
        log "WARN" "No billing alerts configured"
        if [[ "$FORCE" != "true" ]]; then
            read -p "Continue without billing alerts? (y/N): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                log "INFO" "Setup billing alerts first: aws budgets create-budget ..."
                exit 1
            fi
        fi
    else
        log "INFO" "Billing alerts configured"
    fi
}

# Terraform validation
validate_terraform() {
    log "INFO" "Validating Terraform configuration..."

    cd "$TERRAFORM_DIR"

    # Initialize Terraform
    log "INFO" "Initializing Terraform..."
    terraform init -no-color > "$LOG_FILE.init" 2>&1

    # Validate configuration
    log "INFO" "Validating configuration..."
    if ! terraform validate -no-color; then
        log "ERROR" "Terraform validation failed"
        exit 1
    fi

    # Plan deployment
    log "INFO" "Planning deployment..."
    if [[ -n "$MODULE" ]]; then
        terraform plan -target="module.$MODULE" -no-color > "$LOG_FILE.plan" 2>&1
    else
        terraform plan -no-color > "$LOG_FILE.plan" 2>&1
    fi

    # Count resources to be created
    local resource_count=$(grep -c "will be created" "$LOG_FILE.plan" || true)
    log "INFO" "Resources to be created: $resource_count"

    if [[ $resource_count -gt 50 && "$FORCE" != "true" ]]; then
        log "WARN" "Large deployment detected ($resource_count resources)"
        read -p "Continue with deployment? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log "INFO" "Deployment cancelled by user"
            exit 1
        fi
    fi
}

# Deploy specific module
deploy_module() {
    local module_name=$1
    log "INFO" "Deploying module: $module_name"

    cd "$TERRAFORM_DIR"

    if [[ "$DRY_RUN" == "true" ]]; then
        log "INFO" "DRY RUN: Would deploy module $module_name"
        terraform plan -target="module.$module_name" -no-color
        return 0
    fi

    # Deploy module
    if terraform apply -target="module.$module_name" -auto-approve -no-color; then
        log "INFO" "Module $module_name deployed successfully"

        # Module-specific validation
        case $module_name in
            "security")
                validate_security_module
                ;;
            "database")
                validate_database_module
                ;;
            "storage")
                validate_storage_module
                ;;
            "compute")
                validate_compute_module
                ;;
            "networking")
                validate_networking_module
                ;;
            "caching")
                validate_caching_module
                ;;
            "monitoring")
                validate_monitoring_module
                ;;
        esac
    else
        log "ERROR" "Failed to deploy module: $module_name"
        return 1
    fi
}

# Module validation functions
validate_security_module() {
    log "INFO" "Validating security module..."

    # Check IAM roles
    if aws iam list-roles --query 'Roles[?contains(RoleName, `threat-intel`)]' --output text | grep -q "threat-intel"; then
        log "INFO" "IAM roles created successfully"
    else
        log "ERROR" "IAM roles not found"
        return 1
    fi

    # Check Secrets Manager
    if aws secretsmanager list-secrets --query 'SecretList[?contains(Name, `threat-intel`)]' --output text | grep -q "threat-intel"; then
        log "INFO" "Secrets Manager configured successfully"
    else
        log "ERROR" "Secrets Manager not configured"
        return 1
    fi
}

validate_database_module() {
    log "INFO" "Validating database module..."

    # Check DynamoDB tables
    local tables=("threat-intel-dev" "threat-intel-dedup-dev" "osint-enrichment-cache-dev")
    for table in "${tables[@]}"; do
        if aws dynamodb describe-table --table-name "$table" --query 'Table.TableStatus' --output text 2>/dev/null | grep -q "ACTIVE"; then
            log "INFO" "Table $table is active"
        else
            log "ERROR" "Table $table not found or not active"
            return 1
        fi
    done
}

validate_storage_module() {
    log "INFO" "Validating storage module..."

    # Check S3 buckets
    if aws s3 ls | grep -q "threat-intel"; then
        log "INFO" "S3 buckets created successfully"
    else
        log "ERROR" "S3 buckets not found"
        return 1
    fi
}

validate_compute_module() {
    log "INFO" "Validating compute module..."

    # Check Lambda functions
    local function_count=$(aws lambda list-functions --query 'Functions[?contains(FunctionName, `threat-intel`)]' --output text | wc -l)
    if [[ $function_count -ge 10 ]]; then
        log "INFO" "Lambda functions deployed successfully ($function_count functions)"
    else
        log "ERROR" "Expected at least 10 Lambda functions, found $function_count"
        return 1
    fi
}

validate_networking_module() {
    log "INFO" "Validating networking module..."

    # Check API Gateway
    if aws apigateway get-rest-apis --query 'items[?contains(name, `threat-intel`)]' --output text | grep -q "threat-intel"; then
        log "INFO" "API Gateway created successfully"

        # Test API endpoint
        local api_url=$(cd "$TERRAFORM_DIR" && terraform output -raw api_gateway_url 2>/dev/null || echo "")
        if [[ -n "$api_url" ]]; then
            log "INFO" "API Gateway URL: $api_url"
        fi
    else
        log "ERROR" "API Gateway not found"
        return 1
    fi
}

validate_caching_module() {
    log "INFO" "Validating caching module..."

    # Check ElastiCache cluster
    if aws elasticache describe-cache-clusters --query 'CacheClusters[?contains(CacheClusterId, `threat-intel`)]' --output text | grep -q "threat-intel"; then
        log "INFO" "ElastiCache cluster created successfully"
    else
        log "ERROR" "ElastiCache cluster not found"
        return 1
    fi
}

validate_monitoring_module() {
    log "INFO" "Validating monitoring module..."

    # Check CloudWatch dashboards
    local dashboard_count=$(aws cloudwatch list-dashboards --query 'DashboardEntries[?contains(DashboardName, `ThreatIntel`)]' --output text | wc -l)
    if [[ $dashboard_count -ge 4 ]]; then
        log "INFO" "CloudWatch dashboards created successfully ($dashboard_count dashboards)"
    else
        log "ERROR" "Expected at least 4 dashboards, found $dashboard_count"
        return 1
    fi
}

# Rollback function
rollback_deployment() {
    local target_module=${1:-""}

    if [[ -n "$target_module" ]]; then
        log "INFO" "Rolling back module: $target_module"
        cd "$TERRAFORM_DIR"
        terraform destroy -target="module.$target_module" -auto-approve -no-color
    else
        log "INFO" "Rolling back entire deployment"
        read -p "Are you sure you want to destroy ALL resources? (yes/NO): " -r
        if [[ $REPLY == "yes" ]]; then
            cd "$TERRAFORM_DIR"
            terraform destroy -auto-approve -no-color
            log "INFO" "Rollback completed"
        else
            log "INFO" "Rollback cancelled"
        fi
    fi
}

# Cost estimation
estimate_costs() {
    log "INFO" "Estimating monthly costs..."

    cat << EOF
ESTIMATED MONTHLY COSTS:
========================
DynamoDB (pay-per-request): \$5-15
Lambda (16 functions):      \$10-25
S3 (with lifecycle):        \$2-5
API Gateway:                \$3-10
ElastiCache (t4g.micro):    \$12-15
CloudWatch:                 \$5-10
Data Transfer:              \$2-5
------------------------
TOTAL ESTIMATED:            \$39-85/month

Note: Costs depend on usage. First deployment should be <\$10.
EOF
}

# Post-deployment summary
deployment_summary() {
    log "INFO" "Deployment Summary"
    log "INFO" "=================="

    cd "$TERRAFORM_DIR"

    # Count deployed resources
    local resource_count=$(terraform state list | wc -l)
    log "INFO" "Total resources deployed: $resource_count"

    # Get important outputs
    local api_url=$(terraform output -raw api_gateway_url 2>/dev/null || echo "Not available")
    local cloudfront_url=$(terraform output -raw cloudfront_domain_name 2>/dev/null || echo "Not available")

    log "INFO" "API Gateway URL: $api_url"
    log "INFO" "CloudFront URL: https://$cloudfront_url"

    # Check system health
    log "INFO" "System Health Check:"

    # Test API endpoint if available
    if [[ "$api_url" != "Not available" ]]; then
        local api_key=$(terraform output -raw api_key_value 2>/dev/null || echo "")
        if [[ -n "$api_key" ]]; then
            if curl -s -f -H "x-api-key: $api_key" "$api_url/collect" > /dev/null; then
                log "INFO" "✓ API Gateway responding"
            else
                log "WARN" "✗ API Gateway not responding"
            fi
        fi
    fi

    estimate_costs

    log "INFO" "Next Steps:"
    log "INFO" "1. Add API keys to Secrets Manager for real data collection"
    log "INFO" "2. Run system tests: ./test_system.sh"
    log "INFO" "3. Monitor costs: ./cost_monitor.sh"
    log "INFO" "4. Check documentation: docs/DEPLOYMENT.md"
}

# Main execution
main() {
    log "INFO" "Starting Threat Intelligence Platform Deployment"
    log "INFO" "Log file: $LOG_FILE"

    # Handle rollback
    if [[ "$ROLLBACK" == "true" ]]; then
        rollback_deployment
        exit 0
    fi

    if [[ "$ROLLBACK_MODULE" == "true" ]]; then
        if [[ -z "$MODULE" ]]; then
            log "ERROR" "--rollback-module requires --module option"
            exit 1
        fi
        rollback_deployment "$MODULE"
        exit 0
    fi

    # Prerequisites
    check_prerequisites

    if [[ "$SKIP_VALIDATION" != "true" ]]; then
        check_billing_alerts
        validate_terraform
    fi

    if [[ "$VALIDATE_ONLY" == "true" ]]; then
        log "INFO" "Validation completed successfully"
        exit 0
    fi

    # Deployment
    if [[ -n "$MODULE" ]]; then
        deploy_module "$MODULE"
    else
        # Full deployment - incremental approach
        local modules=("security" "database" "storage" "compute" "networking" "caching" "monitoring")

        for module in "${modules[@]}"; do
            deploy_module "$module"
            sleep 5  # Brief pause between modules
        done
    fi

    # Post-deployment
    if [[ "$DRY_RUN" != "true" ]]; then
        deployment_summary
    fi

    log "INFO" "Deployment completed successfully!"
}

# Run main function
main "$@"