#!/bin/bash

# =============================================================================
# S3 Static Website Deployment Script
# =============================================================================
# Deploys the Vite frontend to S3 static website hosting
# Safe to run - does NOT touch Terraform or API Gateway infrastructure

set -e  # Exit on error

# Configuration
BUCKET_NAME="threat-intel-platform-frontend-dev-53cc9e74"
WEBSITE_URL="http://${BUCKET_NAME}.s3-website-us-east-1.amazonaws.com"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FRONTEND_DIR="${PROJECT_ROOT}/frontend"
DIST_DIR="${FRONTEND_DIR}/dist"

# Color output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Functions
print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_info() {
    echo -e "${YELLOW}→${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

# =============================================================================
# Pre-deployment Validation
# =============================================================================

print_info "Starting frontend deployment validation..."

# Check if we're in the right directory
if [ ! -d "$FRONTEND_DIR" ]; then
    print_error "Frontend directory not found: $FRONTEND_DIR"
    exit 1
fi

# Check if AWS CLI is installed
if ! command -v aws &> /dev/null; then
    print_error "AWS CLI is not installed. Please install it first."
    exit 1
fi

# Check if AWS credentials are configured
if ! aws sts get-caller-identity &> /dev/null; then
    print_error "AWS credentials not configured. Please run 'aws configure'."
    exit 1
fi

print_success "Pre-deployment checks passed"

# =============================================================================
# Build Frontend
# =============================================================================

print_info "Building frontend..."
cd "$FRONTEND_DIR"

# Check if node_modules exists
if [ ! -d "node_modules" ]; then
    print_info "Installing dependencies..."
    npm install
fi

# Run build
npm run build

if [ ! -d "$DIST_DIR" ]; then
    print_error "Build failed - dist directory not found"
    exit 1
fi

print_success "Frontend built successfully"

# =============================================================================
# Upload to S3
# =============================================================================

print_info "Uploading files to S3..."

# Sync files with proper cache headers
aws s3 sync "$DIST_DIR/" "s3://${BUCKET_NAME}/" \
    --delete \
    --cache-control "public,max-age=3600" \
    --exclude "*.map"

# Upload source maps separately with different cache headers
if ls "$DIST_DIR"/assets/*.map 1> /dev/null 2>&1; then
    aws s3 sync "$DIST_DIR/" "s3://${BUCKET_NAME}/" \
        --cache-control "public,max-age=31536000" \
        --exclude "*" \
        --include "*.map"
fi

print_success "Files uploaded to S3"

# =============================================================================
# Verify Deployment
# =============================================================================

print_info "Verifying deployment..."

# Check if index.html exists in S3
if aws s3api head-object --bucket "$BUCKET_NAME" --key "index.html" &> /dev/null; then
    print_success "index.html found in S3"
else
    print_error "index.html not found in S3"
    exit 1
fi

# Count uploaded files
FILE_COUNT=$(aws s3 ls "s3://${BUCKET_NAME}/" --recursive | wc -l | tr -d ' ')
print_success "Deployed ${FILE_COUNT} files"

# =============================================================================
# Deployment Summary
# =============================================================================

echo ""
echo "========================================"
echo "  Deployment Successful!"
echo "========================================"
echo ""
echo "Website URL: ${WEBSITE_URL}"
echo "S3 Bucket:   ${BUCKET_NAME}"
echo "Files:       ${FILE_COUNT}"
echo ""
echo "API Endpoint: https://u88kzux168.execute-api.us-east-1.amazonaws.com/dev"
echo ""
echo "Testing:"
echo "  1. Open the website URL in your browser"
echo "  2. Check browser console for errors"
echo "  3. Test threat intelligence search"
echo "  4. Verify heatmap and analytics work"
echo ""
