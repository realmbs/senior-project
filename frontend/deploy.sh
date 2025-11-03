#!/bin/bash

# Threat Intelligence Platform - Frontend Deployment Script
# Deploys to S3 bucket: threat-intel-platform-frontend-dev-53cc9e74

set -e

echo "🚀 Starting frontend deployment to S3..."

# Build the application
echo "📦 Building application..."
npm run build

# S3 bucket name from CLAUDE.md
BUCKET_NAME="threat-intel-platform-frontend-dev-53cc9e74"

# Sync to S3 bucket
echo "☁️  Uploading to S3 bucket: $BUCKET_NAME"
aws s3 sync build/ s3://$BUCKET_NAME --delete

# Get CloudFront distribution ID (will be set manually after first deployment)
CLOUDFRONT_ID=${CLOUDFRONT_DISTRIBUTION_ID:-""}

if [ ! -z "$CLOUDFRONT_ID" ]; then
    echo "🔄 Invalidating CloudFront cache..."
    aws cloudfront create-invalidation --distribution-id $CLOUDFRONT_ID --paths "/*"
    echo "✅ CloudFront cache invalidated"
else
    echo "⚠️  CloudFront distribution ID not set. Set CLOUDFRONT_DISTRIBUTION_ID environment variable for cache invalidation."
fi

echo "✅ Frontend deployment complete!"
echo "🌐 Your application should be available via CloudFront shortly."