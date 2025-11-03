"""
OSINT Data Processor Lambda Function - MVP Version

Minimal viable threat intelligence processing with:
- Basic STIX 2.1 validation and processing
- Simple batch processing for cost optimization
- Basic data quality scoring
- Essential deduplication and correlation

MVP Features:
- Essential STIX 2.1 compliance validation
- Simple confidence scoring
- Basic pattern validation
- DynamoDB storage with basic search
"""

import json
import boto3
import logging
import os
import re
import hashlib
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple
from decimal import Decimal
from botocore.exceptions import ClientError

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# AWS Service Clients
dynamodb = boto3.resource('dynamodb')
s3_client = boto3.client('s3')

# Environment Variables
ENVIRONMENT = os.environ.get('ENVIRONMENT', 'dev')
THREAT_INTEL_TABLE = os.environ['THREAT_INTEL_TABLE']
DEDUP_TABLE = os.environ['DEDUP_TABLE']
PROCESSED_DATA_BUCKET = os.environ['PROCESSED_DATA_BUCKET']
MAX_BATCH_SIZE = int(os.environ.get('MAX_BATCH_SIZE', '50'))  # Reduced for MVP

# DynamoDB Tables
threat_intel_table = dynamodb.Table(THREAT_INTEL_TABLE)
dedup_table = dynamodb.Table(DEDUP_TABLE)

# Basic STIX 2.1 Pattern Validation
STIX_PATTERNS = {
    'ipv4': r'\[ipv4-addr:value\s*=\s*\'([0-9]{1,3}\.){3}[0-9]{1,3}\'\]',
    'ipv6': r'\[ipv6-addr:value\s*=\s*\'[0-9a-fA-F:]+\'\]',
    'domain': r'\[domain-name:value\s*=\s*\'[a-zA-Z0-9.-]+\'\]',
    'url': r'\[url:value\s*=\s*\'https?://[^\s]+\'\]',
    'file_hash': r'\[file:hashes\.(MD5|SHA-1|SHA-256)\s*=\s*\'[a-fA-F0-9]+\'\]'
}


def validate_stix_pattern(pattern: str) -> Tuple[bool, str]:
    """Basic STIX pattern validation"""
    if not pattern or not pattern.startswith('[') or not pattern.endswith(']'):
        return False, "Invalid STIX pattern format"

    for pattern_type, regex in STIX_PATTERNS.items():
        if re.match(regex, pattern):
            return True, pattern_type

    return False, "Unknown pattern type"


def calculate_confidence_score(indicator_data: Dict[str, Any]) -> int:
    """Calculate basic confidence score"""
    base_confidence = indicator_data.get('confidence', 50)

    # Source reliability scoring
    source_scores = {
        'otx': 70,
        'abuse_ch': 85,
        'shodan': 60,
        'manual': 90
    }

    source = indicator_data.get('source', 'unknown')
    source_score = source_scores.get(source, 50)

    # Simple average for MVP
    final_confidence = min(100, max(0, (base_confidence + source_score) // 2))
    return final_confidence


def validate_indicator_data(indicator: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Basic indicator validation"""
    errors = []

    # Required fields
    required_fields = ['indicator_id', 'ioc_type', 'ioc_value', 'source']
    for field in required_fields:
        if not indicator.get(field):
            errors.append(f"Missing required field: {field}")

    # STIX data validation
    if 'stix_data' in indicator:
        stix_data = indicator['stix_data']
        if 'pattern' in stix_data:
            is_valid, pattern_type = validate_stix_pattern(stix_data['pattern'])
            if not is_valid:
                errors.append(f"Invalid STIX pattern: {pattern_type}")

    return len(errors) == 0, errors


def create_processed_indicator(indicator: Dict[str, Any]) -> Dict[str, Any]:
    """Create processed indicator with enhanced metadata"""
    # Calculate confidence score
    confidence = calculate_confidence_score(indicator)

    # Determine threat level based on confidence and source
    if confidence >= 80:
        threat_level = "high"
    elif confidence >= 60:
        threat_level = "medium"
    else:
        threat_level = "low"

    # Create processed record
    processed = {
        'indicator_id': indicator['indicator_id'],
        'pattern_hash': indicator.get('pattern_hash'),
        'source': indicator['source'],
        'ioc_type': indicator['ioc_type'],
        'ioc_value': indicator['ioc_value'],
        'confidence': confidence,
        'threat_level': threat_level,
        'processed_at': datetime.now(timezone.utc).isoformat(),
        'created_at': indicator.get('created_at'),
        'stix_data': indicator.get('stix_data', {}),
        'metadata': {
            'threat_type': indicator.get('threat_type', 'unknown'),
            'tags': indicator.get('tags', []),
            'processing_version': '1.0-mvp'
        }
    }

    return processed


def store_processed_indicator(indicator: Dict[str, Any]) -> bool:
    """Store processed indicator in DynamoDB"""
    try:
        # Convert floats to Decimal for DynamoDB
        def convert_floats(obj):
            if isinstance(obj, float):
                return Decimal(str(obj))
            elif isinstance(obj, dict):
                return {k: convert_floats(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_floats(v) for v in obj]
            return obj

        processed_item = convert_floats(indicator)
        threat_intel_table.put_item(Item=processed_item)
        return True

    except Exception as e:
        logger.error(f"Failed to store processed indicator: {str(e)}")
        return False


def search_indicators(query: Dict[str, Any]) -> Dict[str, Any]:
    """Basic indicator search using available DynamoDB indexes"""
    try:
        items = []

        # Search by IOC type
        if 'ioc_type' in query:
            response = threat_intel_table.query(
                IndexName='ioc-pattern-index',
                KeyConditionExpression=boto3.dynamodb.conditions.Key('ioc_type').eq(query['ioc_type']),
                Limit=query.get('limit', 20)
            )
            items = response.get('Items', [])

        # Search by source
        elif 'source' in query:
            response = threat_intel_table.query(
                IndexName='source-index',
                KeyConditionExpression=boto3.dynamodb.conditions.Key('source_name').eq(query['source']),
                Limit=query.get('limit', 20)
            )
            items = response.get('Items', [])

        # Search by threat type
        elif 'threat_type' in query:
            response = threat_intel_table.query(
                IndexName='risk-analytics-index',
                KeyConditionExpression=boto3.dynamodb.conditions.Key('threat_type').eq(query['threat_type']),
                Limit=query.get('limit', 20)
            )
            items = response.get('Items', [])

        # Search by geographic region
        elif 'geographic_region' in query:
            response = threat_intel_table.query(
                IndexName='geographic-index',
                KeyConditionExpression=boto3.dynamodb.conditions.Key('geographic_region').eq(query['geographic_region']),
                Limit=query.get('limit', 20)
            )
            items = response.get('Items', [])

        else:
            # General scan (limited for MVP)
            scan_filter = {}

            # Add filter conditions for ioc_value if provided
            if 'ioc_value' in query:
                scan_filter['pattern'] = {
                    'AttributeValueList': [f"*{query['ioc_value']}*"],
                    'ComparisonOperator': 'CONTAINS'
                }

            if scan_filter:
                response = threat_intel_table.scan(
                    ScanFilter=scan_filter,
                    Limit=query.get('limit', 10)
                )
            else:
                response = threat_intel_table.scan(
                    Limit=query.get('limit', 10)
                )
            items = response.get('Items', [])

        # Convert Decimal and DynamoDB sets for JSON serialization
        def convert_decimals(obj):
            if isinstance(obj, Decimal):
                return float(obj)
            elif isinstance(obj, set):
                return list(obj)  # Convert DynamoDB sets to lists
            elif isinstance(obj, dict):
                return {k: convert_decimals(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_decimals(v) for v in obj]
            return obj

        results = [convert_decimals(item) for item in items]

        return {
            'results': results,
            'count': len(results),
            'query': query
        }

    except Exception as e:
        logger.error(f"Search failed: {str(e)}")
        return {'results': [], 'count': 0, 'error': str(e)}


def export_indicators(request: Dict[str, Any]) -> Dict[str, Any]:
    """Basic indicator export"""
    try:
        # Get indicators based on criteria
        search_query = {
            'limit': request.get('limit', 100),
            'source': request.get('source'),
            'ioc_type': request.get('ioc_type')
        }

        search_results = search_indicators(search_query)
        indicators = search_results['results']

        if not indicators:
            return {'error': 'No indicators found for export'}

        # Export format
        export_format = request.get('format', 'json').lower()

        if export_format == 'json':
            export_data = {
                'indicators': indicators,
                'export_metadata': {
                    'count': len(indicators),
                    'exported_at': datetime.now(timezone.utc).isoformat(),
                    'format': 'json'
                }
            }
            content = json.dumps(export_data, indent=2)
            content_type = 'application/json'

        elif export_format == 'stix':
            # Basic STIX bundle
            stix_objects = [ind.get('stix_data', {}) for ind in indicators if ind.get('stix_data')]
            bundle = {
                'type': 'bundle',
                'id': f"bundle--{os.urandom(16).hex()}",
                'objects': stix_objects
            }
            content = json.dumps(bundle, indent=2)
            content_type = 'application/json'

        else:
            return {'error': f'Unsupported export format: {export_format}'}

        # Store in S3
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        key = f"exports/{export_format}/{timestamp}_export.{export_format}"

        s3_client.put_object(
            Bucket=PROCESSED_DATA_BUCKET,
            Key=key,
            Body=content,
            ContentType=content_type
        )

        return {
            'export_url': f"s3://{PROCESSED_DATA_BUCKET}/{key}",
            'count': len(indicators),
            'format': export_format
        }

    except Exception as e:
        logger.error(f"Export failed: {str(e)}")
        return {'error': str(e)}


def lambda_handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    """
    Main Lambda handler for threat intelligence processing

    Args:
        event: Lambda event data (API Gateway, SQS, or manual trigger)
        context: Lambda runtime context

    Returns:
        Dict containing processing results
    """
    try:
        logger.info(f"Starting threat intelligence processing - Environment: {ENVIRONMENT}")

        # Check if this is an API Gateway request
        if 'httpMethod' in event:
            # API Gateway request
            http_method = event.get('httpMethod', 'POST')
            path = event.get('path', '/')

            if http_method == 'GET' and '/search' in path:
                # Handle GET /search requests
                query_params = event.get('queryStringParameters') or {}
                body = {
                    'action': 'search',
                    'query': {
                        'ioc_value': query_params.get('q'),
                        'ioc_type': query_params.get('type'),
                        'source': query_params.get('source'),
                        'limit': int(query_params.get('limit', 20))
                    }
                }
                # Remove None values from query
                body['query'] = {k: v for k, v in body['query'].items() if v is not None}
            else:
                # POST request with body
                if event.get('body'):
                    body = json.loads(event['body']) if isinstance(event['body'], str) else event['body']
                else:
                    body = {'action': 'process'}
        else:
            # Direct Lambda invocation
            body = event

        action = body.get('action', 'process')

        # Handle different actions
        if action == 'search':
            results = search_indicators(body.get('query', {}))
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'action': 'search',
                    'results': results,
                    'timestamp': datetime.now(timezone.utc).isoformat()
                })
            }

        elif action == 'export':
            results = export_indicators(body.get('export_request', {}))
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'action': 'export',
                    'results': results,
                    'timestamp': datetime.now(timezone.utc).isoformat()
                })
            }

        elif action == 'process':
            # Process indicators
            indicators = body.get('indicators', [])
            if not indicators:
                return {
                    'statusCode': 400,
                    'body': json.dumps({'error': 'No indicators provided for processing'})
                }

            processed_count = 0
            validation_errors = []

            for indicator in indicators[:MAX_BATCH_SIZE]:  # Limit batch size
                # Validate indicator
                is_valid, errors = validate_indicator_data(indicator)
                if not is_valid:
                    validation_errors.extend(errors)
                    continue

                # Process and store
                processed_indicator = create_processed_indicator(indicator)
                if store_processed_indicator(processed_indicator):
                    processed_count += 1

            return {
                'statusCode': 200,
                'body': json.dumps({
                    'action': 'process',
                    'indicators_processed': processed_count,
                    'total_indicators': len(indicators),
                    'validation_errors': validation_errors,
                    'timestamp': datetime.now(timezone.utc).isoformat()
                })
            }

        else:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': f'Unknown action: {action}'})
            }

    except Exception as e:
        logger.error(f"Processing failed: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': 'Processing failed',
                'message': str(e),
                'timestamp': datetime.now(timezone.utc).isoformat()
            })
        }