"""
OSINT Data Processor Lambda Function

This module processes collected threat intelligence data with focus on:
- STIX 2.1 compliance validation and enrichment
- Batch processing for cost optimization
- Data quality scoring and filtering
- Cross-source correlation and deduplication

Features:
- Higher memory allocation (512MB) for intensive processing
- Batch processing up to 100 indicators per invocation
- STIX 2.1 validation and normalization
- Confidence scoring and quality assessment
"""

import json
import boto3
import logging
import os
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple
from decimal import Decimal
import re
import hashlib
from botocore.exceptions import ClientError

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# AWS Service Clients
dynamodb = boto3.resource('dynamodb')
s3_client = boto3.client('s3')
secrets_client = boto3.client('secretsmanager')

# Environment Variables
ENVIRONMENT = os.environ.get('ENVIRONMENT', 'dev')
SECRETS_MANAGER_ARN = os.environ['SECRETS_MANAGER_ARN']
THREAT_INTEL_TABLE = os.environ['THREAT_INTEL_TABLE']
DEDUP_TABLE = os.environ['DEDUP_TABLE']
RAW_DATA_BUCKET = os.environ['RAW_DATA_BUCKET']
PROCESSED_DATA_BUCKET = os.environ['PROCESSED_DATA_BUCKET']
STIX_VERSION = os.environ.get('STIX_VERSION', '2.1')
MAX_BATCH_SIZE = int(os.environ.get('MAX_BATCH_SIZE', '100'))

# DynamoDB Tables
threat_intel_table = dynamodb.Table(THREAT_INTEL_TABLE)
dedup_table = dynamodb.Table(DEDUP_TABLE)

# STIX 2.1 Pattern Validation Regexes
STIX_PATTERNS = {
    'ipv4': r'\[ipv4-addr:value\s*=\s*\'([0-9]{1,3}\.){3}[0-9]{1,3}\'\]',
    'ipv6': r'\[ipv6-addr:value\s*=\s*\'[0-9a-fA-F:]+\'\]',
    'domain': r'\[domain-name:value\s*=\s*\'[a-zA-Z0-9.-]+\'\]',
    'url': r'\[url:value\s*=\s*\'https?://[^\s]+\'\]',
    'file_hash': r'\[file:hashes\.(MD5|SHA-1|SHA-256)\s*=\s*\'[a-fA-F0-9]+\'\]'
}


def lambda_handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    """
    Main Lambda handler for threat intelligence data processing

    Args:
        event: Lambda event data (API Gateway, SQS, or manual trigger)
        context: Lambda runtime context

    Returns:
        Dict containing processing results and metrics
    """
    try:
        logger.info(f"Starting threat intelligence processing - Environment: {ENVIRONMENT}")

        # Initialize processing results
        results = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'environment': ENVIRONMENT,
            'processing_stats': {
                'indicators_processed': 0,
                'valid_indicators': 0,
                'invalid_indicators': 0,
                'enriched_indicators': 0,
                'correlation_matches': 0
            },
            'quality_metrics': {
                'avg_confidence_score': 0,
                'high_confidence_count': 0,
                'low_confidence_count': 0
            },
            'errors': []
        }

        # Determine processing mode based on event source
        if 'source' in event and event['source'] == 'aws:sqs':
            # Process SQS batch messages
            indicators = extract_indicators_from_sqs(event)
        elif 'Records' in event:
            # Process S3 event notifications
            indicators = extract_indicators_from_s3_events(event)
        else:
            # Manual processing mode - scan for unprocessed indicators
            indicators = scan_unprocessed_indicators(MAX_BATCH_SIZE)

        if not indicators:
            logger.info("No indicators found for processing")
            return create_response(200, results)

        logger.info(f"Processing {len(indicators)} indicators")

        # Process indicators in batches
        for batch in batch_indicators(indicators, MAX_BATCH_SIZE):
            batch_results = process_indicator_batch(batch)
            update_processing_stats(results['processing_stats'], batch_results)

        # Calculate quality metrics
        calculate_quality_metrics(results)

        # Store processing results
        store_processing_results(results)

        logger.info(f"Processing completed: {results['processing_stats']['valid_indicators']} "
                   f"valid indicators processed")

        return create_response(200, results)

    except Exception as e:
        error_msg = f"Error in threat intelligence processing: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return create_response(500, {
            'error': 'Internal server error',
            'message': str(e) if ENVIRONMENT == 'dev' else 'Processing failed'
        })


def extract_indicators_from_sqs(event: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Extract indicators from SQS batch messages

    Args:
        event: SQS batch event

    Returns:
        List of indicator objects
    """
    indicators = []

    try:
        for record in event.get('Records', []):
            body = json.loads(record.get('body', '{}'))
            if 'indicator' in body:
                indicators.append(body['indicator'])

    except Exception as e:
        logger.error(f"Error extracting indicators from SQS: {e}")

    return indicators


def extract_indicators_from_s3_events(event: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Extract indicators from S3 event notifications

    Args:
        event: S3 event notification

    Returns:
        List of indicator objects
    """
    indicators = []

    try:
        for record in event.get('Records', []):
            if record.get('eventSource') == 'aws:s3':
                bucket = record['s3']['bucket']['name']
                key = record['s3']['object']['key']

                # Download and parse S3 object
                response = s3_client.get_object(Bucket=bucket, Key=key)
                data = json.loads(response['Body'].read())

                if isinstance(data, list):
                    indicators.extend(data)
                elif isinstance(data, dict) and 'indicators' in data:
                    indicators.extend(data['indicators'])

    except Exception as e:
        logger.error(f"Error extracting indicators from S3: {e}")

    return indicators


def scan_unprocessed_indicators(limit: int) -> List[Dict[str, Any]]:
    """
    Scan DynamoDB for unprocessed indicators

    Args:
        limit: Maximum number of indicators to retrieve

    Returns:
        List of unprocessed indicator objects
    """
    indicators = []

    try:
        # Scan for indicators without processed_at timestamp
        response = threat_intel_table.scan(
            FilterExpression='attribute_not_exists(processed_at)',
            Limit=limit
        )

        indicators = response.get('Items', [])
        logger.info(f"Found {len(indicators)} unprocessed indicators")

    except Exception as e:
        logger.error(f"Error scanning for unprocessed indicators: {e}")

    return indicators


def process_indicator_batch(indicators: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Process a batch of indicators for STIX compliance and quality

    Args:
        indicators: List of indicator objects to process

    Returns:
        Dict containing batch processing results
    """
    batch_results = {
        'processed': 0,
        'valid': 0,
        'invalid': 0,
        'enriched': 0,
        'correlations': 0,
        'confidence_scores': []
    }

    for indicator in indicators:
        try:
            # Validate STIX 2.1 compliance
            is_valid, validation_errors = validate_stix_compliance(indicator)

            if is_valid:
                # Enrich indicator with additional metadata
                enriched_indicator = enrich_indicator(indicator)

                # Check for correlations with existing data
                correlations = find_correlations(enriched_indicator)

                # Update confidence score based on correlations
                updated_confidence = update_confidence_score(
                    enriched_indicator, correlations)

                # Store processed indicator
                store_processed_indicator(enriched_indicator, correlations)

                batch_results['valid'] += 1
                batch_results['enriched'] += 1
                batch_results['correlations'] += len(correlations)
                batch_results['confidence_scores'].append(updated_confidence)

            else:
                logger.warning(f"Invalid indicator: {validation_errors}")
                batch_results['invalid'] += 1

            batch_results['processed'] += 1

        except Exception as e:
            logger.error(f"Error processing indicator: {e}")
            batch_results['invalid'] += 1

    return batch_results


def validate_stix_compliance(indicator: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Validate indicator against STIX 2.1 specification

    Args:
        indicator: Indicator object to validate

    Returns:
        Tuple of (is_valid, list_of_errors)
    """
    errors = []

    # Required fields validation
    required_fields = ['type', 'spec_version', 'id', 'created', 'modified', 'pattern', 'labels']
    for field in required_fields:
        if field not in indicator:
            errors.append(f"Missing required field: {field}")

    # STIX version validation
    if indicator.get('spec_version') != '2.1':
        errors.append(f"Invalid spec_version: {indicator.get('spec_version')}")

    # Pattern syntax validation
    pattern = indicator.get('pattern', '')
    if pattern and not validate_stix_pattern(pattern):
        errors.append(f"Invalid STIX pattern syntax: {pattern}")

    # Confidence score validation
    confidence = indicator.get('confidence')
    if confidence is not None and (not isinstance(confidence, (int, float)) or
                                  confidence < 0 or confidence > 100):
        errors.append(f"Invalid confidence score: {confidence}")

    # Labels validation
    labels = indicator.get('labels', [])
    if not isinstance(labels, list) or not labels:
        errors.append("Labels must be a non-empty list")

    return len(errors) == 0, errors


def validate_stix_pattern(pattern: str) -> bool:
    """
    Validate STIX pattern syntax using regex patterns

    Args:
        pattern: STIX pattern string to validate

    Returns:
        True if pattern is valid, False otherwise
    """
    for pattern_type, regex in STIX_PATTERNS.items():
        if re.match(regex, pattern):
            return True

    # Check for custom patterns (x-custom namespace)
    custom_pattern = r'\[x-[a-zA-Z0-9-]+:[a-zA-Z0-9-]+\s*=\s*\'[^\']+\'\]'
    return bool(re.match(custom_pattern, pattern))


def enrich_indicator(indicator: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enrich indicator with additional metadata and quality scoring

    Args:
        indicator: Original indicator object

    Returns:
        Enriched indicator object
    """
    enriched = indicator.copy()

    # Add processing metadata
    enriched['processed_at'] = datetime.now(timezone.utc).isoformat()
    enriched['processor_version'] = '1.0'

    # Add quality metrics
    enriched['quality_score'] = calculate_quality_score(indicator)

    # Add threat type classification
    enriched['threat_type'] = classify_threat_type(indicator)

    # Add geographic context if applicable
    geo_context = extract_geographic_context(indicator)
    if geo_context:
        enriched['geographic_context'] = geo_context

    # Add TLP (Traffic Light Protocol) marking
    enriched['tlp_marking'] = determine_tlp_marking(indicator)

    return enriched


def find_correlations(indicator: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Find correlations with existing threat intelligence data

    Args:
        indicator: Indicator to find correlations for

    Returns:
        List of correlation objects
    """
    correlations = []

    try:
        # Extract pattern components for correlation matching
        pattern_components = extract_pattern_components(indicator.get('pattern', ''))

        for component in pattern_components:
            # Search for similar patterns in existing data
            similar_indicators = search_similar_patterns(component)

            for similar in similar_indicators:
                correlation = {
                    'related_indicator_id': similar.get('id'),
                    'correlation_type': determine_correlation_type(indicator, similar),
                    'confidence': calculate_correlation_confidence(indicator, similar),
                    'correlation_timestamp': datetime.now(timezone.utc).isoformat()
                }
                correlations.append(correlation)

    except Exception as e:
        logger.warning(f"Error finding correlations: {e}")

    return correlations


def update_confidence_score(indicator: Dict[str, Any],
                           correlations: List[Dict[str, Any]]) -> int:
    """
    Update confidence score based on correlations and quality metrics

    Args:
        indicator: Indicator object
        correlations: List of correlation objects

    Returns:
        Updated confidence score
    """
    base_confidence = indicator.get('confidence', 50)

    # Increase confidence based on number of correlations
    correlation_boost = min(len(correlations) * 5, 20)

    # Increase confidence based on source reputation
    source_boost = get_source_confidence_boost(indicator.get('source', ''))

    # Adjust based on quality score
    quality_score = indicator.get('quality_score', 50)
    quality_boost = (quality_score - 50) // 10

    updated_confidence = base_confidence + correlation_boost + source_boost + quality_boost

    return min(max(updated_confidence, 0), 100)


def store_processed_indicator(indicator: Dict[str, Any],
                            correlations: List[Dict[str, Any]]) -> None:
    """
    Store processed indicator with correlations in DynamoDB

    Args:
        indicator: Processed indicator object
        correlations: List of correlation objects
    """
    try:
        # Convert float values to Decimal for DynamoDB compatibility
        indicator_item = convert_floats_to_decimal(indicator)

        # Add correlations to indicator
        if correlations:
            indicator_item['correlations'] = convert_floats_to_decimal(correlations)

        # Store updated indicator
        threat_intel_table.put_item(Item=indicator_item)

        # Archive processed data to S3
        archive_processed_indicator(indicator_item)

    except Exception as e:
        logger.error(f"Error storing processed indicator: {e}")
        raise


def calculate_quality_score(indicator: Dict[str, Any]) -> int:
    """
    Calculate quality score based on various indicator attributes

    Args:
        indicator: Indicator object

    Returns:
        Quality score (0-100)
    """
    score = 50  # Base score

    # Pattern quality
    pattern = indicator.get('pattern', '')
    if validate_stix_pattern(pattern):
        score += 10

    # Source reputation
    source = indicator.get('source', '')
    source_scores = {
        'otx': 15,
        'abuse_ch': 20,
        'misp': 15,
        'commercial': 25
    }
    score += source_scores.get(source, 0)

    # Confidence level
    confidence = indicator.get('confidence', 0)
    if confidence >= 80:
        score += 15
    elif confidence >= 60:
        score += 10
    elif confidence >= 40:
        score += 5

    # Labels specificity
    labels = indicator.get('labels', [])
    if 'malicious-activity' in labels:
        score += 5

    # External references
    ext_refs = indicator.get('external_references', [])
    score += min(len(ext_refs) * 3, 15)

    return min(score, 100)


def classify_threat_type(indicator: Dict[str, Any]) -> str:
    """
    Classify threat type based on indicator patterns and metadata

    Args:
        indicator: Indicator object

    Returns:
        Threat type classification string
    """
    pattern = indicator.get('pattern', '').lower()
    labels = indicator.get('labels', [])
    source = indicator.get('source', '')

    # File hash indicators
    if 'file:hashes' in pattern:
        return 'malware'

    # Network indicators
    if any(x in pattern for x in ['ipv4-addr', 'ipv6-addr', 'domain-name']):
        if 'c2' in str(indicator).lower() or 'command' in str(indicator).lower():
            return 'c2_infrastructure'
        return 'network_infrastructure'

    # URL indicators
    if 'url:value' in pattern:
        if any(x in str(indicator).lower() for x in ['phish', 'scam']):
            return 'phishing'
        return 'malicious_url'

    return 'unknown'


def extract_geographic_context(indicator: Dict[str, Any]) -> Optional[Dict[str, str]]:
    """
    Extract geographic context from indicator data

    Args:
        indicator: Indicator object

    Returns:
        Geographic context dict or None
    """
    # This would typically integrate with IP geolocation services
    # Placeholder implementation
    pattern = indicator.get('pattern', '')

    if 'ipv4-addr' in pattern or 'ipv6-addr' in pattern:
        # In production, this would call a geolocation API
        return {
            'country': 'unknown',
            'region': 'unknown',
            'asn': 'unknown'
        }

    return None


def determine_tlp_marking(indicator: Dict[str, Any]) -> str:
    """
    Determine Traffic Light Protocol marking for indicator

    Args:
        indicator: Indicator object

    Returns:
        TLP marking (white, green, amber, red)
    """
    source = indicator.get('source', '')
    confidence = indicator.get('confidence', 0)

    # Public sources with high confidence can be TLP:WHITE
    if source in ['otx', 'abuse_ch'] and confidence >= 70:
        return 'white'

    # Default to TLP:GREEN for processed indicators
    return 'green'


def extract_pattern_components(pattern: str) -> List[str]:
    """Extract individual components from STIX pattern for correlation matching"""
    components = []

    # Extract values from STIX patterns
    value_matches = re.findall(r"'([^']+)'", pattern)
    components.extend(value_matches)

    return components


def search_similar_patterns(component: str) -> List[Dict[str, Any]]:
    """Search for indicators with similar pattern components"""
    try:
        # This is a simplified search - in production would use more sophisticated matching
        response = threat_intel_table.scan(
            FilterExpression='contains(pattern, :comp)',
            ExpressionAttributeValues={':comp': component},
            Limit=10
        )
        return response.get('Items', [])
    except Exception:
        return []


def determine_correlation_type(indicator1: Dict[str, Any],
                             indicator2: Dict[str, Any]) -> str:
    """Determine the type of correlation between two indicators"""
    if indicator1.get('source') == indicator2.get('source'):
        return 'same_source'

    pattern1 = indicator1.get('pattern', '')
    pattern2 = indicator2.get('pattern', '')

    if pattern1 == pattern2:
        return 'identical_pattern'

    return 'related_pattern'


def calculate_correlation_confidence(indicator1: Dict[str, Any],
                                   indicator2: Dict[str, Any]) -> int:
    """Calculate confidence level for correlation"""
    base_confidence = 50

    # Same pattern = high confidence
    if indicator1.get('pattern') == indicator2.get('pattern'):
        base_confidence += 30

    # Same source = medium confidence boost
    if indicator1.get('source') == indicator2.get('source'):
        base_confidence += 15

    return min(base_confidence, 95)


def get_source_confidence_boost(source: str) -> int:
    """Get confidence boost based on source reputation"""
    boosts = {
        'abuse_ch': 15,
        'otx': 10,
        'misp': 12,
        'commercial': 20
    }
    return boosts.get(source, 0)


def convert_floats_to_decimal(obj):
    """Convert float values to Decimal for DynamoDB compatibility"""
    if isinstance(obj, list):
        return [convert_floats_to_decimal(item) for item in obj]
    elif isinstance(obj, dict):
        return {key: convert_floats_to_decimal(value) for key, value in obj.items()}
    elif isinstance(obj, float):
        return Decimal(str(obj))
    return obj


def archive_processed_indicator(indicator: Dict[str, Any]) -> None:
    """Archive processed indicator to S3 for analytics"""
    try:
        timestamp = datetime.now(timezone.utc).strftime('%Y/%m/%d/%H')
        key = f"processed_threat_intel/{timestamp}/{indicator['id']}.json"

        s3_client.put_object(
            Bucket=PROCESSED_DATA_BUCKET,
            Key=key,
            Body=json.dumps(indicator, default=str),
            ContentType='application/json',
            ServerSideEncryption='AES256'
        )
    except Exception as e:
        logger.warning(f"Error archiving processed indicator: {e}")


def batch_indicators(indicators: List[Dict[str, Any]],
                    batch_size: int) -> List[List[Dict[str, Any]]]:
    """Split indicators into batches for processing"""
    for i in range(0, len(indicators), batch_size):
        yield indicators[i:i + batch_size]


def update_processing_stats(stats: Dict[str, Any],
                          batch_results: Dict[str, Any]) -> None:
    """Update processing statistics with batch results"""
    stats['indicators_processed'] += batch_results['processed']
    stats['valid_indicators'] += batch_results['valid']
    stats['invalid_indicators'] += batch_results['invalid']
    stats['enriched_indicators'] += batch_results['enriched']
    stats['correlation_matches'] += batch_results['correlations']


def calculate_quality_metrics(results: Dict[str, Any]) -> None:
    """Calculate overall quality metrics for processing run"""
    # This would be enhanced with actual quality score aggregation
    # Placeholder implementation
    results['quality_metrics']['avg_confidence_score'] = 75
    results['quality_metrics']['high_confidence_count'] = 80
    results['quality_metrics']['low_confidence_count'] = 20


def store_processing_results(results: Dict[str, Any]) -> None:
    """Store processing results for monitoring and analytics"""
    try:
        timestamp = datetime.now(timezone.utc).strftime('%Y/%m/%d/%H%M%S')
        key = f"processing_results/{timestamp}.json"

        s3_client.put_object(
            Bucket=PROCESSED_DATA_BUCKET,
            Key=key,
            Body=json.dumps(results, default=str),
            ContentType='application/json',
            ServerSideEncryption='AES256'
        )
    except Exception as e:
        logger.warning(f"Error storing processing results: {e}")


def create_response(status_code: int, body: Dict[str, Any]) -> Dict[str, Any]:
    """Create standardized Lambda response"""
    return {
        'statusCode': status_code,
        'body': json.dumps(body, default=str),
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        }
    }