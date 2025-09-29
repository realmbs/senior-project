"""
Threat Intelligence Collector Lambda Function

This module collects threat intelligence from OSINT sources including:
- AT&T Alien Labs OTX (Open Threat Exchange)
- Abuse.ch threat feeds

Features:
- STIX 2.1 compliant data formatting
- Automatic deduplication using pattern hashing
- Cost-optimized with 256MB memory allocation
- Raw data archival to S3 for audit trails
"""

import json
import boto3
import hashlib
import logging
import os
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
import requests
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
STIX_VERSION = os.environ.get('STIX_VERSION', '2.1')

# DynamoDB Tables
threat_intel_table = dynamodb.Table(THREAT_INTEL_TABLE)
dedup_table = dynamodb.Table(DEDUP_TABLE)


def lambda_handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    """
    Main Lambda handler for threat intelligence collection

    Args:
        event: Lambda event data (API Gateway request or manual trigger)
        context: Lambda runtime context

    Returns:
        Dict containing collection results and status
    """
    try:
        logger.info(f"Starting threat intelligence collection - Environment: {ENVIRONMENT}")

        # Get API keys from Secrets Manager
        api_keys = get_api_keys()

        # Initialize collection results
        results = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'environment': ENVIRONMENT,
            'collections': {},
            'total_indicators': 0,
            'new_indicators': 0,
            'duplicates_filtered': 0
        }

        # Collection from AT&T Alien Labs OTX
        if api_keys.get('OTX_API_KEY'):
            logger.info("Collecting from AT&T Alien Labs OTX")
            otx_results = collect_from_otx(api_keys['OTX_API_KEY'])
            results['collections']['otx'] = otx_results
            results['total_indicators'] += otx_results['indicators_collected']
            results['new_indicators'] += otx_results['new_indicators']
            results['duplicates_filtered'] += otx_results['duplicates_filtered']
        else:
            logger.warning("OTX API key not found, skipping OTX collection")

        # Collection from Abuse.ch
        if api_keys.get('ABUSE_CH_API_KEY'):
            logger.info("Collecting from Abuse.ch")
            abuse_results = collect_from_abuse_ch(api_keys['ABUSE_CH_API_KEY'])
            results['collections']['abuse_ch'] = abuse_results
            results['total_indicators'] += abuse_results['indicators_collected']
            results['new_indicators'] += abuse_results['new_indicators']
            results['duplicates_filtered'] += abuse_results['duplicates_filtered']
        else:
            logger.warning("Abuse.ch API key not found, skipping Abuse.ch collection")

        logger.info(f"Collection completed: {results['new_indicators']} new indicators, "
                   f"{results['duplicates_filtered']} duplicates filtered")

        return {
            'statusCode': 200,
            'body': json.dumps(results),
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            }
        }

    except Exception as e:
        logger.error(f"Error in threat intelligence collection: {str(e)}", exc_info=True)
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': 'Internal server error',
                'message': str(e) if ENVIRONMENT == 'dev' else 'Collection failed'
            }),
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            }
        }


def get_api_keys() -> Dict[str, str]:
    """
    Retrieve API keys from AWS Secrets Manager

    Returns:
        Dict containing API keys for threat intelligence sources
    """
    try:
        response = secrets_client.get_secret_value(SecretId=SECRETS_MANAGER_ARN)
        return json.loads(response['SecretString'])
    except ClientError as e:
        logger.error(f"Error retrieving API keys: {e}")
        raise


def collect_from_otx(api_key: str) -> Dict[str, Any]:
    """
    Collect threat intelligence from AT&T Alien Labs OTX

    Args:
        api_key: OTX API key for authentication

    Returns:
        Dict containing collection results and metrics
    """
    results = {
        'source': 'otx',
        'indicators_collected': 0,
        'new_indicators': 0,
        'duplicates_filtered': 0,
        'errors': []
    }

    try:
        headers = {'X-OTX-API-KEY': api_key}

        # Get recent pulses (threat intelligence packages)
        url = 'https://otx.alienvault.com/api/v1/pulses/subscribed'
        params = {'limit': 50, 'modified_since': get_collection_timestamp()}

        response = requests.get(url, headers=headers, params=params, timeout=30)
        response.raise_for_status()

        data = response.json()

        # Archive raw data to S3
        archive_raw_data('otx', data)

        # Process pulses and extract indicators
        for pulse in data.get('results', []):
            pulse_indicators = process_otx_pulse(pulse)

            for indicator in pulse_indicators:
                if not is_duplicate(indicator):
                    store_indicator(indicator)
                    results['new_indicators'] += 1
                else:
                    results['duplicates_filtered'] += 1

                results['indicators_collected'] += 1

        logger.info(f"OTX collection: {results['indicators_collected']} indicators, "
                   f"{results['new_indicators']} new")

    except requests.RequestException as e:
        error_msg = f"OTX API request failed: {str(e)}"
        logger.error(error_msg)
        results['errors'].append(error_msg)
    except Exception as e:
        error_msg = f"OTX collection error: {str(e)}"
        logger.error(error_msg, exc_info=True)
        results['errors'].append(error_msg)

    return results


def collect_from_abuse_ch(api_key: str) -> Dict[str, Any]:
    """
    Collect threat intelligence from Abuse.ch

    Args:
        api_key: Abuse.ch API key for authentication

    Returns:
        Dict containing collection results and metrics
    """
    results = {
        'source': 'abuse_ch',
        'indicators_collected': 0,
        'new_indicators': 0,
        'duplicates_filtered': 0,
        'errors': []
    }

    try:
        headers = {'API-KEY': api_key}

        # Get malware hashes
        url = 'https://mb-api.abuse.ch/api/v1/'
        data = {'query': 'get_recent', 'selector': '24h'}

        response = requests.post(url, headers=headers, data=data, timeout=30)
        response.raise_for_status()

        data = response.json()

        # Archive raw data to S3
        archive_raw_data('abuse_ch', data)

        # Process indicators
        for item in data.get('data', []):
            indicator = process_abuse_ch_indicator(item)

            if indicator and not is_duplicate(indicator):
                store_indicator(indicator)
                results['new_indicators'] += 1
            elif indicator:
                results['duplicates_filtered'] += 1

            if indicator:
                results['indicators_collected'] += 1

        logger.info(f"Abuse.ch collection: {results['indicators_collected']} indicators, "
                   f"{results['new_indicators']} new")

    except requests.RequestException as e:
        error_msg = f"Abuse.ch API request failed: {str(e)}"
        logger.error(error_msg)
        results['errors'].append(error_msg)
    except Exception as e:
        error_msg = f"Abuse.ch collection error: {str(e)}"
        logger.error(error_msg, exc_info=True)
        results['errors'].append(error_msg)

    return results


def process_otx_pulse(pulse: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Process OTX pulse data into STIX 2.1 compliant indicators

    Args:
        pulse: OTX pulse data

    Returns:
        List of STIX 2.1 compliant indicator objects
    """
    indicators = []

    for indicator_data in pulse.get('indicators', []):
        try:
            indicator = {
                'type': 'indicator',
                'spec_version': '2.1',
                'id': f"indicator--{generate_stix_id()}",
                'created': datetime.now(timezone.utc).isoformat(),
                'modified': datetime.now(timezone.utc).isoformat(),
                'pattern': format_stix_pattern(indicator_data),
                'labels': ['malicious-activity'],
                'confidence': calculate_confidence(pulse, indicator_data),
                'source': 'otx',
                'external_references': [{
                    'source_name': 'otx_pulse',
                    'url': f"https://otx.alienvault.com/pulse/{pulse.get('id', '')}"
                }],
                'custom_properties': {
                    'pulse_name': pulse.get('name', ''),
                    'pulse_id': pulse.get('id', ''),
                    'indicator_type': indicator_data.get('type', ''),
                    'raw_indicator': indicator_data.get('indicator', '')
                }
            }

            indicators.append(indicator)

        except Exception as e:
            logger.warning(f"Error processing OTX indicator: {e}")
            continue

    return indicators


def process_abuse_ch_indicator(item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Process Abuse.ch indicator into STIX 2.1 compliant format

    Args:
        item: Abuse.ch indicator data

    Returns:
        STIX 2.1 compliant indicator object or None
    """
    try:
        indicator = {
            'type': 'indicator',
            'spec_version': '2.1',
            'id': f"indicator--{generate_stix_id()}",
            'created': datetime.now(timezone.utc).isoformat(),
            'modified': datetime.now(timezone.utc).isoformat(),
            'pattern': f"[file:hashes.MD5 = '{item.get('md5_hash', '')}']",
            'labels': ['malicious-activity'],
            'confidence': 85,  # High confidence for Abuse.ch data
            'source': 'abuse_ch',
            'custom_properties': {
                'malware_family': item.get('malware', ''),
                'file_size': item.get('file_size', 0),
                'first_seen': item.get('first_seen', ''),
                'file_type': item.get('file_type', ''),
                'sha256_hash': item.get('sha256_hash', ''),
                'sha1_hash': item.get('sha1_hash', '')
            }
        }

        return indicator

    except Exception as e:
        logger.warning(f"Error processing Abuse.ch indicator: {e}")
        return None


def is_duplicate(indicator: Dict[str, Any]) -> bool:
    """
    Check if indicator already exists using pattern hash deduplication

    Args:
        indicator: STIX indicator object

    Returns:
        True if duplicate exists, False otherwise
    """
    try:
        pattern_hash = generate_pattern_hash(indicator['pattern'])

        response = dedup_table.get_item(Key={'pattern_hash': pattern_hash})
        return 'Item' in response

    except Exception as e:
        logger.warning(f"Error checking for duplicate: {e}")
        return False


def store_indicator(indicator: Dict[str, Any]) -> None:
    """
    Store indicator in DynamoDB and update deduplication table

    Args:
        indicator: STIX indicator object to store
    """
    try:
        # Store in main threat intelligence table
        threat_intel_table.put_item(Item=indicator)

        # Update deduplication table
        pattern_hash = generate_pattern_hash(indicator['pattern'])
        ttl = int((datetime.now(timezone.utc).timestamp()) + (30 * 24 * 3600))  # 30 days TTL

        dedup_table.put_item(Item={
            'pattern_hash': pattern_hash,
            'first_seen': indicator['created'],
            'ttl': ttl
        })

    except Exception as e:
        logger.error(f"Error storing indicator: {e}")
        raise


def archive_raw_data(source: str, data: Dict[str, Any]) -> None:
    """
    Archive raw threat intelligence data to S3 for audit trails

    Args:
        source: Data source name (otx, abuse_ch)
        data: Raw data to archive
    """
    try:
        timestamp = datetime.now(timezone.utc).strftime('%Y/%m/%d/%H%M%S')
        key = f"raw_threat_intel/{source}/{timestamp}.json"

        s3_client.put_object(
            Bucket=RAW_DATA_BUCKET,
            Key=key,
            Body=json.dumps(data),
            ContentType='application/json',
            ServerSideEncryption='AES256'
        )

    except Exception as e:
        logger.warning(f"Error archiving raw data: {e}")


def generate_pattern_hash(pattern: str) -> str:
    """Generate SHA-256 hash of STIX pattern for deduplication"""
    return hashlib.sha256(pattern.encode()).hexdigest()


def generate_stix_id() -> str:
    """Generate UUID for STIX object identifier"""
    import uuid
    return str(uuid.uuid4())


def format_stix_pattern(indicator_data: Dict[str, Any]) -> str:
    """
    Format indicator data into STIX 2.1 pattern syntax

    Args:
        indicator_data: Raw indicator data

    Returns:
        STIX 2.1 pattern string
    """
    indicator_type = indicator_data.get('type', '').lower()
    indicator_value = indicator_data.get('indicator', '')

    patterns = {
        'ipv4': f"[ipv4-addr:value = '{indicator_value}']",
        'ipv6': f"[ipv6-addr:value = '{indicator_value}']",
        'domain': f"[domain-name:value = '{indicator_value}']",
        'hostname': f"[domain-name:value = '{indicator_value}']",
        'url': f"[url:value = '{indicator_value}']",
        'md5': f"[file:hashes.MD5 = '{indicator_value}']",
        'sha1': f"[file:hashes.SHA-1 = '{indicator_value}']",
        'sha256': f"[file:hashes.SHA-256 = '{indicator_value}']",
    }

    return patterns.get(indicator_type, f"[x-custom:value = '{indicator_value}']")


def calculate_confidence(pulse: Dict[str, Any], indicator_data: Dict[str, Any]) -> int:
    """
    Calculate confidence score for indicator based on source metadata

    Args:
        pulse: OTX pulse data
        indicator_data: Individual indicator data

    Returns:
        Confidence score (0-100)
    """
    base_confidence = 70

    # Increase confidence based on pulse quality
    if pulse.get('votes', {}).get('up', 0) > 5:
        base_confidence += 10

    if pulse.get('subscriber_count', 0) > 100:
        base_confidence += 5

    # Increase confidence for certain indicator types
    high_confidence_types = ['md5', 'sha1', 'sha256']
    if indicator_data.get('type', '').lower() in high_confidence_types:
        base_confidence += 10

    return min(base_confidence, 95)  # Cap at 95


def get_collection_timestamp() -> str:
    """
    Get timestamp for incremental collection (last 24 hours)

    Returns:
        ISO format timestamp string
    """
    from datetime import timedelta
    yesterday = datetime.now(timezone.utc) - timedelta(days=1)
    return yesterday.isoformat()