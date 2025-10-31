"""
Threat Intelligence Collector Lambda Function - MVP Version

Minimal viable threat intelligence collection from:
- AT&T Alien Labs OTX (Open Threat Exchange) - basic collection
- Abuse.ch URLhaus feed - single feed only

MVP Features:
- Basic STIX 2.1 data formatting
- Simple deduplication using hashes
- DynamoDB storage with S3 archival
- Essential error handling
"""

import json
import boto3
import hashlib
import logging
import os
import time
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

# Basic Configuration
OTX_BATCH_SIZE = 20   # Reduced batch size for MVP
MAX_RETRIES = 2

# DynamoDB Tables
threat_intel_table = dynamodb.Table(THREAT_INTEL_TABLE)
dedup_table = dynamodb.Table(DEDUP_TABLE)


def get_api_keys() -> Dict[str, str]:
    """Retrieve API keys from AWS Secrets Manager"""
    try:
        response = secrets_client.get_secret_value(SecretId=SECRETS_MANAGER_ARN)
        secrets = json.loads(response['SecretString'])
        return {
            'otx_api_key': secrets.get('OTX_API_KEY'),
            'abuse_ch_api_key': secrets.get('ABUSE_CH_API_KEY', '')  # Optional for URLhaus
        }
    except Exception as e:
        logger.error(f"Failed to retrieve API keys: {str(e)}")
        raise


def create_pattern_hash(indicator: str, indicator_type: str) -> str:
    """Create hash for deduplication"""
    pattern = f"{indicator_type}:{indicator.lower()}"
    return hashlib.sha256(pattern.encode()).hexdigest()


def check_duplicate(pattern_hash: str) -> bool:
    """Check if indicator already exists"""
    try:
        response = dedup_table.get_item(Key={'pattern_hash': pattern_hash})
        return 'Item' in response
    except Exception as e:
        logger.error(f"Duplicate check failed: {str(e)}")
        return False


def store_indicator(indicator_data: Dict[str, Any]) -> bool:
    """Store indicator in DynamoDB"""
    try:
        # Store in main table
        threat_intel_table.put_item(Item=indicator_data)

        # Store hash for deduplication
        pattern_hash = indicator_data['pattern_hash']
        ttl = int(time.time()) + (30 * 24 * 3600)  # 30 days TTL
        dedup_table.put_item(Item={
            'pattern_hash': pattern_hash,
            'created_at': indicator_data['created_at'],
            'ttl': ttl
        })
        return True
    except Exception as e:
        logger.error(f"Failed to store indicator: {str(e)}")
        return False


def archive_raw_data(source: str, data: Dict[str, Any]) -> None:
    """Archive raw data to S3"""
    try:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        key = f"raw/{source}/{timestamp}_{os.urandom(4).hex()}.json"

        s3_client.put_object(
            Bucket=RAW_DATA_BUCKET,
            Key=key,
            Body=json.dumps(data, indent=2),
            ContentType='application/json'
        )
        logger.info(f"Archived raw data to s3://{RAW_DATA_BUCKET}/{key}")
    except Exception as e:
        logger.error(f"Failed to archive raw data: {str(e)}")


def collect_otx_indicators(api_key: str, limit: int = 50) -> List[Dict[str, Any]]:
    """Collect basic indicators from OTX"""
    indicators = []
    try:
        url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
        headers = {'X-OTX-API-KEY': api_key}
        params = {'limit': min(limit, OTX_BATCH_SIZE)}

        response = requests.get(url, headers=headers, params=params, timeout=30)
        response.raise_for_status()

        data = response.json()
        archive_raw_data('otx', data)

        for pulse in data.get('results', []):
            for indicator in pulse.get('indicators', []):
                ioc_type = indicator.get('type', '').lower()
                ioc_value = indicator.get('indicator', '').strip()

                if not ioc_value or ioc_type not in ['IPv4', 'domain', 'hostname', 'URL']:
                    continue

                # Create basic STIX 2.1 indicator
                stix_indicator = {
                    'id': f"indicator--{os.urandom(16).hex()}",
                    'type': 'indicator',
                    'spec_version': '2.1',
                    'pattern': f"[{get_stix_pattern_type(ioc_type)}:value = '{ioc_value}']",
                    'labels': ['malicious-activity'],
                    'created': datetime.now(timezone.utc).isoformat(),
                    'modified': datetime.now(timezone.utc).isoformat(),
                    'source': 'otx',
                    'confidence': 75,  # Default confidence
                    'ioc_value': ioc_value,
                    'ioc_type': ioc_type
                }

                # Add metadata
                pattern_hash = create_pattern_hash(ioc_value, ioc_type)
                if not check_duplicate(pattern_hash):
                    indicator_record = {
                        'indicator_id': stix_indicator['id'],
                        'pattern_hash': pattern_hash,
                        'source': 'otx',
                        'ioc_type': ioc_type,
                        'ioc_value': ioc_value,
                        'confidence': 75,
                        'created_at': datetime.now(timezone.utc).isoformat(),
                        'stix_data': stix_indicator,
                        'pulse_name': pulse.get('name', ''),
                        'threat_type': 'unknown'
                    }
                    indicators.append(indicator_record)

    except Exception as e:
        logger.error(f"OTX collection failed: {str(e)}")

    return indicators


def collect_abuse_ch_indicators(limit: int = 50) -> List[Dict[str, Any]]:
    """Collect basic indicators from Abuse.ch URLhaus"""
    indicators = []
    try:
        url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
        data = {'limit': min(limit, 100)}

        response = requests.post(url, data=data, timeout=30)
        response.raise_for_status()

        result = response.json()
        archive_raw_data('abuse_ch_urlhaus', result)

        for url_data in result.get('urls', []):
            url_value = url_data.get('url', '').strip()
            if not url_value:
                continue

            # Create basic STIX 2.1 indicator
            stix_indicator = {
                'id': f"indicator--{os.urandom(16).hex()}",
                'type': 'indicator',
                'spec_version': '2.1',
                'pattern': f"[url:value = '{url_value}']",
                'labels': ['malicious-activity'],
                'created': datetime.now(timezone.utc).isoformat(),
                'modified': datetime.now(timezone.utc).isoformat(),
                'source': 'abuse_ch',
                'confidence': 85,  # Abuse.ch typically high confidence
                'ioc_value': url_value,
                'ioc_type': 'URL'
            }

            # Add metadata
            pattern_hash = create_pattern_hash(url_value, 'URL')
            if not check_duplicate(pattern_hash):
                indicator_record = {
                    'indicator_id': stix_indicator['id'],
                    'pattern_hash': pattern_hash,
                    'source': 'abuse_ch',
                    'ioc_type': 'URL',
                    'ioc_value': url_value,
                    'confidence': 85,
                    'created_at': datetime.now(timezone.utc).isoformat(),
                    'stix_data': stix_indicator,
                    'threat_type': url_data.get('threat', 'malware'),
                    'tags': url_data.get('tags', [])
                }
                indicators.append(indicator_record)

    except Exception as e:
        logger.error(f"Abuse.ch collection failed: {str(e)}")

    return indicators


def get_stix_pattern_type(ioc_type: str) -> str:
    """Map IOC type to STIX pattern type"""
    mapping = {
        'ipv4': 'ipv4-addr',
        'domain': 'domain-name',
        'hostname': 'domain-name',
        'url': 'url'
    }
    return mapping.get(ioc_type.lower(), 'domain-name')


def lambda_handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    """
    Main Lambda handler for threat intelligence collection

    Args:
        event: Lambda event data
        context: Lambda runtime context

    Returns:
        Dict containing collection results
    """
    try:
        logger.info(f"Starting threat intelligence collection - Environment: {ENVIRONMENT}")

        # Get API keys
        api_keys = get_api_keys()

        # Parse request
        if 'body' in event and event['body']:
            body = json.loads(event['body']) if isinstance(event['body'], str) else event['body']
        else:
            body = event

        sources = body.get('sources', ['otx', 'abuse_ch'])
        limit = min(body.get('limit', 50), 100)  # Cap at 100 for MVP

        all_indicators = []
        collection_stats = {}

        # Collect from OTX
        if 'otx' in sources and api_keys['otx_api_key']:
            logger.info("Collecting from OTX...")
            otx_indicators = collect_otx_indicators(api_keys['otx_api_key'], limit)
            all_indicators.extend(otx_indicators)
            collection_stats['otx'] = len(otx_indicators)

        # Collect from Abuse.ch
        if 'abuse_ch' in sources:
            logger.info("Collecting from Abuse.ch URLhaus...")
            abuse_indicators = collect_abuse_ch_indicators(limit)
            all_indicators.extend(abuse_indicators)
            collection_stats['abuse_ch'] = len(abuse_indicators)

        # Store indicators
        stored_count = 0
        for indicator in all_indicators:
            if store_indicator(indicator):
                stored_count += 1

        result = {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Collection completed successfully',
                'indicators_collected': len(all_indicators),
                'indicators_stored': stored_count,
                'collection_stats': collection_stats,
                'timestamp': datetime.now(timezone.utc).isoformat()
            })
        }

        logger.info(f"Collection completed: {stored_count}/{len(all_indicators)} indicators stored")
        return result

    except Exception as e:
        logger.error(f"Collection failed: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': 'Collection failed',
                'message': str(e),
                'timestamp': datetime.now(timezone.utc).isoformat()
            })
        }