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
import base64
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

# CORS Headers Helper Function
def get_cors_headers():
    """Returns standard CORS headers for API Gateway Lambda proxy integration"""
    return {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
        'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
        'Content-Type': 'application/json'
    }


def get_api_keys() -> Dict[str, str]:
    """Retrieve API keys from AWS Secrets Manager"""
    try:
        logger.info(f"Retrieving API keys from Secrets Manager: {SECRETS_MANAGER_ARN}")
        response = secrets_client.get_secret_value(SecretId=SECRETS_MANAGER_ARN)
        logger.info("Secrets Manager response received successfully")

        secret_string = response['SecretString']
        logger.info(f"Secret string length: {len(secret_string)}")

        secrets = json.loads(secret_string)
        logger.info("Successfully parsed secrets JSON")

        return {
            'otx_api_key': secrets.get('OTX_API_KEY'),
            'abuse_ch_api_key': secrets.get('ABUSE_CH_API_KEY', '')  # Optional for URLhaus
        }
    except Exception as e:
        logger.error(f"Failed to retrieve API keys: {str(e)}")
        logger.error(f"Exception type: {type(e).__name__}")
        raise


def create_content_hash(indicator: str, indicator_type: str) -> str:
    """Create hash for deduplication"""
    pattern = f"{indicator_type}:{indicator.lower()}"
    return hashlib.sha256(pattern.encode()).hexdigest()


def check_duplicate(content_hash: str) -> bool:
    """Check if indicator already exists"""
    try:
        response = dedup_table.get_item(Key={'content_hash': content_hash})
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
        content_hash = indicator_data['content_hash']
        ttl = int(time.time()) + (30 * 24 * 3600)  # 30 days TTL
        dedup_table.put_item(Item={
            'content_hash': content_hash,
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
    """Collect basic indicators from OTX with enhanced error handling and debugging"""
    indicators = []

    # Enhanced headers to mimic browser requests
    headers = {
        'X-OTX-API-KEY': api_key,
        'User-Agent': 'ThreatIntelPlatform/1.0 (AWS Lambda; Python/3.9)',
        'Accept': 'application/json',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
        'Cache-Control': 'no-cache'
    }

    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    params = {'limit': min(limit, OTX_BATCH_SIZE)}

    # Retry logic with exponential backoff
    for attempt in range(MAX_RETRIES + 1):
        try:
            logger.info(f"OTX API attempt {attempt + 1}/{MAX_RETRIES + 1}")
            logger.info(f"Request URL: {url}")
            logger.info(f"Request params: {params}")
            logger.info(f"Request headers: {dict(headers)}")

            # Make request with enhanced configuration
            response = requests.get(
                url=url,
                headers=headers,
                params=params,
                timeout=45,  # Increased timeout
                verify=True,  # Ensure SSL verification
                allow_redirects=True
            )

            # Log response details before processing
            logger.info(f"OTX API response status: {response.status_code}")
            logger.info(f"OTX API response headers: {dict(response.headers)}")
            logger.info(f"OTX API response size: {len(response.content)} bytes")
            logger.info(f"OTX API response encoding: {response.encoding}")

            # Check response status
            response.raise_for_status()

            # Validate response content
            content_type = response.headers.get('content-type', '').lower()
            if 'application/json' not in content_type:
                logger.warning(f"Unexpected content type: {content_type}")

            # Check if response has content
            if not response.content:
                logger.error("OTX API returned empty response")
                if attempt < MAX_RETRIES:
                    wait_time = 2 ** attempt
                    logger.info(f"Retrying in {wait_time} seconds...")
                    time.sleep(wait_time)
                    continue
                else:
                    logger.error("All retry attempts failed - returning empty indicators")
                    return indicators

            # Log first 500 characters of response for debugging
            response_preview = response.text[:500] if response.text else "No text content"
            logger.info(f"OTX API response preview: {response_preview}")

            # Parse JSON response
            try:
                data = response.json()
                logger.info(f"Successfully parsed JSON response")
                logger.info(f"OTX API response successful: {len(data.get('results', []))} pulses received")
            except json.JSONDecodeError as json_error:
                logger.error(f"JSON parsing failed: {str(json_error)}")
                logger.error(f"Response content type: {response.headers.get('content-type')}")
                logger.error(f"Raw response content: {response.text[:1000]}")

                if attempt < MAX_RETRIES:
                    wait_time = 2 ** attempt
                    logger.info(f"JSON parse error - retrying in {wait_time} seconds...")
                    time.sleep(wait_time)
                    continue
                else:
                    logger.error("All retry attempts failed due to JSON parsing errors")
                    return indicators

            # Archive raw data for analysis
            archive_raw_data('otx', data)

            # Process the pulses and indicators
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
                    content_hash = create_content_hash(ioc_value, ioc_type)
                    if not check_duplicate(content_hash):
                        indicator_record = {
                            'object_id': stix_indicator['id'],  # Required partition key
                            'object_type': 'indicator',         # Required sort key
                            'content_hash': content_hash,       # Required for main table
                            'indicator_id': stix_indicator['id'],
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

            # Success - break out of retry loop
            logger.info(f"OTX collection successful: {len(indicators)} new indicators")
            break

        except requests.exceptions.Timeout as e:
            logger.error(f"OTX API timeout on attempt {attempt + 1}: {str(e)}")
            if attempt < MAX_RETRIES:
                wait_time = 2 ** attempt
                logger.info(f"Timeout - retrying in {wait_time} seconds...")
                time.sleep(wait_time)
            else:
                logger.error("All retry attempts failed due to timeouts")

        except requests.exceptions.ConnectionError as e:
            logger.error(f"OTX API connection error on attempt {attempt + 1}: {str(e)}")
            if attempt < MAX_RETRIES:
                wait_time = 2 ** attempt
                logger.info(f"Connection error - retrying in {wait_time} seconds...")
                time.sleep(wait_time)
            else:
                logger.error("All retry attempts failed due to connection errors")

        except requests.exceptions.HTTPError as e:
            logger.error(f"OTX API HTTP error on attempt {attempt + 1}: {str(e)}")
            if hasattr(e, 'response') and e.response is not None:
                logger.error(f"HTTP status: {e.response.status_code}")
                logger.error(f"HTTP response: {e.response.text[:500]}")

            # Don't retry on 4xx errors (client errors)
            if hasattr(e, 'response') and e.response is not None and 400 <= e.response.status_code < 500:
                logger.error("Client error - not retrying")
                break
            elif attempt < MAX_RETRIES:
                wait_time = 2 ** attempt
                logger.info(f"Server error - retrying in {wait_time} seconds...")
                time.sleep(wait_time)
            else:
                logger.error("All retry attempts failed due to HTTP errors")

        except Exception as e:
            logger.error(f"OTX collection unexpected error on attempt {attempt + 1}: {str(e)}")
            logger.error(f"Exception type: {type(e).__name__}")
            if attempt < MAX_RETRIES:
                wait_time = 2 ** attempt
                logger.info(f"Unexpected error - retrying in {wait_time} seconds...")
                time.sleep(wait_time)
            else:
                logger.error("All retry attempts failed due to unexpected errors")

    return indicators


def collect_abuse_ch_indicators(api_key: str, limit: int = 50) -> List[Dict[str, Any]]:
    """Collect basic indicators from Abuse.ch URLhaus"""
    indicators = []
    try:
        url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
        headers = {
            'Auth-Key': api_key,
            'User-Agent': 'ThreatIntelPlatform/1.0 (AWS Lambda; Python/3.9)'
        }
        params = {'limit': min(limit, 1000)}  # URLhaus supports up to 1000

        response = requests.get(url, headers=headers, params=params, timeout=30)
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
            content_hash = create_content_hash(url_value, 'URL')
            if not check_duplicate(content_hash):
                indicator_record = {
                    'object_id': stix_indicator['id'],  # Required partition key
                    'object_type': 'indicator',         # Required sort key
                    'content_hash': content_hash,       # Required for main table
                    'indicator_id': stix_indicator['id'],
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

        # Parse request with enhanced debugging
        logger.info(f"Event keys: {list(event.keys())}")
        logger.info(f"isBase64Encoded: {event.get('isBase64Encoded', 'Not present')}")

        if 'body' in event and event['body']:
            logger.info(f"Event body type: {type(event['body'])}")

            # Handle base64 encoded body from API Gateway
            if event.get('isBase64Encoded', False):
                logger.info("Decoding base64 encoded body")
                try:
                    decoded_body = base64.b64decode(event['body']).decode('utf-8')
                    logger.info(f"Decoded body: {decoded_body}")
                    body = json.loads(decoded_body)
                    logger.info("Successfully parsed base64 decoded JSON")
                except Exception as e:
                    logger.error(f"Failed to decode base64 body: {e}")
                    raise
            elif isinstance(event['body'], str):
                try:
                    body = json.loads(event['body'])
                    logger.info("Successfully parsed event body JSON")
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse event body: {e}")
                    logger.error(f"Raw body: {repr(event['body'])}")
                    raise
            else:
                body = event['body']
        else:
            logger.info("No body in event, using event directly")
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

        # Collect from Abuse.ch URLhaus
        if 'abuse_ch' in sources and api_keys.get('abuse_ch_api_key'):
            logger.info("Collecting from Abuse.ch URLhaus...")
            abuse_indicators = collect_abuse_ch_indicators(
                api_keys['abuse_ch_api_key'],
                limit
            )
            all_indicators.extend(abuse_indicators)
            collection_stats['abuse_ch'] = len(abuse_indicators)
        elif 'abuse_ch' in sources:
            logger.warning("Abuse.ch API key not found in Secrets Manager")
            collection_stats['abuse_ch'] = 0

        # Store indicators
        stored_count = 0
        for indicator in all_indicators:
            if store_indicator(indicator):
                stored_count += 1

        result = {
            'statusCode': 200,
            'headers': get_cors_headers(),
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
            'headers': get_cors_headers(),
            'body': json.dumps({
                'error': 'Collection failed',
                'message': str(e),
                'timestamp': datetime.now(timezone.utc).isoformat()
            })
        }