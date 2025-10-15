"""
Threat Intelligence Collector Lambda Function
Phase 8B Enhanced: Event-driven architecture integration

This module collects threat intelligence from OSINT sources including:
- AT&T Alien Labs OTX (Open Threat Exchange)
- Abuse.ch threat feeds

Features:
- STIX 2.1 compliant data formatting
- Automatic deduplication using pattern hashing
- Cost-optimized with 256MB memory allocation
- Raw data archival to S3 for audit trails
- EventBridge integration for automated processing triggers
- Priority-based processing classification
- Workflow correlation and tracking
"""

# Import event utilities for Phase 8B integration
try:
    from event_utils import (
        emit_collection_completed, WorkflowTracker, ThreatAnalyzer,
        ProcessingPriority, EventEmitter, EventType
    )
    EVENT_INTEGRATION_AVAILABLE = True
except ImportError:
    logger.warning("Event utilities not available - running without event integration")
    EVENT_INTEGRATION_AVAILABLE = False

import json
import boto3
import hashlib
import logging
import os
import time
import random
from datetime import datetime, timezone, timedelta
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
COLLECTION_STATE_TABLE = os.environ.get('COLLECTION_STATE_TABLE', f'{THREAT_INTEL_TABLE}-state')
STIX_VERSION = os.environ.get('STIX_VERSION', '2.1')

# Rate Limiting and Circuit Breaker Configuration
OTX_RATE_LIMIT = 900  # 900 requests per hour (buffer under 1000 limit)
OTX_BATCH_SIZE = 50   # Pulses per request
CIRCUIT_BREAKER_FAILURE_THRESHOLD = 5
CIRCUIT_BREAKER_TIMEOUT = 300  # 5 minutes
MAX_RETRIES = 3
BASE_BACKOFF_DELAY = 1  # seconds

# DynamoDB Tables
threat_intel_table = dynamodb.Table(THREAT_INTEL_TABLE)
dedup_table = dynamodb.Table(DEDUP_TABLE)
collection_state_table = dynamodb.Table(COLLECTION_STATE_TABLE)


class CircuitBreaker:
    """
    Circuit breaker implementation for API resilience

    Tracks failure rates and implements circuit breaker pattern with:
    - Failure threshold monitoring
    - Exponential backoff with jitter
    - Automatic recovery attempts
    """

    def __init__(self, service_name: str):
        self.service_name = service_name
        self.failure_count = 0
        self.last_failure_time = None
        self.state = 'closed'  # closed, open, half_open

    def call(self, func, *args, **kwargs):
        """Execute function with circuit breaker protection"""
        if self.state == 'open':
            if time.time() - self.last_failure_time > CIRCUIT_BREAKER_TIMEOUT:
                self.state = 'half_open'
                logger.info(f"Circuit breaker for {self.service_name} entering half-open state")
            else:
                raise Exception(f"Circuit breaker for {self.service_name} is OPEN")

        try:
            result = func(*args, **kwargs)
            if self.state == 'half_open':
                self.state = 'closed'
                self.failure_count = 0
                logger.info(f"Circuit breaker for {self.service_name} reset to closed state")
            return result

        except Exception as e:
            self.failure_count += 1
            self.last_failure_time = time.time()

            if self.failure_count >= CIRCUIT_BREAKER_FAILURE_THRESHOLD:
                self.state = 'open'
                logger.warning(f"Circuit breaker for {self.service_name} opened after {self.failure_count} failures")

            raise e


class RateLimiter:
    """
    Token bucket rate limiter for API calls

    Implements sliding window rate limiting with:
    - Configurable rate limits per service
    - Automatic token replenishment
    - Request queuing and throttling
    """

    def __init__(self, service_name: str, max_requests: int, time_window: int = 3600):
        self.service_name = service_name
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = []

    def can_make_request(self) -> bool:
        """Check if request can be made within rate limits"""
        current_time = time.time()

        # Remove requests outside time window
        self.requests = [req_time for req_time in self.requests
                        if current_time - req_time < self.time_window]

        return len(self.requests) < self.max_requests

    def record_request(self):
        """Record a new request timestamp"""
        self.requests.append(time.time())

    def wait_if_needed(self):
        """Block until request can be made within rate limits"""
        while not self.can_make_request():
            sleep_time = 1 + (len(self.requests) / self.max_requests) * 10
            logger.info(f"Rate limiting {self.service_name}: sleeping {sleep_time:.2f}s")
            time.sleep(sleep_time)


# Global circuit breakers and rate limiters
otx_circuit_breaker = CircuitBreaker('otx')
abuse_ch_circuit_breaker = CircuitBreaker('abuse_ch')
otx_rate_limiter = RateLimiter('otx', OTX_RATE_LIMIT)
abuse_ch_rate_limiter = RateLimiter('abuse_ch', 1000)  # Abuse.ch allows 1000 req/day


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
            results['total_indicators'] += abuse_results['total_indicators']
            results['new_indicators'] += abuse_results['total_new_indicators']
            results['duplicates_filtered'] += abuse_results['total_duplicates_filtered']
        else:
            logger.warning("Abuse.ch API key not found, skipping Abuse.ch collection")

        logger.info(f"Collection completed: {results['new_indicators']} new indicators, "
                   f"{results['duplicates_filtered']} duplicates filtered")

        # Phase 8B: Emit collection completed events for event-driven processing
        if EVENT_INTEGRATION_AVAILABLE and results['new_indicators'] > 0:
            correlation_id = WorkflowTracker.generate_correlation_id()

            # Prepare collection data with indicators for processing
            collection_data = {
                'indicators_collected': results['total_indicators'],
                'new_indicators': results['new_indicators'],
                'duplicates_filtered': results['duplicates_filtered'],
                'collections': results['collections'],
                'indicators': _extract_collected_indicators(results)  # Include actual indicators
            }

            # Emit overall collection completed event
            success = emit_collection_completed(
                source='multi-source',
                stats=collection_data,
                correlation_id=correlation_id
            )

            if success:
                logger.info(f"Collection completed event emitted with correlation_id: {correlation_id}")
                results['workflow'] = {
                    'correlation_id': correlation_id,
                    'event_emitted': True,
                    'processing_triggered': True
                }
            else:
                logger.warning("Failed to emit collection completed event")
                results['workflow'] = {
                    'event_emitted': False,
                    'processing_triggered': False
                }

            # Emit source-specific events for individual collections
            for source, collection_result in results['collections'].items():
                if collection_result.get('new_indicators', 0) > 0:
                    source_success = emit_collection_completed(
                        source=source,
                        stats=collection_result,
                        correlation_id=correlation_id
                    )
                    logger.info(f"Source-specific event for {source}: {'success' if source_success else 'failed'}")

        elif EVENT_INTEGRATION_AVAILABLE:
            logger.info("No new indicators collected - skipping event emission")
            results['workflow'] = {
                'event_emitted': False,
                'processing_triggered': False,
                'reason': 'no_new_indicators'
            }

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


def collect_from_otx(api_key: str, max_pages: int = 10) -> Dict[str, Any]:
    """
    Collect threat intelligence from AT&T Alien Labs OTX with pagination and resilience

    Features:
    - Full pagination through available pulses
    - Rate limiting with intelligent backoff
    - Circuit breaker protection
    - Resume capability with state persistence
    - Exponential backoff on failures

    Args:
        api_key: OTX API key for authentication
        max_pages: Maximum pages to collect per invocation (prevents Lambda timeout)

    Returns:
        Dict containing collection results and metrics
    """
    results = {
        'source': 'otx',
        'indicators_collected': 0,
        'new_indicators': 0,
        'duplicates_filtered': 0,
        'pages_processed': 0,
        'errors': [],
        'collection_complete': False
    }

    try:
        headers = {'X-OTX-API-KEY': api_key}
        base_url = 'https://otx.alienvault.com/api/v1/pulses/subscribed'

        # Get or initialize collection state
        collection_state = get_collection_state('otx')
        next_url = collection_state.get('next_url')

        # If no existing collection, start fresh
        if not next_url:
            params = {
                'limit': OTX_BATCH_SIZE,
                'modified_since': get_collection_timestamp()
            }
            next_url = f"{base_url}?" + "&".join([f"{k}={v}" for k, v in params.items()])

        page_count = 0
        while next_url and page_count < max_pages:
            try:
                # Rate limiting and circuit breaker protection
                otx_rate_limiter.wait_if_needed()

                # Make API request with circuit breaker
                response_data = otx_circuit_breaker.call(
                    make_otx_request, headers, next_url
                )

                otx_rate_limiter.record_request()

                # Archive raw data to S3
                archive_raw_data('otx', response_data, f"page_{page_count}")

                # Process pulses and extract indicators
                for pulse in response_data.get('results', []):
                    pulse_indicators = process_otx_pulse(pulse)

                    for indicator in pulse_indicators:
                        if not is_duplicate(indicator):
                            store_indicator(indicator)
                            results['new_indicators'] += 1
                        else:
                            results['duplicates_filtered'] += 1

                        results['indicators_collected'] += 1

                # Update pagination
                next_url = response_data.get('next')
                page_count += 1
                results['pages_processed'] = page_count

                # Save collection state for resume capability
                update_collection_state('otx', {
                    'next_url': next_url,
                    'last_processed': datetime.now(timezone.utc).isoformat(),
                    'indicators_collected': results['indicators_collected']
                })

                logger.info(f"OTX page {page_count}: {len(response_data.get('results', []))} pulses processed")

                # Add small delay to be respectful to API
                time.sleep(0.5)

            except Exception as e:
                error_msg = f"OTX page {page_count} failed: {str(e)}"
                logger.error(error_msg)
                results['errors'].append(error_msg)

                # Exponential backoff on page failures
                if page_count < max_pages - 1:  # Don't sleep on last iteration
                    backoff_delay = min(BASE_BACKOFF_DELAY * (2 ** page_count), 60)
                    jitter = random.uniform(0.1, 0.5) * backoff_delay
                    sleep_time = backoff_delay + jitter
                    logger.info(f"Backing off for {sleep_time:.2f}s after OTX error")
                    time.sleep(sleep_time)

        # Mark collection as complete if no more pages
        if not next_url:
            results['collection_complete'] = True
            clear_collection_state('otx')
            logger.info("OTX collection completed - no more pages")

        logger.info(f"OTX collection: {results['pages_processed']} pages, "
                   f"{results['indicators_collected']} indicators, "
                   f"{results['new_indicators']} new")

    except Exception as e:
        error_msg = f"OTX collection error: {str(e)}"
        logger.error(error_msg, exc_info=True)
        results['errors'].append(error_msg)

    return results


def make_otx_request(headers: Dict[str, str], url: str) -> Dict[str, Any]:
    """
    Make OTX API request with retry logic

    Args:
        headers: Request headers including API key
        url: Full URL to request

    Returns:
        JSON response data
    """
    for attempt in range(MAX_RETRIES):
        try:
            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            return response.json()

        except requests.RequestException as e:
            if attempt == MAX_RETRIES - 1:
                raise

            backoff_delay = BASE_BACKOFF_DELAY * (2 ** attempt)
            jitter = random.uniform(0.1, 0.5) * backoff_delay
            sleep_time = backoff_delay + jitter

            logger.warning(f"OTX request attempt {attempt + 1} failed: {e}. "
                         f"Retrying in {sleep_time:.2f}s")
            time.sleep(sleep_time)


def get_collection_state(source: str) -> Dict[str, Any]:
    """
    Get collection state for resumable collection

    Args:
        source: Data source name (otx, abuse_ch, etc.)

    Returns:
        Collection state dict or empty dict if not found
    """
    try:
        response = collection_state_table.get_item(
            Key={'source': source}
        )
        return response.get('Item', {})
    except Exception as e:
        logger.warning(f"Error getting collection state for {source}: {e}")
        return {}


def update_collection_state(source: str, state: Dict[str, Any]) -> None:
    """
    Update collection state for resume capability

    Args:
        source: Data source name
        state: State data to save
    """
    try:
        collection_state_table.put_item(
            Item={
                'source': source,
                'updated': datetime.now(timezone.utc).isoformat(),
                **state
            }
        )
    except Exception as e:
        logger.warning(f"Error updating collection state for {source}: {e}")


def clear_collection_state(source: str) -> None:
    """
    Clear collection state when collection is complete

    Args:
        source: Data source name
    """
    try:
        collection_state_table.delete_item(
            Key={'source': source}
        )
    except Exception as e:
        logger.warning(f"Error clearing collection state for {source}: {e}")


def collect_from_abuse_ch(api_key: str) -> Dict[str, Any]:
    """
    Collect threat intelligence from multiple Abuse.ch feeds with circuit breaker protection

    Supported Feeds:
    - MalwareBazaar: Malware samples and hashes
    - URLhaus: Malicious URLs and domains
    - ThreatFox: IOCs from various sources
    - Feodo Tracker: Botnet C&C servers

    Args:
        api_key: Abuse.ch API key for authentication

    Returns:
        Dict containing collection results and metrics
    """
    results = {
        'source': 'abuse_ch',
        'feeds': {},
        'total_indicators': 0,
        'total_new_indicators': 0,
        'total_duplicates_filtered': 0,
        'errors': []
    }

    # Define Abuse.ch feeds configuration
    feeds_config = {
        'malwarebazaar': {
            'url': 'https://mb-api.abuse.ch/api/v1/',
            'payload': {'query': 'get_recent', 'selector': '24h'},
            'method': 'POST'
        },
        'urlhaus': {
            'url': 'https://urlhaus-api.abuse.ch/v1/urls/recent/',
            'payload': {'days': '1'},
            'method': 'POST'
        },
        'threatfox': {
            'url': 'https://threatfox-api.abuse.ch/api/v1/',
            'payload': {'query': 'get_iocs', 'days': '1'},
            'method': 'POST'
        },
        'feodo': {
            'url': 'https://feodotracker.abuse.ch/downloads/ipblocklist.json',
            'payload': None,
            'method': 'GET'
        }
    }

    headers = {'API-KEY': api_key, 'User-Agent': 'threat-intel-platform/1.0'}

    # Collect from each feed
    for feed_name, feed_config in feeds_config.items():
        feed_results = {
            'feed': feed_name,
            'indicators_collected': 0,
            'new_indicators': 0,
            'duplicates_filtered': 0,
            'errors': []
        }

        try:
            logger.info(f"Collecting from Abuse.ch {feed_name}")

            # Rate limiting and circuit breaker protection
            abuse_ch_rate_limiter.wait_if_needed()

            # Make API request with circuit breaker
            response_data = abuse_ch_circuit_breaker.call(
                make_abuse_ch_request, headers, feed_config
            )

            abuse_ch_rate_limiter.record_request()

            # Archive raw data to S3
            archive_raw_data('abuse_ch', response_data, feed_name)

            # Process indicators based on feed type
            indicators = process_abuse_ch_feed(feed_name, response_data)

            for indicator in indicators:
                if indicator and not is_duplicate(indicator):
                    store_indicator(indicator)
                    feed_results['new_indicators'] += 1
                elif indicator:
                    feed_results['duplicates_filtered'] += 1

                if indicator:
                    feed_results['indicators_collected'] += 1

            # Update totals
            results['total_indicators'] += feed_results['indicators_collected']
            results['total_new_indicators'] += feed_results['new_indicators']
            results['total_duplicates_filtered'] += feed_results['duplicates_filtered']

            logger.info(f"Abuse.ch {feed_name}: {feed_results['indicators_collected']} indicators, "
                       f"{feed_results['new_indicators']} new")

            # Add small delay between feeds
            time.sleep(1)

        except Exception as e:
            error_msg = f"Abuse.ch {feed_name} failed: {str(e)}"
            logger.error(error_msg)
            feed_results['errors'].append(error_msg)
            results['errors'].append(error_msg)

        results['feeds'][feed_name] = feed_results

    logger.info(f"Abuse.ch total: {results['total_indicators']} indicators, "
               f"{results['total_new_indicators']} new")

    return results


def make_abuse_ch_request(headers: Dict[str, str], feed_config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Make Abuse.ch API request with retry logic

    Args:
        headers: Request headers including API key
        feed_config: Feed configuration with URL, payload, method

    Returns:
        JSON response data or parsed data
    """
    for attempt in range(MAX_RETRIES):
        try:
            if feed_config['method'] == 'POST':
                response = requests.post(
                    feed_config['url'],
                    headers=headers,
                    data=feed_config['payload'],
                    timeout=30
                )
            else:  # GET
                response = requests.get(
                    feed_config['url'],
                    headers=headers,
                    timeout=30
                )

            response.raise_for_status()

            # Handle different response formats
            if 'json' in feed_config['url'] or response.headers.get('content-type', '').startswith('application/json'):
                return response.json()
            else:
                return {'data': response.text.strip().split('\n')}

        except requests.RequestException as e:
            if attempt == MAX_RETRIES - 1:
                raise

            backoff_delay = BASE_BACKOFF_DELAY * (2 ** attempt)
            jitter = random.uniform(0.1, 0.5) * backoff_delay
            sleep_time = backoff_delay + jitter

            logger.warning(f"Abuse.ch request attempt {attempt + 1} failed: {e}. "
                         f"Retrying in {sleep_time:.2f}s")
            time.sleep(sleep_time)


def process_abuse_ch_feed(feed_name: str, data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Process different Abuse.ch feed formats into STIX 2.1 indicators

    Args:
        feed_name: Name of the Abuse.ch feed
        data: Raw feed data

    Returns:
        List of STIX 2.1 compliant indicator objects
    """
    indicators = []

    try:
        if feed_name == 'malwarebazaar':
            indicators = process_malwarebazaar_feed(data)
        elif feed_name == 'urlhaus':
            indicators = process_urlhaus_feed(data)
        elif feed_name == 'threatfox':
            indicators = process_threatfox_feed(data)
        elif feed_name == 'feodo':
            indicators = process_feodo_feed(data)

    except Exception as e:
        logger.error(f"Error processing {feed_name} feed: {e}")

    return indicators


def process_malwarebazaar_feed(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Process MalwareBazaar feed (malware hashes)"""
    indicators = []

    for item in data.get('data', []):
        try:
            # Create STIX indicator for file hash
            sha256 = item.get('sha256_hash', '')
            if sha256:
                indicator = {
                    'type': 'indicator',
                    'spec_version': '2.1',
                    'id': f"indicator--{generate_stix_id()}",
                    'created': datetime.now(timezone.utc).isoformat(),
                    'modified': datetime.now(timezone.utc).isoformat(),
                    'pattern': f"[file:hashes.SHA-256 = '{sha256}']",
                    'labels': ['malicious-activity'],
                    'confidence': 90,  # High confidence for MalwareBazaar
                    'source': 'abuse_ch_malwarebazaar',
                    'custom_properties': {
                        'malware_family': item.get('malware', ''),
                        'file_size': item.get('file_size', 0),
                        'first_seen': item.get('first_seen', ''),
                        'file_type': item.get('file_type', ''),
                        'md5_hash': item.get('md5_hash', ''),
                        'sha1_hash': item.get('sha1_hash', ''),
                        'feed': 'malwarebazaar'
                    }
                }
                indicators.append(indicator)

        except Exception as e:
            logger.warning(f"Error processing MalwareBazaar item: {e}")

    return indicators


def process_urlhaus_feed(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Process URLhaus feed (malicious URLs)"""
    indicators = []

    for item in data.get('urls', []):
        try:
            url = item.get('url', '')
            if url:
                indicator = {
                    'type': 'indicator',
                    'spec_version': '2.1',
                    'id': f"indicator--{generate_stix_id()}",
                    'created': datetime.now(timezone.utc).isoformat(),
                    'modified': datetime.now(timezone.utc).isoformat(),
                    'pattern': f"[url:value = '{url}']",
                    'labels': ['malicious-activity'],
                    'confidence': 85,
                    'source': 'abuse_ch_urlhaus',
                    'custom_properties': {
                        'url_status': item.get('url_status', ''),
                        'threat': item.get('threat', ''),
                        'host': item.get('host', ''),
                        'date_added': item.get('date_added', ''),
                        'larted': item.get('larted', ''),
                        'feed': 'urlhaus'
                    }
                }
                indicators.append(indicator)

        except Exception as e:
            logger.warning(f"Error processing URLhaus item: {e}")

    return indicators


def process_threatfox_feed(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Process ThreatFox feed (IOCs)"""
    indicators = []

    for item in data.get('data', []):
        try:
            ioc = item.get('ioc', '')
            ioc_type = item.get('ioc_type', '')

            if ioc and ioc_type:
                # Map IOC types to STIX patterns
                pattern = format_threatfox_pattern(ioc, ioc_type)

                indicator = {
                    'type': 'indicator',
                    'spec_version': '2.1',
                    'id': f"indicator--{generate_stix_id()}",
                    'created': datetime.now(timezone.utc).isoformat(),
                    'modified': datetime.now(timezone.utc).isoformat(),
                    'pattern': pattern,
                    'labels': ['malicious-activity'],
                    'confidence': 80,
                    'source': 'abuse_ch_threatfox',
                    'custom_properties': {
                        'malware_family': item.get('malware', ''),
                        'threat_type': item.get('threat_type', ''),
                        'ioc_type': ioc_type,
                        'first_seen': item.get('first_seen', ''),
                        'confidence_level': item.get('confidence_level', 0),
                        'feed': 'threatfox'
                    }
                }
                indicators.append(indicator)

        except Exception as e:
            logger.warning(f"Error processing ThreatFox item: {e}")

    return indicators


def process_feodo_feed(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Process Feodo Tracker feed (botnet C&C IPs)"""
    indicators = []

    for item in data.get('data', []):
        if isinstance(item, str):
            # Handle simple IP list format
            if item.strip():
                indicator = create_feodo_ip_indicator(item.strip())
                if indicator:
                    indicators.append(indicator)
        elif isinstance(item, dict):
            # Handle structured format
            ip = item.get('ip_address', '')
            if ip:
                indicator = create_feodo_ip_indicator(ip, item)
                if indicator:
                    indicators.append(indicator)

    return indicators


def create_feodo_ip_indicator(ip: str, metadata: Dict[str, Any] = None) -> Dict[str, Any]:
    """Create STIX indicator for Feodo IP"""
    try:
        metadata = metadata or {}
        indicator = {
            'type': 'indicator',
            'spec_version': '2.1',
            'id': f"indicator--{generate_stix_id()}",
            'created': datetime.now(timezone.utc).isoformat(),
            'modified': datetime.now(timezone.utc).isoformat(),
            'pattern': f"[ipv4-addr:value = '{ip}']",
            'labels': ['malicious-activity'],
            'confidence': 85,
            'source': 'abuse_ch_feodo',
            'custom_properties': {
                'malware_family': metadata.get('malware', 'feodo'),
                'threat_type': 'c2',
                'port': metadata.get('port', ''),
                'status': metadata.get('status', 'online'),
                'first_seen': metadata.get('first_seen', ''),
                'feed': 'feodo'
            }
        }
        return indicator
    except Exception as e:
        logger.warning(f"Error creating Feodo indicator for IP {ip}: {e}")
        return None


def format_threatfox_pattern(ioc: str, ioc_type: str) -> str:
    """Format ThreatFox IOC into STIX pattern"""
    patterns = {
        'ip:port': f"[ipv4-addr:value = '{ioc.split(':')[0]}']",
        'domain': f"[domain-name:value = '{ioc}']",
        'url': f"[url:value = '{ioc}']",
        'md5_hash': f"[file:hashes.MD5 = '{ioc}']",
        'sha1_hash': f"[file:hashes.SHA-1 = '{ioc}']",
        'sha256_hash': f"[file:hashes.SHA-256 = '{ioc}']",
        'ip': f"[ipv4-addr:value = '{ioc}']"
    }

    return patterns.get(ioc_type.lower(), f"[x-custom:value = '{ioc}']")


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


def archive_raw_data(source: str, data: Dict[str, Any], suffix: str = None) -> None:
    """
    Archive raw threat intelligence data to S3 for audit trails

    Args:
        source: Data source name (otx, abuse_ch)
        data: Raw data to archive
        suffix: Optional suffix for the filename (e.g., page number)
    """
    try:
        timestamp = datetime.now(timezone.utc).strftime('%Y/%m/%d/%H%M%S')
        filename = f"{timestamp}_{suffix}.json" if suffix else f"{timestamp}.json"
        key = f"raw_threat_intel/{source}/{filename}"

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


def _extract_collected_indicators(results: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Extract all collected indicators from collection results for event emission

    Args:
        results: Collection results dictionary

    Returns:
        List of indicator objects for processing
    """
    indicators = []

    try:
        # Extract from each collection source
        for source, collection_data in results.get('collections', {}).items():
            source_indicators = collection_data.get('indicators', [])

            # Add priority classification for each indicator
            for indicator in source_indicators:
                # Analyze priority using threat analyzer if available
                if EVENT_INTEGRATION_AVAILABLE:
                    priority = ThreatAnalyzer.analyze_threat_priority(indicator)
                    indicator['processing_priority'] = priority.value

                    # Add additional metadata for event processing
                    indicator['collection_source'] = source
                    indicator['collection_timestamp'] = datetime.now(timezone.utc).isoformat()

                indicators.append(indicator)

        logger.info(f"Extracted {len(indicators)} indicators for event processing")

        # Log priority distribution
        if EVENT_INTEGRATION_AVAILABLE and indicators:
            priority_counts = {}
            for indicator in indicators:
                priority = indicator.get('processing_priority', 'standard')
                priority_counts[priority] = priority_counts.get(priority, 0) + 1

            logger.info(f"Priority distribution: {priority_counts}")

        return indicators

    except Exception as e:
        logger.warning(f"Error extracting indicators for event processing: {e}")
        return []


def _emit_error_event(error_message: str, error_context: Dict[str, Any]) -> None:
    """
    Emit error event for failed collections

    Args:
        error_message: Error description
        error_context: Additional error context
    """
    if not EVENT_INTEGRATION_AVAILABLE:
        return

    try:
        EventEmitter.emit_system_error(
            error_message=error_message,
            error_context=error_context
        )
        logger.info("Collection error event emitted")
    except Exception as e:
        logger.warning(f"Failed to emit error event: {e}")