"""
OSINT Enrichment Lambda Function - MVP Version

Minimal viable OSINT enrichment using:
- Basic Shodan integration for IP/domain analysis
- Simple DNS resolution and basic checks
- Essential geolocation using free APIs
- Basic caching with DynamoDB TTL

MVP Features:
- Core Shodan API integration
- Basic IP geolocation
- Simple DNS resolution
- Essential error handling and caching
"""

import json
import boto3
import logging
import os
import socket
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional
from decimal import Decimal
import requests
from botocore.exceptions import ClientError

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# AWS Service Clients
dynamodb = boto3.resource('dynamodb')
secrets_client = boto3.client('secretsmanager')

# Environment Variables
ENVIRONMENT = os.environ.get('ENVIRONMENT', 'dev')
SECRETS_MANAGER_ARN = os.environ['SECRETS_MANAGER_ARN']
ENRICHMENT_CACHE_TABLE = os.environ['ENRICHMENT_CACHE_TABLE']
ENRICHMENT_TTL_DAYS = int(os.environ.get('ENRICHMENT_TTL_DAYS', '7'))

# DynamoDB Tables
enrichment_cache_table = dynamodb.Table(ENRICHMENT_CACHE_TABLE)

# Rate limiting
request_timestamps = []


def get_api_keys() -> Dict[str, str]:
    """Retrieve API keys from AWS Secrets Manager"""
    try:
        response = secrets_client.get_secret_value(SecretId=SECRETS_MANAGER_ARN)
        secrets = json.loads(response['SecretString'])
        return {
            'shodan_api_key': secrets.get('SHODAN_API_KEY', '')
        }
    except Exception as e:
        logger.error(f"Failed to retrieve API keys: {str(e)}")
        return {'shodan_api_key': ''}


def check_cache(cache_key: str) -> Optional[Dict[str, Any]]:
    """Check if enrichment data exists in cache"""
    try:
        response = enrichment_cache_table.get_item(Key={'cache_key': cache_key})
        if 'Item' in response:
            item = response['Item']
            # Check if not expired
            if item.get('ttl', 0) > int(time.time()):
                return item.get('enrichment_data')
    except Exception as e:
        logger.error(f"Cache check failed: {str(e)}")
    return None


def store_cache(cache_key: str, enrichment_data: Dict[str, Any]) -> None:
    """Store enrichment data in cache"""
    try:
        ttl = int(time.time()) + (ENRICHMENT_TTL_DAYS * 24 * 3600)

        def convert_floats(obj):
            if isinstance(obj, float):
                return Decimal(str(obj))
            elif isinstance(obj, dict):
                return {k: convert_floats(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_floats(v) for v in obj]
            return obj

        enrichment_cache_table.put_item(Item={
            'cache_key': cache_key,
            'enrichment_data': convert_floats(enrichment_data),
            'created_at': datetime.now(timezone.utc).isoformat(),
            'ttl': ttl
        })
    except Exception as e:
        logger.error(f"Cache storage failed: {str(e)}")


def rate_limit_check() -> bool:
    """Simple rate limiting check"""
    global request_timestamps
    current_time = time.time()

    # Remove old timestamps (older than 1 minute)
    request_timestamps = [ts for ts in request_timestamps if current_time - ts < 60]

    # Check if we're under limit (10 requests per minute for MVP)
    if len(request_timestamps) >= 10:
        return False

    request_timestamps.append(current_time)
    return True


def parse_api_gateway_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Parse API Gateway event and handle base64 encoding

    Args:
        event: Lambda event from API Gateway or direct invocation

    Returns:
        Parsed request body as dictionary
    """
    # Direct Lambda invocation (no API Gateway)
    if 'httpMethod' not in event and 'body' not in event:
        return event

    # API Gateway request
    if 'body' in event and event['body']:
        body = event['body']

        # Handle base64 encoded body from API Gateway
        if event.get('isBase64Encoded', False):
            import base64
            try:
                body = base64.b64decode(body).decode('utf-8')
                logger.info("Decoded base64 encoded request body")
            except Exception as e:
                logger.error(f"Failed to decode base64 body: {str(e)}")
                raise ValueError("Invalid base64 encoded request body")

        # Parse JSON body
        if isinstance(body, str):
            try:
                return json.loads(body)
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse JSON body: {str(e)} - Body: {body[:200]}")
                raise ValueError("Invalid JSON in request body")
        else:
            return body
    else:
        # No body provided
        return {}


def get_ip_geolocation(ip_address: str) -> Dict[str, Any]:
    """Get basic IP geolocation using free API"""
    try:
        # Use ip-api.com free tier (limited to 1000 requests/month)
        url = f"http://ip-api.com/json/{ip_address}"
        response = requests.get(url, timeout=10)
        response.raise_for_status()

        data = response.json()
        if data.get('status') == 'success':
            return {
                'country': data.get('country'),
                'country_code': data.get('countryCode'),
                'region': data.get('regionName'),
                'city': data.get('city'),
                'latitude': data.get('lat'),
                'longitude': data.get('lon'),
                'isp': data.get('isp'),
                'org': data.get('org'),
                'timezone': data.get('timezone'),
                'source': 'ip-api.com'
            }
    except Exception as e:
        logger.error(f"Geolocation lookup failed for {ip_address}: {str(e)}")

    return {'error': 'Geolocation lookup failed'}


def get_dns_info(domain: str) -> Dict[str, Any]:
    """Get basic DNS information"""
    dns_info = {'domain': domain}

    try:
        # A record
        try:
            a_records = socket.gethostbyname_ex(domain)[2]
            dns_info['a_records'] = a_records
        except:
            dns_info['a_records'] = []

        # Basic domain validation
        if '.' in domain and len(domain) > 3:
            dns_info['valid_domain'] = True
        else:
            dns_info['valid_domain'] = False

        # Simple subdomain detection
        parts = domain.split('.')
        if len(parts) > 2:
            dns_info['is_subdomain'] = True
            dns_info['root_domain'] = '.'.join(parts[-2:])
        else:
            dns_info['is_subdomain'] = False
            dns_info['root_domain'] = domain

    except Exception as e:
        logger.error(f"DNS lookup failed for {domain}: {str(e)}")
        dns_info['error'] = str(e)

    return dns_info


def get_shodan_info(target: str, api_key: str) -> Dict[str, Any]:
    """Get basic Shodan information"""
    if not api_key:
        return {'error': 'No Shodan API key available'}

    if not rate_limit_check():
        return {'error': 'Rate limit exceeded'}

    try:
        # Determine if target is IP or domain
        import re
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'

        if re.match(ip_pattern, target):
            # IP address lookup
            url = f"https://api.shodan.io/shodan/host/{target}"
        else:
            # Domain lookup
            url = f"https://api.shodan.io/dns/resolve"
            params = {'hostnames': target, 'key': api_key}
            response = requests.get(url, params=params, timeout=15)
            response.raise_for_status()

            dns_data = response.json()
            if target not in dns_data:
                return {'error': 'Domain not found in Shodan'}

            ip = dns_data[target]
            url = f"https://api.shodan.io/shodan/host/{ip}"

        # Get host information
        params = {'key': api_key}
        response = requests.get(url, params=params, timeout=15)
        response.raise_for_status()

        data = response.json()

        # Extract essential information
        shodan_info = {
            'ip': data.get('ip_str'),
            'hostnames': data.get('hostnames', []),
            'country_code': data.get('country_code'),
            'country_name': data.get('country_name'),
            'city': data.get('city'),
            'org': data.get('org'),
            'isp': data.get('isp'),
            'ports': data.get('ports', []),
            'vulns': list(data.get('vulns', [])),
            'last_update': data.get('last_update'),
            'tags': data.get('tags', []),
            'os': data.get('os'),
            'source': 'shodan'
        }

        # Basic service information
        services = []
        for service in data.get('data', [])[:5]:  # Limit to 5 services for MVP
            services.append({
                'port': service.get('port'),
                'protocol': service.get('transport'),
                'product': service.get('product'),
                'version': service.get('version'),
                'banner': service.get('data', '')[:200]  # Truncate banner
            })

        shodan_info['services'] = services
        return shodan_info

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            return {'error': 'Host not found in Shodan'}
        elif e.response.status_code == 401:
            return {'error': 'Invalid Shodan API key'}
        else:
            return {'error': f'Shodan API error: {e.response.status_code}'}
    except Exception as e:
        logger.error(f"Shodan lookup failed for {target}: {str(e)}")
        return {'error': str(e)}


def calculate_risk_score(enrichment_data: Dict[str, Any]) -> int:
    """Calculate basic risk score"""
    risk_score = 0

    # Shodan-based risk factors
    if 'shodan' in enrichment_data:
        shodan_data = enrichment_data['shodan']

        # Vulnerabilities
        vulns = shodan_data.get('vulns', [])
        risk_score += min(len(vulns) * 20, 60)  # Max 60 points for vulns

        # Open ports
        ports = shodan_data.get('ports', [])
        if ports:
            sensitive_ports = [22, 23, 21, 3389, 1433, 3306, 5432, 27017]
            for port in ports:
                if port in sensitive_ports:
                    risk_score += 10

        # Geographic risk (basic)
        country_code = shodan_data.get('country_code', '')
        high_risk_countries = ['CN', 'RU', 'KP', 'IR']
        if country_code in high_risk_countries:
            risk_score += 15

    return min(risk_score, 100)  # Cap at 100


def enrich_indicator(ioc_value: str, ioc_type: str, api_keys: Dict[str, str]) -> Dict[str, Any]:
    """Enrich a single indicator"""
    cache_key = f"{ioc_type}:{ioc_value}"

    # Check cache first
    cached_data = check_cache(cache_key)
    if cached_data:
        logger.info(f"Using cached enrichment for {ioc_value}")
        return cached_data

    enrichment_data = {
        'ioc_value': ioc_value,
        'ioc_type': ioc_type,
        'enriched_at': datetime.now(timezone.utc).isoformat(),
        'sources': []
    }

    # IP address enrichment
    if ioc_type.lower() in ['ipv4', 'ip']:
        # Geolocation
        geo_data = get_ip_geolocation(ioc_value)
        if 'error' not in geo_data:
            enrichment_data['geolocation'] = geo_data
            enrichment_data['sources'].append('geolocation')

        # Shodan
        shodan_data = get_shodan_info(ioc_value, api_keys['shodan_api_key'])
        if 'error' not in shodan_data:
            enrichment_data['shodan'] = shodan_data
            enrichment_data['sources'].append('shodan')

    # Domain enrichment
    elif ioc_type.lower() in ['domain', 'hostname']:
        # DNS info
        dns_data = get_dns_info(ioc_value)
        if 'error' not in dns_data:
            enrichment_data['dns'] = dns_data
            enrichment_data['sources'].append('dns')

        # Shodan (if API key available)
        if api_keys['shodan_api_key']:
            shodan_data = get_shodan_info(ioc_value, api_keys['shodan_api_key'])
            if 'error' not in shodan_data:
                enrichment_data['shodan'] = shodan_data
                enrichment_data['sources'].append('shodan')

    # Calculate risk score
    enrichment_data['risk_score'] = calculate_risk_score(enrichment_data)

    # Store in cache
    store_cache(cache_key, enrichment_data)

    return enrichment_data


def lambda_handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    """
    Main Lambda handler for OSINT enrichment

    Args:
        event: Lambda event data containing enrichment requests
        context: Lambda runtime context

    Returns:
        Dict containing enrichment results
    """
    try:
        logger.info(f"Starting OSINT enrichment - Environment: {ENVIRONMENT}")

        # Get API keys
        api_keys = get_api_keys()

        # Parse request using enhanced API Gateway handling
        body = parse_api_gateway_event(event)

        indicators = body.get('indicators', [])
        if not indicators:
            # Single indicator format
            if 'ioc_value' in body and 'ioc_type' in body:
                indicators = [{'ioc_value': body['ioc_value'], 'ioc_type': body['ioc_type']}]

        if not indicators:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'No indicators provided for enrichment'})
            }

        enriched_indicators = []

        # Limit to 10 indicators for MVP to avoid timeouts
        for indicator in indicators[:10]:
            # Handle both string and dict formats
            if isinstance(indicator, str):
                ioc_value = indicator.strip()
                # Auto-detect IOC type based on format
                if '.' in ioc_value and all(part.isdigit() for part in ioc_value.split('.') if part):
                    ioc_type = 'ip'
                elif '.' in ioc_value:
                    ioc_type = 'domain'
                else:
                    ioc_type = 'hash'
            else:
                ioc_value = indicator.get('ioc_value', '').strip()
                ioc_type = indicator.get('ioc_type', '').strip()

            if not ioc_value:
                continue

            try:
                enrichment_result = enrich_indicator(ioc_value, ioc_type, api_keys)
                enriched_indicators.append(enrichment_result)
            except Exception as e:
                logger.error(f"Enrichment failed for {ioc_value}: {str(e)}")
                enriched_indicators.append({
                    'ioc_value': ioc_value,
                    'ioc_type': ioc_type,
                    'error': str(e)
                })

        # Convert Decimal back to float for JSON serialization
        def convert_decimals(obj):
            if isinstance(obj, Decimal):
                return float(obj)
            elif isinstance(obj, dict):
                return {k: convert_decimals(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_decimals(v) for v in obj]
            return obj

        result = {
            'statusCode': 200,
            'body': json.dumps({
                'enriched_indicators': convert_decimals(enriched_indicators),
                'total_processed': len(enriched_indicators),
                'timestamp': datetime.now(timezone.utc).isoformat()
            })
        }

        logger.info(f"Enrichment completed: {len(enriched_indicators)} indicators processed")
        return result

    except Exception as e:
        logger.error(f"Enrichment failed: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': 'Enrichment failed',
                'message': str(e),
                'timestamp': datetime.now(timezone.utc).isoformat()
            })
        }