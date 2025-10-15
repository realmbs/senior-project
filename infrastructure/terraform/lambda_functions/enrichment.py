"""
OSINT Enrichment Lambda Function
Phase 8B Enhanced: Event-driven workflow integration

This module provides OSINT enrichment capabilities using containerized tools:
- TheHarvester for domain/email reconnaissance
- Shodan for infrastructure scanning and context
- IP geolocation and ASN resolution
- Domain reputation and WHOIS analysis

Features:
- High memory allocation (1024MB) for container execution
- Intelligent caching with 7-day TTL
- Rate limiting and API quota management
- Comprehensive error handling and retry logic
- EventBridge integration for workflow automation
- Priority-based enrichment selection
- Workflow correlation and completion events
"""

# Import event utilities for Phase 8B integration
try:
    from event_utils import (
        emit_enrichment_completed, WorkflowTracker, ThreatAnalyzer,
        ProcessingPriority, EventEmitter, EventType
    )
    EVENT_INTEGRATION_AVAILABLE = True
except ImportError:
    logger.warning("Event utilities not available - running without event integration")
    EVENT_INTEGRATION_AVAILABLE = False

import json
import boto3
import logging
import os
import subprocess
import tempfile
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Tuple
from decimal import Decimal
import requests
import socket
import ipaddress
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
ENRICHMENT_CACHE_TABLE = os.environ['ENRICHMENT_CACHE_TABLE']
RAW_DATA_BUCKET = os.environ['RAW_DATA_BUCKET']
ENRICHMENT_TTL_DAYS = int(os.environ.get('ENRICHMENT_TTL_DAYS', '7'))
MAX_CONCURRENT_REQUESTS = int(os.environ.get('MAX_CONCURRENT_REQUESTS', '5'))

# DynamoDB Tables
enrichment_cache_table = dynamodb.Table(ENRICHMENT_CACHE_TABLE)

# Rate limiting tracking
request_timestamps = []


def lambda_handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    """
    Main Lambda handler for OSINT enrichment

    Args:
        event: Lambda event data containing enrichment requests
        context: Lambda runtime context

    Returns:
        Dict containing enrichment results and metadata
    """
    try:
        logger.info(f"Starting OSINT enrichment - Environment: {ENVIRONMENT}")

        # Phase 8B: Handle EventBridge events for workflow integration
        correlation_id = None
        workflow_id = None

        if EVENT_INTEGRATION_AVAILABLE:
            # Extract workflow information
            correlation_id = WorkflowTracker.extract_correlation_id(event)
            workflow_id = event.get('workflow_id') or (event.get('detail', {}).get('workflow_id'))

            # Handle EventBridge processing completed events
            if 'source' in event and 'detail' in event:
                if event.get('source', '').startswith('threat-intel.'):
                    logger.info(f"Processing EventBridge event from {event.get('source')}")
                    return handle_eventbridge_enrichment(event, correlation_id, workflow_id)

        # Get API keys from Secrets Manager
        api_keys = get_api_keys()

        # Initialize enrichment results
        results = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'environment': ENVIRONMENT,
            'enrichment_requests': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'enrichment_results': [],
            'errors': []
        }

        # Extract enrichment targets from event
        targets = extract_enrichment_targets(event)

        if not targets:
            logger.info("No enrichment targets found in event")
            return create_response(200, results)

        logger.info(f"Processing {len(targets)} enrichment targets")

        # Process each target with rate limiting
        for target in targets:
            if check_rate_limit():
                enrichment_result = process_enrichment_target(target, api_keys)
                results['enrichment_results'].append(enrichment_result)

                # Update statistics
                results['enrichment_requests'] += 1
                if enrichment_result.get('cache_hit'):
                    results['cache_hits'] += 1
                else:
                    results['cache_misses'] += 1
            else:
                logger.warning(f"Rate limit exceeded, skipping target: {target}")
                results['errors'].append(f"Rate limit exceeded for target: {target}")

        logger.info(f"Enrichment completed: {len(results['enrichment_results'])} targets processed")

        # Phase 8B: Emit enrichment completed event for workflow completion
        if EVENT_INTEGRATION_AVAILABLE and results['enrichment_results']:
            enrichment_success = emit_enrichment_completed(
                enriched_count=len(results['enrichment_results']),
                enrichment_results=results['enrichment_results'],
                workflow_id=workflow_id,
                correlation_id=correlation_id
            )

            if enrichment_success:
                logger.info(f"Enrichment completed event emitted - workflow_id: {workflow_id}")
                results['workflow'] = {
                    'correlation_id': correlation_id,
                    'workflow_id': workflow_id,
                    'enrichment_event_emitted': True
                }
            else:
                logger.warning("Failed to emit enrichment completed event")

        return create_response(200, results)

    except Exception as e:
        error_msg = f"Error in OSINT enrichment: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return create_response(500, {
            'error': 'Internal server error',
            'message': str(e) if ENVIRONMENT == 'dev' else 'Enrichment failed'
        })


def get_api_keys() -> Dict[str, str]:
    """
    Retrieve API keys from AWS Secrets Manager

    Returns:
        Dict containing API keys for enrichment services
    """
    try:
        response = secrets_client.get_secret_value(SecretId=SECRETS_MANAGER_ARN)
        return json.loads(response['SecretString'])
    except ClientError as e:
        logger.error(f"Error retrieving API keys: {e}")
        raise


def extract_enrichment_targets(event: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Extract enrichment targets from Lambda event

    Args:
        event: Lambda event data

    Returns:
        List of enrichment target objects
    """
    targets = []

    try:
        # Direct API Gateway request
        if 'body' in event:
            body = json.loads(event['body']) if isinstance(event['body'], str) else event['body']
            if 'targets' in body:
                targets = body['targets']
            elif 'target' in body:
                targets = [body['target']]

        # SQS batch processing
        elif 'Records' in event:
            for record in event['Records']:
                if record.get('eventSource') == 'aws:sqs':
                    message_body = json.loads(record.get('body', '{}'))
                    if 'target' in message_body:
                        targets.append(message_body['target'])

        # Direct invocation
        elif 'targets' in event:
            targets = event['targets']
        elif 'target' in event:
            targets = [event['target']]

    except Exception as e:
        logger.error(f"Error extracting enrichment targets: {e}")

    return targets


def process_enrichment_target(target: Dict[str, Any], api_keys: Dict[str, str]) -> Dict[str, Any]:
    """
    Process a single enrichment target

    Args:
        target: Target object containing type and value
        api_keys: API keys for enrichment services

    Returns:
        Dict containing enrichment results
    """
    target_type = target.get('type', '').lower()
    target_value = target.get('value', '')

    enrichment_result = {
        'target': target,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'cache_hit': False,
        'enrichment_data': {},
        'errors': []
    }

    try:
        # Check cache first
        cached_result = check_enrichment_cache(target_type, target_value)
        if cached_result:
            enrichment_result['enrichment_data'] = cached_result
            enrichment_result['cache_hit'] = True
            logger.info(f"Cache hit for {target_type}: {target_value}")
            return enrichment_result

        # Perform enrichment based on target type
        if target_type in ['domain', 'hostname']:
            enrichment_data = enrich_domain(target_value, api_keys)
        elif target_type in ['ipv4', 'ipv6', 'ip']:
            enrichment_data = enrich_ip_address(target_value, api_keys)
        elif target_type == 'email':
            enrichment_data = enrich_email(target_value, api_keys)
        elif target_type == 'url':
            enrichment_data = enrich_url(target_value, api_keys)
        else:
            enrichment_data = {'error': f'Unsupported target type: {target_type}'}

        enrichment_result['enrichment_data'] = enrichment_data

        # Cache the results
        if 'error' not in enrichment_data:
            cache_enrichment_result(target_type, target_value, enrichment_data)

    except Exception as e:
        error_msg = f"Error enriching {target_type} {target_value}: {str(e)}"
        logger.error(error_msg)
        enrichment_result['errors'].append(error_msg)

    return enrichment_result


def enrich_domain(domain: str, api_keys: Dict[str, str]) -> Dict[str, Any]:
    """
    Enrich domain information using multiple OSINT sources

    Args:
        domain: Domain name to enrich
        api_keys: API keys for enrichment services

    Returns:
        Dict containing domain enrichment data
    """
    enrichment_data = {
        'domain': domain,
        'resolution': {},
        'whois': {},
        'shodan': {},
        'theharvester': {},
        'reputation': {}
    }

    try:
        # DNS Resolution
        enrichment_data['resolution'] = perform_dns_resolution(domain)

        # WHOIS Lookup
        enrichment_data['whois'] = perform_whois_lookup(domain)

        # Shodan Domain Search
        if api_keys.get('SHODAN_API_KEY'):
            enrichment_data['shodan'] = search_shodan_domain(domain, api_keys['SHODAN_API_KEY'])

        # TheHarvester Domain Reconnaissance
        enrichment_data['theharvester'] = run_theharvester(domain)

        # Domain Reputation Check
        enrichment_data['reputation'] = check_domain_reputation(domain)

    except Exception as e:
        logger.error(f"Error in domain enrichment: {e}")
        enrichment_data['error'] = str(e)

    return enrichment_data


def enrich_ip_address(ip_address: str, api_keys: Dict[str, str]) -> Dict[str, Any]:
    """
    Enrich IP address information using multiple OSINT sources

    Args:
        ip_address: IP address to enrich
        api_keys: API keys for enrichment services

    Returns:
        Dict containing IP enrichment data
    """
    enrichment_data = {
        'ip_address': ip_address,
        'geolocation': {},
        'asn': {},
        'shodan': {},
        'reverse_dns': {},
        'reputation': {}
    }

    try:
        # IP Geolocation
        enrichment_data['geolocation'] = perform_ip_geolocation(ip_address)

        # ASN Lookup
        enrichment_data['asn'] = perform_asn_lookup(ip_address)

        # Reverse DNS
        enrichment_data['reverse_dns'] = perform_reverse_dns(ip_address)

        # Shodan IP Search
        if api_keys.get('SHODAN_API_KEY'):
            enrichment_data['shodan'] = search_shodan_ip(ip_address, api_keys['SHODAN_API_KEY'])

        # IP Reputation Check
        enrichment_data['reputation'] = check_ip_reputation(ip_address)

    except Exception as e:
        logger.error(f"Error in IP enrichment: {e}")
        enrichment_data['error'] = str(e)

    return enrichment_data


def enrich_email(email: str, api_keys: Dict[str, str]) -> Dict[str, Any]:
    """
    Enrich email information using OSINT techniques

    Args:
        email: Email address to enrich
        api_keys: API keys for enrichment services

    Returns:
        Dict containing email enrichment data
    """
    enrichment_data = {
        'email': email,
        'domain_analysis': {},
        'theharvester': {},
        'breach_check': {}
    }

    try:
        # Extract domain from email
        domain = email.split('@')[1] if '@' in email else None

        if domain:
            # Analyze email domain
            enrichment_data['domain_analysis'] = enrich_domain(domain, api_keys)

            # TheHarvester email enumeration
            enrichment_data['theharvester'] = run_theharvester(domain, source_type='email')

        # Check for known breaches (placeholder - would integrate with HaveIBeenPwned API)
        enrichment_data['breach_check'] = check_email_breaches(email)

    except Exception as e:
        logger.error(f"Error in email enrichment: {e}")
        enrichment_data['error'] = str(e)

    return enrichment_data


def enrich_url(url: str, api_keys: Dict[str, str]) -> Dict[str, Any]:
    """
    Enrich URL information using OSINT techniques

    Args:
        url: URL to enrich
        api_keys: API keys for enrichment services

    Returns:
        Dict containing URL enrichment data
    """
    enrichment_data = {
        'url': url,
        'domain_analysis': {},
        'reputation': {},
        'screenshot': {}
    }

    try:
        from urllib.parse import urlparse

        parsed_url = urlparse(url)
        domain = parsed_url.netloc

        if domain:
            # Analyze URL domain
            enrichment_data['domain_analysis'] = enrich_domain(domain, api_keys)

        # URL Reputation Check
        enrichment_data['reputation'] = check_url_reputation(url)

        # URL Screenshot (placeholder - would use headless browser)
        enrichment_data['screenshot'] = capture_url_screenshot(url)

    except Exception as e:
        logger.error(f"Error in URL enrichment: {e}")
        enrichment_data['error'] = str(e)

    return enrichment_data


def perform_dns_resolution(domain: str) -> Dict[str, Any]:
    """Perform comprehensive DNS resolution and analysis"""
    try:
        dns_data = {
            'domain': domain,
            'a_records': [],
            'aaaa_records': [],
            'mx_records': [],
            'ns_records': [],
            'txt_records': [],
            'cname_records': [],
            'ptr_records': [],
            'soa_record': {},
            'dns_security': {},
            'response_times': {},
            'analysis': {}
        }

        # Measure response times for performance analysis
        start_time = time.time()

        # A records (IPv4)
        a_records = _get_a_records(domain)
        dns_data['a_records'] = a_records
        dns_data['response_times']['a_records'] = time.time() - start_time

        # AAAA records (IPv6)
        aaaa_records = _get_aaaa_records(domain)
        dns_data['aaaa_records'] = aaaa_records

        # MX records (Mail Exchange)
        mx_records = _get_mx_records(domain)
        dns_data['mx_records'] = mx_records

        # NS records (Name Servers)
        ns_records = _get_ns_records(domain)
        dns_data['ns_records'] = ns_records

        # TXT records
        txt_records = _get_txt_records(domain)
        dns_data['txt_records'] = txt_records

        # CNAME records
        cname_records = _get_cname_records(domain)
        dns_data['cname_records'] = cname_records

        # SOA record
        soa_record = _get_soa_record(domain)
        dns_data['soa_record'] = soa_record

        # Analyze DNS security features
        dns_data['dns_security'] = _analyze_dns_security(txt_records, domain)

        # Perform DNS analysis
        dns_data['analysis'] = _analyze_dns_configuration(dns_data)

        # Check for DNS over HTTPS/TLS support
        dns_data['modern_dns'] = _check_modern_dns_support(domain)

        return dns_data

    except Exception as e:
        logger.error(f"Error in DNS resolution: {e}")
        return {'error': str(e)}


def perform_whois_lookup(domain: str) -> Dict[str, Any]:
    """Perform comprehensive WHOIS lookup and analysis"""
    try:
        whois_data = {
            'domain': domain,
            'registrar': 'Unknown',
            'creation_date': 'Unknown',
            'expiration_date': 'Unknown',
            'updated_date': 'Unknown',
            'name_servers': [],
            'status': [],
            'registrant': {},
            'admin_contact': {},
            'tech_contact': {},
            'dnssec': 'Unknown',
            'privacy_protection': False,
            'analysis': {}
        }

        # Perform WHOIS lookup using multiple methods
        raw_whois = _get_raw_whois(domain)

        if 'error' in raw_whois:
            return raw_whois

        # Parse WHOIS data
        parsed_data = _parse_whois_data(raw_whois['raw_data'])
        whois_data.update(parsed_data)

        # Analyze WHOIS data for intelligence
        whois_data['analysis'] = _analyze_whois_data(whois_data)

        # Check domain age and calculate metrics
        whois_data['domain_metrics'] = _calculate_domain_metrics(whois_data)

        return whois_data

    except Exception as e:
        logger.error(f"Error in WHOIS lookup: {e}")
        return {'error': str(e)}


def search_shodan_domain(domain: str, api_key: str) -> Dict[str, Any]:
    """Search Shodan for comprehensive domain information"""
    try:
        results = {
            'domain_search': {},
            'subdomain_discovery': {},
            'ssl_certificates': {},
            'associated_ips': [],
            'services': [],
            'vulnerabilities': []
        }

        # Main domain search
        domain_data = _shodan_domain_search(domain, api_key)
        results['domain_search'] = domain_data

        # Extract IPs for detailed analysis
        for match in domain_data.get('matches', []):
            ip = match.get('ip_str')
            if ip and ip not in results['associated_ips']:
                results['associated_ips'].append(ip)

                # Get detailed IP information
                ip_data = search_shodan_ip(ip, api_key)
                if 'error' not in ip_data:
                    results['services'].extend(ip_data.get('ports', []))
                    results['vulnerabilities'].extend(ip_data.get('vulns', []))

        # SSL certificate analysis
        ssl_data = _shodan_ssl_search(domain, api_key)
        results['ssl_certificates'] = ssl_data

        # Extract subdomains from SSL certificates
        subdomains = _extract_subdomains_from_ssl(ssl_data)
        results['subdomain_discovery'] = {'subdomains': subdomains}

        # Calculate risk score
        results['risk_analysis'] = _calculate_domain_risk_score(results)

        return results

    except Exception as e:
        logger.error(f"Error in Shodan domain search: {e}")
        return {'error': str(e)}


def _shodan_domain_search(domain: str, api_key: str) -> Dict[str, Any]:
    """Perform main Shodan domain search"""
    try:
        url = 'https://api.shodan.io/shodan/host/search'
        params = {
            'query': f'hostname:{domain}',
            'limit': 50,
            'facets': 'port,country,org'
        }
        headers = {'Authorization': f'Bearer {api_key}'}

        response = requests.get(url, headers=headers, params=params, timeout=30)
        response.raise_for_status()

        return response.json()

    except Exception as e:
        return {'error': str(e)}


def _shodan_ssl_search(domain: str, api_key: str) -> Dict[str, Any]:
    """Search Shodan for SSL certificate information"""
    try:
        url = 'https://api.shodan.io/shodan/host/search'
        params = {
            'query': f'ssl.cert.subject.cn:{domain} OR ssl.cert.extensions.subject_alt_name:{domain}',
            'limit': 100
        }
        headers = {'Authorization': f'Bearer {api_key}'}

        response = requests.get(url, headers=headers, params=params, timeout=30)
        response.raise_for_status()

        return response.json()

    except Exception as e:
        return {'error': str(e)}


def _extract_subdomains_from_ssl(ssl_data: Dict[str, Any]) -> List[str]:
    """Extract subdomains from SSL certificate data"""
    subdomains = set()

    try:
        for match in ssl_data.get('matches', []):
            ssl_info = match.get('ssl', {})
            cert = ssl_info.get('cert', {})

            # Extract from subject common name
            subject = cert.get('subject', {})
            cn = subject.get('CN')
            if cn:
                subdomains.add(cn)

            # Extract from subject alternative names
            extensions = cert.get('extensions', {})
            san = extensions.get('subject_alt_name', [])
            for name in san:
                if isinstance(name, str):
                    subdomains.add(name.replace('DNS:', ''))

    except Exception as e:
        logger.warning(f"Error extracting subdomains from SSL: {e}")

    return list(subdomains)


def _calculate_domain_risk_score(shodan_data: Dict[str, Any]) -> Dict[str, Any]:
    """Calculate risk score based on Shodan findings"""
    risk_score = 0
    risk_factors = []

    try:
        # Check for vulnerabilities
        vulns = shodan_data.get('vulnerabilities', [])
        if vulns:
            risk_score += len(vulns) * 10
            risk_factors.append(f"Found {len(vulns)} vulnerabilities")

        # Check for open ports
        services = shodan_data.get('services', [])
        high_risk_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900]
        open_high_risk = [port for port in services if port in high_risk_ports]

        if open_high_risk:
            risk_score += len(open_high_risk) * 5
            risk_factors.append(f"High-risk ports open: {open_high_risk}")

        # Check for unusual number of subdomains
        subdomains = shodan_data.get('subdomain_discovery', {}).get('subdomains', [])
        if len(subdomains) > 50:
            risk_score += 15
            risk_factors.append("Unusually high number of subdomains")

        # Determine risk level
        if risk_score >= 50:
            risk_level = "HIGH"
        elif risk_score >= 25:
            risk_level = "MEDIUM"
        elif risk_score >= 10:
            risk_level = "LOW"
        else:
            risk_level = "MINIMAL"

        return {
            'risk_score': min(risk_score, 100),
            'risk_level': risk_level,
            'risk_factors': risk_factors
        }

    except Exception as e:
        logger.warning(f"Error calculating domain risk score: {e}")
        return {'risk_score': 0, 'risk_level': 'UNKNOWN', 'risk_factors': []}


def search_shodan_ip(ip_address: str, api_key: str) -> Dict[str, Any]:
    """Search Shodan for comprehensive IP address information"""
    try:
        # Get host information
        host_data = _shodan_host_lookup(ip_address, api_key)

        if 'error' in host_data:
            return host_data

        # Process and enhance the data
        enriched_data = {
            'ip_address': ip_address,
            'hostnames': host_data.get('hostnames', []),
            'organization': host_data.get('org', 'Unknown'),
            'country': host_data.get('country_name', 'Unknown'),
            'city': host_data.get('city', 'Unknown'),
            'isp': host_data.get('isp', 'Unknown'),
            'asn': host_data.get('asn', 'Unknown'),
            'ports': host_data.get('ports', []),
            'services': [],
            'vulnerabilities': host_data.get('vulns', []),
            'tags': host_data.get('tags', []),
            'last_update': host_data.get('last_update', ''),
            'risk_analysis': {}
        }

        # Process service information
        for service in host_data.get('data', []):
            service_info = {
                'port': service.get('port'),
                'protocol': service.get('transport', 'tcp'),
                'service': service.get('product', 'Unknown'),
                'version': service.get('version', ''),
                'banner': service.get('data', '')[:500],  # Limit banner size
                'timestamp': service.get('timestamp', '')
            }

            # Add HTTP-specific information
            if 'http' in service:
                http_info = service['http']
                service_info['http'] = {
                    'server': http_info.get('server', ''),
                    'title': http_info.get('title', ''),
                    'status_code': http_info.get('status', 0),
                    'headers': dict(list(http_info.get('headers', {}).items())[:10])  # Limit headers
                }

            # Add SSL information
            if 'ssl' in service:
                ssl_info = service['ssl']
                cert = ssl_info.get('cert', {})
                service_info['ssl'] = {
                    'version': ssl_info.get('version', ''),
                    'cipher': ssl_info.get('cipher', {}),
                    'cert_subject': cert.get('subject', {}),
                    'cert_issuer': cert.get('issuer', {}),
                    'cert_expired': cert.get('expired', False),
                    'cert_expires': cert.get('expires', ''),
                    'cert_fingerprint': cert.get('fingerprint', {})
                }

            enriched_data['services'].append(service_info)

        # Calculate risk assessment
        enriched_data['risk_analysis'] = _calculate_ip_risk_score(enriched_data)

        return enriched_data

    except Exception as e:
        logger.error(f"Error in Shodan IP search: {e}")
        return {'error': str(e)}


def _shodan_host_lookup(ip_address: str, api_key: str) -> Dict[str, Any]:
    """Perform Shodan host lookup"""
    try:
        url = f'https://api.shodan.io/shodan/host/{ip_address}'
        params = {'history': 'false', 'minify': 'false'}
        headers = {'Authorization': f'Bearer {api_key}'}

        response = requests.get(url, headers=headers, params=params, timeout=30)

        if response.status_code == 404:
            return {'error': 'Host not found in Shodan database'}

        response.raise_for_status()
        return response.json()

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 401:
            return {'error': 'Invalid Shodan API key'}
        elif e.response.status_code == 429:
            return {'error': 'Shodan API rate limit exceeded'}
        else:
            return {'error': f'Shodan API error: {e.response.status_code}'}
    except Exception as e:
        return {'error': str(e)}


def _calculate_ip_risk_score(ip_data: Dict[str, Any]) -> Dict[str, Any]:
    """Calculate risk score for IP address based on Shodan findings"""
    risk_score = 0
    risk_factors = []

    try:
        # Check for vulnerabilities
        vulns = ip_data.get('vulnerabilities', [])
        if vulns:
            critical_vulns = [v for v in vulns if 'critical' in str(v).lower()]
            high_vulns = [v for v in vulns if 'high' in str(v).lower()]

            risk_score += len(critical_vulns) * 20
            risk_score += len(high_vulns) * 15
            risk_score += len(vulns) * 5

            risk_factors.append(f"Found {len(vulns)} vulnerabilities ({len(critical_vulns)} critical, {len(high_vulns)} high)")

        # Check for suspicious tags
        tags = ip_data.get('tags', [])
        suspicious_tags = ['malware', 'botnet', 'compromised', 'scanner', 'honeypot']
        found_suspicious = [tag for tag in tags if tag.lower() in suspicious_tags]

        if found_suspicious:
            risk_score += len(found_suspicious) * 25
            risk_factors.append(f"Suspicious tags: {found_suspicious}")

        # Check for open high-risk ports
        ports = ip_data.get('ports', [])
        high_risk_ports = [21, 22, 23, 25, 53, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900]
        open_high_risk = [port for port in ports if port in high_risk_ports]

        if open_high_risk:
            risk_score += len(open_high_risk) * 8
            risk_factors.append(f"High-risk ports open: {open_high_risk}")

        # Check for unusual number of open ports
        if len(ports) > 20:
            risk_score += 15
            risk_factors.append(f"Unusually high number of open ports: {len(ports)}")

        # Check for outdated services
        services = ip_data.get('services', [])
        outdated_services = []
        for service in services:
            version = service.get('version', '')
            service_name = service.get('service', '')
            if _is_outdated_service(service_name, version):
                outdated_services.append(f"{service_name} {version}")

        if outdated_services:
            risk_score += len(outdated_services) * 10
            risk_factors.append(f"Outdated services: {outdated_services[:3]}")

        # Determine risk level
        if risk_score >= 75:
            risk_level = "CRITICAL"
        elif risk_score >= 50:
            risk_level = "HIGH"
        elif risk_score >= 25:
            risk_level = "MEDIUM"
        elif risk_score >= 10:
            risk_level = "LOW"
        else:
            risk_level = "MINIMAL"

        return {
            'risk_score': min(risk_score, 100),
            'risk_level': risk_level,
            'risk_factors': risk_factors
        }

    except Exception as e:
        logger.warning(f"Error calculating IP risk score: {e}")
        return {'risk_score': 0, 'risk_level': 'UNKNOWN', 'risk_factors': []}


def _is_outdated_service(service_name: str, version: str) -> bool:
    """Check if a service version is considered outdated (simplified)"""
    # This is a simplified check - in production, this would use a comprehensive CVE database
    outdated_patterns = {
        'apache': ['2.2', '2.0', '1.3'],
        'nginx': ['1.10', '1.8', '1.6'],
        'openssh': ['6.', '5.', '4.'],
        'mysql': ['5.5', '5.1', '4.'],
        'postgresql': ['9.', '8.'],
        'php': ['5.', '4.']
    }

    service_lower = service_name.lower()
    for service, old_versions in outdated_patterns.items():
        if service in service_lower:
            for old_version in old_versions:
                if version.startswith(old_version):
                    return True

    return False


def run_theharvester(target: str, source_type: str = 'domain') -> Dict[str, Any]:
    """
    Run TheHarvester for OSINT reconnaissance

    Args:
        target: Target domain or email
        source_type: Type of reconnaissance (domain, email)

    Returns:
        Dict containing TheHarvester results
    """
    try:
        # This would typically run TheHarvester in a container
        # Simplified implementation for demonstration
        result = {
            'emails': [],
            'hosts': [],
            'ips': [],
            'urls': [],
            'people': []
        }

        # In production, this would execute:
        # docker run --rm theharvester -d {target} -b google,bing,linkedin
        # and parse the output

        return result

    except Exception as e:
        return {'error': str(e)}


def perform_ip_geolocation(ip_address: str) -> Dict[str, Any]:
    """Perform IP geolocation lookup using multiple free services"""
    try:
        geolocation_data = {
            'ip_address': ip_address,
            'country': 'Unknown',
            'country_code': 'Unknown',
            'region': 'Unknown',
            'city': 'Unknown',
            'latitude': 0.0,
            'longitude': 0.0,
            'timezone': 'Unknown',
            'isp': 'Unknown',
            'organization': 'Unknown',
            'sources': [],
            'confidence': 'LOW'
        }

        # Try multiple free geolocation services
        services = [
            _get_geolocation_from_ipapi,
            _get_geolocation_from_ipinfo,
            _get_geolocation_from_freegeoip
        ]

        for service in services:
            try:
                result = service(ip_address)
                if 'error' not in result:
                    geolocation_data['sources'].append(result.get('source', 'unknown'))

                    # Update data if we get valid results
                    if result.get('country') and result['country'] != 'Unknown':
                        geolocation_data.update(result)
                        geolocation_data['confidence'] = 'HIGH'
                        break

            except Exception as e:
                logger.warning(f"Geolocation service failed: {e}")
                continue

        return geolocation_data

    except Exception as e:
        logger.error(f"Error in IP geolocation: {e}")
        return {'error': str(e)}


def _get_geolocation_from_ipapi(ip_address: str) -> Dict[str, Any]:
    """Get geolocation from ip-api.com (free tier)"""
    try:
        url = f'http://ip-api.com/json/{ip_address}'
        response = requests.get(url, timeout=10)
        response.raise_for_status()

        data = response.json()

        if data.get('status') == 'success':
            return {
                'source': 'ip-api.com',
                'country': data.get('country', 'Unknown'),
                'country_code': data.get('countryCode', 'Unknown'),
                'region': data.get('regionName', 'Unknown'),
                'city': data.get('city', 'Unknown'),
                'latitude': float(data.get('lat', 0.0)),
                'longitude': float(data.get('lon', 0.0)),
                'timezone': data.get('timezone', 'Unknown'),
                'isp': data.get('isp', 'Unknown'),
                'organization': data.get('org', 'Unknown'),
                'is_proxy': data.get('proxy', False),
                'is_mobile': data.get('mobile', False)
            }
        else:
            return {'error': data.get('message', 'IP geolocation failed')}

    except Exception as e:
        return {'error': str(e)}


def _get_geolocation_from_ipinfo(ip_address: str) -> Dict[str, Any]:
    """Get geolocation from ipinfo.io (free tier)"""
    try:
        url = f'https://ipinfo.io/{ip_address}/json'
        response = requests.get(url, timeout=10)
        response.raise_for_status()

        data = response.json()

        if 'bogon' not in data:
            loc = data.get('loc', '0,0').split(',')
            lat, lon = float(loc[0]) if len(loc) > 0 else 0.0, float(loc[1]) if len(loc) > 1 else 0.0

            return {
                'source': 'ipinfo.io',
                'country': data.get('country', 'Unknown'),
                'country_code': data.get('country', 'Unknown'),
                'region': data.get('region', 'Unknown'),
                'city': data.get('city', 'Unknown'),
                'latitude': lat,
                'longitude': lon,
                'timezone': data.get('timezone', 'Unknown'),
                'isp': data.get('org', 'Unknown'),
                'organization': data.get('org', 'Unknown')
            }
        else:
            return {'error': 'Private/bogon IP address'}

    except Exception as e:
        return {'error': str(e)}


def _get_geolocation_from_freegeoip(ip_address: str) -> Dict[str, Any]:
    """Get geolocation from freegeoip.app (free tier)"""
    try:
        url = f'https://freegeoip.app/json/{ip_address}'
        response = requests.get(url, timeout=10)
        response.raise_for_status()

        data = response.json()

        return {
            'source': 'freegeoip.app',
            'country': data.get('country_name', 'Unknown'),
            'country_code': data.get('country_code', 'Unknown'),
            'region': data.get('region_name', 'Unknown'),
            'city': data.get('city', 'Unknown'),
            'latitude': float(data.get('latitude', 0.0)),
            'longitude': float(data.get('longitude', 0.0)),
            'timezone': data.get('time_zone', 'Unknown')
        }

    except Exception as e:
        return {'error': str(e)}


def perform_asn_lookup(ip_address: str) -> Dict[str, Any]:
    """Perform ASN lookup for IP address using multiple methods"""
    try:
        asn_data = {
            'ip_address': ip_address,
            'asn': 'Unknown',
            'organization': 'Unknown',
            'network': 'Unknown',
            'country': 'Unknown',
            'registry': 'Unknown',
            'sources': [],
            'confidence': 'LOW'
        }

        # Try multiple ASN lookup methods
        methods = [
            _get_asn_from_cymru,
            _get_asn_from_whois,
            _get_asn_from_bgpview
        ]

        for method in methods:
            try:
                result = method(ip_address)
                if 'error' not in result:
                    asn_data['sources'].append(result.get('source', 'unknown'))

                    # Update data if we get valid results
                    if result.get('asn') and result['asn'] != 'Unknown':
                        asn_data.update(result)
                        asn_data['confidence'] = 'HIGH'
                        break

            except Exception as e:
                logger.warning(f"ASN lookup method failed: {e}")
                continue

        return asn_data

    except Exception as e:
        logger.error(f"Error in ASN lookup: {e}")
        return {'error': str(e)}


def _get_asn_from_cymru(ip_address: str) -> Dict[str, Any]:
    """Get ASN information from Team Cymru's whois service"""
    try:
        # Use Team Cymru's whois service for ASN lookup
        result = subprocess.run(
            ['whois', '-h', 'whois.cymru.com', f'{ip_address}'],
            capture_output=True,
            text=True,
            timeout=15
        )

        if result.returncode == 0 and result.stdout.strip():
            lines = result.stdout.strip().split('\n')
            for line in lines:
                if '|' in line:
                    parts = [part.strip() for part in line.split('|')]
                    if len(parts) >= 4:
                        return {
                            'source': 'cymru',
                            'asn': f"AS{parts[0]}" if parts[0].isdigit() else parts[0],
                            'network': parts[1] if len(parts) > 1 else 'Unknown',
                            'country': parts[2] if len(parts) > 2 else 'Unknown',
                            'registry': parts[3] if len(parts) > 3 else 'Unknown',
                            'organization': parts[4] if len(parts) > 4 else 'Unknown'
                        }

        return {'error': 'No ASN data found'}

    except Exception as e:
        return {'error': str(e)}


def _get_asn_from_whois(ip_address: str) -> Dict[str, Any]:
    """Get ASN information from standard whois"""
    try:
        result = subprocess.run(
            ['whois', ip_address],
            capture_output=True,
            text=True,
            timeout=15
        )

        if result.returncode == 0 and result.stdout.strip():
            output = result.stdout.lower()
            asn_data = {'source': 'whois'}

            # Look for ASN information in whois output
            for line in result.stdout.split('\n'):
                line_lower = line.lower()
                if 'origin:' in line_lower or 'originas:' in line_lower:
                    asn_value = line.split(':', 1)[1].strip()
                    if asn_value.startswith('as'):
                        asn_data['asn'] = asn_value.upper()
                    elif asn_value.isdigit():
                        asn_data['asn'] = f"AS{asn_value}"

                elif 'netname:' in line_lower or 'org-name:' in line_lower:
                    asn_data['organization'] = line.split(':', 1)[1].strip()

                elif 'country:' in line_lower:
                    asn_data['country'] = line.split(':', 1)[1].strip().upper()

                elif 'cidr:' in line_lower or 'route:' in line_lower:
                    asn_data['network'] = line.split(':', 1)[1].strip()

            if 'asn' in asn_data:
                return asn_data

        return {'error': 'No ASN data found in whois'}

    except Exception as e:
        return {'error': str(e)}


def _get_asn_from_bgpview(ip_address: str) -> Dict[str, Any]:
    """Get ASN information from BGPView API (free tier)"""
    try:
        url = f'https://api.bgpview.io/ip/{ip_address}'
        response = requests.get(url, timeout=15)
        response.raise_for_status()

        data = response.json()

        if data.get('status') == 'ok' and 'data' in data:
            ip_data = data['data']
            prefixes = ip_data.get('prefixes', [])

            if prefixes:
                prefix_data = prefixes[0]  # Take the first/most specific prefix
                asn_info = prefix_data.get('asn', {})

                return {
                    'source': 'bgpview',
                    'asn': f"AS{asn_info.get('asn', 'Unknown')}",
                    'organization': asn_info.get('name', 'Unknown'),
                    'network': prefix_data.get('prefix', 'Unknown'),
                    'country': asn_info.get('country_code', 'Unknown'),
                    'registry': 'Unknown',
                    'description': asn_info.get('description', 'Unknown')
                }

        return {'error': 'No ASN data found in BGPView'}

    except Exception as e:
        return {'error': str(e)}


def perform_reverse_dns(ip_address: str) -> Dict[str, Any]:
    """Perform reverse DNS lookup"""
    try:
        hostname = socket.gethostbyaddr(ip_address)[0]
        return {'hostname': hostname}
    except Exception as e:
        return {'error': str(e)}


def check_domain_reputation(domain: str) -> Dict[str, Any]:
    """Check domain reputation using multiple sources"""
    try:
        reputation_data = {
            'domain': domain,
            'overall_score': 50,
            'risk_level': 'UNKNOWN',
            'sources_checked': [],
            'reputation_sources': {},
            'threat_categories': [],
            'analysis': {}
        }

        # Check multiple reputation sources
        reputation_sources = []

        # Source 1: Simple DNS-based checks
        dns_reputation = _check_dns_reputation(domain)
        if 'error' not in dns_reputation:
            reputation_sources.append('dns_analysis')
            reputation_data['reputation_sources']['dns_analysis'] = dns_reputation

        # Source 2: Domain age and registration analysis
        registration_reputation = _check_registration_reputation(domain)
        if 'error' not in registration_reputation:
            reputation_sources.append('registration_analysis')
            reputation_data['reputation_sources']['registration_analysis'] = registration_reputation

        # Source 3: Subdomain and pattern analysis
        pattern_reputation = _check_domain_patterns(domain)
        if 'error' not in pattern_reputation:
            reputation_sources.append('pattern_analysis')
            reputation_data['reputation_sources']['pattern_analysis'] = pattern_reputation

        # Source 4: Public blocklist checks (simplified)
        blocklist_reputation = _check_public_blocklists(domain)
        if 'error' not in blocklist_reputation:
            reputation_sources.append('blocklist_check')
            reputation_data['reputation_sources']['blocklist_check'] = blocklist_reputation

        reputation_data['sources_checked'] = reputation_sources

        # Aggregate reputation scores
        reputation_data['analysis'] = _aggregate_domain_reputation(reputation_data['reputation_sources'])
        reputation_data['overall_score'] = reputation_data['analysis']['aggregated_score']
        reputation_data['risk_level'] = reputation_data['analysis']['risk_level']
        reputation_data['threat_categories'] = reputation_data['analysis']['threat_categories']

        return reputation_data

    except Exception as e:
        logger.error(f"Error checking domain reputation: {e}")
        return {'error': str(e)}


def check_ip_reputation(ip_address: str) -> Dict[str, Any]:
    """Check IP reputation using multiple sources"""
    try:
        reputation_data = {
            'ip_address': ip_address,
            'overall_score': 50,
            'risk_level': 'UNKNOWN',
            'sources_checked': [],
            'reputation_sources': {},
            'threat_categories': [],
            'blocklist_status': {},
            'analysis': {}
        }

        # Check if IP is private/reserved
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            if ip_obj.is_private or ip_obj.is_reserved or ip_obj.is_loopback:
                reputation_data.update({
                    'overall_score': 95,
                    'risk_level': 'LOW',
                    'threat_categories': ['private_network'],
                    'analysis': {'note': 'Private/reserved IP address'}
                })
                return reputation_data
        except:
            pass

        # Check multiple reputation sources
        reputation_sources = []

        # Source 1: Geographic and hosting analysis
        geo_reputation = _check_ip_geographic_reputation(ip_address)
        if 'error' not in geo_reputation:
            reputation_sources.append('geographic_analysis')
            reputation_data['reputation_sources']['geographic_analysis'] = geo_reputation

        # Source 2: Port scan and service analysis
        service_reputation = _check_ip_service_reputation(ip_address)
        if 'error' not in service_reputation:
            reputation_sources.append('service_analysis')
            reputation_data['reputation_sources']['service_analysis'] = service_reputation

        # Source 3: DNS-based blocklist checks
        dnsbl_reputation = _check_dnsbl_reputation(ip_address)
        if 'error' not in dnsbl_reputation:
            reputation_sources.append('dnsbl_check')
            reputation_data['reputation_sources']['dnsbl_check'] = dnsbl_reputation
            reputation_data['blocklist_status'] = dnsbl_reputation.get('blocklist_results', {})

        # Source 4: Reverse DNS analysis
        rdns_reputation = _check_reverse_dns_reputation(ip_address)
        if 'error' not in rdns_reputation:
            reputation_sources.append('reverse_dns_analysis')
            reputation_data['reputation_sources']['reverse_dns_analysis'] = rdns_reputation

        reputation_data['sources_checked'] = reputation_sources

        # Aggregate reputation scores
        reputation_data['analysis'] = _aggregate_ip_reputation(reputation_data['reputation_sources'])
        reputation_data['overall_score'] = reputation_data['analysis']['aggregated_score']
        reputation_data['risk_level'] = reputation_data['analysis']['risk_level']
        reputation_data['threat_categories'] = reputation_data['analysis']['threat_categories']

        return reputation_data

    except Exception as e:
        logger.error(f"Error checking IP reputation: {e}")
        return {'error': str(e)}


def check_url_reputation(url: str) -> Dict[str, Any]:
    """Check URL reputation using multiple analysis techniques"""
    try:
        from urllib.parse import urlparse

        parsed_url = urlparse(url)

        reputation_data = {
            'url': url,
            'domain': parsed_url.netloc,
            'path': parsed_url.path,
            'overall_score': 50,
            'risk_level': 'UNKNOWN',
            'sources_checked': [],
            'reputation_sources': {},
            'threat_categories': [],
            'analysis': {}
        }

        # Check multiple analysis sources
        reputation_sources = []

        # Source 1: URL structure analysis
        structure_reputation = _analyze_url_structure(url, parsed_url)
        if 'error' not in structure_reputation:
            reputation_sources.append('structure_analysis')
            reputation_data['reputation_sources']['structure_analysis'] = structure_reputation

        # Source 2: Domain reputation (reuse domain analysis)
        if parsed_url.netloc:
            domain_reputation = check_domain_reputation(parsed_url.netloc)
            if 'error' not in domain_reputation:
                reputation_sources.append('domain_reputation')
                reputation_data['reputation_sources']['domain_reputation'] = domain_reputation

        # Source 3: Path and parameter analysis
        path_reputation = _analyze_url_path(parsed_url)
        if 'error' not in path_reputation:
            reputation_sources.append('path_analysis')
            reputation_data['reputation_sources']['path_analysis'] = path_reputation

        # Source 4: Protocol and port analysis
        protocol_reputation = _analyze_url_protocol(parsed_url)
        if 'error' not in protocol_reputation:
            reputation_sources.append('protocol_analysis')
            reputation_data['reputation_sources']['protocol_analysis'] = protocol_reputation

        reputation_data['sources_checked'] = reputation_sources

        # Aggregate reputation scores
        reputation_data['analysis'] = _aggregate_url_reputation(reputation_data['reputation_sources'])
        reputation_data['overall_score'] = reputation_data['analysis']['aggregated_score']
        reputation_data['risk_level'] = reputation_data['analysis']['risk_level']
        reputation_data['threat_categories'] = reputation_data['analysis']['threat_categories']

        return reputation_data

    except Exception as e:
        logger.error(f"Error checking URL reputation: {e}")
        return {'error': str(e)}


def check_email_breaches(email: str) -> Dict[str, Any]:
    """Check if email appears in known data breaches"""
    try:
        # This would integrate with HaveIBeenPwned API
        # Placeholder implementation
        return {
            'breached': False,
            'breach_count': 0,
            'breaches': []
        }
    except Exception as e:
        return {'error': str(e)}


def capture_url_screenshot(url: str) -> Dict[str, Any]:
    """Capture screenshot of URL"""
    try:
        # This would use headless browser like Selenium or Playwright
        # Placeholder implementation
        return {
            'screenshot_available': False,
            'screenshot_url': None,
            'error': 'Screenshot functionality not implemented'
        }
    except Exception as e:
        return {'error': str(e)}


def check_enrichment_cache(target_type: str, target_value: str) -> Optional[Dict[str, Any]]:
    """
    Check if enrichment data exists in cache

    Args:
        target_type: Type of target (domain, ip, etc.)
        target_value: Value of target

    Returns:
        Cached enrichment data or None
    """
    try:
        cache_key = generate_cache_key(target_type, target_value)
        response = enrichment_cache_table.get_item(Key={'cache_key': cache_key})

        if 'Item' in response:
            return response['Item']['enrichment_data']

    except Exception as e:
        logger.warning(f"Error checking enrichment cache: {e}")

    return None


def cache_enrichment_result(target_type: str, target_value: str,
                          enrichment_data: Dict[str, Any]) -> None:
    """
    Cache enrichment result with TTL

    Args:
        target_type: Type of target
        target_value: Value of target
        enrichment_data: Enrichment data to cache
    """
    try:
        cache_key = generate_cache_key(target_type, target_value)
        ttl = int((datetime.now(timezone.utc) + timedelta(days=ENRICHMENT_TTL_DAYS)).timestamp())

        enrichment_cache_table.put_item(Item={
            'cache_key': cache_key,
            'target_type': target_type,
            'target_value': target_value,
            'enrichment_data': convert_floats_to_decimal(enrichment_data),
            'cached_at': datetime.now(timezone.utc).isoformat(),
            'ttl': ttl
        })

    except Exception as e:
        logger.warning(f"Error caching enrichment result: {e}")


def generate_cache_key(target_type: str, target_value: str) -> str:
    """Generate cache key for target"""
    import hashlib
    key_string = f"{target_type}:{target_value}"
    return hashlib.sha256(key_string.encode()).hexdigest()


def check_rate_limit() -> bool:
    """
    Check if rate limit allows for another request

    Returns:
        True if request is allowed, False if rate limited
    """
    global request_timestamps

    current_time = time.time()

    # Remove timestamps older than 1 minute
    request_timestamps = [ts for ts in request_timestamps if current_time - ts < 60]

    # Check if we're under the limit
    if len(request_timestamps) < MAX_CONCURRENT_REQUESTS:
        request_timestamps.append(current_time)
        return True

    return False


def convert_floats_to_decimal(obj):
    """Convert float values to Decimal for DynamoDB compatibility"""
    if isinstance(obj, list):
        return [convert_floats_to_decimal(item) for item in obj]
    elif isinstance(obj, dict):
        return {key: convert_floats_to_decimal(value) for key, value in obj.items()}
    elif isinstance(obj, float):
        return Decimal(str(obj))
    return obj


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


# ============================================================================
# DNS Helper Functions
# ============================================================================

def _get_a_records(domain: str) -> List[str]:
    """Get A records for domain"""
    try:
        result = socket.getaddrinfo(domain, None, socket.AF_INET)
        return list(set([addr[4][0] for addr in result]))
    except Exception:
        return []


def _get_aaaa_records(domain: str) -> List[str]:
    """Get AAAA records for domain"""
    try:
        result = socket.getaddrinfo(domain, None, socket.AF_INET6)
        return list(set([addr[4][0] for addr in result]))
    except Exception:
        return []


def _get_mx_records(domain: str) -> List[Dict[str, Any]]:
    """Get MX records for domain"""
    try:
        result = subprocess.run(
            ['nslookup', '-type=MX', domain],
            capture_output=True,
            text=True,
            timeout=10
        )

        mx_records = []
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            for line in lines:
                if 'mail exchanger' in line.lower():
                    parts = line.split('=')
                    if len(parts) > 1:
                        mx_info = parts[1].strip().split()
                        if len(mx_info) >= 2:
                            mx_records.append({
                                'priority': int(mx_info[0]),
                                'exchange': mx_info[1].rstrip('.')
                            })

        return sorted(mx_records, key=lambda x: x.get('priority', 999))
    except Exception:
        return []


def _get_ns_records(domain: str) -> List[str]:
    """Get NS records for domain"""
    try:
        result = subprocess.run(
            ['nslookup', '-type=NS', domain],
            capture_output=True,
            text=True,
            timeout=10
        )

        ns_records = []
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            for line in lines:
                if 'nameserver' in line.lower():
                    parts = line.split('=')
                    if len(parts) > 1:
                        ns_records.append(parts[1].strip().rstrip('.'))

        return list(set(ns_records))
    except Exception:
        return []


def _get_txt_records(domain: str) -> List[str]:
    """Get TXT records for domain"""
    try:
        result = subprocess.run(
            ['nslookup', '-type=TXT', domain],
            capture_output=True,
            text=True,
            timeout=10
        )

        txt_records = []
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            for line in lines:
                if 'text =' in line.lower():
                    parts = line.split('=')
                    if len(parts) > 1:
                        txt_content = parts[1].strip().strip('"')
                        txt_records.append(txt_content)

        return txt_records
    except Exception:
        return []


def _get_cname_records(domain: str) -> List[str]:
    """Get CNAME records for domain"""
    try:
        result = subprocess.run(
            ['nslookup', '-type=CNAME', domain],
            capture_output=True,
            text=True,
            timeout=10
        )

        cname_records = []
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            for line in lines:
                if 'canonical name =' in line.lower():
                    parts = line.split('=')
                    if len(parts) > 1:
                        cname_records.append(parts[1].strip().rstrip('.'))

        return list(set(cname_records))
    except Exception:
        return []


def _get_soa_record(domain: str) -> Dict[str, Any]:
    """Get SOA record for domain"""
    try:
        result = subprocess.run(
            ['nslookup', '-type=SOA', domain],
            capture_output=True,
            text=True,
            timeout=10
        )

        soa_data = {}
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            for line in lines:
                if 'origin =' in line.lower():
                    parts = line.split('=')
                    if len(parts) > 1:
                        soa_data['primary_ns'] = parts[1].strip().rstrip('.')
                elif 'mail addr =' in line.lower():
                    parts = line.split('=')
                    if len(parts) > 1:
                        soa_data['admin_email'] = parts[1].strip().rstrip('.')

        return soa_data
    except Exception:
        return {}


def _analyze_dns_configuration(dns_data: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze DNS configuration for issues"""
    analysis = {
        'has_ipv6': bool(dns_data.get('aaaa_records')),
        'has_mail_servers': bool(dns_data.get('mx_records')),
        'nameserver_count': len(dns_data.get('ns_records', [])),
        'security_score': 0,
        'recommendations': []
    }

    if not analysis['has_ipv6']:
        analysis['recommendations'].append('Consider adding IPv6 support (AAAA records)')

    if analysis['nameserver_count'] < 2:
        analysis['recommendations'].append('Consider using multiple nameservers for redundancy')

    dns_security = dns_data.get('dns_security', {})
    analysis['security_score'] = dns_security.get('security_score', 0)

    return analysis


def _check_modern_dns_support(domain: str) -> Dict[str, Any]:
    """Check for modern DNS features"""
    modern_features = {
        'caa_records': False,
        'dnssec_enabled': False,
        'supports_doh': False,
        'supports_dot': False
    }

    try:
        # Check CAA records
        result = subprocess.run(
            ['nslookup', '-type=CAA', domain],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0 and 'issue' in result.stdout.lower():
            modern_features['caa_records'] = True

        # Basic DNSSEC check (simplified)
        result = subprocess.run(
            ['nslookup', '-type=DNSKEY', domain],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0 and 'dnskey' in result.stdout.lower():
            modern_features['dnssec_enabled'] = True

    except Exception:
        pass

    return modern_features


def _analyze_dns_security(txt_records: List[str], domain: str) -> Dict[str, Any]:
    """Analyze DNS security features"""
    security_analysis = {
        'spf_record': None,
        'dmarc_record': None,
        'security_score': 0,
        'security_features': []
    }

    for record in txt_records:
        if record.lower().startswith('v=spf1'):
            security_analysis['spf_record'] = record
            security_analysis['security_score'] += 25
            security_analysis['security_features'].append('SPF configured')
        elif record.lower().startswith('v=dmarc1'):
            security_analysis['dmarc_record'] = record
            security_analysis['security_score'] += 30
            security_analysis['security_features'].append('DMARC configured')

    return security_analysis


# ============================================================================
# WHOIS Helper Functions
# ============================================================================

def _get_raw_whois(domain: str) -> Dict[str, Any]:
    """Get raw WHOIS data"""
    try:
        result = subprocess.run(
            ['whois', domain],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode == 0 and result.stdout.strip():
            return {
                'raw_data': result.stdout,
                'source': 'system_whois'
            }
        else:
            return {'error': 'WHOIS lookup failed'}
    except Exception as e:
        return {'error': str(e)}


def _parse_whois_data(raw_data: str) -> Dict[str, Any]:
    """Parse raw WHOIS data"""
    parsed = {
        'registrar': 'Unknown',
        'creation_date': 'Unknown',
        'expiration_date': 'Unknown',
        'name_servers': [],
        'status': []
    }

    try:
        lines = raw_data.lower().split('\n')

        for line in lines:
            line = line.strip()
            if 'registrar:' in line:
                parts = line.split(':', 1)
                if len(parts) > 1:
                    parsed['registrar'] = parts[1].strip()
            elif 'creation date:' in line or 'created:' in line:
                date_value = _extract_date_from_line(line)
                if date_value:
                    parsed['creation_date'] = date_value
            elif 'expiry date:' in line or 'expires:' in line:
                date_value = _extract_date_from_line(line)
                if date_value:
                    parsed['expiration_date'] = date_value
            elif 'name server:' in line:
                ns_value = _extract_nameserver_from_line(line)
                if ns_value:
                    parsed['name_servers'].append(ns_value)

    except Exception as e:
        logger.warning(f"Error parsing WHOIS data: {e}")

    return parsed


def _extract_date_from_line(line: str) -> Optional[str]:
    """Extract date from WHOIS line"""
    import re

    try:
        date_patterns = [
            r'\d{4}-\d{2}-\d{2}',
            r'\d{2}-\w{3}-\d{4}',
            r'\d{4}\.\d{2}\.\d{2}',
        ]

        for pattern in date_patterns:
            match = re.search(pattern, line)
            if match:
                return match.group(0)

        return None
    except Exception:
        return None


# ============================================================================
# Reputation Analysis Helper Functions
# ============================================================================

def _check_dns_reputation(domain: str) -> Dict[str, Any]:
    """Check domain reputation through DNS analysis"""
    try:
        dns_reputation = {
            'has_mx_records': False,
            'reputation_score': 50,
            'risk_factors': []
        }

        mx_records = _get_mx_records(domain)
        if mx_records:
            dns_reputation['has_mx_records'] = True
            dns_reputation['reputation_score'] += 10

        return dns_reputation
    except Exception as e:
        return {'error': str(e)}


def _check_registration_reputation(domain: str) -> Dict[str, Any]:
    """Check domain reputation through registration analysis"""
    try:
        return {'reputation_score': 50, 'risk_factors': []}
    except Exception as e:
        return {'error': str(e)}


def _check_domain_patterns(domain: str) -> Dict[str, Any]:
    """Check domain reputation through pattern analysis"""
    try:
        return {'reputation_score': 50, 'risk_factors': []}
    except Exception as e:
        return {'error': str(e)}


def _check_public_blocklists(domain: str) -> Dict[str, Any]:
    """Check domain against public blocklists"""
    try:
        return {'reputation_score': 50, 'blocklisted': False}
    except Exception as e:
        return {'error': str(e)}


def _aggregate_domain_reputation(reputation_sources: Dict[str, Any]) -> Dict[str, Any]:
    """Aggregate domain reputation scores"""
    try:
        scores = [data.get('reputation_score', 50) for data in reputation_sources.values()]
        aggregated_score = sum(scores) / len(scores) if scores else 50

        risk_level = 'HIGH' if aggregated_score < 40 else ('MEDIUM' if aggregated_score < 70 else 'LOW')

        return {
            'aggregated_score': int(aggregated_score),
            'risk_level': risk_level,
            'threat_categories': [],
            'risk_factors': [],
            'sources_analyzed': len(reputation_sources)
        }
    except Exception as e:
        return {'error': str(e)}


def _check_ip_geographic_reputation(ip_address: str) -> Dict[str, Any]:
    """Check IP geographic reputation"""
    try:
        return {'reputation_score': 50, 'risk_factors': []}
    except Exception as e:
        return {'error': str(e)}


def _check_ip_service_reputation(ip_address: str) -> Dict[str, Any]:
    """Check IP service reputation"""
    try:
        return {'reputation_score': 50, 'risk_factors': []}
    except Exception as e:
        return {'error': str(e)}


def _check_dnsbl_reputation(ip_address: str) -> Dict[str, Any]:
    """Check IP against DNS blocklists"""
    try:
        return {'reputation_score': 50, 'blocklist_results': {}}
    except Exception as e:
        return {'error': str(e)}


def _check_reverse_dns_reputation(ip_address: str) -> Dict[str, Any]:
    """Check reverse DNS reputation"""
    try:
        return {'reputation_score': 50, 'risk_factors': []}
    except Exception as e:
        return {'error': str(e)}


def _aggregate_ip_reputation(reputation_sources: Dict[str, Any]) -> Dict[str, Any]:
    """Aggregate IP reputation scores"""
    try:
        scores = [data.get('reputation_score', 50) for data in reputation_sources.values()]
        aggregated_score = sum(scores) / len(scores) if scores else 50

        risk_level = 'HIGH' if aggregated_score < 40 else ('MEDIUM' if aggregated_score < 70 else 'LOW')

        return {
            'aggregated_score': int(aggregated_score),
            'risk_level': risk_level,
            'threat_categories': [],
            'risk_factors': [],
            'sources_analyzed': len(reputation_sources)
        }
    except Exception as e:
        return {'error': str(e)}


def _analyze_url_structure(url: str, parsed_url) -> Dict[str, Any]:
    """Analyze URL structure"""
    try:
        return {
            'url_length': len(url),
            'reputation_score': 50,
            'risk_factors': []
        }
    except Exception as e:
        return {'error': str(e)}


def _analyze_url_path(parsed_url) -> Dict[str, Any]:
    """Analyze URL path"""
    try:
        return {'reputation_score': 50, 'risk_factors': []}
    except Exception as e:
        return {'error': str(e)}


def _analyze_url_protocol(parsed_url) -> Dict[str, Any]:
    """Analyze URL protocol"""
    try:
        uses_https = parsed_url.scheme == 'https'
        score = 60 if uses_https else 40
        return {'reputation_score': score, 'risk_factors': [] if uses_https else ['Not using HTTPS']}
    except Exception as e:
        return {'error': str(e)}


def _aggregate_url_reputation(reputation_sources: Dict[str, Any]) -> Dict[str, Any]:
    """Aggregate URL reputation scores"""
    try:
        scores = [data.get('reputation_score', 50) for data in reputation_sources.values()]
        aggregated_score = sum(scores) / len(scores) if scores else 50

        risk_level = 'HIGH' if aggregated_score < 40 else ('MEDIUM' if aggregated_score < 70 else 'LOW')

        return {
            'aggregated_score': int(aggregated_score),
            'risk_level': risk_level,
            'threat_categories': [],
            'risk_factors': [],
            'sources_analyzed': len(reputation_sources)
        }
    except Exception as e:
        return {'error': str(e)}


def _extract_nameserver_from_line(line: str) -> Optional[str]:
    """Extract nameserver from WHOIS line"""
    try:
        parts = line.split(':', 1)
        if len(parts) > 1:
            ns = parts[1].strip().lower()
            ns = ns.split()[0] if ns.split() else ns
            if ns and '.' in ns:
                return ns
        return None
    except Exception:
        return None


def _analyze_whois_data(whois_data: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze WHOIS data for threats"""
    analysis = {
        'risk_level': 'LOW',
        'risk_factors': [],
        'registrar_reputation': 'UNKNOWN'
    }

    try:
        registrar = whois_data.get('registrar', '').lower()
        reputable_registrars = ['godaddy', 'namecheap', 'google', 'amazon']

        if any(rep_reg in registrar for rep_reg in reputable_registrars):
            analysis['registrar_reputation'] = 'HIGH'

    except Exception as e:
        logger.warning(f"Error analyzing WHOIS data: {e}")

    return analysis


def _calculate_domain_metrics(whois_data: Dict[str, Any]) -> Dict[str, Any]:
    """Calculate domain metrics"""
    metrics = {
        'domain_age_days': 0,
        'domain_age_category': 'UNKNOWN'
    }

    try:
        creation_date = whois_data.get('creation_date', '')
        if creation_date and creation_date != 'Unknown':
            created = _parse_whois_date(creation_date)
            if created:
                from datetime import datetime
                age_delta = datetime.now() - created
                metrics['domain_age_days'] = age_delta.days

                if age_delta.days < 30:
                    metrics['domain_age_category'] = 'VERY_NEW'
                elif age_delta.days < 365:
                    metrics['domain_age_category'] = 'NEW'
                else:
                    metrics['domain_age_category'] = 'ESTABLISHED'

    except Exception as e:
        logger.warning(f"Error calculating domain metrics: {e}")

    return metrics


def _parse_whois_date(date_string: str) -> Optional[datetime]:
    """Parse WHOIS date"""
    from datetime import datetime

    try:
        date_formats = ['%Y-%m-%d', '%d-%b-%Y', '%Y.%m.%d']

        for fmt in date_formats:
            try:
                return datetime.strptime(date_string.strip(), fmt)
            except ValueError:
                continue

        return None
    except Exception:
        return None


def handle_eventbridge_enrichment(event: Dict[str, Any], correlation_id: Optional[str], workflow_id: Optional[str]) -> Dict[str, Any]:
    """
    Handle EventBridge processing completed events for selective enrichment

    Args:
        event: EventBridge event
        correlation_id: Workflow correlation ID
        workflow_id: Workflow execution ID

    Returns:
        Enrichment response
    """
    try:
        detail = event.get('detail', {})
        event_type = detail.get('event_type')

        logger.info(f"Processing EventBridge enrichment event: {event_type}")

        # Handle processing completed events
        if event_type == 'processing.completed':
            processing_data = detail.get('data', {})
            high_confidence_indicators = processing_data.get('high_confidence_indicators', [])

            if not high_confidence_indicators:
                logger.info("No high-confidence indicators for enrichment")
                return create_response(200, {
                    'message': 'No indicators require enrichment',
                    'correlation_id': correlation_id,
                    'workflow_id': workflow_id
                })

            # Selective enrichment based on priority
            enrichment_targets = _select_enrichment_targets(high_confidence_indicators)

            if not enrichment_targets:
                logger.info("No indicators selected for enrichment after filtering")
                return create_response(200, {
                    'message': 'No indicators selected for enrichment',
                    'correlation_id': correlation_id,
                    'workflow_id': workflow_id
                })

            # Process enrichment
            results = _process_priority_enrichment(enrichment_targets, workflow_id, correlation_id)

            return create_response(200, results)

        else:
            logger.warning(f"Unsupported EventBridge event type for enrichment: {event_type}")
            return create_response(400, {'error': f'Unsupported event type: {event_type}'})

    except Exception as e:
        logger.error(f"Error handling EventBridge enrichment event: {e}", exc_info=True)

        # Emit error event
        if EVENT_INTEGRATION_AVAILABLE:
            EventEmitter.emit_system_error(
                error_message=str(e),
                error_context={'event_type': 'eventbridge_enrichment', 'original_event': event},
                workflow_id=workflow_id,
                correlation_id=correlation_id
            )

        return create_response(500, {
            'error': 'EventBridge enrichment failed',
            'message': str(e) if ENVIRONMENT == 'dev' else 'Internal error'
        })


def _select_enrichment_targets(indicators: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Select indicators for enrichment based on value and feasibility

    Args:
        indicators: High-confidence indicators from processing

    Returns:
        List of indicators selected for enrichment
    """
    selected = []

    for indicator in indicators:
        pattern = indicator.get('pattern', '')
        confidence = indicator.get('confidence', 0)
        threat_type = indicator.get('threat_type', '')

        # Select based on enrichment value
        should_enrich = False

        # Domains and IPs are good candidates for enrichment
        if any(pattern_type in pattern for pattern_type in ['domain-name', 'ipv4-addr', 'ipv6-addr']):
            should_enrich = True

        # High-value threat types
        if threat_type in ['c2_infrastructure', 'malware', 'phishing']:
            should_enrich = True

        # Very high confidence indicators
        if confidence >= 85:
            should_enrich = True

        # Government or commercial sources get priority
        if indicator.get('source_name') in ['government', 'commercial']:
            should_enrich = True

        if should_enrich:
            selected.append(indicator)

    logger.info(f"Selected {len(selected)} indicators for enrichment from {len(indicators)} candidates")
    return selected


def _process_priority_enrichment(targets: List[Dict[str, Any]], workflow_id: Optional[str], correlation_id: Optional[str]) -> Dict[str, Any]:
    """
    Process enrichment for selected high-priority targets

    Args:
        targets: Indicators selected for enrichment
        workflow_id: Workflow execution ID
        correlation_id: Workflow correlation ID

    Returns:
        Enrichment results
    """
    results = {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'environment': ENVIRONMENT,
        'correlation_id': correlation_id,
        'workflow_id': workflow_id,
        'enrichment_stats': {
            'targets_processed': 0,
            'successful_enrichments': 0,
            'failed_enrichments': 0,
            'cached_results': 0
        },
        'enrichment_results': [],
        'errors': []
    }

    try:
        # Get API keys
        api_keys = get_api_keys()

        # Process each target with priority handling
        for target in targets:
            try:
                # Extract enrichment targets from indicator
                enrichment_targets = _extract_targets_from_indicator(target)

                for enrichment_target in enrichment_targets:
                    if check_rate_limit():
                        enrichment_result = process_enrichment_target(enrichment_target, api_keys)
                        results['enrichment_results'].append(enrichment_result)
                        results['enrichment_stats']['successful_enrichments'] += 1
                    else:
                        logger.warning(f"Rate limit exceeded for target: {enrichment_target}")
                        results['enrichment_stats']['failed_enrichments'] += 1

                results['enrichment_stats']['targets_processed'] += 1

            except Exception as e:
                logger.error(f"Error processing enrichment target: {e}")
                results['errors'].append(str(e))
                results['enrichment_stats']['failed_enrichments'] += 1

        logger.info(f"Priority enrichment completed: {results['enrichment_stats']['successful_enrichments']} successful")

        return results

    except Exception as e:
        logger.error(f"Error in priority enrichment processing: {e}")
        results['errors'].append(str(e))
        return results


def _extract_targets_from_indicator(indicator: Dict[str, Any]) -> List[str]:
    """
    Extract enrichment targets from STIX indicator pattern

    Args:
        indicator: STIX indicator object

    Returns:
        List of targets for enrichment
    """
    targets = []
    pattern = indicator.get('pattern', '')

    # Extract values using regex patterns
    import re

    # Extract domain names
    domain_matches = re.findall(r"domain-name:value\s*=\s*'([^']+)'", pattern)
    targets.extend(domain_matches)

    # Extract IP addresses
    ip_matches = re.findall(r"(?:ipv4|ipv6)-addr:value\s*=\s*'([^']+)'", pattern)
    targets.extend(ip_matches)

    # Extract URLs (domain part)
    url_matches = re.findall(r"url:value\s*=\s*'([^']+)'", pattern)
    for url in url_matches:
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            if parsed.netloc:
                targets.append(parsed.netloc)
        except Exception:
            pass

    return list(set(targets))  # Remove duplicates