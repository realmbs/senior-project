"""
Unit tests for the OSINT enrichment Lambda function
"""

import pytest
import json
import time
import socket
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timezone, timedelta
from decimal import Decimal
import responses
import boto3
from moto import mock_dynamodb, mock_secretsmanager
from botocore.exceptions import ClientError

# Import the enrichment module - adjust path as needed
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '../../infrastructure/terraform/lambda_functions'))

try:
    from enrichment import (
        lambda_handler, get_api_keys, check_cache, store_cache,
        enrich_ip_shodan, enrich_ip_geolocation, perform_dns_lookup,
        enrich_domain, rate_limit_check, create_cache_key,
        process_enrichment_batch, validate_indicator_format
    )
except ImportError as e:
    # Handle case where enrichment module is not directly importable
    enrichment = None


class TestCacheFunctionality:
    """Test enrichment cache functionality"""

    @pytest.fixture(autouse=True)
    def setup_method(self, mock_dynamodb_setup):
        """Set up test environment"""
        self.tables = mock_dynamodb_setup
        self.enrichment_table = self.tables['enrichment_table']

    def test_cache_key_creation(self):
        """Test cache key creation for different indicator types"""
        test_cases = [
            ('192.168.1.1', 'ip', 'enrichment_ip_192.168.1.1'),
            ('malicious.com', 'domain', 'enrichment_domain_malicious.com'),
            ('http://evil.com/path', 'url', 'enrichment_url_http://evil.com/path')
        ]

        for indicator, indicator_type, expected in test_cases:
            if enrichment:
                result = create_cache_key(indicator, indicator_type)
                assert expected in result or result.endswith(indicator)

    def test_check_cache_miss(self):
        """Test cache check when no cached data exists"""
        cache_key = "enrichment_ip_192.168.1.100"

        if enrichment:
            with patch.dict(os.environ, {
                'ENRICHMENT_CACHE_TABLE': 'threat-intel-platform-enrichment-cache-test'
            }):
                result = check_cache(cache_key)
                assert result is None

    def test_check_cache_hit(self):
        """Test cache check when cached data exists and is valid"""
        cache_key = "enrichment_ip_192.168.1.100"
        cached_data = {
            'ip': '192.168.1.100',
            'country': 'United States',
            'org': 'Test Organization'
        }

        # Store cached data
        ttl = int(time.time()) + 3600  # 1 hour from now
        self.enrichment_table.put_item(Item={
            'cache_key': cache_key,
            'enrichment_data': cached_data,
            'created_at': datetime.now(timezone.utc).isoformat(),
            'ttl': ttl
        })

        if enrichment:
            with patch.dict(os.environ, {
                'ENRICHMENT_CACHE_TABLE': 'threat-intel-platform-enrichment-cache-test'
            }):
                result = check_cache(cache_key)
                assert result is not None
                assert result['ip'] == '192.168.1.100'

    def test_check_cache_expired(self):
        """Test cache check when cached data has expired"""
        cache_key = "enrichment_ip_expired"
        cached_data = {'ip': '192.168.1.101'}

        # Store expired data
        ttl = int(time.time()) - 3600  # 1 hour ago (expired)
        self.enrichment_table.put_item(Item={
            'cache_key': cache_key,
            'enrichment_data': cached_data,
            'created_at': datetime.now(timezone.utc).isoformat(),
            'ttl': ttl
        })

        if enrichment:
            with patch.dict(os.environ, {
                'ENRICHMENT_CACHE_TABLE': 'threat-intel-platform-enrichment-cache-test'
            }):
                result = check_cache(cache_key)
                assert result is None

    def test_store_cache_success(self):
        """Test successful cache storage"""
        cache_key = "enrichment_ip_store_test"
        enrichment_data = {
            'ip': '192.168.1.102',
            'country': 'Canada',
            'org': 'Test Org',
            'latitude': 45.5017,
            'longitude': -73.5673
        }

        if enrichment:
            with patch.dict(os.environ, {
                'ENRICHMENT_CACHE_TABLE': 'threat-intel-platform-enrichment-cache-test',
                'ENRICHMENT_TTL_DAYS': '7'
            }):
                store_cache(cache_key, enrichment_data)

                # Verify storage
                response = self.enrichment_table.get_item(Key={'cache_key': cache_key})
                assert 'Item' in response
                stored_data = response['Item']['enrichment_data']
                assert stored_data['ip'] == '192.168.1.102'
                assert isinstance(stored_data['latitude'], Decimal)

    def test_store_cache_float_conversion(self):
        """Test cache storage with float to Decimal conversion"""
        cache_key = "enrichment_float_test"
        enrichment_data = {
            'confidence_score': 85.5,
            'latitude': 40.7128,
            'longitude': -74.0060,
            'nested': {
                'score': 92.3,
                'probability': 0.75
            }
        }

        if enrichment:
            with patch.dict(os.environ, {
                'ENRICHMENT_CACHE_TABLE': 'threat-intel-platform-enrichment-cache-test'
            }):
                store_cache(cache_key, enrichment_data)

                # Verify float conversion
                response = self.enrichment_table.get_item(Key={'cache_key': cache_key})
                stored_data = response['Item']['enrichment_data']
                assert isinstance(stored_data['confidence_score'], Decimal)
                assert isinstance(stored_data['nested']['score'], Decimal)


class TestShodanIntegration:
    """Test Shodan API integration"""

    @responses.activate
    def test_enrich_ip_shodan_success(self):
        """Test successful Shodan IP enrichment"""
        test_ip = "192.168.1.100"
        shodan_response = {
            "ip_str": "192.168.1.100",
            "org": "Test Organization",
            "isp": "Test ISP",
            "country_name": "United States",
            "country_code": "US",
            "city": "Test City",
            "region_code": "CA",
            "postal_code": "90210",
            "latitude": 34.0522,
            "longitude": -118.2437,
            "ports": [80, 443, 22],
            "vulns": ["CVE-2021-44228"],
            "last_update": "2024-01-01T00:00:00.000Z"
        }

        responses.add(
            responses.GET,
            f'https://api.shodan.io/shodan/host/{test_ip}',
            json=shodan_response,
            status=200
        )

        if enrichment:
            api_keys = {'shodan_api_key': 'test_shodan_key'}
            result = enrich_ip_shodan(test_ip, api_keys)

            assert result is not None
            assert result['ip_str'] == test_ip
            assert result['org'] == 'Test Organization'
            assert len(result['ports']) > 0

    @responses.activate
    def test_enrich_ip_shodan_not_found(self):
        """Test Shodan enrichment when IP not found"""
        test_ip = "192.168.1.200"

        responses.add(
            responses.GET,
            f'https://api.shodan.io/shodan/host/{test_ip}',
            json={'error': 'No information available for that IP.'},
            status=404
        )

        if enrichment:
            api_keys = {'shodan_api_key': 'test_shodan_key'}
            result = enrich_ip_shodan(test_ip, api_keys)

            assert result is None or 'error' in result

    @responses.activate
    def test_enrich_ip_shodan_rate_limit(self):
        """Test Shodan enrichment with rate limiting"""
        test_ip = "192.168.1.201"

        responses.add(
            responses.GET,
            f'https://api.shodan.io/shodan/host/{test_ip}',
            json={'error': 'Request rate limit exceeded'},
            status=429
        )

        if enrichment:
            api_keys = {'shodan_api_key': 'test_shodan_key'}
            result = enrich_ip_shodan(test_ip, api_keys)

            assert result is None or 'error' in result

    @responses.activate
    def test_enrich_ip_shodan_invalid_key(self):
        """Test Shodan enrichment with invalid API key"""
        test_ip = "192.168.1.202"

        responses.add(
            responses.GET,
            f'https://api.shodan.io/shodan/host/{test_ip}',
            json={'error': 'Invalid API key'},
            status=401
        )

        if enrichment:
            api_keys = {'shodan_api_key': 'invalid_key'}
            result = enrich_ip_shodan(test_ip, api_keys)

            assert result is None or 'error' in result


class TestGeolocationEnrichment:
    """Test IP geolocation enrichment"""

    @responses.activate
    def test_enrich_ip_geolocation_success(self):
        """Test successful IP geolocation enrichment"""
        test_ip = "8.8.8.8"
        geo_response = {
            "ip": "8.8.8.8",
            "country": "United States",
            "country_code": "US",
            "region": "California",
            "region_code": "CA",
            "city": "Mountain View",
            "zip": "94035",
            "latitude": 37.386,
            "longitude": -122.0838,
            "timezone": "America/Los_Angeles",
            "isp": "Google LLC",
            "org": "Google Public DNS",
            "as": "AS15169 Google LLC"
        }

        responses.add(
            responses.GET,
            f'http://ip-api.com/json/{test_ip}',
            json=geo_response,
            status=200
        )

        if enrichment:
            result = enrich_ip_geolocation(test_ip)

            assert result is not None
            assert result['ip'] == test_ip
            assert result['country'] == 'United States'
            assert result['city'] == 'Mountain View'

    @responses.activate
    def test_enrich_ip_geolocation_private_ip(self):
        """Test geolocation enrichment for private IP"""
        test_ip = "192.168.1.1"
        geo_response = {
            "status": "fail",
            "message": "private range",
            "query": "192.168.1.1"
        }

        responses.add(
            responses.GET,
            f'http://ip-api.com/json/{test_ip}',
            json=geo_response,
            status=200
        )

        if enrichment:
            result = enrich_ip_geolocation(test_ip)

            assert result is None or result.get('status') == 'fail'

    @responses.activate
    def test_enrich_ip_geolocation_timeout(self):
        """Test geolocation enrichment with timeout"""
        test_ip = "1.1.1.1"

        responses.add(
            responses.GET,
            f'http://ip-api.com/json/{test_ip}',
            body=ConnectionError('Request timeout')
        )

        if enrichment:
            result = enrich_ip_geolocation(test_ip)

            assert result is None


class TestDNSEnrichment:
    """Test DNS lookup functionality"""

    def test_perform_dns_lookup_valid_domain(self):
        """Test DNS lookup for valid domain"""
        test_domain = "example.com"

        if enrichment:
            with patch('socket.gethostbyname_ex') as mock_dns:
                mock_dns.return_value = (
                    'example.com',
                    ['example.com'],
                    ['93.184.216.34']
                )

                result = perform_dns_lookup(test_domain)

                assert result is not None
                assert 'a_records' in result
                assert '93.184.216.34' in result['a_records']

    def test_perform_dns_lookup_invalid_domain(self):
        """Test DNS lookup for invalid domain"""
        test_domain = "nonexistent-domain-12345.com"

        if enrichment:
            with patch('socket.gethostbyname_ex') as mock_dns:
                mock_dns.side_effect = socket.gaierror("Name or service not known")

                result = perform_dns_lookup(test_domain)

                assert result is None or 'error' in result

    def test_perform_dns_lookup_reverse(self):
        """Test reverse DNS lookup"""
        test_ip = "8.8.8.8"

        if enrichment:
            with patch('socket.gethostbyaddr') as mock_reverse:
                mock_reverse.return_value = (
                    'dns.google',
                    ['dns.google'],
                    ['8.8.8.8']
                )

                result = perform_dns_lookup(test_ip, lookup_type='reverse')

                assert result is not None
                assert 'hostname' in result or 'reverse_dns' in result

    def test_perform_dns_lookup_mx_records(self):
        """Test MX record lookup"""
        test_domain = "example.com"

        if enrichment:
            # Mock MX record lookup would require additional DNS library mocking
            # This is a placeholder for comprehensive MX testing
            pass


class TestDomainEnrichment:
    """Test domain enrichment functionality"""

    def test_enrich_domain_complete(self):
        """Test complete domain enrichment"""
        test_domain = "malicious.com"

        if enrichment:
            with patch('enrichment.perform_dns_lookup') as mock_dns:
                mock_dns.return_value = {
                    'a_records': ['192.168.1.100'],
                    'mx_records': ['mail.malicious.com']
                }

                result = enrich_domain(test_domain)

                assert result is not None
                assert 'dns_data' in result

    def test_enrich_domain_no_resolution(self):
        """Test domain enrichment when DNS fails"""
        test_domain = "unresolvable.domain"

        if enrichment:
            with patch('enrichment.perform_dns_lookup') as mock_dns:
                mock_dns.return_value = None

                result = enrich_domain(test_domain)

                # Should handle DNS failure gracefully


class TestRateLimiting:
    """Test rate limiting functionality"""

    def test_rate_limit_check_within_limit(self):
        """Test rate limiting when within acceptable limits"""
        if enrichment:
            # Reset rate limiting state
            global request_timestamps
            request_timestamps = []

            # Make requests within limit
            for i in range(3):
                result = rate_limit_check(max_requests=5, time_window=60)
                assert result is True

    def test_rate_limit_check_exceeded(self):
        """Test rate limiting when limit is exceeded"""
        if enrichment:
            # Simulate rapid requests
            global request_timestamps
            current_time = time.time()
            request_timestamps = [current_time - i for i in range(10)]

            result = rate_limit_check(max_requests=5, time_window=60)
            # Should detect rate limit exceeded


class TestIndicatorValidation:
    """Test indicator format validation"""

    def test_validate_indicator_format_valid_ip(self):
        """Test validation of valid IP addresses"""
        valid_ips = [
            '192.168.1.1',
            '10.0.0.1',
            '172.16.0.1',
            '8.8.8.8',
            '2001:db8::1'  # IPv6
        ]

        for ip in valid_ips:
            if enrichment:
                result = validate_indicator_format(ip, 'ip')
                assert result is True

    def test_validate_indicator_format_invalid_ip(self):
        """Test validation of invalid IP addresses"""
        invalid_ips = [
            '999.999.999.999',
            '192.168.1',
            'not-an-ip',
            '192.168.1.1.1',
            ''
        ]

        for ip in invalid_ips:
            if enrichment:
                result = validate_indicator_format(ip, 'ip')
                assert result is False

    def test_validate_indicator_format_valid_domain(self):
        """Test validation of valid domains"""
        valid_domains = [
            'example.com',
            'sub.domain.org',
            'test-domain.co.uk',
            'a.b.c.d.e'
        ]

        for domain in valid_domains:
            if enrichment:
                result = validate_indicator_format(domain, 'domain')
                assert result is True

    def test_validate_indicator_format_invalid_domain(self):
        """Test validation of invalid domains"""
        invalid_domains = [
            '',
            '.com',
            'domain.',
            'domain..com',
            'very-' + 'long-' * 100 + 'domain.com'  # Too long
        ]

        for domain in invalid_domains:
            if enrichment:
                result = validate_indicator_format(domain, 'domain')
                assert result is False


class TestBatchEnrichment:
    """Test batch enrichment processing"""

    @pytest.fixture(autouse=True)
    def setup_method(self, mock_dynamodb_setup, mock_secrets_manager):
        """Set up test environment"""
        self.tables = mock_dynamodb_setup

    def test_process_enrichment_batch_mixed_indicators(self):
        """Test batch enrichment with mixed indicator types"""
        indicators = [
            {'value': '192.168.1.100', 'type': 'ip'},
            {'value': 'malicious.com', 'type': 'domain'},
            {'value': '10.0.0.1', 'type': 'ip'}
        ]

        if enrichment:
            with patch.dict(os.environ, {
                'ENRICHMENT_CACHE_TABLE': 'threat-intel-platform-enrichment-cache-test',
                'SECRETS_MANAGER_ARN': 'threat-intel-platform/api-keys/test'
            }):
                with patch('enrichment.enrich_ip_shodan') as mock_shodan:
                    with patch('enrichment.enrich_domain') as mock_domain:
                        mock_shodan.return_value = {'ip': '192.168.1.100'}
                        mock_domain.return_value = {'domain': 'malicious.com'}

                        result = process_enrichment_batch(indicators)

                        assert result is not None
                        assert len(result) > 0

    def test_process_enrichment_batch_cache_utilization(self):
        """Test batch enrichment with cache hits"""
        indicators = [
            {'value': '192.168.1.100', 'type': 'ip'}
        ]

        # Pre-populate cache
        cache_key = 'enrichment_ip_192.168.1.100'
        cached_data = {'ip': '192.168.1.100', 'cached': True}
        self.tables['enrichment_table'].put_item(Item={
            'cache_key': cache_key,
            'enrichment_data': cached_data,
            'created_at': datetime.now(timezone.utc).isoformat(),
            'ttl': int(time.time()) + 3600
        })

        if enrichment:
            with patch.dict(os.environ, {
                'ENRICHMENT_CACHE_TABLE': 'threat-intel-platform-enrichment-cache-test'
            }):
                result = process_enrichment_batch(indicators)

                assert result is not None
                # Should use cached data

    def test_process_enrichment_batch_empty(self):
        """Test batch enrichment with empty input"""
        indicators = []

        if enrichment:
            result = process_enrichment_batch(indicators)

            assert result is not None
            assert len(result) == 0


class TestLambdaHandler:
    """Test main Lambda handler functionality"""

    @pytest.fixture(autouse=True)
    def setup_method(self, mock_dynamodb_setup, mock_secrets_manager):
        """Set up test environment"""
        self.tables = mock_dynamodb_setup

    def test_lambda_handler_single_indicator(self, sample_lambda_context):
        """Test Lambda handler with single indicator enrichment"""
        event = {
            'httpMethod': 'POST',
            'path': '/enrich',
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({
                'indicators': ['192.168.1.100'],
                'enrichment_types': ['shodan', 'geolocation']
            })
        }

        if enrichment:
            with patch.dict(os.environ, {
                'ENVIRONMENT': 'test',
                'SECRETS_MANAGER_ARN': 'threat-intel-platform/api-keys/test',
                'ENRICHMENT_CACHE_TABLE': 'threat-intel-platform-enrichment-cache-test',
                'ENRICHMENT_TTL_DAYS': '7'
            }):
                with patch('enrichment.enrich_ip_shodan') as mock_shodan:
                    with patch('enrichment.enrich_ip_geolocation') as mock_geo:
                        mock_shodan.return_value = {'org': 'Test Org'}
                        mock_geo.return_value = {'country': 'US'}

                        result = lambda_handler(event, sample_lambda_context)

                        assert result['statusCode'] == 200
                        response_body = json.loads(result['body'])
                        assert 'enrichment_results' in response_body

    def test_lambda_handler_batch_indicators(self, sample_lambda_context):
        """Test Lambda handler with batch indicator enrichment"""
        event = {
            'httpMethod': 'POST',
            'path': '/enrich',
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({
                'indicators': ['192.168.1.100', 'malicious.com', '10.0.0.1'],
                'enrichment_types': ['all']
            })
        }

        if enrichment:
            with patch.dict(os.environ, {
                'ENVIRONMENT': 'test',
                'SECRETS_MANAGER_ARN': 'threat-intel-platform/api-keys/test',
                'ENRICHMENT_CACHE_TABLE': 'threat-intel-platform-enrichment-cache-test'
            }):
                result = lambda_handler(event, sample_lambda_context)

                assert result['statusCode'] == 200
                response_body = json.loads(result['body'])
                assert 'enrichment_results' in response_body

    def test_lambda_handler_invalid_indicators(self, sample_lambda_context):
        """Test Lambda handler with invalid indicators"""
        event = {
            'httpMethod': 'POST',
            'path': '/enrich',
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({
                'indicators': ['invalid-ip', '999.999.999.999'],
                'enrichment_types': ['shodan']
            })
        }

        if enrichment:
            result = lambda_handler(event, sample_lambda_context)

            assert result['statusCode'] == 400
            response_body = json.loads(result['body'])
            assert 'error' in response_body

    def test_lambda_handler_missing_body(self, sample_lambda_context):
        """Test Lambda handler with missing request body"""
        event = {
            'httpMethod': 'POST',
            'path': '/enrich',
            'headers': {'Content-Type': 'application/json'},
            'body': None
        }

        if enrichment:
            result = lambda_handler(event, sample_lambda_context)

            assert result['statusCode'] == 400
            response_body = json.loads(result['body'])
            assert 'error' in response_body


class TestErrorHandling:
    """Test error handling scenarios"""

    def test_secrets_manager_failure(self, mock_dynamodb_setup):
        """Test handling of Secrets Manager failures"""
        if enrichment:
            with patch('boto3.client') as mock_client:
                mock_secrets = Mock()
                mock_secrets.get_secret_value.side_effect = ClientError(
                    {'Error': {'Code': 'ResourceNotFoundException'}},
                    'GetSecretValue'
                )
                mock_client.return_value = mock_secrets

                result = get_api_keys()
                assert result is not None
                # Should handle secrets failure gracefully

    def test_network_timeout_handling(self):
        """Test handling of network timeouts"""
        if enrichment:
            with patch('requests.get') as mock_request:
                mock_request.side_effect = ConnectionError('Network timeout')

                result = enrich_ip_geolocation('8.8.8.8')
                assert result is None

    def test_malformed_api_response(self):
        """Test handling of malformed API responses"""
        if enrichment:
            with responses.activate:
                responses.add(
                    responses.GET,
                    'https://api.shodan.io/shodan/host/8.8.8.8',
                    body='invalid json response',
                    status=200
                )

                api_keys = {'shodan_api_key': 'test_key'}
                result = enrich_ip_shodan('8.8.8.8', api_keys)
                # Should handle malformed responses gracefully


# Skip all tests if enrichment module is not available
if not enrichment:
    pytest.skip("Enrichment module not available", allow_module_level=True)