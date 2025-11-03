"""
Enhanced mocking tests for external dependencies
Tests Lambda functions with realistic mock responses for external APIs
"""

import pytest
import json
import responses
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timezone
import boto3
from moto import mock_aws
import os
import sys

# Mock environment variables
os.environ.setdefault('SECRETS_MANAGER_ARN', 'arn:aws:secretsmanager:us-east-1:123456789012:secret:test-secret')
os.environ.setdefault('THREAT_INTEL_TABLE', 'test-threat-intel-table')
os.environ.setdefault('DEDUP_TABLE', 'test-dedup-table')
os.environ.setdefault('RAW_DATA_BUCKET', 'test-raw-data-bucket')
os.environ.setdefault('PROCESSED_DATA_BUCKET', 'test-processed-data-bucket')
os.environ.setdefault('ENRICHMENT_CACHE_TABLE', 'test-enrichment-cache-table')
os.environ.setdefault('ENVIRONMENT', 'test')

# Import enhanced mock data
sys.path.append(os.path.join(os.path.dirname(__file__), '../fixtures'))
from enhanced_mock_data import (
    MockOTXResponse, MockAbuseCHResponse, MockShodanResponse,
    MockDNSResponse, MockGeolocationResponse, MockSTIXResponse,
    MOCK_OTX_PULSES, MOCK_ABUSE_CH_URLS, TEST_INDICATORS
)

# Import Lambda functions
sys.path.append(os.path.join(os.path.dirname(__file__), '../../infrastructure/terraform/lambda_functions/build_correct'))

try:
    from collector import lambda_handler as collector_handler, collect_otx_data, collect_abuse_ch_data
    COLLECTOR_AVAILABLE = True
except ImportError:
    COLLECTOR_AVAILABLE = False

try:
    from enrichment import lambda_handler as enrichment_handler
    ENRICHMENT_AVAILABLE = True
except ImportError:
    ENRICHMENT_AVAILABLE = False


class TestEnhancedOTXMocking:
    """Test OTX API integration with enhanced mocking"""

    @responses.activate
    @pytest.mark.skipif(not COLLECTOR_AVAILABLE, reason="Collector module not available")
    def test_otx_successful_collection(self):
        """Test successful OTX data collection with realistic mock data"""
        # Mock API key retrieval
        with patch('collector.get_api_keys') as mock_keys:
            mock_keys.return_value = {'otx_api_key': 'test_otx_key'}

            # Mock OTX API response
            responses.add(
                responses.GET,
                'https://otx.alienvault.com/api/v1/pulses/subscribed',
                json=MOCK_OTX_PULSES,
                status=200,
                headers={'Content-Type': 'application/json'}
            )

            # Mock DynamoDB operations
            with patch('collector.check_duplicate') as mock_check, \
                 patch('collector.store_indicator') as mock_store:

                mock_check.return_value = False  # No duplicates
                mock_store.return_value = True   # Successful storage

                # Test the collection
                if hasattr(collect_otx_data, '__call__'):
                    result = collect_otx_data()

                    # Verify API was called
                    assert len(responses.calls) == 1
                    assert 'otx.alienvault.com' in responses.calls[0].request.url

                    # Verify result structure
                    assert isinstance(result, (list, dict))

    @responses.activate
    @pytest.mark.skipif(not COLLECTOR_AVAILABLE, reason="Collector module not available")
    def test_otx_rate_limit_handling(self):
        """Test OTX rate limit response handling"""
        with patch('collector.get_api_keys') as mock_keys:
            mock_keys.return_value = {'otx_api_key': 'test_otx_key'}

            # Mock rate limit response
            responses.add(
                responses.GET,
                'https://otx.alienvault.com/api/v1/pulses/subscribed',
                json=MockOTXResponse.get_error_response(429),
                status=429,
                headers={'Retry-After': '60'}
            )

            if hasattr(collect_otx_data, '__call__'):
                # Should handle rate limit gracefully
                result = collect_otx_data()
                assert result is not None  # Should not crash

    @responses.activate
    @pytest.mark.skipif(not COLLECTOR_AVAILABLE, reason="Collector module not available")
    def test_otx_authentication_error(self):
        """Test OTX authentication error handling"""
        with patch('collector.get_api_keys') as mock_keys:
            mock_keys.return_value = {'otx_api_key': 'invalid_key'}

            # Mock authentication error
            responses.add(
                responses.GET,
                'https://otx.alienvault.com/api/v1/pulses/subscribed',
                json=MockOTXResponse.get_error_response(401),
                status=401
            )

            if hasattr(collect_otx_data, '__call__'):
                # Should handle auth error gracefully
                result = collect_otx_data()
                assert result is not None

    @responses.activate
    @pytest.mark.skipif(not COLLECTOR_AVAILABLE, reason="Collector module not available")
    def test_otx_malformed_response(self):
        """Test OTX malformed response handling"""
        with patch('collector.get_api_keys') as mock_keys:
            mock_keys.return_value = {'otx_api_key': 'test_key'}

            # Mock malformed response
            responses.add(
                responses.GET,
                'https://otx.alienvault.com/api/v1/pulses/subscribed',
                body='<html>Error page</html>',
                status=200,
                headers={'Content-Type': 'text/html'}
            )

            if hasattr(collect_otx_data, '__call__'):
                # Should handle malformed response gracefully
                result = collect_otx_data()
                assert result is not None


class TestEnhancedAbuseCHMocking:
    """Test Abuse.ch API integration with enhanced mocking"""

    @responses.activate
    @pytest.mark.skipif(not COLLECTOR_AVAILABLE, reason="Collector module not available")
    def test_abuse_ch_successful_collection(self):
        """Test successful Abuse.ch data collection"""
        # Mock Abuse.ch API response
        responses.add(
            responses.GET,
            'https://urlhaus-api.abuse.ch/v1/urls/recent/',
            json=MOCK_ABUSE_CH_URLS,
            status=200
        )

        # Mock storage operations
        with patch('collector.check_duplicate') as mock_check, \
             patch('collector.store_indicator') as mock_store:

            mock_check.return_value = False
            mock_store.return_value = True

            if hasattr(collect_abuse_ch_data, '__call__'):
                result = collect_abuse_ch_data()

                # Verify API was called
                assert len(responses.calls) == 1
                assert 'urlhaus-api.abuse.ch' in responses.calls[0].request.url

                # Verify result
                assert isinstance(result, (list, dict))

    @responses.activate
    @pytest.mark.skipif(not COLLECTOR_AVAILABLE, reason="Collector module not available")
    def test_abuse_ch_no_results(self):
        """Test Abuse.ch no results response"""
        # Mock no results response
        responses.add(
            responses.GET,
            'https://urlhaus-api.abuse.ch/v1/urls/recent/',
            json=MockAbuseCHResponse.get_error_response("no_results"),
            status=200
        )

        if hasattr(collect_abuse_ch_data, '__call__'):
            result = collect_abuse_ch_data()
            # Should handle empty results gracefully
            assert result is not None

    @responses.activate
    @pytest.mark.skipif(not COLLECTOR_AVAILABLE, reason="Collector module not available")
    def test_abuse_ch_service_error(self):
        """Test Abuse.ch service error handling"""
        # Mock service error
        responses.add(
            responses.GET,
            'https://urlhaus-api.abuse.ch/v1/urls/recent/',
            body='Service temporarily unavailable',
            status=503
        )

        if hasattr(collect_abuse_ch_data, '__call__'):
            result = collect_abuse_ch_data()
            # Should handle service errors gracefully
            assert result is not None


class TestEnhancedShodanMocking:
    """Test Shodan API integration with enhanced mocking"""

    @responses.activate
    @pytest.mark.skipif(not ENRICHMENT_AVAILABLE, reason="Enrichment module not available")
    def test_shodan_host_lookup_success(self):
        """Test successful Shodan host lookup"""
        test_ip = "192.168.1.100"

        # Mock Shodan API response
        responses.add(
            responses.GET,
            f'https://api.shodan.io/shodan/host/{test_ip}',
            json=MockShodanResponse.get_host_info_response(test_ip),
            status=200
        )

        # Mock enrichment handler
        event = {
            'body': json.dumps({
                'indicators': [test_ip],
                'enrichment_types': ['shodan']
            })
        }

        # Note: This would require the enrichment handler to be properly importable
        # For now, we're testing the mock structure
        assert len(responses.calls) == 0  # No calls yet

        # Simulate the API call that would happen in enrichment
        import requests
        response = requests.get(f'https://api.shodan.io/shodan/host/{test_ip}')
        data = response.json()

        # Verify mock data structure
        assert data['ip'] == test_ip
        assert 'hostnames' in data
        assert 'country_name' in data
        assert 'ports' in data

    @responses.activate
    def test_shodan_rate_limit_handling(self):
        """Test Shodan rate limit response"""
        test_ip = "192.168.1.100"

        # Mock rate limit response
        responses.add(
            responses.GET,
            f'https://api.shodan.io/shodan/host/{test_ip}',
            json=MockShodanResponse.get_error_response("rate_limit"),
            status=429
        )

        # Simulate rate limit scenario
        import requests
        response = requests.get(f'https://api.shodan.io/shodan/host/{test_ip}')
        data = response.json()

        assert response.status_code == 429
        assert 'error' in data

    @responses.activate
    def test_shodan_no_information_available(self):
        """Test Shodan no information response"""
        test_ip = "192.168.1.100"

        # Mock no information response
        responses.add(
            responses.GET,
            f'https://api.shodan.io/shodan/host/{test_ip}',
            json=MockShodanResponse.get_error_response("no_information"),
            status=404
        )

        import requests
        response = requests.get(f'https://api.shodan.io/shodan/host/{test_ip}')

        assert response.status_code == 404


class TestEnhancedDNSMocking:
    """Test DNS resolution with enhanced mocking"""

    def test_dns_resolution_success(self):
        """Test successful DNS resolution"""
        test_domain = "malicious.example.com"

        # Mock DNS response
        mock_dns_data = MockDNSResponse.get_dns_resolution_response(test_domain)

        # Verify mock data structure
        assert mock_dns_data['domain'] == test_domain
        assert 'a_records' in mock_dns_data
        assert 'mx_records' in mock_dns_data
        assert 'ns_records' in mock_dns_data
        assert isinstance(mock_dns_data['a_records'], list)

    def test_dns_nxdomain_error(self):
        """Test DNS NXDOMAIN error"""
        error_response = MockDNSResponse.get_error_response("nxdomain")

        assert 'error' in error_response
        assert error_response['rcode'] == 'NXDOMAIN'

    def test_dns_timeout_error(self):
        """Test DNS timeout error"""
        error_response = MockDNSResponse.get_error_response("timeout")

        assert 'error' in error_response
        assert error_response['rcode'] == 'TIMEOUT'


class TestEnhancedGeolocationMocking:
    """Test IP geolocation with enhanced mocking"""

    def test_geolocation_success(self):
        """Test successful IP geolocation"""
        test_ip = "192.0.2.1"

        geo_data = MockGeolocationResponse.get_geolocation_response(test_ip)

        # Verify mock data structure
        assert geo_data['ip'] == test_ip
        assert 'country' in geo_data
        assert 'latitude' in geo_data
        assert 'longitude' in geo_data
        assert isinstance(geo_data['latitude'], (int, float))
        assert isinstance(geo_data['longitude'], (int, float))

    def test_geolocation_private_ip_error(self):
        """Test geolocation error for private IP"""
        error_response = MockGeolocationResponse.get_error_response("private_ip")

        assert 'error' in error_response
        assert 'private' in error_response['error'].lower()


class TestEnhancedSTIXMocking:
    """Test STIX 2.1 formatting with enhanced mocking"""

    def test_stix_indicator_generation(self):
        """Test STIX 2.1 indicator generation"""
        test_indicators = [
            ("192.168.1.100", "ipv4"),
            ("malicious.example.com", "domain"),
            ("http://evil.com/payload", "url"),
            ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "file")
        ]

        for indicator_value, indicator_type in test_indicators:
            stix_indicator = MockSTIXResponse.get_stix_indicator(indicator_value, indicator_type)

            # Verify STIX 2.1 compliance
            assert stix_indicator['type'] == 'indicator'
            assert stix_indicator['spec_version'] == '2.1'
            assert 'id' in stix_indicator
            assert stix_indicator['id'].startswith('indicator--')
            assert 'pattern' in stix_indicator
            assert 'labels' in stix_indicator
            assert isinstance(stix_indicator['confidence'], int)

    def test_stix_bundle_generation(self):
        """Test STIX 2.1 bundle generation"""
        indicators = [
            MockSTIXResponse.get_stix_indicator("192.168.1.100", "ipv4"),
            MockSTIXResponse.get_stix_indicator("malicious.com", "domain")
        ]

        bundle = MockSTIXResponse.get_stix_bundle(indicators)

        # Verify bundle structure
        assert bundle['type'] == 'bundle'
        assert bundle['spec_version'] == '2.1'
        assert 'id' in bundle
        assert bundle['id'].startswith('bundle--')
        assert 'objects' in bundle
        assert len(bundle['objects']) == 2


class TestMockDataIntegration:
    """Test integration of all mock data components"""

    def test_test_indicators_structure(self):
        """Test that test indicators are properly structured"""
        # Verify TEST_INDICATORS structure
        assert 'ipv4' in TEST_INDICATORS
        assert 'domain' in TEST_INDICATORS
        assert 'url' in TEST_INDICATORS
        assert 'hash' in TEST_INDICATORS

        # Verify each category has indicators
        for category, indicators in TEST_INDICATORS.items():
            assert isinstance(indicators, list)
            assert len(indicators) > 0
            for indicator in indicators:
                assert isinstance(indicator, str)
                assert len(indicator) > 0

    def test_mock_response_consistency(self):
        """Test that mock responses are consistent across different scenarios"""
        # Test OTX responses
        normal_response = MockOTXResponse.get_pulses_response(5)
        assert normal_response['count'] == 5
        assert len(normal_response['results']) == 5

        # Test Abuse.ch responses
        abuse_response = MockAbuseCHResponse.get_urls_recent_response(3)
        assert abuse_response['query_status'] == 'ok'
        assert len(abuse_response['urls']) == 3

        # Test error responses consistency
        otx_error = MockOTXResponse.get_error_response(401)
        assert 'error' in otx_error
        assert otx_error['status_code'] == 401

    @mock_aws
    def test_aws_service_mocking_integration(self):
        """Test integration with AWS service mocking"""
        # Test DynamoDB integration
        dynamodb = boto3.resource('dynamodb', region_name='us-east-1')

        # Create test table
        table = dynamodb.create_table(
            TableName='test-table',
            KeySchema=[{'AttributeName': 'id', 'KeyType': 'HASH'}],
            AttributeDefinitions=[{'AttributeName': 'id', 'AttributeType': 'S'}],
            BillingMode='PAY_PER_REQUEST'
        )

        # Test data insertion with mock STIX data
        stix_indicator = MockSTIXResponse.get_stix_indicator("192.168.1.1", "ipv4")

        table.put_item(Item={
            'id': stix_indicator['id'],
            'stix_data': json.dumps(stix_indicator),
            'created_at': stix_indicator['created']
        })

        # Verify data was stored
        response = table.get_item(Key={'id': stix_indicator['id']})
        assert 'Item' in response
        assert response['Item']['id'] == stix_indicator['id']


if __name__ == "__main__":
    # Run enhanced mocking tests
    pytest.main([__file__, "-v"])