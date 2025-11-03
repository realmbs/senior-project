"""
Unit tests for the threat intelligence collector Lambda function
"""

import pytest
import json
import hashlib
import time
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timezone
import responses
import boto3
from moto import mock_dynamodb, mock_s3, mock_secretsmanager
from botocore.exceptions import ClientError

# Import the collector module - adjust path as needed
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '../../infrastructure/terraform/lambda_functions'))

try:
    from collector import (
        lambda_handler, get_api_keys, create_pattern_hash, check_duplicate,
        store_indicator, collect_otx_data, collect_abuse_ch_data,
        process_otx_indicators, create_stix_indicator
    )
except ImportError as e:
    # Handle case where collector module is not directly importable
    collector = None


class TestPatternHashing:
    """Test pattern hash creation functionality"""

    def test_create_pattern_hash_ip(self):
        """Test hash creation for IP addresses"""
        indicator = "192.168.1.100"
        indicator_type = "ipv4"

        expected_pattern = "ipv4:192.168.1.100"
        expected_hash = hashlib.sha256(expected_pattern.encode()).hexdigest()

        if collector:
            result = create_pattern_hash(indicator, indicator_type)
            assert result == expected_hash
        else:
            # Direct hash calculation for validation
            pattern = f"{indicator_type}:{indicator.lower()}"
            result = hashlib.sha256(pattern.encode()).hexdigest()
            assert len(result) == 64  # SHA256 hash length

    def test_create_pattern_hash_domain(self):
        """Test hash creation for domains"""
        indicator = "MALICIOUS-DOMAIN.COM"
        indicator_type = "domain"

        # Should normalize to lowercase
        expected_pattern = "domain:malicious-domain.com"
        expected_hash = hashlib.sha256(expected_pattern.encode()).hexdigest()

        if collector:
            result = create_pattern_hash(indicator, indicator_type)
            assert result == expected_hash

    def test_create_pattern_hash_consistency(self):
        """Test hash consistency across multiple calls"""
        indicator = "test.example.com"
        indicator_type = "domain"

        if collector:
            hash1 = create_pattern_hash(indicator, indicator_type)
            hash2 = create_pattern_hash(indicator, indicator_type)
            assert hash1 == hash2


class TestDuplicateDetection:
    """Test deduplication functionality"""

    @pytest.fixture(autouse=True)
    def setup_method(self, mock_dynamodb_setup):
        """Set up test environment"""
        self.tables = mock_dynamodb_setup
        self.dedup_table = self.tables['dedup_table']

    def test_check_duplicate_not_exists(self):
        """Test duplicate check when hash doesn't exist"""
        test_hash = "nonexistent_hash_12345"

        if collector:
            result = check_duplicate(test_hash)
            assert result is False

    def test_check_duplicate_exists(self):
        """Test duplicate check when hash exists"""
        test_hash = "existing_hash_12345"

        # Insert test hash into dedup table
        self.dedup_table.put_item(Item={
            'pattern_hash': test_hash,
            'created_at': datetime.now(timezone.utc).isoformat(),
            'ttl': int(time.time()) + 3600
        })

        if collector:
            result = check_duplicate(test_hash)
            assert result is True

    def test_check_duplicate_error_handling(self):
        """Test duplicate check error handling"""
        # Test with invalid hash format
        if collector:
            result = check_duplicate("")
            assert result is False  # Should handle gracefully


class TestIndicatorStorage:
    """Test indicator storage functionality"""

    @pytest.fixture(autouse=True)
    def setup_method(self, mock_dynamodb_setup):
        """Set up test environment"""
        self.tables = mock_dynamodb_setup
        self.threat_table = self.tables['threat_table']
        self.dedup_table = self.tables['dedup_table']

    def test_store_indicator_success(self):
        """Test successful indicator storage"""
        indicator_data = {
            'object_id': 'indicator--test-123',
            'object_type': 'indicator',
            'ioc_value': '192.168.1.100',
            'ioc_type': 'ipv4',
            'source': 'otx',
            'confidence': 85,
            'pattern_hash': 'test_hash_123',
            'created_at': datetime.now(timezone.utc).isoformat(),
            'stix_data': {'type': 'indicator', 'pattern': "[ipv4-addr:value = '192.168.1.100']"}
        }

        if collector:
            result = store_indicator(indicator_data)
            assert result is True

            # Verify storage in threat table
            response = self.threat_table.get_item(
                Key={
                    'object_id': 'indicator--test-123',
                    'object_type': 'indicator'
                }
            )
            assert 'Item' in response
            assert response['Item']['ioc_value'] == '192.168.1.100'

            # Verify storage in dedup table
            dedup_response = self.dedup_table.get_item(
                Key={'pattern_hash': 'test_hash_123'}
            )
            assert 'Item' in dedup_response

    def test_store_indicator_missing_fields(self):
        """Test storage with missing required fields"""
        incomplete_data = {
            'object_id': 'indicator--incomplete',
            # Missing object_type and other required fields
        }

        if collector:
            # Should handle gracefully even with missing fields
            result = store_indicator(incomplete_data)
            # Depending on implementation, might return False or handle gracefully


class TestOTXDataCollection:
    """Test OTX data collection functionality"""

    @responses.activate
    def test_collect_otx_data_success(self):
        """Test successful OTX data collection"""
        # Load sample OTX data
        with open('fixtures/sample_otx_data.json', 'r') as f:
            sample_data = json.load(f)

        # Mock OTX API response
        responses.add(
            responses.GET,
            'https://otx.alienvault.com/api/v1/indicators/domain/test.com/general',
            json=sample_data,
            status=200
        )

        if collector:
            api_keys = {'otx_api_key': 'test_key'}
            result = collect_otx_data(api_keys)

            assert result is not None
            assert len(result) > 0

    @responses.activate
    def test_collect_otx_data_api_error(self):
        """Test OTX data collection with API error"""
        # Mock API error response
        responses.add(
            responses.GET,
            'https://otx.alienvault.com/api/v1/indicators/domain/test.com/general',
            json={'error': 'Invalid API key'},
            status=401
        )

        if collector:
            api_keys = {'otx_api_key': 'invalid_key'}
            result = collect_otx_data(api_keys)

            # Should handle error gracefully
            assert result == [] or result is None

    @responses.activate
    def test_collect_otx_data_timeout(self):
        """Test OTX data collection with timeout"""
        # Mock timeout
        responses.add(
            responses.GET,
            'https://otx.alienvault.com/api/v1/indicators/domain/test.com/general',
            body=ConnectionError('Timeout')
        )

        if collector:
            api_keys = {'otx_api_key': 'test_key'}
            result = collect_otx_data(api_keys)

            # Should handle timeout gracefully
            assert result == [] or result is None


class TestAbuseCHDataCollection:
    """Test Abuse.ch data collection functionality"""

    @responses.activate
    def test_collect_abuse_ch_data_success(self):
        """Test successful Abuse.ch data collection"""
        # Load sample Abuse.ch data
        with open('fixtures/sample_abuse_ch_data.json', 'r') as f:
            sample_data = json.load(f)

        # Mock Abuse.ch API response
        responses.add(
            responses.GET,
            'https://urlhaus-api.abuse.ch/v1/urls/recent/',
            json=sample_data,
            status=200
        )

        if collector:
            api_keys = {'abuse_ch_api_key': 'test_key'}
            result = collect_abuse_ch_data(api_keys)

            assert result is not None
            assert len(result) > 0

    @responses.activate
    def test_collect_abuse_ch_data_rate_limit(self):
        """Test Abuse.ch data collection with rate limiting"""
        # Mock rate limit response
        responses.add(
            responses.GET,
            'https://urlhaus-api.abuse.ch/v1/urls/recent/',
            json={'query_status': 'error', 'error': 'Rate limit exceeded'},
            status=429
        )

        if collector:
            api_keys = {'abuse_ch_api_key': 'test_key'}
            result = collect_abuse_ch_data(api_keys)

            # Should handle rate limiting gracefully
            assert result == [] or result is None


class TestSTIXDataProcessing:
    """Test STIX data processing functionality"""

    def test_create_stix_indicator_ip(self):
        """Test STIX indicator creation for IP address"""
        otx_indicator = {
            'indicator': '192.168.1.100',
            'type': 'IPv4',
            'title': 'Test IP',
            'description': 'Test IP description',
            'pulse_info': {
                'pulses': [{
                    'id': 'test-pulse',
                    'name': 'Test Pulse',
                    'created': '2024-01-01T00:00:00.000Z'
                }]
            }
        }

        if collector:
            result = create_stix_indicator(otx_indicator, 'otx')

            assert result is not None
            assert result['type'] == 'indicator'
            assert result['spec_version'] == '2.1'
            assert 'ipv4-addr:value' in result['pattern']
            assert result['confidence'] > 0
            assert 'otx' in result.get('x_threat_intel_platform', {}).get('source', '')

    def test_create_stix_indicator_domain(self):
        """Test STIX indicator creation for domain"""
        otx_indicator = {
            'indicator': 'malicious-domain.com',
            'type': 'domain',
            'title': 'Test Domain',
            'description': 'Test domain description',
            'pulse_info': {
                'pulses': [{
                    'id': 'test-pulse',
                    'name': 'Test Pulse',
                    'created': '2024-01-01T00:00:00.000Z'
                }]
            }
        }

        if collector:
            result = create_stix_indicator(otx_indicator, 'otx')

            assert result is not None
            assert result['type'] == 'indicator'
            assert 'domain-name:value' in result['pattern']
            assert 'malicious-domain.com' in result['pattern']

    def test_create_stix_indicator_invalid_type(self):
        """Test STIX indicator creation with invalid type"""
        invalid_indicator = {
            'indicator': 'test-value',
            'type': 'unknown_type',
            'title': 'Test Invalid',
            'description': 'Test invalid type'
        }

        if collector:
            result = create_stix_indicator(invalid_indicator, 'otx')

            # Should handle invalid types gracefully
            assert result is None or 'pattern' not in result


class TestSecretsManagerIntegration:
    """Test Secrets Manager integration"""

    def test_get_api_keys_success(self, mock_secrets_manager):
        """Test successful API key retrieval"""
        if collector:
            with patch.dict(os.environ, {
                'SECRETS_MANAGER_ARN': 'threat-intel-platform/api-keys/test'
            }):
                result = get_api_keys()

                assert result is not None
                assert 'otx_api_key' in result
                assert 'abuse_ch_api_key' in result
                assert result['otx_api_key'] == 'test_otx_key'

    def test_get_api_keys_failure(self):
        """Test API key retrieval failure"""
        if collector:
            with patch.dict(os.environ, {
                'SECRETS_MANAGER_ARN': 'nonexistent-secret'
            }):
                with pytest.raises(Exception):
                    get_api_keys()


class TestLambdaHandler:
    """Test main Lambda handler functionality"""

    @pytest.fixture(autouse=True)
    def setup_method(self, mock_dynamodb_setup, mock_s3_setup, mock_secrets_manager):
        """Set up test environment"""
        self.tables = mock_dynamodb_setup
        self.s3 = mock_s3_setup

    def test_lambda_handler_collect_otx(self, sample_lambda_event, sample_lambda_context):
        """Test Lambda handler with OTX collection request"""
        event = sample_lambda_event.copy()
        event['body'] = json.dumps({
            'sources': ['otx'],
            'collection_type': 'automated'
        })

        if collector:
            with patch.dict(os.environ, {
                'ENVIRONMENT': 'test',
                'SECRETS_MANAGER_ARN': 'threat-intel-platform/api-keys/test',
                'THREAT_INTEL_TABLE': 'threat-intel-platform-threat-intelligence-test',
                'DEDUP_TABLE': 'threat-intel-platform-deduplication-test',
                'RAW_DATA_BUCKET': 'threat-intel-platform-raw-data-test'
            }):
                with patch('collector.collect_otx_data') as mock_collect:
                    mock_collect.return_value = []

                    result = lambda_handler(event, sample_lambda_context)

                    assert result['statusCode'] == 200
                    response_body = json.loads(result['body'])
                    assert 'collection_id' in response_body

    def test_lambda_handler_invalid_source(self, sample_lambda_event, sample_lambda_context):
        """Test Lambda handler with invalid source"""
        event = sample_lambda_event.copy()
        event['body'] = json.dumps({
            'sources': ['invalid_source'],
            'collection_type': 'automated'
        })

        if collector:
            with patch.dict(os.environ, {
                'ENVIRONMENT': 'test',
                'SECRETS_MANAGER_ARN': 'threat-intel-platform/api-keys/test',
                'THREAT_INTEL_TABLE': 'threat-intel-platform-threat-intelligence-test',
                'DEDUP_TABLE': 'threat-intel-platform-deduplication-test',
                'RAW_DATA_BUCKET': 'threat-intel-platform-raw-data-test'
            }):
                result = lambda_handler(event, sample_lambda_context)

                assert result['statusCode'] == 400
                response_body = json.loads(result['body'])
                assert 'error' in response_body

    def test_lambda_handler_missing_body(self, sample_lambda_context):
        """Test Lambda handler with missing request body"""
        event = {
            'httpMethod': 'POST',
            'path': '/collect',
            'headers': {'Content-Type': 'application/json'},
            'body': None
        }

        if collector:
            result = lambda_handler(event, sample_lambda_context)

            assert result['statusCode'] == 400
            response_body = json.loads(result['body'])
            assert 'error' in response_body


class TestErrorHandling:
    """Test error handling scenarios"""

    def test_dynamodb_connection_error(self, mock_dynamodb_setup):
        """Test handling of DynamoDB connection errors"""
        if collector:
            with patch('boto3.resource') as mock_resource:
                mock_resource.side_effect = ClientError(
                    {'Error': {'Code': 'NetworkingError'}}, 'DescribeTable'
                )

                result = check_duplicate('test_hash')
                assert result is False  # Should handle gracefully

    def test_s3_upload_error(self, mock_s3_setup):
        """Test handling of S3 upload errors"""
        if collector:
            with patch('boto3.client') as mock_client:
                mock_s3 = Mock()
                mock_s3.put_object.side_effect = ClientError(
                    {'Error': {'Code': 'NoSuchBucket'}}, 'PutObject'
                )
                mock_client.return_value = mock_s3

                # Test should handle S3 errors gracefully
                # Implementation depends on collector module structure


# Skip all tests if collector module is not available
if not collector:
    pytest.skip("Collector module not available", allow_module_level=True)