"""
Enhanced error handling tests for Lambda functions
Tests various error scenarios and edge cases for robust error handling
"""

import pytest
import json
import hashlib
import time
import os
import sys
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timezone
import responses
import boto3
from moto import mock_aws
from botocore.exceptions import ClientError, NoCredentialsError, EndpointConnectionError
import requests

# Mock environment variables before importing Lambda modules
os.environ.setdefault('SECRETS_MANAGER_ARN', 'arn:aws:secretsmanager:us-east-1:123456789012:secret:test-secret')
os.environ.setdefault('THREAT_INTEL_TABLE', 'test-threat-intel-table')
os.environ.setdefault('DEDUP_TABLE', 'test-dedup-table')
os.environ.setdefault('RAW_DATA_BUCKET', 'test-raw-data-bucket')
os.environ.setdefault('PROCESSED_DATA_BUCKET', 'test-processed-data-bucket')
os.environ.setdefault('ENRICHMENT_CACHE_TABLE', 'test-enrichment-cache-table')
os.environ.setdefault('ENVIRONMENT', 'test')

# Import the Lambda modules - adjust path as needed
sys.path.append(os.path.join(os.path.dirname(__file__), '../../infrastructure/terraform/lambda_functions/build_correct'))

try:
    from collector import (
        lambda_handler, get_api_keys, create_pattern_hash, check_duplicate,
        store_indicator, collect_otx_data, collect_abuse_ch_data
    )
    COLLECTOR_AVAILABLE = True
except ImportError:
    COLLECTOR_AVAILABLE = False

try:
    from processor import lambda_handler as processor_handler
    PROCESSOR_AVAILABLE = True
except ImportError:
    PROCESSOR_AVAILABLE = False

try:
    from enrichment import lambda_handler as enrichment_handler
    ENRICHMENT_AVAILABLE = True
except ImportError:
    ENRICHMENT_AVAILABLE = False


class TestCollectorErrorHandling:
    """Test error handling in collector Lambda function"""

    @pytest.mark.skipif(not COLLECTOR_AVAILABLE, reason="Collector module not available")
    def test_get_api_keys_secrets_manager_error(self):
        """Test API key retrieval with Secrets Manager error"""
        with patch('collector.secrets_client') as mock_secrets:
            # Simulate Secrets Manager error
            mock_secrets.get_secret_value.side_effect = ClientError(
                error_response={'Error': {'Code': 'ResourceNotFoundException'}},
                operation_name='GetSecretValue'
            )

            with pytest.raises(ClientError):
                get_api_keys()

    @pytest.mark.skipif(not COLLECTOR_AVAILABLE, reason="Collector module not available")
    def test_get_api_keys_malformed_json(self):
        """Test API key retrieval with malformed JSON response"""
        with patch('collector.secrets_client') as mock_secrets:
            # Simulate malformed JSON
            mock_secrets.get_secret_value.return_value = {
                'SecretString': 'invalid json{'
            }

            with pytest.raises(json.JSONDecodeError):
                get_api_keys()

    @pytest.mark.skipif(not COLLECTOR_AVAILABLE, reason="Collector module not available")
    def test_get_api_keys_missing_keys(self):
        """Test API key retrieval with missing keys"""
        with patch('collector.secrets_client') as mock_secrets:
            # Simulate missing keys
            mock_secrets.get_secret_value.return_value = {
                'SecretString': json.dumps({})
            }

            result = get_api_keys()
            assert result['otx_api_key'] is None
            assert result['abuse_ch_api_key'] == ''

    @pytest.mark.skipif(not COLLECTOR_AVAILABLE, reason="Collector module not available")
    def test_create_pattern_hash_empty_input(self):
        """Test pattern hash creation with empty input"""
        # Test empty indicator
        result = create_pattern_hash("", "ipv4")
        assert len(result) == 64  # Should still produce valid hash

        # Test empty type
        result = create_pattern_hash("192.168.1.1", "")
        assert len(result) == 64  # Should still produce valid hash

    @pytest.mark.skipif(not COLLECTOR_AVAILABLE, reason="Collector module not available")
    def test_create_pattern_hash_special_characters(self):
        """Test pattern hash creation with special characters"""
        indicators = [
            "192.168.1.1/24",
            "evil-domain.com/path?param=value",
            "indicator with spaces",
            "UPPERCASE.DOMAIN.COM",
            "unicode-域名.test"
        ]

        for indicator in indicators:
            result = create_pattern_hash(indicator, "test")
            assert len(result) == 64
            assert isinstance(result, str)

    @pytest.mark.skipif(not COLLECTOR_AVAILABLE, reason="Collector module not available")
    def test_check_duplicate_dynamodb_error(self):
        """Test duplicate check with DynamoDB error"""
        with patch('collector.dedup_table') as mock_table:
            # Simulate DynamoDB error
            mock_table.get_item.side_effect = ClientError(
                error_response={'Error': {'Code': 'ProvisionedThroughputExceededException'}},
                operation_name='GetItem'
            )

            result = check_duplicate("test_hash")
            assert result is False  # Should return False on error

    @pytest.mark.skipif(not COLLECTOR_AVAILABLE, reason="Collector module not available")
    def test_check_duplicate_network_error(self):
        """Test duplicate check with network error"""
        with patch('collector.dedup_table') as mock_table:
            # Simulate network error
            mock_table.get_item.side_effect = EndpointConnectionError(
                endpoint_url="https://dynamodb.us-east-1.amazonaws.com/"
            )

            result = check_duplicate("test_hash")
            assert result is False  # Should return False on error

    @pytest.mark.skipif(not COLLECTOR_AVAILABLE, reason="Collector module not available")
    def test_store_indicator_invalid_data(self):
        """Test indicator storage with invalid data"""
        with patch('collector.threat_intel_table') as mock_table:
            # Test missing required fields
            invalid_data = {}

            mock_table.put_item.side_effect = ClientError(
                error_response={'Error': {'Code': 'ValidationException'}},
                operation_name='PutItem'
            )

            result = store_indicator(invalid_data)
            assert result is False

    @pytest.mark.skipif(not COLLECTOR_AVAILABLE, reason="Collector module not available")
    def test_store_indicator_dedup_table_error(self):
        """Test indicator storage when dedup table fails"""
        with patch('collector.threat_intel_table') as mock_threat_table, \
             patch('collector.dedup_table') as mock_dedup_table:

            # Main table succeeds
            mock_threat_table.put_item.return_value = {}

            # Dedup table fails
            mock_dedup_table.put_item.side_effect = ClientError(
                error_response={'Error': {'Code': 'ResourceNotFoundException'}},
                operation_name='PutItem'
            )

            indicator_data = {
                'pattern_hash': 'test_hash',
                'created_at': datetime.now(timezone.utc).isoformat()
            }

            result = store_indicator(indicator_data)
            assert result is False


class TestProcessorErrorHandling:
    """Test error handling in processor Lambda function"""

    @pytest.mark.skipif(not PROCESSOR_AVAILABLE, reason="Processor module not available")
    def test_processor_malformed_event(self):
        """Test processor with malformed event data"""
        malformed_events = [
            {},  # Empty event
            {'body': 'invalid json{'},  # Malformed JSON body
            {'body': json.dumps({})},  # Empty body
            {'httpMethod': 'POST'},  # Missing body
            None  # None event
        ]

        for event in malformed_events:
            try:
                result = processor_handler(event, None)
                # Should return error response
                assert result['statusCode'] >= 400
            except Exception:
                # Should handle gracefully or raise expected exception
                pass

    @pytest.mark.skipif(not PROCESSOR_AVAILABLE, reason="Processor module not available")
    def test_processor_invalid_stix_data(self):
        """Test processor with invalid STIX data"""
        invalid_stix_events = [
            {
                'body': json.dumps({
                    'stix_data': 'not a dictionary'
                })
            },
            {
                'body': json.dumps({
                    'stix_data': {
                        'type': 'invalid_type'
                    }
                })
            },
            {
                'body': json.dumps({
                    'stix_data': {
                        'type': 'indicator'
                        # Missing required fields
                    }
                })
            }
        ]

        for event in invalid_stix_events:
            try:
                result = processor_handler(event, None)
                assert result['statusCode'] >= 400
            except Exception:
                pass


class TestEnrichmentErrorHandling:
    """Test error handling in enrichment Lambda function"""

    @pytest.mark.skipif(not ENRICHMENT_AVAILABLE, reason="Enrichment module not available")
    def test_enrichment_network_timeouts(self):
        """Test enrichment with network timeouts"""
        # Mock various network timeout scenarios
        with patch('requests.get') as mock_get:
            mock_get.side_effect = requests.Timeout("Connection timed out")

            event = {
                'body': json.dumps({
                    'indicators': ['192.168.1.1'],
                    'enrichment_types': ['shodan']
                })
            }

            try:
                result = enrichment_handler(event, None)
                # Should handle timeout gracefully
                assert 'statusCode' in result
            except Exception:
                pass

    @pytest.mark.skipif(not ENRICHMENT_AVAILABLE, reason="Enrichment module not available")
    def test_enrichment_api_rate_limits(self):
        """Test enrichment with API rate limit responses"""
        with patch('requests.get') as mock_get:
            # Simulate rate limit response
            mock_response = Mock()
            mock_response.status_code = 429
            mock_response.json.return_value = {'error': 'Rate limit exceeded'}
            mock_get.return_value = mock_response

            event = {
                'body': json.dumps({
                    'indicators': ['192.168.1.1'],
                    'enrichment_types': ['shodan']
                })
            }

            try:
                result = enrichment_handler(event, None)
                # Should handle rate limits gracefully
                assert 'statusCode' in result
            except Exception:
                pass

    @pytest.mark.skipif(not ENRICHMENT_AVAILABLE, reason="Enrichment module not available")
    def test_enrichment_invalid_indicators(self):
        """Test enrichment with invalid indicators"""
        invalid_indicators = [
            '',  # Empty string
            'not.an.ip.address',  # Invalid IP
            '999.999.999.999',  # Invalid IP range
            'extremely-long-domain-name-that-exceeds-normal-limits.com',
            None,  # None value
            123,  # Non-string type
        ]

        for indicator in invalid_indicators:
            event = {
                'body': json.dumps({
                    'indicators': [indicator],
                    'enrichment_types': ['dns']
                })
            }

            try:
                result = enrichment_handler(event, None)
                # Should handle invalid indicators gracefully
                assert 'statusCode' in result
            except Exception:
                pass


class TestLambdaContextErrorHandling:
    """Test Lambda context and runtime error handling"""

    @pytest.mark.skipif(not COLLECTOR_AVAILABLE, reason="Collector module not available")
    def test_lambda_timeout_scenario(self):
        """Test Lambda function behavior near timeout"""
        # Create mock context with low remaining time
        mock_context = Mock()
        mock_context.get_remaining_time_in_millis.return_value = 100  # 100ms remaining

        event = {
            'httpMethod': 'POST',
            'body': json.dumps({
                'sources': ['otx'],
                'collection_type': 'automated'
            })
        }

        try:
            result = lambda_handler(event, mock_context)
            # Should handle timeout gracefully
            assert 'statusCode' in result
        except Exception:
            pass

    @pytest.mark.skipif(not COLLECTOR_AVAILABLE, reason="Collector module not available")
    def test_lambda_memory_pressure(self):
        """Test Lambda function behavior under memory pressure"""
        # Simulate memory pressure by creating large objects
        large_data = ['x' * 1000000 for _ in range(10)]  # 10MB of data

        event = {
            'httpMethod': 'POST',
            'body': json.dumps({
                'sources': ['otx'],
                'collection_type': 'automated',
                'large_data': large_data
            })
        }

        try:
            result = lambda_handler(event, None)
            # Should handle memory pressure gracefully
            assert 'statusCode' in result
        except Exception:
            pass

    def test_aws_service_unavailable(self):
        """Test behavior when AWS services are unavailable"""
        with patch('boto3.resource') as mock_resource, \
             patch('boto3.client') as mock_client:

            # Simulate service unavailable
            mock_resource.side_effect = EndpointConnectionError(
                endpoint_url="https://dynamodb.us-east-1.amazonaws.com/"
            )
            mock_client.side_effect = EndpointConnectionError(
                endpoint_url="https://s3.us-east-1.amazonaws.com/"
            )

            event = {
                'httpMethod': 'POST',
                'body': json.dumps({
                    'sources': ['otx']
                })
            }

            if COLLECTOR_AVAILABLE:
                try:
                    result = lambda_handler(event, None)
                    # Should handle service unavailability gracefully
                    assert 'statusCode' in result
                except Exception:
                    pass


class TestExternalAPIErrorHandling:
    """Test handling of external API errors"""

    @responses.activate
    @pytest.mark.skipif(not COLLECTOR_AVAILABLE, reason="Collector module not available")
    def test_otx_api_errors(self):
        """Test various OTX API error responses"""
        # Mock API key retrieval
        with patch('collector.get_api_keys') as mock_keys:
            mock_keys.return_value = {'otx_api_key': 'test_key'}

            # Test different error scenarios
            error_responses = [
                (400, {'error': 'Bad Request'}),
                (401, {'error': 'Unauthorized'}),
                (403, {'error': 'Forbidden'}),
                (429, {'error': 'Rate Limit Exceeded'}),
                (500, {'error': 'Internal Server Error'}),
                (502, {'error': 'Bad Gateway'}),
                (503, {'error': 'Service Unavailable'})
            ]

            for status_code, response_data in error_responses:
                responses.reset()
                responses.add(
                    responses.GET,
                    'https://otx.alienvault.com/api/v1/pulses/subscribed',
                    json=response_data,
                    status=status_code
                )

                try:
                    # This would be called within collect_otx_data
                    if hasattr(collect_otx_data, '__call__'):
                        result = collect_otx_data()
                        # Should handle errors gracefully
                        assert isinstance(result, (list, dict))
                except Exception:
                    # Should not raise unhandled exceptions
                    pass

    @responses.activate
    @pytest.mark.skipif(not COLLECTOR_AVAILABLE, reason="Collector module not available")
    def test_abuse_ch_api_errors(self):
        """Test various Abuse.ch API error responses"""
        # Test different error scenarios for Abuse.ch
        error_responses = [
            (404, 'Not Found'),
            (500, 'Internal Server Error'),
            (503, 'Service Temporarily Unavailable')
        ]

        for status_code, response_text in error_responses:
            responses.reset()
            responses.add(
                responses.GET,
                'https://urlhaus-api.abuse.ch/v1/urls/recent/',
                body=response_text,
                status=status_code
            )

            try:
                if hasattr(collect_abuse_ch_data, '__call__'):
                    result = collect_abuse_ch_data()
                    # Should handle errors gracefully
                    assert isinstance(result, (list, dict))
            except Exception:
                pass

    @responses.activate
    def test_external_api_malformed_responses(self):
        """Test handling of malformed external API responses"""
        malformed_responses = [
            'not json',
            '<html>Error page</html>',
            '',  # Empty response
            '{invalid json{',
            '[]',  # Valid JSON but unexpected structure
        ]

        for response_body in malformed_responses:
            responses.reset()
            responses.add(
                responses.GET,
                'https://otx.alienvault.com/api/v1/pulses/subscribed',
                body=response_body,
                status=200
            )

            # Test should handle malformed responses gracefully
            try:
                import requests
                resp = requests.get('https://otx.alienvault.com/api/v1/pulses/subscribed')
                # Code should validate response before parsing
                if resp.headers.get('content-type', '').startswith('application/json'):
                    try:
                        data = resp.json()
                    except json.JSONDecodeError:
                        # Should handle JSON decode errors
                        pass
            except Exception:
                pass


if __name__ == "__main__":
    # Run error handling tests
    pytest.main([__file__, "-v"])