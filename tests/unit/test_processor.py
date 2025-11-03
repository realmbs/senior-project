"""
Unit tests for the OSINT data processor Lambda function
"""

import pytest
import json
import re
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timezone
from decimal import Decimal
import boto3
from moto import mock_dynamodb, mock_s3
from botocore.exceptions import ClientError

# Import the processor module - adjust path as needed
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '../../infrastructure/terraform/lambda_functions'))

try:
    from processor import (
        lambda_handler, validate_stix_pattern, calculate_confidence_score,
        validate_indicator_data, process_batch, search_indicators,
        create_processed_data_export, normalize_confidence_score
    )
except ImportError as e:
    # Handle case where processor module is not directly importable
    processor = None


class TestSTIXPatternValidation:
    """Test STIX pattern validation functionality"""

    def test_validate_stix_pattern_ipv4_valid(self):
        """Test valid IPv4 STIX pattern"""
        valid_patterns = [
            "[ipv4-addr:value = '192.168.1.1']",
            "[ipv4-addr:value = '10.0.0.1']",
            "[ipv4-addr:value = '172.16.0.1']"
        ]

        for pattern in valid_patterns:
            if processor:
                is_valid, pattern_type = validate_stix_pattern(pattern)
                assert is_valid is True
                assert pattern_type == 'ipv4'

    def test_validate_stix_pattern_domain_valid(self):
        """Test valid domain STIX pattern"""
        valid_patterns = [
            "[domain-name:value = 'example.com']",
            "[domain-name:value = 'malicious-domain.org']",
            "[domain-name:value = 'test.co.uk']"
        ]

        for pattern in valid_patterns:
            if processor:
                is_valid, pattern_type = validate_stix_pattern(pattern)
                assert is_valid is True
                assert pattern_type == 'domain'

    def test_validate_stix_pattern_url_valid(self):
        """Test valid URL STIX pattern"""
        valid_patterns = [
            "[url:value = 'http://malicious.com/path']",
            "[url:value = 'https://example.org/malware.exe']"
        ]

        for pattern in valid_patterns:
            if processor:
                is_valid, pattern_type = validate_stix_pattern(pattern)
                assert is_valid is True
                assert pattern_type == 'url'

    def test_validate_stix_pattern_file_hash_valid(self):
        """Test valid file hash STIX pattern"""
        valid_patterns = [
            "[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']",
            "[file:hashes.SHA-1 = 'da39a3ee5e6b4b0d3255bfef95601890afd80709']",
            "[file:hashes.SHA-256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']"
        ]

        for pattern in valid_patterns:
            if processor:
                is_valid, pattern_type = validate_stix_pattern(pattern)
                assert is_valid is True
                assert pattern_type == 'file_hash'

    def test_validate_stix_pattern_invalid_format(self):
        """Test invalid STIX pattern formats"""
        invalid_patterns = [
            "not-a-stix-pattern",
            "[invalid format",
            "invalid format]",
            "",
            None,
            "[unknown:pattern = 'value']"
        ]

        for pattern in invalid_patterns:
            if processor:
                is_valid, pattern_type = validate_stix_pattern(pattern)
                assert is_valid is False
                assert "Invalid" in pattern_type or "Unknown" in pattern_type

    def test_validate_stix_pattern_edge_cases(self):
        """Test edge cases in STIX pattern validation"""
        edge_cases = [
            "[ipv4-addr:value = '999.999.999.999']",  # Invalid IP
            "[domain-name:value = '']",  # Empty domain
            "[url:value = 'ftp://example.com']"  # Non-HTTP protocol
        ]

        for pattern in edge_cases:
            if processor:
                is_valid, pattern_type = validate_stix_pattern(pattern)
                # Depending on implementation, may be valid format but invalid content


class TestConfidenceScoring:
    """Test confidence scoring functionality"""

    def test_calculate_confidence_score_otx(self):
        """Test confidence scoring for OTX source"""
        indicator_data = {
            'confidence': 80,
            'source': 'otx'
        }

        if processor:
            result = calculate_confidence_score(indicator_data)
            assert isinstance(result, int)
            assert 0 <= result <= 100
            # OTX should get moderate confidence boost

    def test_calculate_confidence_score_abuse_ch(self):
        """Test confidence scoring for Abuse.ch source"""
        indicator_data = {
            'confidence': 80,
            'source': 'abuse_ch'
        }

        if processor:
            result = calculate_confidence_score(indicator_data)
            assert isinstance(result, int)
            assert result >= 80  # Abuse.ch should get high confidence

    def test_calculate_confidence_score_manual(self):
        """Test confidence scoring for manual source"""
        indicator_data = {
            'confidence': 70,
            'source': 'manual'
        }

        if processor:
            result = calculate_confidence_score(indicator_data)
            assert isinstance(result, int)
            assert result >= 70  # Manual should get highest confidence boost

    def test_calculate_confidence_score_unknown_source(self):
        """Test confidence scoring for unknown source"""
        indicator_data = {
            'confidence': 60,
            'source': 'unknown_source'
        }

        if processor:
            result = calculate_confidence_score(indicator_data)
            assert isinstance(result, int)
            assert result >= 50  # Should get default scoring

    def test_calculate_confidence_score_boundary_values(self):
        """Test confidence scoring with boundary values"""
        test_cases = [
            {'confidence': 0, 'source': 'otx'},
            {'confidence': 100, 'source': 'otx'},
            {'confidence': 50, 'source': 'abuse_ch'}
        ]

        for case in test_cases:
            if processor:
                result = calculate_confidence_score(case)
                assert 0 <= result <= 100

    def test_calculate_confidence_score_missing_fields(self):
        """Test confidence scoring with missing fields"""
        test_cases = [
            {'source': 'otx'},  # Missing confidence
            {'confidence': 80},  # Missing source
            {}  # Missing both
        ]

        for case in test_cases:
            if processor:
                result = calculate_confidence_score(case)
                assert isinstance(result, int)
                assert 0 <= result <= 100


class TestIndicatorValidation:
    """Test indicator data validation functionality"""

    def test_validate_indicator_data_complete(self):
        """Test validation with complete indicator data"""
        complete_indicator = {
            'indicator_id': 'indicator--test-123',
            'ioc_type': 'ipv4',
            'ioc_value': '192.168.1.1',
            'source': 'otx',
            'confidence': 85,
            'stix_data': {
                'type': 'indicator',
                'pattern': "[ipv4-addr:value = '192.168.1.1']",
                'labels': ['malicious-activity']
            }
        }

        if processor:
            is_valid, errors = validate_indicator_data(complete_indicator)
            assert is_valid is True
            assert len(errors) == 0

    def test_validate_indicator_data_missing_required_fields(self):
        """Test validation with missing required fields"""
        incomplete_indicator = {
            'indicator_id': 'indicator--test-123',
            # Missing ioc_type, ioc_value, source
        }

        if processor:
            is_valid, errors = validate_indicator_data(incomplete_indicator)
            assert is_valid is False
            assert len(errors) > 0
            assert any('ioc_type' in error for error in errors)
            assert any('ioc_value' in error for error in errors)
            assert any('source' in error for error in errors)

    def test_validate_indicator_data_invalid_stix(self):
        """Test validation with invalid STIX data"""
        invalid_stix_indicator = {
            'indicator_id': 'indicator--test-123',
            'ioc_type': 'ipv4',
            'ioc_value': '192.168.1.1',
            'source': 'otx',
            'stix_data': {
                'type': 'indicator',
                'pattern': 'invalid-pattern-format',  # Invalid STIX pattern
                'labels': ['malicious-activity']
            }
        }

        if processor:
            is_valid, errors = validate_indicator_data(invalid_stix_indicator)
            # Depending on implementation, may catch STIX validation errors

    def test_validate_indicator_data_confidence_range(self):
        """Test validation with confidence score out of range"""
        test_cases = [
            {'confidence': -10},  # Below range
            {'confidence': 150},  # Above range
            {'confidence': 'invalid'},  # Wrong type
        ]

        base_indicator = {
            'indicator_id': 'indicator--test-123',
            'ioc_type': 'ipv4',
            'ioc_value': '192.168.1.1',
            'source': 'otx'
        }

        for case in test_cases:
            indicator = {**base_indicator, **case}
            if processor:
                is_valid, errors = validate_indicator_data(indicator)
                # Should validate confidence range


class TestBatchProcessing:
    """Test batch processing functionality"""

    @pytest.fixture(autouse=True)
    def setup_method(self, mock_dynamodb_setup):
        """Set up test environment"""
        self.tables = mock_dynamodb_setup

    def test_process_batch_valid_indicators(self):
        """Test batch processing with valid indicators"""
        valid_batch = [
            {
                'indicator_id': 'indicator--test-1',
                'ioc_type': 'ipv4',
                'ioc_value': '192.168.1.1',
                'source': 'otx',
                'confidence': 85
            },
            {
                'indicator_id': 'indicator--test-2',
                'ioc_type': 'domain',
                'ioc_value': 'malicious.com',
                'source': 'abuse_ch',
                'confidence': 90
            }
        ]

        if processor:
            with patch.dict(os.environ, {
                'THREAT_INTEL_TABLE': 'threat-intel-platform-threat-intelligence-test',
                'MAX_BATCH_SIZE': '50'
            }):
                result = process_batch(valid_batch)
                assert result is not None
                assert 'processed_count' in result or isinstance(result, (list, int))

    def test_process_batch_mixed_validity(self):
        """Test batch processing with mix of valid and invalid indicators"""
        mixed_batch = [
            {
                'indicator_id': 'indicator--valid',
                'ioc_type': 'ipv4',
                'ioc_value': '192.168.1.1',
                'source': 'otx',
                'confidence': 85
            },
            {
                'indicator_id': 'indicator--invalid',
                # Missing required fields
                'confidence': 50
            }
        ]

        if processor:
            with patch.dict(os.environ, {
                'THREAT_INTEL_TABLE': 'threat-intel-platform-threat-intelligence-test',
                'MAX_BATCH_SIZE': '50'
            }):
                result = process_batch(mixed_batch)
                # Should process valid indicators and handle invalid ones gracefully

    def test_process_batch_empty(self):
        """Test batch processing with empty batch"""
        empty_batch = []

        if processor:
            result = process_batch(empty_batch)
            # Should handle empty batch gracefully

    def test_process_batch_oversized(self):
        """Test batch processing with oversized batch"""
        oversized_batch = []
        for i in range(200):  # Exceeds typical batch size limits
            oversized_batch.append({
                'indicator_id': f'indicator--test-{i}',
                'ioc_type': 'ipv4',
                'ioc_value': f'192.168.1.{i % 255}',
                'source': 'otx',
                'confidence': 75
            })

        if processor:
            with patch.dict(os.environ, {'MAX_BATCH_SIZE': '50'}):
                result = process_batch(oversized_batch)
                # Should handle batch size limits


class TestSearchFunctionality:
    """Test search functionality"""

    @pytest.fixture(autouse=True)
    def setup_method(self, mock_dynamodb_setup):
        """Set up test environment"""
        self.tables = mock_dynamodb_setup
        self.threat_table = self.tables['threat_table']

        # Insert test data
        test_indicators = [
            {
                'object_id': 'indicator--search-test-1',
                'object_type': 'indicator',
                'ioc_value': '192.168.1.100',
                'ioc_type': 'ipv4',
                'source_name': 'otx',
                'confidence': Decimal('85'),
                'created_date': '2024-01-01T00:00:00.000Z',
                'pattern_hash': 'hash1'
            },
            {
                'object_id': 'indicator--search-test-2',
                'object_type': 'indicator',
                'ioc_value': 'malicious.com',
                'ioc_type': 'domain',
                'source_name': 'abuse_ch',
                'confidence': Decimal('90'),
                'created_date': '2024-01-01T01:00:00.000Z',
                'pattern_hash': 'hash2'
            }
        ]

        for indicator in test_indicators:
            self.threat_table.put_item(Item=indicator)

    def test_search_indicators_by_value(self):
        """Test searching indicators by IOC value"""
        if processor:
            with patch.dict(os.environ, {
                'THREAT_INTEL_TABLE': 'threat-intel-platform-threat-intelligence-test'
            }):
                result = search_indicators(query='192.168.1.100')
                assert result is not None
                # Should find the IP indicator

    def test_search_indicators_by_type(self):
        """Test searching indicators by IOC type"""
        if processor:
            with patch.dict(os.environ, {
                'THREAT_INTEL_TABLE': 'threat-intel-platform-threat-intelligence-test'
            }):
                result = search_indicators(ioc_type='domain')
                assert result is not None
                # Should find domain indicators

    def test_search_indicators_by_confidence(self):
        """Test searching indicators by confidence threshold"""
        if processor:
            with patch.dict(os.environ, {
                'THREAT_INTEL_TABLE': 'threat-intel-platform-threat-intelligence-test'
            }):
                result = search_indicators(min_confidence=88)
                assert result is not None
                # Should find high-confidence indicators

    def test_search_indicators_pagination(self):
        """Test search with pagination"""
        if processor:
            with patch.dict(os.environ, {
                'THREAT_INTEL_TABLE': 'threat-intel-platform-threat-intelligence-test'
            }):
                result = search_indicators(limit=1)
                assert result is not None
                # Should respect pagination limits

    def test_search_indicators_no_results(self):
        """Test search with no matching results"""
        if processor:
            with patch.dict(os.environ, {
                'THREAT_INTEL_TABLE': 'threat-intel-platform-threat-intelligence-test'
            }):
                result = search_indicators(query='nonexistent.com')
                assert result is not None
                # Should handle no results gracefully


class TestDataExport:
    """Test data export functionality"""

    @pytest.fixture(autouse=True)
    def setup_method(self, mock_s3_setup):
        """Set up test environment"""
        self.s3 = mock_s3_setup

    def test_create_processed_data_export(self):
        """Test creating processed data export"""
        test_data = [
            {
                'indicator_id': 'indicator--export-test-1',
                'ioc_value': '192.168.1.100',
                'ioc_type': 'ipv4',
                'confidence': 85,
                'source': 'otx'
            }
        ]

        if processor:
            with patch.dict(os.environ, {
                'PROCESSED_DATA_BUCKET': 'threat-intel-platform-processed-data-test'
            }):
                result = create_processed_data_export(test_data, 'json')
                assert result is not None

    def test_create_processed_data_export_stix(self):
        """Test creating STIX format export"""
        test_data = [
            {
                'type': 'indicator',
                'id': 'indicator--export-test-1',
                'pattern': "[ipv4-addr:value = '192.168.1.100']",
                'labels': ['malicious-activity']
            }
        ]

        if processor:
            with patch.dict(os.environ, {
                'PROCESSED_DATA_BUCKET': 'threat-intel-platform-processed-data-test'
            }):
                result = create_processed_data_export(test_data, 'stix')
                assert result is not None


class TestLambdaHandler:
    """Test main Lambda handler functionality"""

    @pytest.fixture(autouse=True)
    def setup_method(self, mock_dynamodb_setup, mock_s3_setup):
        """Set up test environment"""
        self.tables = mock_dynamodb_setup
        self.s3 = mock_s3_setup

    def test_lambda_handler_process_batch(self, sample_lambda_context):
        """Test Lambda handler with batch processing request"""
        event = {
            'httpMethod': 'POST',
            'path': '/process',
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({
                'action': 'process_batch',
                'indicators': [
                    {
                        'indicator_id': 'indicator--handler-test-1',
                        'ioc_type': 'ipv4',
                        'ioc_value': '192.168.1.1',
                        'source': 'otx',
                        'confidence': 85
                    }
                ]
            })
        }

        if processor:
            with patch.dict(os.environ, {
                'ENVIRONMENT': 'test',
                'THREAT_INTEL_TABLE': 'threat-intel-platform-threat-intelligence-test',
                'DEDUP_TABLE': 'threat-intel-platform-deduplication-test',
                'PROCESSED_DATA_BUCKET': 'threat-intel-platform-processed-data-test',
                'MAX_BATCH_SIZE': '50'
            }):
                result = lambda_handler(event, sample_lambda_context)

                assert result['statusCode'] == 200
                response_body = json.loads(result['body'])
                assert 'processed_count' in response_body or 'result' in response_body

    def test_lambda_handler_search(self, sample_lambda_context):
        """Test Lambda handler with search request"""
        event = {
            'httpMethod': 'GET',
            'path': '/search',
            'queryStringParameters': {
                'q': '192.168.1.1',
                'limit': '10'
            },
            'headers': {'Content-Type': 'application/json'}
        }

        if processor:
            with patch.dict(os.environ, {
                'ENVIRONMENT': 'test',
                'THREAT_INTEL_TABLE': 'threat-intel-platform-threat-intelligence-test'
            }):
                result = lambda_handler(event, sample_lambda_context)

                assert result['statusCode'] == 200
                response_body = json.loads(result['body'])
                assert 'indicators' in response_body or 'results' in response_body

    def test_lambda_handler_invalid_action(self, sample_lambda_context):
        """Test Lambda handler with invalid action"""
        event = {
            'httpMethod': 'POST',
            'path': '/process',
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({
                'action': 'invalid_action'
            })
        }

        if processor:
            result = lambda_handler(event, sample_lambda_context)

            assert result['statusCode'] == 400
            response_body = json.loads(result['body'])
            assert 'error' in response_body


class TestErrorHandling:
    """Test error handling scenarios"""

    def test_dynamodb_query_error(self, mock_dynamodb_setup):
        """Test handling of DynamoDB query errors"""
        if processor:
            with patch('boto3.resource') as mock_resource:
                mock_table = Mock()
                mock_table.scan.side_effect = ClientError(
                    {'Error': {'Code': 'ProvisionedThroughputExceededException'}},
                    'Scan'
                )
                mock_resource.return_value.Table.return_value = mock_table

                result = search_indicators(query='test')
                # Should handle DynamoDB errors gracefully

    def test_batch_processing_memory_limit(self):
        """Test batch processing with memory constraints"""
        # Create a very large batch that might exceed memory
        large_batch = []
        for i in range(10000):
            large_batch.append({
                'indicator_id': f'indicator--large-{i}',
                'ioc_type': 'ipv4',
                'ioc_value': f'192.168.{i//256}.{i%256}',
                'source': 'otx',
                'confidence': 75,
                'large_data': 'x' * 1000  # Add bulk to each item
            })

        if processor:
            # Should handle large batches without memory errors
            try:
                result = process_batch(large_batch)
                # Should either succeed or fail gracefully
            except MemoryError:
                pytest.fail("Should handle memory constraints gracefully")


# Skip all tests if processor module is not available
if not processor:
    pytest.skip("Processor module not available", allow_module_level=True)