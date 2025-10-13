#!/usr/bin/env python3
"""
Enhanced Collector Testing Script

Tests the Phase 7.2 enhancements:
- OTX pagination with rate limiting
- Multi-feed Abuse.ch integration
- Circuit breaker pattern
- State persistence

Usage:
    python test_collector_enhanced.py
"""

import json
import boto3
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timezone

# Mock AWS services for testing
def setup_test_environment():
    """Setup mock AWS environment for testing"""

    # Mock environment variables
    test_env = {
        'ENVIRONMENT': 'test',
        'SECRETS_MANAGER_ARN': 'arn:aws:secretsmanager:us-east-1:123456789012:secret:test-keys',
        'THREAT_INTEL_TABLE': 'test-threat-intel',
        'DEDUP_TABLE': 'test-dedup',
        'RAW_DATA_BUCKET': 'test-raw-data-bucket',
        'COLLECTION_STATE_TABLE': 'test-collection-state'
    }

    return test_env

def test_otx_pagination_logic():
    """Test OTX pagination and rate limiting"""
    print("🔄 Testing OTX pagination logic...")

    # Test pagination state management
    from collector import get_collection_state, update_collection_state, clear_collection_state

    # Mock DynamoDB responses
    with patch('collector.collection_state_table') as mock_table:
        # Test getting empty state
        mock_table.get_item.return_value = {}
        state = get_collection_state('otx')
        assert state == {}, "Empty state should return empty dict"

        # Test updating state
        test_state = {
            'next_url': 'https://otx.alienvault.com/api/v1/pulses/subscribed?page=2',
            'indicators_collected': 150
        }
        update_collection_state('otx', test_state)
        mock_table.put_item.assert_called_once()

        # Test clearing state
        clear_collection_state('otx')
        mock_table.delete_item.assert_called_once()

    print("✅ OTX pagination logic tests passed")

def test_circuit_breaker():
    """Test circuit breaker functionality"""
    print("🛡️ Testing circuit breaker pattern...")

    from collector import CircuitBreaker

    # Test normal operation
    cb = CircuitBreaker('test-service')
    assert cb.state == 'closed', "Circuit breaker should start closed"

    # Test successful calls
    result = cb.call(lambda x: x * 2, 5)
    assert result == 10, "Circuit breaker should allow normal calls"

    # Test failure handling
    def failing_function():
        raise Exception("Test failure")

    # Trigger multiple failures to open circuit
    for i in range(6):
        try:
            cb.call(failing_function)
        except Exception:
            pass

    assert cb.state == 'open', "Circuit breaker should open after threshold failures"

    print("✅ Circuit breaker tests passed")

def test_rate_limiter():
    """Test rate limiting functionality"""
    print("⏱️ Testing rate limiter...")

    from collector import RateLimiter

    # Test rate limiter with small limits for quick testing
    rl = RateLimiter('test-service', max_requests=2, time_window=1)

    # Should allow first requests
    assert rl.can_make_request() == True, "Should allow initial request"
    rl.record_request()

    assert rl.can_make_request() == True, "Should allow second request"
    rl.record_request()

    # Should block after limit
    assert rl.can_make_request() == False, "Should block after rate limit"

    print("✅ Rate limiter tests passed")

def test_multi_feed_processing():
    """Test multi-feed Abuse.ch processing"""
    print("📡 Testing multi-feed processing...")

    from collector import (
        process_malwarebazaar_feed,
        process_urlhaus_feed,
        process_threatfox_feed,
        process_feodo_feed,
        format_threatfox_pattern
    )

    # Test MalwareBazaar processing
    mb_data = {
        'data': [{
            'sha256_hash': 'abc123def456',
            'malware': 'trojan',
            'file_size': 1024,
            'first_seen': '2024-01-01'
        }]
    }
    mb_indicators = process_malwarebazaar_feed(mb_data)
    assert len(mb_indicators) == 1, "Should process one MalwareBazaar indicator"
    assert 'file:hashes.SHA-256' in mb_indicators[0]['pattern'], "Should create file hash pattern"

    # Test URLhaus processing
    uh_data = {
        'urls': [{
            'url': 'http://malicious-site.com/payload',
            'url_status': 'online',
            'threat': 'malware_download'
        }]
    }
    uh_indicators = process_urlhaus_feed(uh_data)
    assert len(uh_indicators) == 1, "Should process one URLhaus indicator"
    assert 'url:value' in uh_indicators[0]['pattern'], "Should create URL pattern"

    # Test ThreatFox processing
    tf_data = {
        'data': [{
            'ioc': '192.168.1.100',
            'ioc_type': 'ip',
            'malware': 'botnet',
            'confidence_level': 75
        }]
    }
    tf_indicators = process_threatfox_feed(tf_data)
    assert len(tf_indicators) == 1, "Should process one ThreatFox indicator"
    assert 'ipv4-addr:value' in tf_indicators[0]['pattern'], "Should create IP pattern"

    # Test pattern formatting
    pattern = format_threatfox_pattern('malware.exe.sha256', 'sha256_hash')
    assert 'SHA-256' in pattern, "Should format SHA-256 pattern correctly"

    print("✅ Multi-feed processing tests passed")

def test_stix_compliance():
    """Test STIX 2.1 compliance of generated indicators"""
    print("📊 Testing STIX 2.1 compliance...")

    from collector import process_malwarebazaar_feed

    # Test STIX indicator structure
    test_data = {
        'data': [{
            'sha256_hash': 'test_hash_123',
            'malware': 'test_malware',
            'file_size': 2048
        }]
    }

    indicators = process_malwarebazaar_feed(test_data)
    indicator = indicators[0]

    # Validate required STIX 2.1 fields
    required_fields = ['type', 'spec_version', 'id', 'created', 'modified', 'pattern', 'labels']
    for field in required_fields:
        assert field in indicator, f"Missing required STIX field: {field}"

    assert indicator['type'] == 'indicator', "Should be indicator type"
    assert indicator['spec_version'] == '2.1', "Should be STIX 2.1 compliant"
    assert indicator['labels'] == ['malicious-activity'], "Should have malicious-activity label"
    assert indicator['confidence'] >= 0 and indicator['confidence'] <= 100, "Confidence should be 0-100"

    print("✅ STIX 2.1 compliance tests passed")

def main():
    """Run all enhanced collector tests"""
    print("🚀 Running Phase 7.2 Enhanced Collector Tests\n")

    # Setup test environment
    setup_test_environment()

    try:
        # Run all test suites
        test_otx_pagination_logic()
        test_circuit_breaker()
        test_rate_limiter()
        test_multi_feed_processing()
        test_stix_compliance()

        print("\n✅ All Phase 7.2 enhancement tests passed!")
        print("🎉 Enhanced threat intelligence collector is ready for deployment")

    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        raise

if __name__ == '__main__':
    main()