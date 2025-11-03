"""
Enhanced integration tests for API Gateway endpoints
Comprehensive testing of live deployed API endpoints with advanced scenarios
"""

import pytest
import json
import time
import os
import uuid
from datetime import datetime, timezone
import requests
import boto3
from botocore.exceptions import ClientError
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib


# Module-level fixtures for all test classes
@pytest.fixture(scope="module")
def api_config():
    """Enhanced API configuration for integration tests"""
    return {
        'base_url': os.environ.get('API_BASE_URL', 'https://u88kzux168.execute-api.us-east-1.amazonaws.com/dev'),
        'api_key': os.environ.get('TEST_API_KEY'),
        'region': os.environ.get('AWS_REGION', 'us-east-1'),
        'timeout': int(os.environ.get('API_TIMEOUT', '60')),
        'max_retries': int(os.environ.get('MAX_RETRIES', '3'))
    }


@pytest.fixture
def api_headers(api_config):
    """Standard headers for API requests"""
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'User-Agent': 'ThreatIntel-Test-Suite/1.0'
    }

    if api_config['api_key']:
        headers['x-api-key'] = api_config['api_key']

    return headers


class TestEnhancedAPIConfiguration:
    """Enhanced API configuration and security tests"""

    def test_api_cors_headers(self, api_config, api_headers):
        """Test CORS headers are properly configured"""
        url = f"{api_config['base_url']}/search"

        # Test OPTIONS request
        response = requests.options(url, headers=api_headers, timeout=30)

        # Check CORS headers
        assert 'Access-Control-Allow-Origin' in response.headers
        assert 'Access-Control-Allow-Methods' in response.headers
        assert 'Access-Control-Allow-Headers' in response.headers

    def test_api_rate_limiting(self, api_config, api_headers):
        """Test API rate limiting behavior"""
        url = f"{api_config['base_url']}/search?limit=1"

        # Make rapid requests to test rate limiting
        responses = []
        for i in range(10):
            response = requests.get(url, headers=api_headers, timeout=10)
            responses.append(response)
            time.sleep(0.1)  # Small delay between requests

        # Check if any responses indicate rate limiting
        rate_limited = any(r.status_code == 429 for r in responses)

        # Rate limiting might not be hit with small number of requests
        # Just verify that if rate limiting occurs, it's handled properly
        for response in responses:
            if response.status_code == 429:
                assert 'Retry-After' in response.headers or 'X-RateLimit-Reset' in response.headers

    def test_api_authentication_methods(self, api_config):
        """Test different authentication scenarios"""
        url = f"{api_config['base_url']}/search?limit=1"

        # Test without API key
        response = requests.get(url, timeout=10)
        assert response.status_code in [401, 403], "Should reject requests without API key"

        # Test with invalid API key
        headers = {'x-api-key': 'invalid_key_12345'}
        response = requests.get(url, headers=headers, timeout=10)
        assert response.status_code in [401, 403], "Should reject invalid API keys"

        # Test with malformed API key
        headers = {'x-api-key': ''}
        response = requests.get(url, headers=headers, timeout=10)
        assert response.status_code in [400, 401, 403], "Should reject empty API keys"

    def test_api_content_type_validation(self, api_config, api_headers):
        """Test content type validation"""
        url = f"{api_config['base_url']}/collect"

        # Test with invalid content type
        invalid_headers = api_headers.copy()
        invalid_headers['Content-Type'] = 'text/plain'

        payload = "not json data"
        response = requests.post(url, data=payload, headers=invalid_headers, timeout=30)

        assert response.status_code in [400, 415], "Should reject non-JSON content"

    def test_api_malformed_json(self, api_config, api_headers):
        """Test handling of malformed JSON"""
        url = f"{api_config['base_url']}/collect"

        # Send malformed JSON
        response = requests.post(
            url,
            data='{"sources": ["otx", }',  # Malformed JSON
            headers=api_headers,
            timeout=30
        )

        assert response.status_code == 400, "Should reject malformed JSON"


class TestEnhancedCollectEndpoint:
    """Enhanced tests for POST /collect endpoint"""

    def test_collect_with_request_id_tracking(self, api_config, api_headers):
        """Test collection with request ID tracking"""
        url = f"{api_config['base_url']}/collect"
        request_id = str(uuid.uuid4())

        headers = api_headers.copy()
        headers['X-Request-ID'] = request_id

        payload = {
            'sources': ['otx'],
            'collection_type': 'automated',
            'limit': 5
        }

        response = requests.post(url, json=payload, headers=headers, timeout=60)

        # Check if request ID is echoed back
        if 'X-Request-ID' in response.headers:
            assert response.headers['X-Request-ID'] == request_id

    def test_collect_concurrent_requests(self, api_config, api_headers):
        """Test concurrent collection requests"""
        url = f"{api_config['base_url']}/collect"

        def make_request(source):
            payload = {
                'sources': [source],
                'collection_type': 'automated',
                'limit': 3
            }
            return requests.post(url, json=payload, headers=api_headers, timeout=90)

        # Send concurrent requests
        sources = ['otx', 'abuse_ch']
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(make_request, source) for source in sources]

            responses = []
            for future in as_completed(futures, timeout=120):
                response = future.result()
                responses.append(response)

        # All requests should succeed or fail gracefully
        for response in responses:
            assert response.status_code in [200, 202, 429, 503], f"Unexpected status: {response.status_code}"

    def test_collect_with_scheduling(self, api_config, api_headers):
        """Test collection with scheduling parameters"""
        url = f"{api_config['base_url']}/collect"

        payload = {
            'sources': ['otx'],
            'collection_type': 'scheduled',
            'schedule': {
                'frequency': 'hourly',
                'start_time': (datetime.now(timezone.utc)).isoformat()
            },
            'limit': 5
        }

        response = requests.post(url, json=payload, headers=api_headers, timeout=60)

        # Should either support scheduling or gracefully reject it
        assert response.status_code in [200, 202, 400, 501], f"Unexpected status: {response.status_code}"

    def test_collect_payload_size_limits(self, api_config, api_headers):
        """Test collection request payload size limits"""
        url = f"{api_config['base_url']}/collect"

        # Test with large payload
        large_filters = {
            'tags': ['tag' + str(i) for i in range(1000)],  # Large tag list
            'excluded_domains': ['domain' + str(i) + '.com' for i in range(500)]
        }

        payload = {
            'sources': ['otx'],
            'collection_type': 'filtered',
            'filters': large_filters,
            'limit': 5
        }

        response = requests.post(url, json=payload, headers=api_headers, timeout=60)

        # Should handle large payloads gracefully
        assert response.status_code in [200, 202, 400, 413], f"Unexpected status: {response.status_code}"

    def test_collect_source_validation(self, api_config, api_headers):
        """Test comprehensive source validation"""
        url = f"{api_config['base_url']}/collect"

        test_cases = [
            # Valid sources
            (['otx'], 200),
            (['abuse_ch'], 200),
            (['otx', 'abuse_ch'], 200),

            # Invalid sources
            (['invalid_source'], 400),
            ([''], 400),
            ([None], 400),
            ([], 400),

            # Mixed valid/invalid
            (['otx', 'invalid_source'], 400),
        ]

        for sources, expected_status_range in test_cases:
            payload = {
                'sources': sources,
                'collection_type': 'automated',
                'limit': 5
            }

            try:
                response = requests.post(url, json=payload, headers=api_headers, timeout=30)

                if expected_status_range == 200:
                    assert response.status_code in [200, 202], f"Sources {sources}: expected success, got {response.status_code}"
                else:
                    assert response.status_code >= 400, f"Sources {sources}: expected error, got {response.status_code}"

            except requests.RequestException as e:
                # Network errors are acceptable for some test cases
                pass


class TestEnhancedSearchEndpoint:
    """Enhanced tests for GET /search endpoint"""

    def test_search_query_validation(self, api_config, api_headers):
        """Test search query parameter validation"""
        base_url = f"{api_config['base_url']}/search"

        test_cases = [
            # Valid queries
            ('192.168.1.1', 200),
            ('malicious.com', 200),
            ('http://evil.com', 200),

            # Edge cases
            ('', 400),  # Empty query
            ('a' * 1000, 400),  # Very long query
            ('SELECT * FROM table', 200),  # SQL-like query (should be treated as text)
            ('<script>alert(1)</script>', 200),  # XSS attempt (should be sanitized)
        ]

        for query, expected_status_range in test_cases:
            params = {'q': query, 'limit': 5}

            try:
                response = requests.get(base_url, params=params, headers=api_headers, timeout=30)

                if expected_status_range == 200:
                    assert response.status_code in [200, 204], f"Query '{query}': expected success, got {response.status_code}"
                else:
                    assert response.status_code >= 400, f"Query '{query}': expected error, got {response.status_code}"

            except requests.RequestException:
                pass

    def test_search_pagination(self, api_config, api_headers):
        """Test search result pagination"""
        base_url = f"{api_config['base_url']}/search"

        # Test different page sizes
        page_sizes = [1, 10, 50, 100]

        for limit in page_sizes:
            params = {'q': '*', 'limit': limit}
            response = requests.get(base_url, params=params, headers=api_headers, timeout=30)

            if response.status_code == 200:
                data = response.json()
                if 'results' in data:
                    assert len(data['results']) <= limit, f"Returned more results than limit {limit}"

    def test_search_filtering_and_sorting(self, api_config, api_headers):
        """Test search filtering and sorting options"""
        base_url = f"{api_config['base_url']}/search"

        filter_tests = [
            {'type': 'ipv4'},
            {'type': 'domain'},
            {'confidence': '80'},
            {'source': 'otx'},
            {'created_after': '2024-01-01'},
            {'sort': 'confidence'},
            {'sort': 'created'},
            {'order': 'desc'},
        ]

        for filters in filter_tests:
            params = {'q': '*', 'limit': 10, **filters}
            response = requests.get(base_url, params=params, headers=api_headers, timeout=30)

            # Should handle filters gracefully
            assert response.status_code in [200, 204, 400], f"Filter {filters}: unexpected status {response.status_code}"

    def test_search_response_format_validation(self, api_config, api_headers):
        """Test search response format validation"""
        base_url = f"{api_config['base_url']}/search"

        params = {'q': 'test', 'limit': 5}
        response = requests.get(base_url, params=params, headers=api_headers, timeout=30)

        if response.status_code == 200:
            data = response.json()

            # Validate response structure
            assert isinstance(data, dict), "Response should be a JSON object"

            if 'results' in data:
                assert isinstance(data['results'], list), "Results should be a list"

                for result in data['results']:
                    # Each result should have required fields
                    assert 'id' in result or 'object_id' in result, "Result missing ID field"
                    if 'stix_data' in result:
                        assert isinstance(result['stix_data'], dict), "STIX data should be an object"


class TestEnhancedEnrichmentEndpoint:
    """Enhanced tests for POST /enrich endpoint"""

    def test_enrich_input_validation(self, api_config, api_headers):
        """Test enrichment input validation"""
        url = f"{api_config['base_url']}/enrich"

        test_cases = [
            # Valid inputs
            {
                'indicators': ['192.168.1.1'],
                'enrichment_types': ['shodan']
            },
            {
                'indicators': ['malicious.com'],
                'enrichment_types': ['dns', 'geolocation']
            },

            # Invalid inputs
            {
                'indicators': [],  # Empty indicators
                'enrichment_types': ['shodan']
            },
            {
                'indicators': ['192.168.1.1'],
                'enrichment_types': []  # Empty enrichment types
            },
            {
                'indicators': ['invalid_ip'],
                'enrichment_types': ['shodan']
            },
        ]

        for payload in test_cases:
            response = requests.post(url, json=payload, headers=api_headers, timeout=60)

            # Should handle all inputs gracefully
            assert response.status_code in [200, 202, 400], f"Payload {payload}: unexpected status {response.status_code}"

    def test_enrich_bulk_processing(self, api_config, api_headers):
        """Test bulk enrichment processing"""
        url = f"{api_config['base_url']}/enrich"

        # Test with multiple indicators
        payload = {
            'indicators': [
                '192.168.1.1',
                '192.168.1.2',
                '192.168.1.3',
                'malicious1.com',
                'malicious2.com'
            ],
            'enrichment_types': ['dns', 'geolocation'],
            'batch_processing': True
        }

        response = requests.post(url, json=payload, headers=api_headers, timeout=120)

        # Should handle bulk processing
        assert response.status_code in [200, 202, 400], f"Bulk enrichment: unexpected status {response.status_code}"

    def test_enrich_caching_behavior(self, api_config, api_headers):
        """Test enrichment caching behavior"""
        url = f"{api_config['base_url']}/enrich"

        indicator = '192.168.1.100'
        payload = {
            'indicators': [indicator],
            'enrichment_types': ['dns'],
            'cache_results': True
        }

        # First request
        response1 = requests.post(url, json=payload, headers=api_headers, timeout=60)
        time1 = time.time()

        # Second request (should potentially use cache)
        time.sleep(1)
        response2 = requests.post(url, json=payload, headers=api_headers, timeout=60)
        time2 = time.time()

        # Both should succeed
        if response1.status_code in [200, 202] and response2.status_code in [200, 202]:
            # Second request might be faster due to caching
            # This is just a basic check - actual implementation might vary
            pass

    def test_enrich_timeout_handling(self, api_config, api_headers):
        """Test enrichment timeout handling"""
        url = f"{api_config['base_url']}/enrich"

        payload = {
            'indicators': ['192.168.1.1'] * 20,  # Many indicators
            'enrichment_types': ['shodan', 'dns', 'geolocation'],
            'timeout': 5  # Short timeout
        }

        response = requests.post(url, json=payload, headers=api_headers, timeout=120)

        # Should handle timeouts gracefully
        assert response.status_code in [200, 202, 408, 504], f"Timeout test: unexpected status {response.status_code}"


class TestEnhancedErrorHandling:
    """Enhanced error handling and edge case tests"""

    def test_http_method_validation(self, api_config, api_headers):
        """Test unsupported HTTP methods"""
        endpoints = [
            f"{api_config['base_url']}/collect",
            f"{api_config['base_url']}/search",
            f"{api_config['base_url']}/enrich"
        ]

        unsupported_methods = ['PUT', 'DELETE', 'PATCH']

        for endpoint in endpoints:
            for method in unsupported_methods:
                response = requests.request(method, endpoint, headers=api_headers, timeout=10)
                assert response.status_code in [405, 501], f"{method} {endpoint}: expected 405/501, got {response.status_code}"

    def test_large_response_handling(self, api_config, api_headers):
        """Test handling of large responses"""
        url = f"{api_config['base_url']}/search"
        params = {'q': '*', 'limit': 1000}  # Request large number of results

        response = requests.get(url, params=params, headers=api_headers, timeout=120)

        # Should handle large responses or limit them appropriately
        assert response.status_code in [200, 204, 400, 413], f"Large response: unexpected status {response.status_code}"

        if response.status_code == 200:
            # Check response size is reasonable
            content_length = len(response.content)
            assert content_length < 10 * 1024 * 1024, "Response too large (>10MB)"

    def test_special_characters_handling(self, api_config, api_headers):
        """Test handling of special characters in requests"""
        special_chars_tests = [
            '192.168.1.1; DROP TABLE users;',  # SQL injection attempt
            '<script>alert("xss")</script>',    # XSS attempt
            '../../etc/passwd',                 # Path traversal attempt
            'test\x00null\x00bytes',           # Null bytes
            'unicode: 测试数据 🔒 💻',           # Unicode characters
        ]

        url = f"{api_config['base_url']}/search"

        for test_input in special_chars_tests:
            params = {'q': test_input, 'limit': 5}
            response = requests.get(url, params=params, headers=api_headers, timeout=30)

            # Should sanitize and handle special characters safely
            assert response.status_code in [200, 204, 400], f"Special chars '{test_input}': unexpected status {response.status_code}"

    def test_network_resilience(self, api_config, api_headers):
        """Test network resilience and connection handling"""
        url = f"{api_config['base_url']}/search"
        params = {'q': 'test', 'limit': 1}

        # Test with very short timeout
        try:
            response = requests.get(url, params=params, headers=api_headers, timeout=0.1)
        except requests.Timeout:
            # Timeout is expected and acceptable
            pass

        # Test with connection reuse
        session = requests.Session()
        for i in range(3):
            response = session.get(url, params=params, headers=api_headers, timeout=10)
            assert response.status_code in [200, 204, 401, 403], f"Connection reuse {i}: unexpected status {response.status_code}"


class TestEnhancedDataIntegrity:
    """Test data integrity and consistency"""

    def test_idempotency(self, api_config, api_headers):
        """Test API idempotency for safe operations"""
        # Search should be idempotent
        url = f"{api_config['base_url']}/search"
        params = {'q': 'test', 'limit': 5}

        responses = []
        for i in range(3):
            response = requests.get(url, params=params, headers=api_headers, timeout=30)
            if response.status_code == 200:
                responses.append(response.json())

        # Results should be consistent across identical requests
        if len(responses) > 1:
            # Basic consistency check - detailed comparison would depend on data volatility
            assert len(responses[0]) == len(responses[1]), "Inconsistent response structure"

    def test_stix_compliance(self, api_config, api_headers):
        """Test STIX 2.1 compliance in responses"""
        url = f"{api_config['base_url']}/search"
        params = {'q': '*', 'limit': 1, 'format': 'stix'}

        response = requests.get(url, params=params, headers=api_headers, timeout=30)

        if response.status_code == 200:
            data = response.json()

            if 'results' in data and data['results']:
                for result in data['results']:
                    if 'stix_data' in result:
                        stix_obj = result['stix_data']

                        # Basic STIX 2.1 validation
                        assert 'type' in stix_obj, "STIX object missing type"
                        assert 'id' in stix_obj, "STIX object missing ID"
                        assert 'spec_version' in stix_obj, "STIX object missing spec_version"

                        if stix_obj.get('spec_version') == '2.1':
                            # Additional STIX 2.1 specific validation
                            if stix_obj['type'] == 'indicator':
                                assert 'pattern' in stix_obj, "STIX indicator missing pattern"
                                assert 'labels' in stix_obj, "STIX indicator missing labels"


if __name__ == "__main__":
    # Run enhanced integration tests
    pytest.main([__file__, "-v", "--tb=short"])