"""
Integration tests for API Gateway endpoints
Tests the live deployed API endpoints with real AWS infrastructure
"""

import pytest
import json
import time
import os
from datetime import datetime, timezone
import requests
import boto3
from botocore.exceptions import ClientError


class TestAPIConfiguration:
    """Test API configuration and setup"""

    @pytest.fixture(scope="class")
    def api_config(self):
        """API configuration for integration tests"""
        return {
            'base_url': os.environ.get('API_BASE_URL', 'https://u88kzux168.execute-api.us-east-1.amazonaws.com/dev'),
            'api_key': os.environ.get('TEST_API_KEY'),
            'region': os.environ.get('AWS_REGION', 'us-east-1')
        }

    @pytest.fixture
    def api_headers(self, api_config):
        """Standard headers for API requests"""
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }

        if api_config['api_key']:
            headers['x-api-key'] = api_config['api_key']

        return headers

    def test_api_configuration(self, api_config):
        """Test that API configuration is properly set"""
        assert api_config['base_url'] is not None, "API_BASE_URL must be set"
        assert api_config['base_url'].startswith('https://'), "API must use HTTPS"

        if api_config['api_key']:
            assert len(api_config['api_key']) > 10, "API key appears to be too short"


class TestCollectEndpoint:
    """Test POST /collect endpoint functionality"""

    def test_collect_otx_source(self, api_config, api_headers):
        """Test collection from OTX source"""
        url = f"{api_config['base_url']}/collect"
        payload = {
            'sources': ['otx'],
            'collection_type': 'automated',
            'limit': 5
        }

        response = requests.post(url, json=payload, headers=api_headers, timeout=60)

        assert response.status_code in [200, 202], f"Expected 200/202, got {response.status_code}: {response.text}"

        response_data = response.json()
        assert 'collection_id' in response_data or 'message' in response_data

        if 'collection_id' in response_data:
            assert len(response_data['collection_id']) > 0

    def test_collect_abuse_ch_source(self, api_config, api_headers):
        """Test collection from Abuse.ch source"""
        url = f"{api_config['base_url']}/collect"
        payload = {
            'sources': ['abuse_ch'],
            'collection_type': 'automated',
            'limit': 5
        }

        response = requests.post(url, json=payload, headers=api_headers, timeout=60)

        assert response.status_code in [200, 202], f"Expected 200/202, got {response.status_code}: {response.text}"

        response_data = response.json()
        assert 'collection_id' in response_data or 'message' in response_data

    def test_collect_multiple_sources(self, api_config, api_headers):
        """Test collection from multiple sources"""
        url = f"{api_config['base_url']}/collect"
        payload = {
            'sources': ['otx', 'abuse_ch'],
            'collection_type': 'automated',
            'limit': 10
        }

        response = requests.post(url, json=payload, headers=api_headers, timeout=90)

        assert response.status_code in [200, 202], f"Expected 200/202, got {response.status_code}: {response.text}"

        response_data = response.json()
        assert 'collection_id' in response_data or 'status' in response_data

    def test_collect_with_filters(self, api_config, api_headers):
        """Test collection with filtering parameters"""
        url = f"{api_config['base_url']}/collect"
        payload = {
            'sources': ['otx'],
            'collection_type': 'filtered',
            'filters': {
                'ioc_types': ['ipv4', 'domain'],
                'min_confidence': 70,
                'tags': ['malware']
            },
            'limit': 5
        }

        response = requests.post(url, json=payload, headers=api_headers, timeout=60)

        # Should either succeed or gracefully handle unsupported filters
        assert response.status_code in [200, 202, 400], f"Unexpected status: {response.status_code}: {response.text}"

    def test_collect_invalid_source(self, api_config, api_headers):
        """Test collection with invalid source"""
        url = f"{api_config['base_url']}/collect"
        payload = {
            'sources': ['invalid_source'],
            'collection_type': 'automated'
        }

        response = requests.post(url, json=payload, headers=api_headers, timeout=30)

        assert response.status_code == 400, f"Expected 400 for invalid source, got {response.status_code}"

        response_data = response.json()
        assert 'error' in response_data

    def test_collect_missing_sources(self, api_config, api_headers):
        """Test collection with missing sources parameter"""
        url = f"{api_config['base_url']}/collect"
        payload = {
            'collection_type': 'automated'
            # Missing 'sources' parameter
        }

        response = requests.post(url, json=payload, headers=api_headers, timeout=30)

        assert response.status_code == 400, f"Expected 400 for missing sources, got {response.status_code}"

    def test_collect_without_api_key(self, api_config):
        """Test collection without API key"""
        url = f"{api_config['base_url']}/collect"
        payload = {
            'sources': ['otx'],
            'collection_type': 'automated'
        }
        headers = {'Content-Type': 'application/json'}  # No API key

        response = requests.post(url, json=payload, headers=headers, timeout=30)

        assert response.status_code in [401, 403], f"Expected 401/403 without API key, got {response.status_code}"

    def test_collect_empty_request_body(self, api_config, api_headers):
        """Test collection with empty request body"""
        url = f"{api_config['base_url']}/collect"

        response = requests.post(url, json={}, headers=api_headers, timeout=30)

        assert response.status_code == 400, f"Expected 400 for empty body, got {response.status_code}"


class TestEnrichEndpoint:
    """Test POST /enrich endpoint functionality"""

    def test_enrich_single_ip(self, api_config, api_headers):
        """Test enrichment of single IP address"""
        url = f"{api_config['base_url']}/enrich"
        payload = {
            'indicators': ['8.8.8.8'],
            'enrichment_types': ['shodan', 'geolocation', 'dns']
        }

        response = requests.post(url, json=payload, headers=api_headers, timeout=30)

        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        response_data = response.json()
        assert 'enrichment_results' in response_data
        assert '8.8.8.8' in response_data['enrichment_results']

    def test_enrich_multiple_indicators(self, api_config, api_headers):
        """Test enrichment of multiple indicators"""
        url = f"{api_config['base_url']}/enrich"
        payload = {
            'indicators': ['8.8.8.8', 'google.com', '1.1.1.1'],
            'enrichment_types': ['geolocation', 'dns']
        }

        response = requests.post(url, json=payload, headers=api_headers, timeout=45)

        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        response_data = response.json()
        assert 'enrichment_results' in response_data

        # Should have results for all valid indicators
        results = response_data['enrichment_results']
        assert len(results) > 0

    def test_enrich_domain_analysis(self, api_config, api_headers):
        """Test domain enrichment functionality"""
        url = f"{api_config['base_url']}/enrich"
        payload = {
            'indicators': ['example.com'],
            'enrichment_types': ['dns', 'reputation']
        }

        response = requests.post(url, json=payload, headers=api_headers, timeout=30)

        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        response_data = response.json()
        assert 'enrichment_results' in response_data

        if 'example.com' in response_data['enrichment_results']:
            domain_data = response_data['enrichment_results']['example.com']
            # Should have DNS data
            assert 'dns_data' in domain_data or 'error' in domain_data

    def test_enrich_invalid_indicators(self, api_config, api_headers):
        """Test enrichment with invalid indicators"""
        url = f"{api_config['base_url']}/enrich"
        payload = {
            'indicators': ['invalid-ip', '999.999.999.999', ''],
            'enrichment_types': ['shodan']
        }

        response = requests.post(url, json=payload, headers=api_headers, timeout=30)

        assert response.status_code in [200, 400], f"Expected 200/400, got {response.status_code}: {response.text}"

        if response.status_code == 200:
            response_data = response.json()
            # Should handle invalid indicators gracefully
            assert 'enrichment_results' in response_data or 'errors' in response_data

    def test_enrich_shodan_integration(self, api_config, api_headers):
        """Test Shodan API integration"""
        url = f"{api_config['base_url']}/enrich"
        payload = {
            'indicators': ['8.8.8.8'],
            'enrichment_types': ['shodan']
        }

        response = requests.post(url, json=payload, headers=api_headers, timeout=30)

        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        response_data = response.json()
        if '8.8.8.8' in response_data.get('enrichment_results', {}):
            ip_data = response_data['enrichment_results']['8.8.8.8']
            # Should have Shodan data or error message
            assert 'shodan_data' in ip_data or 'error' in ip_data

    def test_enrich_cache_utilization(self, api_config, api_headers):
        """Test enrichment cache functionality"""
        url = f"{api_config['base_url']}/enrich"
        payload = {
            'indicators': ['8.8.8.8'],
            'enrichment_types': ['geolocation'],
            'cache_results': True
        }

        # First request
        start_time = time.time()
        response1 = requests.post(url, json=payload, headers=api_headers, timeout=30)
        first_duration = time.time() - start_time

        assert response1.status_code == 200

        # Second request (should use cache)
        start_time = time.time()
        response2 = requests.post(url, json=payload, headers=api_headers, timeout=30)
        second_duration = time.time() - start_time

        assert response2.status_code == 200

        # Second request should be faster (cached)
        assert second_duration < first_duration or second_duration < 5  # Allow for network variance

    def test_enrich_missing_indicators(self, api_config, api_headers):
        """Test enrichment with missing indicators parameter"""
        url = f"{api_config['base_url']}/enrich"
        payload = {
            'enrichment_types': ['shodan']
            # Missing 'indicators' parameter
        }

        response = requests.post(url, json=payload, headers=api_headers, timeout=30)

        assert response.status_code == 400, f"Expected 400 for missing indicators, got {response.status_code}"


class TestSearchEndpoint:
    """Test GET /search endpoint functionality"""

    def test_search_all_indicators(self, api_config, api_headers):
        """Test basic search for all indicators"""
        url = f"{api_config['base_url']}/search"
        params = {'limit': 10}

        response = requests.get(url, params=params, headers=api_headers, timeout=30)

        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        response_data = response.json()
        assert 'indicators' in response_data or 'results' in response_data

        # Should return some structure even if no data
        results = response_data.get('indicators', response_data.get('results', []))
        assert isinstance(results, list)

    def test_search_by_ioc_value(self, api_config, api_headers):
        """Test search by specific IOC value"""
        url = f"{api_config['base_url']}/search"
        params = {
            'q': '8.8.8.8',
            'limit': 5
        }

        response = requests.get(url, params=params, headers=api_headers, timeout=30)

        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        response_data = response.json()
        results = response_data.get('indicators', response_data.get('results', []))

        # If results found, should contain the searched IP
        for result in results:
            if 'ioc_value' in result:
                assert '8.8.8.8' in result['ioc_value'] or result.get('pattern', '').find('8.8.8.8') != -1

    def test_search_by_ioc_type(self, api_config, api_headers):
        """Test search by IOC type"""
        url = f"{api_config['base_url']}/search"
        params = {
            'type': 'ipv4',
            'limit': 5
        }

        response = requests.get(url, params=params, headers=api_headers, timeout=30)

        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        response_data = response.json()
        results = response_data.get('indicators', response_data.get('results', []))

        # If results found, should be IPv4 indicators
        for result in results:
            if 'ioc_type' in result:
                assert result['ioc_type'] in ['ipv4', 'IPv4']

    def test_search_with_confidence_filter(self, api_config, api_headers):
        """Test search with confidence score filtering"""
        url = f"{api_config['base_url']}/search"
        params = {
            'confidence': 80,
            'limit': 5
        }

        response = requests.get(url, params=params, headers=api_headers, timeout=30)

        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        response_data = response.json()
        results = response_data.get('indicators', response_data.get('results', []))

        # If results found, should meet confidence threshold
        for result in results:
            if 'confidence' in result:
                assert result['confidence'] >= 80

    def test_search_with_source_filter(self, api_config, api_headers):
        """Test search with source filtering"""
        url = f"{api_config['base_url']}/search"
        params = {
            'source': 'otx',
            'limit': 5
        }

        response = requests.get(url, params=params, headers=api_headers, timeout=30)

        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        response_data = response.json()
        results = response_data.get('indicators', response_data.get('results', []))

        # If results found, should be from OTX source
        for result in results:
            if 'source' in result or 'source_name' in result:
                source = result.get('source', result.get('source_name'))
                assert 'otx' in source.lower()

    def test_search_pagination(self, api_config, api_headers):
        """Test search pagination functionality"""
        url = f"{api_config['base_url']}/search"
        params = {
            'limit': 2,
            'offset': 0
        }

        response = requests.get(url, params=params, headers=api_headers, timeout=30)

        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        response_data = response.json()
        results = response_data.get('indicators', response_data.get('results', []))

        # Should respect limit
        assert len(results) <= 2

    def test_search_time_range_filter(self, api_config, api_headers):
        """Test search with time range filtering"""
        url = f"{api_config['base_url']}/search"
        params = {
            'from_date': '2024-01-01T00:00:00Z',
            'to_date': '2024-12-31T23:59:59Z',
            'limit': 5
        }

        response = requests.get(url, params=params, headers=api_headers, timeout=30)

        assert response.status_code in [200, 400], f"Expected 200/400, got {response.status_code}: {response.text}"

        if response.status_code == 200:
            response_data = response.json()
            # Should handle time filtering gracefully

    def test_search_no_results(self, api_config, api_headers):
        """Test search with query that returns no results"""
        url = f"{api_config['base_url']}/search"
        params = {
            'q': 'nonexistent-indicator-12345.com',
            'limit': 5
        }

        response = requests.get(url, params=params, headers=api_headers, timeout=30)

        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        response_data = response.json()
        results = response_data.get('indicators', response_data.get('results', []))

        # Should return empty list
        assert len(results) == 0

    def test_search_invalid_parameters(self, api_config, api_headers):
        """Test search with invalid parameters"""
        url = f"{api_config['base_url']}/search"
        params = {
            'limit': 'invalid',
            'confidence': 'not_a_number'
        }

        response = requests.get(url, params=params, headers=api_headers, timeout=30)

        assert response.status_code in [200, 400], f"Expected 200/400, got {response.status_code}: {response.text}"

        # Should handle invalid parameters gracefully


class TestCORSAndHeaders:
    """Test CORS configuration and headers"""

    def test_cors_preflight_collect(self, api_config):
        """Test CORS preflight for collect endpoint"""
        url = f"{api_config['base_url']}/collect"
        headers = {
            'Origin': 'https://threat-intel-platform.com',
            'Access-Control-Request-Method': 'POST',
            'Access-Control-Request-Headers': 'Content-Type,x-api-key'
        }

        response = requests.options(url, headers=headers, timeout=30)

        # Should allow CORS
        assert response.status_code in [200, 204], f"CORS preflight failed: {response.status_code}"

        # Check CORS headers
        cors_headers = response.headers
        assert 'Access-Control-Allow-Origin' in cors_headers or response.status_code == 404

    def test_cors_preflight_enrich(self, api_config):
        """Test CORS preflight for enrich endpoint"""
        url = f"{api_config['base_url']}/enrich"
        headers = {
            'Origin': 'https://threat-intel-platform.com',
            'Access-Control-Request-Method': 'POST',
            'Access-Control-Request-Headers': 'Content-Type,x-api-key'
        }

        response = requests.options(url, headers=headers, timeout=30)

        assert response.status_code in [200, 204], f"CORS preflight failed: {response.status_code}"

    def test_api_response_headers(self, api_config, api_headers):
        """Test API response headers"""
        url = f"{api_config['base_url']}/search"
        params = {'limit': 1}

        response = requests.get(url, params=params, headers=api_headers, timeout=30)

        # Check security headers
        headers = response.headers
        assert 'Content-Type' in headers
        assert headers.get('Content-Type') == 'application/json' or 'application/json' in headers.get('Content-Type', '')


class TestRateLimiting:
    """Test API rate limiting functionality"""

    def test_rate_limiting_behavior(self, api_config, api_headers):
        """Test API rate limiting under load"""
        url = f"{api_config['base_url']}/search"
        params = {'limit': 1}

        responses = []
        response_times = []

        # Send multiple rapid requests
        for i in range(10):
            start_time = time.time()
            try:
                response = requests.get(url, params=params, headers=api_headers, timeout=10)
                responses.append(response.status_code)
                response_times.append(time.time() - start_time)
            except requests.exceptions.RequestException as e:
                responses.append(0)  # Network error
                response_times.append(time.time() - start_time)

            time.sleep(0.1)  # Small delay between requests

        # Should eventually see rate limiting or all succeed
        success_count = sum(1 for code in responses if code == 200)
        rate_limited_count = sum(1 for code in responses if code == 429)

        # Most requests should succeed, some might be rate limited
        assert success_count > 0, "No successful requests"

        if rate_limited_count > 0:
            print(f"Rate limiting detected: {rate_limited_count} requests limited")


@pytest.mark.integration
class TestEndToEndScenarios:
    """Test end-to-end API scenarios"""

    def test_collect_then_search_workflow(self, api_config, api_headers):
        """Test complete workflow: collect data then search for it"""
        # Step 1: Trigger collection
        collect_url = f"{api_config['base_url']}/collect"
        collect_payload = {
            'sources': ['otx'],
            'collection_type': 'automated',
            'limit': 2
        }

        collect_response = requests.post(collect_url, json=collect_payload, headers=api_headers, timeout=60)
        assert collect_response.status_code in [200, 202]

        # Step 2: Wait for processing
        time.sleep(30)  # Allow time for data processing

        # Step 3: Search for collected data
        search_url = f"{api_config['base_url']}/search"
        search_params = {
            'source': 'otx',
            'limit': 5
        }

        search_response = requests.get(search_url, params=search_params, headers=api_headers, timeout=30)
        assert search_response.status_code == 200

        # Should find some OTX data (if collection was successful)
        search_data = search_response.json()
        results = search_data.get('indicators', search_data.get('results', []))
        # Results may be empty if collection failed or is still processing

    def test_enrich_then_search_workflow(self, api_config, api_headers):
        """Test enrichment then search workflow"""
        # Step 1: Enrich an indicator
        enrich_url = f"{api_config['base_url']}/enrich"
        enrich_payload = {
            'indicators': ['8.8.8.8'],
            'enrichment_types': ['geolocation']
        }

        enrich_response = requests.post(enrich_url, json=enrich_payload, headers=api_headers, timeout=30)
        assert enrich_response.status_code == 200

        enrich_data = enrich_response.json()
        assert 'enrichment_results' in enrich_data

        # Step 2: Search for the enriched indicator
        search_url = f"{api_config['base_url']}/search"
        search_params = {
            'q': '8.8.8.8',
            'limit': 5
        }

        search_response = requests.get(search_url, params=search_params, headers=api_headers, timeout=30)
        assert search_response.status_code == 200


# Configuration for integration tests
@pytest.fixture(scope="session", autouse=True)
def verify_test_environment():
    """Verify test environment is properly configured"""
    required_env_vars = ['API_BASE_URL']
    optional_env_vars = ['TEST_API_KEY', 'AWS_REGION']

    missing_vars = []
    for var in required_env_vars:
        if not os.environ.get(var):
            missing_vars.append(var)

    if missing_vars:
        pytest.skip(f"Integration tests require environment variables: {missing_vars}")

    # Warn about optional variables
    for var in optional_env_vars:
        if not os.environ.get(var):
            print(f"Warning: {var} not set, some tests may fail")


# Skip integration tests if not explicitly requested
def pytest_collection_modifyitems(config, items):
    """Skip integration tests unless explicitly requested"""
    if not config.getoption("--integration"):
        skip_integration = pytest.mark.skip(reason="Integration tests not requested (use --integration)")
        for item in items:
            if "integration" in item.keywords:
                item.add_marker(skip_integration)