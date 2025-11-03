"""
End-to-end data flow tests for the threat intelligence platform
Tests complete data pipeline from collection through processing to search
"""

import pytest
import json
import time
import os
from datetime import datetime, timezone, timedelta
import requests
import boto3
from botocore.exceptions import ClientError
import uuid


class TestDataFlowConfiguration:
    """Test configuration for data flow tests"""

    @pytest.fixture(scope="class")
    def flow_config(self):
        """Configuration for data flow tests"""
        return {
            'base_url': os.environ.get('API_BASE_URL', 'https://u88kzux168.execute-api.us-east-1.amazonaws.com/dev'),
            'api_key': os.environ.get('TEST_API_KEY'),
            'region': os.environ.get('AWS_REGION', 'us-east-1'),
            'timeout_short': 30,
            'timeout_medium': 60,
            'timeout_long': 120,
            'processing_wait': 45  # Time to wait for async processing
        }

    @pytest.fixture
    def flow_headers(self, flow_config):
        """Headers for data flow requests"""
        headers = {'Content-Type': 'application/json'}
        if flow_config['api_key']:
            headers['x-api-key'] = flow_config['api_key']
        return headers

    @pytest.fixture
    def unique_test_id(self):
        """Generate unique test ID for tracking"""
        return f"test_{int(time.time())}_{uuid.uuid4().hex[:8]}"


class TestOTXCollectionPipeline:
    """Test complete OTX collection to search pipeline"""

    def test_otx_collection_to_storage_pipeline(self, flow_config, flow_headers, unique_test_id):
        """Test OTX collection → processing → storage → search pipeline"""

        # Step 1: Trigger OTX collection
        collect_url = f"{flow_config['base_url']}/collect"
        collect_payload = {
            'sources': ['otx'],
            'collection_type': 'automated',
            'limit': 5,
            'test_id': unique_test_id
        }

        print(f"Starting OTX collection test {unique_test_id}")

        collect_response = requests.post(
            collect_url,
            json=collect_payload,
            headers=flow_headers,
            timeout=flow_config['timeout_medium']
        )

        assert collect_response.status_code in [200, 202], \
            f"Collection failed: {collect_response.status_code} - {collect_response.text}"

        collect_data = collect_response.json()
        collection_id = collect_data.get('collection_id', unique_test_id)

        print(f"Collection initiated: {collection_id}")

        # Step 2: Wait for processing to complete
        print(f"Waiting {flow_config['processing_wait']} seconds for processing...")
        time.sleep(flow_config['processing_wait'])

        # Step 3: Search for collected data
        search_url = f"{flow_config['base_url']}/search"
        search_params = {
            'source': 'otx',
            'limit': 10,
            'from_date': (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
        }

        search_response = requests.get(
            search_url,
            params=search_params,
            headers=flow_headers,
            timeout=flow_config['timeout_short']
        )

        assert search_response.status_code == 200, \
            f"Search failed: {search_response.status_code} - {search_response.text}"

        search_data = search_response.json()
        results = search_data.get('indicators', search_data.get('results', []))

        print(f"Found {len(results)} OTX indicators")

        # Step 4: Validate data integrity
        if len(results) > 0:
            # Verify STIX compliance
            for indicator in results[:3]:  # Check first 3 results
                self._validate_stix_compliance(indicator)
                self._validate_otx_attribution(indicator)

        # Test passes if pipeline completes without errors
        # Results may be empty if OTX API is unavailable or rate-limited

    def test_otx_collection_with_filters(self, flow_config, flow_headers, unique_test_id):
        """Test OTX collection with filtering parameters"""

        collect_url = f"{flow_config['base_url']}/collect"
        collect_payload = {
            'sources': ['otx'],
            'collection_type': 'filtered',
            'filters': {
                'ioc_types': ['ipv4', 'domain'],
                'min_confidence': 75,
                'tags': ['malware', 'apt']
            },
            'limit': 3,
            'test_id': unique_test_id
        }

        collect_response = requests.post(
            collect_url,
            json=collect_payload,
            headers=flow_headers,
            timeout=flow_config['timeout_medium']
        )

        # Should either succeed or gracefully handle unsupported filters
        assert collect_response.status_code in [200, 202, 400], \
            f"Filtered collection failed: {collect_response.status_code} - {collect_response.text}"

        if collect_response.status_code in [200, 202]:
            time.sleep(30)  # Wait for processing

            # Search for filtered results
            search_url = f"{flow_config['base_url']}/search"
            search_params = {
                'source': 'otx',
                'confidence': 75,
                'limit': 5
            }

            search_response = requests.get(
                search_url,
                params=search_params,
                headers=flow_headers,
                timeout=flow_config['timeout_short']
            )

            assert search_response.status_code == 200

    def _validate_stix_compliance(self, indicator):
        """Validate indicator follows STIX 2.1 format"""
        if 'stix_data' in indicator:
            stix_data = indicator['stix_data']
            assert 'type' in stix_data
            assert stix_data['type'] == 'indicator'
            assert 'id' in stix_data
            assert 'pattern' in stix_data
            assert 'created' in stix_data or 'created_date' in indicator

    def _validate_otx_attribution(self, indicator):
        """Validate proper OTX source attribution"""
        source = indicator.get('source', indicator.get('source_name', ''))
        assert 'otx' in source.lower(), f"Expected OTX source, got: {source}"


class TestAbuseCHCollectionPipeline:
    """Test complete Abuse.ch collection to search pipeline"""

    def test_abuse_ch_collection_pipeline(self, flow_config, flow_headers, unique_test_id):
        """Test Abuse.ch collection → processing → storage → search pipeline"""

        # Step 1: Trigger Abuse.ch collection
        collect_url = f"{flow_config['base_url']}/collect"
        collect_payload = {
            'sources': ['abuse_ch'],
            'collection_type': 'automated',
            'limit': 5,
            'test_id': unique_test_id
        }

        collect_response = requests.post(
            collect_url,
            json=collect_payload,
            headers=flow_headers,
            timeout=flow_config['timeout_medium']
        )

        assert collect_response.status_code in [200, 202], \
            f"Abuse.ch collection failed: {collect_response.status_code} - {collect_response.text}"

        # Step 2: Wait for processing
        time.sleep(flow_config['processing_wait'])

        # Step 3: Search for Abuse.ch data
        search_url = f"{flow_config['base_url']}/search"
        search_params = {
            'source': 'abuse_ch',
            'limit': 10
        }

        search_response = requests.get(
            search_url,
            params=search_params,
            headers=flow_headers,
            timeout=flow_config['timeout_short']
        )

        assert search_response.status_code == 200

        search_data = search_response.json()
        results = search_data.get('indicators', search_data.get('results', []))

        print(f"Found {len(results)} Abuse.ch indicators")

        # Validate Abuse.ch specific data
        if len(results) > 0:
            for indicator in results[:2]:
                self._validate_abuse_ch_attribution(indicator)

    def _validate_abuse_ch_attribution(self, indicator):
        """Validate proper Abuse.ch source attribution"""
        source = indicator.get('source', indicator.get('source_name', ''))
        assert 'abuse' in source.lower() or 'urlhaus' in source.lower(), \
            f"Expected Abuse.ch source, got: {source}"


class TestEnrichmentPipeline:
    """Test complete enrichment pipeline"""

    def test_ip_enrichment_pipeline(self, flow_config, flow_headers, unique_test_id):
        """Test IP enrichment → caching → retrieval pipeline"""

        test_ip = "8.8.8.8"  # Google DNS - reliable for testing

        # Step 1: Trigger enrichment
        enrich_url = f"{flow_config['base_url']}/enrich"
        enrich_payload = {
            'indicators': [test_ip],
            'enrichment_types': ['shodan', 'geolocation', 'dns'],
            'cache_results': True,
            'test_id': unique_test_id
        }

        print(f"Starting IP enrichment test for {test_ip}")

        first_start = time.time()
        enrich_response = requests.post(
            enrich_url,
            json=enrich_payload,
            headers=flow_headers,
            timeout=flow_config['timeout_short']
        )
        first_duration = time.time() - first_start

        assert enrich_response.status_code == 200, \
            f"Enrichment failed: {enrich_response.status_code} - {enrich_response.text}"

        enrich_data = enrich_response.json()
        assert 'enrichment_results' in enrich_data
        assert test_ip in enrich_data['enrichment_results']

        ip_enrichment = enrich_data['enrichment_results'][test_ip]
        print(f"First enrichment completed in {first_duration:.2f}s")

        # Step 2: Validate enrichment data
        self._validate_ip_enrichment_data(ip_enrichment, test_ip)

        # Step 3: Test cache utilization (second request)
        print("Testing cache utilization...")
        time.sleep(2)  # Brief pause

        second_start = time.time()
        cached_response = requests.post(
            enrich_url,
            json=enrich_payload,
            headers=flow_headers,
            timeout=flow_config['timeout_short']
        )
        second_duration = time.time() - second_start

        assert cached_response.status_code == 200

        cached_data = cached_response.json()
        assert test_ip in cached_data['enrichment_results']

        print(f"Cached enrichment completed in {second_duration:.2f}s")

        # Cache should be faster (or at least not significantly slower)
        cache_improvement = first_duration - second_duration
        print(f"Cache performance improvement: {cache_improvement:.2f}s")

        # Step 4: Search for enriched data
        search_url = f"{flow_config['base_url']}/search"
        search_params = {
            'q': test_ip,
            'limit': 5
        }

        search_response = requests.get(
            search_url,
            params=search_params,
            headers=flow_headers,
            timeout=flow_config['timeout_short']
        )

        assert search_response.status_code == 200

    def test_domain_enrichment_pipeline(self, flow_config, flow_headers, unique_test_id):
        """Test domain enrichment pipeline"""

        test_domain = "example.com"  # Reliable test domain

        enrich_url = f"{flow_config['base_url']}/enrich"
        enrich_payload = {
            'indicators': [test_domain],
            'enrichment_types': ['dns', 'reputation'],
            'test_id': unique_test_id
        }

        enrich_response = requests.post(
            enrich_url,
            json=enrich_payload,
            headers=flow_headers,
            timeout=flow_config['timeout_short']
        )

        assert enrich_response.status_code == 200

        enrich_data = enrich_response.json()
        assert 'enrichment_results' in enrich_data

        if test_domain in enrich_data['enrichment_results']:
            domain_enrichment = enrich_data['enrichment_results'][test_domain]
            self._validate_domain_enrichment_data(domain_enrichment, test_domain)

    def test_batch_enrichment_pipeline(self, flow_config, flow_headers, unique_test_id):
        """Test batch enrichment pipeline"""

        test_indicators = ["8.8.8.8", "1.1.1.1", "example.com"]

        enrich_url = f"{flow_config['base_url']}/enrich"
        enrich_payload = {
            'indicators': test_indicators,
            'enrichment_types': ['geolocation', 'dns'],
            'test_id': unique_test_id
        }

        enrich_response = requests.post(
            enrich_url,
            json=enrich_payload,
            headers=flow_headers,
            timeout=flow_config['timeout_medium']
        )

        assert enrich_response.status_code == 200

        enrich_data = enrich_response.json()
        results = enrich_data.get('enrichment_results', {})

        print(f"Batch enrichment processed {len(results)} indicators")

        # Should have results for valid indicators
        assert len(results) > 0

        # Validate each result
        for indicator, data in results.items():
            if indicator in test_indicators:
                assert data is not None
                print(f"Enrichment data for {indicator}: {list(data.keys())}")

    def _validate_ip_enrichment_data(self, enrichment_data, ip_address):
        """Validate IP enrichment data structure"""
        assert enrichment_data is not None

        # Should have at least one type of enrichment data
        expected_keys = ['shodan_data', 'geolocation_data', 'dns_data', 'reputation_data']
        has_enrichment = any(key in enrichment_data for key in expected_keys)

        if not has_enrichment:
            # If no enrichment data, should have error information
            assert 'error' in enrichment_data or 'errors' in enrichment_data

    def _validate_domain_enrichment_data(self, enrichment_data, domain):
        """Validate domain enrichment data structure"""
        assert enrichment_data is not None

        # Should have DNS data for valid domains
        if 'dns_data' in enrichment_data:
            dns_data = enrichment_data['dns_data']
            assert isinstance(dns_data, dict)


class TestMultiSourcePipeline:
    """Test pipeline with multiple sources"""

    def test_multi_source_collection_pipeline(self, flow_config, flow_headers, unique_test_id):
        """Test collection from multiple sources simultaneously"""

        collect_url = f"{flow_config['base_url']}/collect"
        collect_payload = {
            'sources': ['otx', 'abuse_ch'],
            'collection_type': 'automated',
            'limit': 8,
            'test_id': unique_test_id
        }

        collect_response = requests.post(
            collect_url,
            json=collect_payload,
            headers=flow_headers,
            timeout=flow_config['timeout_long']
        )

        assert collect_response.status_code in [200, 202]

        # Wait for processing
        time.sleep(flow_config['processing_wait'])

        # Search for data from both sources
        search_url = f"{flow_config['base_url']}/search"
        search_params = {'limit': 20}

        search_response = requests.get(
            search_url,
            params=search_params,
            headers=flow_headers,
            timeout=flow_config['timeout_short']
        )

        assert search_response.status_code == 200

        search_data = search_response.json()
        results = search_data.get('indicators', search_data.get('results', []))

        # Analyze sources in results
        sources_found = set()
        for result in results:
            source = result.get('source', result.get('source_name', '')).lower()
            if 'otx' in source:
                sources_found.add('otx')
            elif 'abuse' in source or 'urlhaus' in source:
                sources_found.add('abuse_ch')

        print(f"Found data from sources: {sources_found}")

        # Should find data from at least one source
        # (Results may vary based on API availability)


class TestDeduplicationPipeline:
    """Test deduplication across the pipeline"""

    def test_duplicate_indicator_handling(self, flow_config, flow_headers, unique_test_id):
        """Test that duplicate indicators are properly handled"""

        # Use a specific indicator that might appear in multiple sources
        test_domain = "malicious-test-domain.com"

        # Step 1: Enrich the same indicator twice
        enrich_url = f"{flow_config['base_url']}/enrich"
        enrich_payload = {
            'indicators': [test_domain],
            'enrichment_types': ['dns'],
            'test_id': unique_test_id
        }

        # First enrichment
        first_response = requests.post(
            enrich_url,
            json=enrich_payload,
            headers=flow_headers,
            timeout=flow_config['timeout_short']
        )

        assert first_response.status_code == 200

        # Second enrichment (should use cache or handle gracefully)
        second_response = requests.post(
            enrich_url,
            json=enrich_payload,
            headers=flow_headers,
            timeout=flow_config['timeout_short']
        )

        assert second_response.status_code == 200

        # Both should return consistent results
        first_data = first_response.json()
        second_data = second_response.json()

        if test_domain in first_data.get('enrichment_results', {}):
            assert test_domain in second_data.get('enrichment_results', {})


class TestErrorHandlingPipeline:
    """Test error handling throughout the pipeline"""

    def test_invalid_source_error_handling(self, flow_config, flow_headers):
        """Test pipeline error handling with invalid sources"""

        collect_url = f"{flow_config['base_url']}/collect"
        collect_payload = {
            'sources': ['invalid_source'],
            'collection_type': 'automated'
        }

        response = requests.post(
            collect_url,
            json=collect_payload,
            headers=flow_headers,
            timeout=flow_config['timeout_short']
        )

        assert response.status_code == 400
        error_data = response.json()
        assert 'error' in error_data

    def test_invalid_enrichment_indicator_handling(self, flow_config, flow_headers):
        """Test error handling with invalid indicators"""

        enrich_url = f"{flow_config['base_url']}/enrich"
        enrich_payload = {
            'indicators': ['invalid-ip-address', '999.999.999.999'],
            'enrichment_types': ['shodan']
        }

        response = requests.post(
            enrich_url,
            json=enrich_payload,
            headers=flow_headers,
            timeout=flow_config['timeout_short']
        )

        # Should either return 400 or handle gracefully with error messages
        assert response.status_code in [200, 400]

        if response.status_code == 200:
            data = response.json()
            # Should have error information for invalid indicators
            results = data.get('enrichment_results', {})
            for indicator, result in results.items():
                if indicator in ['invalid-ip-address', '999.999.999.999']:
                    assert 'error' in result or result is None

    def test_search_error_handling(self, flow_config, flow_headers):
        """Test search error handling"""

        search_url = f"{flow_config['base_url']}/search"
        search_params = {
            'limit': 'invalid_limit',
            'confidence': 'not_a_number'
        }

        response = requests.get(
            search_url,
            params=search_params,
            headers=flow_headers,
            timeout=flow_config['timeout_short']
        )

        # Should handle invalid parameters gracefully
        assert response.status_code in [200, 400]


class TestDataConsistencyPipeline:
    """Test data consistency across the pipeline"""

    def test_stix_format_consistency(self, flow_config, flow_headers, unique_test_id):
        """Test STIX format consistency throughout pipeline"""

        # Collect some data
        collect_url = f"{flow_config['base_url']}/collect"
        collect_payload = {
            'sources': ['otx'],
            'collection_type': 'automated',
            'limit': 3,
            'test_id': unique_test_id
        }

        collect_response = requests.post(
            collect_url,
            json=collect_payload,
            headers=flow_headers,
            timeout=flow_config['timeout_medium']
        )

        if collect_response.status_code in [200, 202]:
            time.sleep(30)  # Wait for processing

            # Search and validate STIX format
            search_url = f"{flow_config['base_url']}/search"
            search_params = {
                'source': 'otx',
                'limit': 5
            }

            search_response = requests.get(
                search_url,
                params=search_params,
                headers=flow_headers,
                timeout=flow_config['timeout_short']
            )

            if search_response.status_code == 200:
                search_data = search_response.json()
                results = search_data.get('indicators', search_data.get('results', []))

                for result in results[:2]:  # Check first 2 results
                    self._validate_stix_consistency(result)

    def _validate_stix_consistency(self, indicator):
        """Validate STIX format consistency"""
        if 'stix_data' in indicator:
            stix_data = indicator['stix_data']

            # Required STIX fields
            required_fields = ['type', 'id', 'pattern']
            for field in required_fields:
                assert field in stix_data, f"Missing STIX field: {field}"

            # Validate pattern format
            pattern = stix_data['pattern']
            assert pattern.startswith('[') and pattern.endswith(']'), \
                f"Invalid STIX pattern format: {pattern}"


# Configuration for data flow tests
@pytest.fixture(scope="session", autouse=True)
def verify_data_flow_environment():
    """Verify environment for data flow tests"""
    required_vars = ['API_BASE_URL']
    missing_vars = [var for var in required_vars if not os.environ.get(var)]

    if missing_vars:
        pytest.skip(f"Data flow tests require: {missing_vars}")

    # Check API accessibility
    try:
        api_url = os.environ.get('API_BASE_URL')
        response = requests.get(f"{api_url}/search?limit=1", timeout=10)
        if response.status_code not in [200, 401, 403]:
            pytest.skip(f"API not accessible: {response.status_code}")
    except requests.exceptions.RequestException as e:
        pytest.skip(f"Cannot reach API: {e}")


# Mark all tests in this module as integration tests
pytestmark = pytest.mark.integration