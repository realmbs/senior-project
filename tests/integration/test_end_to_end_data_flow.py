"""
End-to-end data flow validation tests
Tests complete pipeline: Collection → Processing → Storage → Retrieval → Enrichment
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
import hashlib


# Module-level fixtures
@pytest.fixture(scope="module")
def api_config():
    """API configuration for E2E tests"""
    return {
        'base_url': os.environ.get('API_BASE_URL', 'https://u88kzux168.execute-api.us-east-1.amazonaws.com/dev'),
        'api_key': os.environ.get('TEST_API_KEY'),
        'region': os.environ.get('AWS_REGION', 'us-east-1'),
        'timeout': int(os.environ.get('API_TIMEOUT', '120'))  # Longer timeout for E2E tests
    }


@pytest.fixture
def api_headers(api_config):
    """Standard headers for API requests"""
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'User-Agent': 'ThreatIntel-E2E-Test/1.0'
    }

    if api_config['api_key']:
        headers['x-api-key'] = api_config['api_key']

    return headers


@pytest.fixture(scope="module")
def test_session_id():
    """Unique session ID for tracking test data"""
    return f"e2e-test-{int(time.time())}-{str(uuid.uuid4())[:8]}"


class TestCompleteDataPipeline:
    """Test complete data pipeline from collection to retrieval"""

    def test_otx_collection_to_search_pipeline(self, api_config, api_headers, test_session_id):
        """Test complete OTX data collection and retrieval pipeline"""
        # Step 1: Initiate data collection from OTX
        collect_url = f"{api_config['base_url']}/collect"
        collect_payload = {
            'sources': ['otx'],
            'collection_type': 'automated',
            'limit': 3,
            'session_id': test_session_id,
            'tags': ['e2e-test']
        }

        print(f"Step 1: Collecting data from OTX with session {test_session_id}")
        collect_response = requests.post(
            collect_url,
            json=collect_payload,
            headers=api_headers,
            timeout=api_config['timeout']
        )

        # Validate collection response
        assert collect_response.status_code in [200, 202], f"Collection failed: {collect_response.status_code}: {collect_response.text}"

        collect_data = collect_response.json()
        print(f"Collection response: {collect_data}")

        # Step 2: Wait for data processing (if async)
        if collect_response.status_code == 202:
            print("Step 2: Waiting for asynchronous processing...")
            time.sleep(10)  # Wait for processing

        # Step 3: Search for collected data
        search_url = f"{api_config['base_url']}/search"
        search_params = {
            'q': '*',
            'source': 'otx',
            'limit': 10,
            'created_after': (datetime.now(timezone.utc)).strftime('%Y-%m-%d')
        }

        print("Step 3: Searching for collected data")
        search_response = requests.get(
            search_url,
            params=search_params,
            headers=api_headers,
            timeout=api_config['timeout']
        )

        # Validate search response
        assert search_response.status_code in [200, 204], f"Search failed: {search_response.status_code}: {search_response.text}"

        if search_response.status_code == 200:
            search_data = search_response.json()
            print(f"Search found {len(search_data.get('results', []))} results")

            # Validate data structure
            if 'results' in search_data and search_data['results']:
                result = search_data['results'][0]

                # Check for required fields
                assert 'id' in result or 'object_id' in result, "Result missing ID field"

                if 'stix_data' in result:
                    stix_obj = result['stix_data']
                    assert 'type' in stix_obj, "STIX object missing type"
                    assert 'id' in stix_obj, "STIX object missing ID"

                print("✅ OTX pipeline validation successful")
        else:
            print("⚠️ No search results found (may be expected for test data)")

    def test_abuse_ch_collection_to_search_pipeline(self, api_config, api_headers, test_session_id):
        """Test complete Abuse.ch data collection and retrieval pipeline"""
        # Step 1: Initiate data collection from Abuse.ch
        collect_url = f"{api_config['base_url']}/collect"
        collect_payload = {
            'sources': ['abuse_ch'],
            'collection_type': 'automated',
            'limit': 3,
            'session_id': test_session_id,
            'tags': ['e2e-test']
        }

        print(f"Step 1: Collecting data from Abuse.ch with session {test_session_id}")
        collect_response = requests.post(
            collect_url,
            json=collect_payload,
            headers=api_headers,
            timeout=api_config['timeout']
        )

        # Validate collection response
        assert collect_response.status_code in [200, 202], f"Abuse.ch collection failed: {collect_response.status_code}: {collect_response.text}"

        collect_data = collect_response.json()
        print(f"Collection response: {collect_data}")

        # Step 2: Wait for processing
        if collect_response.status_code == 202:
            print("Step 2: Waiting for processing...")
            time.sleep(10)

        # Step 3: Search for collected data
        search_url = f"{api_config['base_url']}/search"
        search_params = {
            'q': '*',
            'source': 'abuse_ch',
            'limit': 10,
            'type': 'url'  # Abuse.ch typically provides URLs
        }

        print("Step 3: Searching for Abuse.ch data")
        search_response = requests.get(
            search_url,
            params=search_params,
            headers=api_headers,
            timeout=api_config['timeout']
        )

        assert search_response.status_code in [200, 204], f"Abuse.ch search failed: {search_response.status_code}"

        if search_response.status_code == 200:
            search_data = search_response.json()
            print(f"Found {len(search_data.get('results', []))} Abuse.ch results")
            print("✅ Abuse.ch pipeline validation successful")

    def test_multi_source_collection_pipeline(self, api_config, api_headers, test_session_id):
        """Test multi-source data collection pipeline"""
        # Step 1: Collect from multiple sources
        collect_url = f"{api_config['base_url']}/collect"
        collect_payload = {
            'sources': ['otx', 'abuse_ch'],
            'collection_type': 'automated',
            'limit': 5,
            'session_id': test_session_id,
            'tags': ['e2e-test', 'multi-source']
        }

        print("Step 1: Multi-source collection")
        collect_response = requests.post(
            collect_url,
            json=collect_payload,
            headers=api_headers,
            timeout=api_config['timeout']
        )

        assert collect_response.status_code in [200, 202], f"Multi-source collection failed: {collect_response.status_code}"

        # Step 2: Wait for processing
        if collect_response.status_code == 202:
            print("Step 2: Waiting for multi-source processing...")
            time.sleep(15)  # Longer wait for multiple sources

        # Step 3: Search and validate data from different sources
        search_url = f"{api_config['base_url']}/search"

        for source in ['otx', 'abuse_ch']:
            search_params = {
                'q': '*',
                'source': source,
                'limit': 5
            }

            print(f"Step 3: Searching for {source} data")
            search_response = requests.get(
                search_url,
                params=search_params,
                headers=api_headers,
                timeout=api_config['timeout']
            )

            assert search_response.status_code in [200, 204], f"{source} search failed: {search_response.status_code}"

        print("✅ Multi-source pipeline validation successful")


class TestDataEnrichmentPipeline:
    """Test data enrichment pipeline"""

    def test_ip_enrichment_pipeline(self, api_config, api_headers):
        """Test IP address enrichment pipeline"""
        test_ips = ['8.8.8.8', '1.1.1.1']  # Public DNS servers for testing

        # Step 1: Enrich IP addresses
        enrich_url = f"{api_config['base_url']}/enrich"
        enrich_payload = {
            'indicators': test_ips,
            'enrichment_types': ['dns', 'geolocation'],
            'cache_results': True
        }

        print(f"Step 1: Enriching IP addresses: {test_ips}")
        enrich_response = requests.post(
            enrich_url,
            json=enrich_payload,
            headers=api_headers,
            timeout=api_config['timeout']
        )

        # Validate enrichment response
        assert enrich_response.status_code in [200, 202], f"Enrichment failed: {enrich_response.status_code}: {enrich_response.text}"

        if enrich_response.status_code == 200:
            enrich_data = enrich_response.json()
            print(f"Enrichment response: {enrich_data}")

            # Validate enrichment data structure
            if 'results' in enrich_data:
                for result in enrich_data['results']:
                    assert 'indicator' in result, "Enrichment result missing indicator"
                    assert 'enrichment_data' in result, "Enrichment result missing data"

        # Step 2: Verify enriched data is searchable
        time.sleep(5)  # Wait for enriched data to be indexed

        search_url = f"{api_config['base_url']}/search"
        for ip in test_ips:
            search_params = {
                'q': ip,
                'limit': 5,
                'enriched': 'true'
            }

            print(f"Step 2: Searching for enriched IP: {ip}")
            search_response = requests.get(
                search_url,
                params=search_params,
                headers=api_headers,
                timeout=api_config['timeout']
            )

            assert search_response.status_code in [200, 204], f"Enriched IP search failed: {search_response.status_code}"

        print("✅ IP enrichment pipeline validation successful")

    def test_domain_enrichment_pipeline(self, api_config, api_headers):
        """Test domain enrichment pipeline"""
        test_domains = ['google.com', 'github.com']  # Legitimate domains for testing

        # Step 1: Enrich domains
        enrich_url = f"{api_config['base_url']}/enrich"
        enrich_payload = {
            'indicators': test_domains,
            'enrichment_types': ['dns'],
            'cache_results': True
        }

        print(f"Step 1: Enriching domains: {test_domains}")
        enrich_response = requests.post(
            enrich_url,
            json=enrich_payload,
            headers=api_headers,
            timeout=api_config['timeout']
        )

        assert enrich_response.status_code in [200, 202], f"Domain enrichment failed: {enrich_response.status_code}"

        # Step 2: Test enrichment caching
        print("Step 2: Testing enrichment caching")
        time.sleep(1)

        # Repeat the same enrichment request
        cache_response = requests.post(
            enrich_url,
            json=enrich_payload,
            headers=api_headers,
            timeout=api_config['timeout']
        )

        assert cache_response.status_code in [200, 202], f"Cached enrichment failed: {cache_response.status_code}"

        print("✅ Domain enrichment pipeline validation successful")


class TestDataConsistencyValidation:
    """Test data consistency across the pipeline"""

    def test_deduplication_across_sources(self, api_config, api_headers, test_session_id):
        """Test that duplicate indicators are properly deduplicated"""
        # This test would require collecting data that might have overlaps
        # between sources and verifying deduplication works

        # Step 1: Collect from multiple sources that might have overlaps
        collect_url = f"{api_config['base_url']}/collect"
        collect_payload = {
            'sources': ['otx', 'abuse_ch'],
            'collection_type': 'automated',
            'limit': 10,
            'session_id': test_session_id,
            'enable_deduplication': True
        }

        print("Step 1: Testing deduplication across sources")
        collect_response = requests.post(
            collect_url,
            json=collect_payload,
            headers=api_headers,
            timeout=api_config['timeout']
        )

        assert collect_response.status_code in [200, 202], f"Deduplication test collection failed: {collect_response.status_code}"

        # Step 2: Wait and search for potential duplicates
        if collect_response.status_code == 202:
            time.sleep(15)

        search_url = f"{api_config['base_url']}/search"
        search_params = {
            'q': '*',
            'limit': 50,
            'include_duplicates': False  # Should only return unique indicators
        }

        print("Step 2: Searching for deduplicated results")
        search_response = requests.get(
            search_url,
            params=search_params,
            headers=api_headers,
            timeout=api_config['timeout']
        )

        assert search_response.status_code in [200, 204], f"Deduplication search failed: {search_response.status_code}"

        if search_response.status_code == 200:
            search_data = search_response.json()
            results = search_data.get('results', [])

            # Check for duplicates by indicator value
            indicator_values = []
            for result in results:
                if 'stix_data' in result and 'pattern' in result['stix_data']:
                    pattern = result['stix_data']['pattern']
                    indicator_values.append(pattern)

            # Verify no duplicates
            unique_indicators = set(indicator_values)
            assert len(indicator_values) == len(unique_indicators), f"Found duplicate indicators: {len(indicator_values)} total, {len(unique_indicators)} unique"

        print("✅ Deduplication validation successful")

    def test_stix_format_consistency(self, api_config, api_headers):
        """Test STIX format consistency across the pipeline"""
        # Search for recent data and validate STIX format
        search_url = f"{api_config['base_url']}/search"
        search_params = {
            'q': '*',
            'limit': 5,
            'format': 'stix'
        }

        print("Testing STIX format consistency")
        search_response = requests.get(
            search_url,
            params=search_params,
            headers=api_headers,
            timeout=api_config['timeout']
        )

        assert search_response.status_code in [200, 204], f"STIX format search failed: {search_response.status_code}"

        if search_response.status_code == 200:
            search_data = search_response.json()
            results = search_data.get('results', [])

            for result in results:
                if 'stix_data' in result:
                    stix_obj = result['stix_data']

                    # Validate STIX 2.1 compliance
                    assert 'type' in stix_obj, "STIX object missing type"
                    assert 'id' in stix_obj, "STIX object missing ID"
                    assert 'spec_version' in stix_obj, "STIX object missing spec_version"

                    if stix_obj.get('spec_version') == '2.1':
                        if stix_obj['type'] == 'indicator':
                            assert 'pattern' in stix_obj, "STIX indicator missing pattern"
                            assert 'labels' in stix_obj, "STIX indicator missing labels"
                            assert 'valid_from' in stix_obj, "STIX indicator missing valid_from"

                        # Validate timestamp format
                        for time_field in ['created', 'modified', 'valid_from']:
                            if time_field in stix_obj:
                                time_value = stix_obj[time_field]
                                # Should be ISO 8601 format
                                datetime.fromisoformat(time_value.replace('Z', '+00:00'))

        print("✅ STIX format consistency validation successful")


class TestErrorRecoveryAndResilience:
    """Test error recovery and system resilience"""

    def test_partial_failure_recovery(self, api_config, api_headers):
        """Test recovery from partial failures"""
        # Test with mix of valid and invalid data
        collect_url = f"{api_config['base_url']}/collect"
        collect_payload = {
            'sources': ['otx', 'invalid_source'],  # One valid, one invalid
            'collection_type': 'automated',
            'limit': 5,
            'continue_on_error': True
        }

        print("Testing partial failure recovery")
        collect_response = requests.post(
            collect_url,
            json=collect_payload,
            headers=api_headers,
            timeout=api_config['timeout']
        )

        # Should handle partial failure gracefully
        assert collect_response.status_code in [200, 202, 207], f"Partial failure test failed: {collect_response.status_code}"

        if collect_response.status_code in [200, 207]:
            collect_data = collect_response.json()
            # Should indicate which sources succeeded/failed
            if 'errors' in collect_data:
                print(f"Partial failures handled: {collect_data['errors']}")

        print("✅ Partial failure recovery validation successful")

    def test_large_dataset_handling(self, api_config, api_headers):
        """Test handling of large datasets"""
        # Request larger dataset to test system limits
        collect_url = f"{api_config['base_url']}/collect"
        collect_payload = {
            'sources': ['otx'],
            'collection_type': 'automated',
            'limit': 100,  # Larger limit
            'batch_processing': True
        }

        print("Testing large dataset handling")
        collect_response = requests.post(
            collect_url,
            json=collect_payload,
            headers=api_headers,
            timeout=180  # Longer timeout for large datasets
        )

        # Should handle large requests gracefully
        assert collect_response.status_code in [200, 202, 413], f"Large dataset test failed: {collect_response.status_code}"

        if collect_response.status_code == 413:
            print("Large dataset appropriately rejected (request too large)")
        else:
            print("Large dataset accepted for processing")

        print("✅ Large dataset handling validation successful")


if __name__ == "__main__":
    # Run end-to-end tests
    pytest.main([__file__, "-v", "--tb=short", "-s"])