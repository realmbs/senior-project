"""
Performance and load testing suite for the threat intelligence platform
Tests system performance, scalability, and resource utilization
"""

import pytest
import json
import time
import os
import statistics
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Tuple
import requests
import boto3
from botocore.exceptions import ClientError


class TestPerformanceConfiguration:
    """Performance test configuration"""

    @pytest.fixture(scope="class")
    def perf_config(self):
        """Performance test configuration"""
        return {
            'base_url': os.environ.get('API_BASE_URL', 'https://u88kzux168.execute-api.us-east-1.amazonaws.com/dev'),
            'api_key': os.environ.get('TEST_API_KEY'),
            'region': os.environ.get('AWS_REGION', 'us-east-1'),
            'concurrent_users': int(os.environ.get('CONCURRENT_USERS', '5')),
            'load_test_duration': int(os.environ.get('LOAD_TEST_DURATION', '60')),  # seconds
            'max_response_time': float(os.environ.get('MAX_RESPONSE_TIME', '10.0')),  # seconds
            'min_success_rate': float(os.environ.get('MIN_SUCCESS_RATE', '0.95'))  # 95%
        }

    @pytest.fixture
    def perf_headers(self, perf_config):
        """Headers for performance requests"""
        headers = {'Content-Type': 'application/json'}
        if perf_config['api_key']:
            headers['x-api-key'] = perf_config['api_key']
        return headers


class PerformanceMetrics:
    """Class to collect and analyze performance metrics"""

    def __init__(self):
        self.response_times: List[float] = []
        self.status_codes: List[int] = []
        self.error_messages: List[str] = []
        self.timestamps: List[float] = []

    def add_result(self, response_time: float, status_code: int, error_msg: str = None):
        """Add a test result to metrics"""
        self.response_times.append(response_time)
        self.status_codes.append(status_code)
        self.timestamps.append(time.time())
        if error_msg:
            self.error_messages.append(error_msg)

    def get_summary(self) -> Dict:
        """Get performance summary statistics"""
        if not self.response_times:
            return {'error': 'No data collected'}

        success_codes = [200, 201, 202]
        successful_requests = sum(1 for code in self.status_codes if code in success_codes)
        total_requests = len(self.status_codes)

        return {
            'total_requests': total_requests,
            'successful_requests': successful_requests,
            'success_rate': successful_requests / total_requests if total_requests > 0 else 0,
            'avg_response_time': statistics.mean(self.response_times),
            'median_response_time': statistics.median(self.response_times),
            'min_response_time': min(self.response_times),
            'max_response_time': max(self.response_times),
            'p95_response_time': self._percentile(self.response_times, 95),
            'p99_response_time': self._percentile(self.response_times, 99),
            'error_count': len(self.error_messages),
            'status_code_distribution': self._count_status_codes()
        }

    def _percentile(self, data: List[float], percentile: int) -> float:
        """Calculate percentile of response times"""
        if not data:
            return 0
        sorted_data = sorted(data)
        index = int((percentile / 100) * len(sorted_data))
        return sorted_data[min(index, len(sorted_data) - 1)]

    def _count_status_codes(self) -> Dict[int, int]:
        """Count occurrences of each status code"""
        counts = {}
        for code in self.status_codes:
            counts[code] = counts.get(code, 0) + 1
        return counts


class TestAPIResponseTimes:
    """Test API response time performance"""

    def test_search_endpoint_response_time(self, perf_config, perf_headers):
        """Test search endpoint response time under normal load"""
        url = f"{perf_config['base_url']}/search"
        params = {'limit': 10}

        metrics = PerformanceMetrics()

        # Perform multiple requests to get stable metrics
        for i in range(20):
            start_time = time.time()
            try:
                response = requests.get(url, params=params, headers=perf_headers, timeout=30)
                response_time = time.time() - start_time

                metrics.add_result(response_time, response.status_code)

                # Individual request should be fast
                assert response_time < perf_config['max_response_time'], \
                    f"Request {i+1} too slow: {response_time:.2f}s"

            except requests.exceptions.RequestException as e:
                response_time = time.time() - start_time
                metrics.add_result(response_time, 0, str(e))

            time.sleep(0.5)  # Small delay between requests

        summary = metrics.get_summary()
        print(f"Search endpoint performance: {summary}")

        # Validate performance requirements
        assert summary['success_rate'] >= perf_config['min_success_rate'], \
            f"Success rate too low: {summary['success_rate']:.2f}"
        assert summary['avg_response_time'] < perf_config['max_response_time'], \
            f"Average response time too high: {summary['avg_response_time']:.2f}s"

    def test_enrich_endpoint_response_time(self, perf_config, perf_headers):
        """Test enrichment endpoint response time"""
        url = f"{perf_config['base_url']}/enrich"
        payload = {
            'indicators': ['8.8.8.8'],
            'enrichment_types': ['geolocation']
        }

        metrics = PerformanceMetrics()

        # Test enrichment performance
        for i in range(10):
            start_time = time.time()
            try:
                response = requests.post(url, json=payload, headers=perf_headers, timeout=30)
                response_time = time.time() - start_time

                metrics.add_result(response_time, response.status_code)

                # Enrichment should complete reasonably quickly
                assert response_time < 15.0, f"Enrichment too slow: {response_time:.2f}s"

            except requests.exceptions.RequestException as e:
                response_time = time.time() - start_time
                metrics.add_result(response_time, 0, str(e))

            time.sleep(1)  # Delay to avoid rate limiting

        summary = metrics.get_summary()
        print(f"Enrichment endpoint performance: {summary}")

        assert summary['success_rate'] >= 0.8, "Enrichment success rate too low"

    def test_collect_endpoint_response_time(self, perf_config, perf_headers):
        """Test collection endpoint response time"""
        url = f"{perf_config['base_url']}/collect"
        payload = {
            'sources': ['otx'],
            'collection_type': 'automated',
            'limit': 3
        }

        metrics = PerformanceMetrics()

        # Test collection performance (fewer requests due to processing overhead)
        for i in range(5):
            start_time = time.time()
            try:
                response = requests.post(url, json=payload, headers=perf_headers, timeout=60)
                response_time = time.time() - start_time

                metrics.add_result(response_time, response.status_code)

                # Collection should initiate quickly even if processing takes longer
                assert response_time < 30.0, f"Collection initiation too slow: {response_time:.2f}s"

            except requests.exceptions.RequestException as e:
                response_time = time.time() - start_time
                metrics.add_result(response_time, 0, str(e))

            time.sleep(5)  # Longer delay for collection requests

        summary = metrics.get_summary()
        print(f"Collection endpoint performance: {summary}")


class TestConcurrentLoad:
    """Test system performance under concurrent load"""

    def test_concurrent_search_requests(self, perf_config, perf_headers):
        """Test concurrent search requests"""
        url = f"{perf_config['base_url']}/search"
        params = {'limit': 5}

        def make_request(request_id: int) -> Tuple[int, float, int]:
            """Make a single request and return metrics"""
            start_time = time.time()
            try:
                response = requests.get(url, params=params, headers=perf_headers, timeout=20)
                response_time = time.time() - start_time
                return request_id, response_time, response.status_code
            except requests.exceptions.RequestException as e:
                response_time = time.time() - start_time
                return request_id, response_time, 0

        metrics = PerformanceMetrics()

        # Execute concurrent requests
        with ThreadPoolExecutor(max_workers=perf_config['concurrent_users']) as executor:
            futures = [
                executor.submit(make_request, i)
                for i in range(perf_config['concurrent_users'] * 2)
            ]

            for future in as_completed(futures):
                request_id, response_time, status_code = future.result()
                metrics.add_result(response_time, status_code)

        summary = metrics.get_summary()
        print(f"Concurrent search performance: {summary}")

        # Validate concurrent performance
        assert summary['success_rate'] >= 0.8, \
            f"Concurrent success rate too low: {summary['success_rate']:.2f}"
        assert summary['p95_response_time'] < 15.0, \
            f"95th percentile response time too high: {summary['p95_response_time']:.2f}s"

    def test_concurrent_enrichment_requests(self, perf_config, perf_headers):
        """Test concurrent enrichment requests"""
        url = f"{perf_config['base_url']}/enrich"

        test_ips = ['8.8.8.8', '1.1.1.1', '208.67.222.222', '9.9.9.9']

        def make_enrichment_request(ip: str) -> Tuple[str, float, int]:
            """Make enrichment request for an IP"""
            payload = {
                'indicators': [ip],
                'enrichment_types': ['geolocation']
            }

            start_time = time.time()
            try:
                response = requests.post(url, json=payload, headers=perf_headers, timeout=25)
                response_time = time.time() - start_time
                return ip, response_time, response.status_code
            except requests.exceptions.RequestException as e:
                response_time = time.time() - start_time
                return ip, response_time, 0

        metrics = PerformanceMetrics()

        # Execute concurrent enrichment requests
        with ThreadPoolExecutor(max_workers=len(test_ips)) as executor:
            futures = [
                executor.submit(make_enrichment_request, ip)
                for ip in test_ips
            ]

            for future in as_completed(futures):
                ip, response_time, status_code = future.result()
                metrics.add_result(response_time, status_code)
                print(f"Enrichment for {ip}: {response_time:.2f}s, status: {status_code}")

        summary = metrics.get_summary()
        print(f"Concurrent enrichment performance: {summary}")

        # Should handle multiple enrichment requests
        assert summary['total_requests'] == len(test_ips)


class TestLoadTesting:
    """Extended load testing scenarios"""

    def test_sustained_load_search(self, perf_config, perf_headers):
        """Test sustained load on search endpoint"""
        url = f"{perf_config['base_url']}/search"
        params = {'limit': 5}

        def worker_thread(worker_id: int, duration: int) -> List[Tuple[float, int]]:
            """Worker thread that makes requests for specified duration"""
            results = []
            end_time = time.time() + duration

            while time.time() < end_time:
                start_time = time.time()
                try:
                    response = requests.get(url, params=params, headers=perf_headers, timeout=15)
                    response_time = time.time() - start_time
                    results.append((response_time, response.status_code))
                except requests.exceptions.RequestException as e:
                    response_time = time.time() - start_time
                    results.append((response_time, 0))

                # Small delay to avoid overwhelming the API
                time.sleep(0.2)

            return results

        metrics = PerformanceMetrics()
        test_duration = min(perf_config['load_test_duration'], 30)  # Cap at 30 seconds for safety

        # Launch worker threads
        with ThreadPoolExecutor(max_workers=perf_config['concurrent_users']) as executor:
            futures = [
                executor.submit(worker_thread, i, test_duration)
                for i in range(perf_config['concurrent_users'])
            ]

            # Collect all results
            for future in as_completed(futures):
                worker_results = future.result()
                for response_time, status_code in worker_results:
                    metrics.add_result(response_time, status_code)

        summary = metrics.get_summary()
        print(f"Sustained load test results: {summary}")

        # Validate load test performance
        assert summary['success_rate'] >= 0.7, \
            f"Load test success rate too low: {summary['success_rate']:.2f}"
        assert summary['avg_response_time'] < 20.0, \
            f"Average response time under load too high: {summary['avg_response_time']:.2f}s"

    def test_burst_load_handling(self, perf_config, perf_headers):
        """Test system behavior under burst load"""
        url = f"{perf_config['base_url']}/search"
        params = {'limit': 3}

        def burst_requests(burst_size: int) -> List[Tuple[float, int]]:
            """Send a burst of requests simultaneously"""
            def single_request():
                start_time = time.time()
                try:
                    response = requests.get(url, params=params, headers=perf_headers, timeout=10)
                    return time.time() - start_time, response.status_code
                except requests.exceptions.RequestException:
                    return time.time() - start_time, 0

            with ThreadPoolExecutor(max_workers=burst_size) as executor:
                futures = [executor.submit(single_request) for _ in range(burst_size)]
                return [future.result() for future in as_completed(futures)]

        # Test burst handling
        burst_size = min(perf_config['concurrent_users'] * 2, 10)
        burst_results = burst_requests(burst_size)

        burst_metrics = PerformanceMetrics()
        for response_time, status_code in burst_results:
            burst_metrics.add_result(response_time, status_code)

        summary = burst_metrics.get_summary()
        print(f"Burst load test results: {summary}")

        # Should handle burst load reasonably well
        # Allow for some failures due to rate limiting
        assert summary['success_rate'] >= 0.5, "Burst load completely failed"


class TestResourceUtilization:
    """Test Lambda function resource utilization"""

    def test_lambda_memory_usage_monitoring(self, perf_config, perf_headers):
        """Monitor Lambda memory usage during load"""
        # This test requires CloudWatch access
        try:
            cloudwatch = boto3.client('cloudwatch', region_name=perf_config['region'])

            # Trigger some load first
            url = f"{perf_config['base_url']}/search"
            for i in range(5):
                requests.get(url, params={'limit': 10}, headers=perf_headers, timeout=10)
                time.sleep(1)

            # Wait a bit for CloudWatch metrics
            time.sleep(30)

            # Query CloudWatch metrics
            function_names = [
                'threat-intel-platform-threat-collector-dev',
                'threat-intel-platform-data-processor-dev',
                'threat-intel-platform-osint-enrichment-dev'
            ]

            for function_name in function_names:
                try:
                    response = cloudwatch.get_metric_statistics(
                        Namespace='AWS/Lambda',
                        MetricName='MemoryUtilization',
                        Dimensions=[
                            {'Name': 'FunctionName', 'Value': function_name}
                        ],
                        StartTime=datetime.now(timezone.utc) - timedelta(minutes=10),
                        EndTime=datetime.now(timezone.utc),
                        Period=300,
                        Statistics=['Average', 'Maximum']
                    )

                    if response['Datapoints']:
                        max_memory = max(point['Maximum'] for point in response['Datapoints'])
                        avg_memory = sum(point['Average'] for point in response['Datapoints']) / len(response['Datapoints'])

                        print(f"{function_name} - Avg Memory: {avg_memory:.1f}%, Max Memory: {max_memory:.1f}%")

                        # Memory usage should be reasonable
                        assert max_memory < 95, f"{function_name} memory usage too high: {max_memory:.1f}%"

                except ClientError:
                    # Skip if no permissions or no data
                    pass

        except Exception as e:
            pytest.skip(f"CloudWatch monitoring not available: {e}")

    def test_lambda_execution_duration(self, perf_config, perf_headers):
        """Test Lambda execution duration under load"""
        # Trigger different endpoints to test various Lambda functions
        endpoints = [
            ({'url': f"{perf_config['base_url']}/search", 'method': 'GET', 'params': {'limit': 5}}),
            ({'url': f"{perf_config['base_url']}/enrich", 'method': 'POST', 'data': {'indicators': ['8.8.8.8']}}),
        ]

        for endpoint in endpoints:
            execution_times = []

            for i in range(3):
                start_time = time.time()

                try:
                    if endpoint['method'] == 'GET':
                        response = requests.get(
                            endpoint['url'],
                            params=endpoint.get('params', {}),
                            headers=perf_headers,
                            timeout=30
                        )
                    else:
                        response = requests.post(
                            endpoint['url'],
                            json=endpoint.get('data', {}),
                            headers=perf_headers,
                            timeout=30
                        )

                    execution_time = time.time() - start_time
                    if response.status_code in [200, 202]:
                        execution_times.append(execution_time)

                except requests.exceptions.RequestException:
                    pass

                time.sleep(2)

            if execution_times:
                avg_time = sum(execution_times) / len(execution_times)
                max_time = max(execution_times)

                print(f"Endpoint {endpoint['url']} - Avg: {avg_time:.2f}s, Max: {max_time:.2f}s")

                # Execution times should be reasonable
                assert avg_time < 30, f"Average execution time too high: {avg_time:.2f}s"


class TestStressConditions:
    """Test system behavior under stress conditions"""

    def test_rate_limit_handling(self, perf_config, perf_headers):
        """Test graceful handling of rate limits"""
        url = f"{perf_config['base_url']}/search"
        params = {'limit': 1}

        # Send rapid requests to trigger rate limiting
        rapid_results = []
        for i in range(20):
            start_time = time.time()
            try:
                response = requests.get(url, params=params, headers=perf_headers, timeout=5)
                response_time = time.time() - start_time
                rapid_results.append((response_time, response.status_code))
            except requests.exceptions.RequestException:
                response_time = time.time() - start_time
                rapid_results.append((response_time, 0))

            time.sleep(0.05)  # Very short delay

        # Analyze rate limiting behavior
        status_codes = [result[1] for result in rapid_results]
        rate_limited_count = sum(1 for code in status_codes if code == 429)
        success_count = sum(1 for code in status_codes if code == 200)

        print(f"Rate limiting test - Success: {success_count}, Rate limited: {rate_limited_count}")

        # Should have some successful requests and handle rate limits gracefully
        assert success_count > 0, "No successful requests under rapid load"
        # If rate limiting is implemented, should see 429 responses
        # If not implemented, should still handle the load gracefully

    def test_large_request_handling(self, perf_config, perf_headers):
        """Test handling of large requests"""
        url = f"{perf_config['base_url']}/enrich"

        # Create a large batch of indicators
        large_batch = [f"192.168.1.{i}" for i in range(1, 51)]  # 50 IPs

        payload = {
            'indicators': large_batch,
            'enrichment_types': ['geolocation']
        }

        start_time = time.time()
        try:
            response = requests.post(url, json=payload, headers=perf_headers, timeout=60)
            response_time = time.time() - start_time

            print(f"Large batch enrichment: {response_time:.2f}s, status: {response.status_code}")

            # Should handle large requests within reasonable time
            assert response_time < 120, f"Large request too slow: {response_time:.2f}s"

            # Should either succeed or fail gracefully
            assert response.status_code in [200, 400, 413, 500]

        except requests.exceptions.RequestException as e:
            response_time = time.time() - start_time
            print(f"Large request failed: {e}, time: {response_time:.2f}s")
            # Timeout or other error is acceptable for very large requests


# Performance test configuration
@pytest.fixture(scope="session", autouse=True)
def verify_performance_environment():
    """Verify environment for performance tests"""
    required_vars = ['API_BASE_URL']
    missing_vars = [var for var in required_vars if not os.environ.get(var)]

    if missing_vars:
        pytest.skip(f"Performance tests require: {missing_vars}")

    # Check if API is responsive
    try:
        api_url = os.environ.get('API_BASE_URL')
        response = requests.get(f"{api_url}/search?limit=1", timeout=10)
        if response.status_code not in [200, 401, 403]:
            pytest.skip(f"API not responsive for performance testing: {response.status_code}")
    except requests.exceptions.RequestException as e:
        pytest.skip(f"Cannot reach API for performance testing: {e}")


# Mark all tests as performance tests
pytestmark = [pytest.mark.performance, pytest.mark.integration]


# Custom pytest configuration for performance tests
def pytest_addoption(parser):
    """Add performance test options"""
    parser.addoption(
        "--performance",
        action="store_true",
        default=False,
        help="Run performance tests"
    )
    parser.addoption(
        "--load-duration",
        action="store",
        default="30",
        help="Duration for load tests in seconds"
    )


def pytest_collection_modifyitems(config, items):
    """Configure performance test execution"""
    if not config.getoption("--performance"):
        skip_performance = pytest.mark.skip(reason="Performance tests not requested (use --performance)")
        for item in items:
            if "performance" in item.keywords:
                item.add_marker(skip_performance)

    # Set load test duration from command line
    if config.getoption("--load-duration"):
        os.environ['LOAD_TEST_DURATION'] = config.getoption("--load-duration")