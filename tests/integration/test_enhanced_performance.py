"""
Enhanced performance testing suite for threat intelligence platform
Comprehensive performance, scalability, and resource utilization testing
"""

import pytest
import json
import time
import os
import statistics
import threading
import psutil
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Tuple, Optional
import requests
import boto3
from botocore.exceptions import ClientError
import numpy as np


# Module-level fixtures
@pytest.fixture(scope="module")
def perf_config():
    """Enhanced performance test configuration"""
    return {
        'base_url': os.environ.get('API_BASE_URL', 'https://u88kzux168.execute-api.us-east-1.amazonaws.com/dev'),
        'api_key': os.environ.get('TEST_API_KEY'),
        'region': os.environ.get('AWS_REGION', 'us-east-1'),
        'concurrent_users': int(os.environ.get('CONCURRENT_USERS', '5')),
        'load_test_duration': int(os.environ.get('LOAD_TEST_DURATION', '60')),
        'max_response_time': float(os.environ.get('MAX_RESPONSE_TIME', '10.0')),
        'min_success_rate': float(os.environ.get('MIN_SUCCESS_RATE', '0.95')),
        'ramp_up_time': int(os.environ.get('RAMP_UP_TIME', '10')),
        'cool_down_time': int(os.environ.get('COOL_DOWN_TIME', '5'))
    }


@pytest.fixture
def perf_headers(perf_config):
    """Headers for performance requests"""
    headers = {
        'Content-Type': 'application/json',
        'User-Agent': 'ThreatIntel-Performance-Test/1.0'
    }
    if perf_config['api_key']:
        headers['x-api-key'] = perf_config['api_key']
    return headers


class EnhancedPerformanceMetrics:
    """Enhanced performance metrics collection and analysis"""

    def __init__(self):
        self.response_times: List[float] = []
        self.status_codes: List[int] = []
        self.error_messages: List[str] = []
        self.timestamps: List[float] = []
        self.request_sizes: List[int] = []
        self.response_sizes: List[int] = []
        self.cpu_usage: List[float] = []
        self.memory_usage: List[float] = []
        self.network_latency: List[float] = []

    def add_result(self, response_time: float, status_code: int,
                   request_size: int = 0, response_size: int = 0,
                   cpu_usage: float = 0, memory_usage: float = 0,
                   network_latency: float = 0, error_msg: str = None):
        """Add comprehensive test result"""
        self.response_times.append(response_time)
        self.status_codes.append(status_code)
        self.timestamps.append(time.time())
        self.request_sizes.append(request_size)
        self.response_sizes.append(response_size)
        self.cpu_usage.append(cpu_usage)
        self.memory_usage.append(memory_usage)
        self.network_latency.append(network_latency)

        if error_msg:
            self.error_messages.append(error_msg)

    def get_comprehensive_summary(self) -> Dict:
        """Get comprehensive performance statistics"""
        if not self.response_times:
            return {'error': 'No data collected'}

        success_codes = [200, 201, 202, 204]
        successful_requests = sum(1 for code in self.status_codes if code in success_codes)
        total_requests = len(self.status_codes)

        return {
            # Basic metrics
            'total_requests': total_requests,
            'successful_requests': successful_requests,
            'success_rate': successful_requests / total_requests if total_requests > 0 else 0,
            'error_count': len(self.error_messages),

            # Response time metrics
            'response_time_stats': self._calculate_stats(self.response_times),
            'response_time_percentiles': self._calculate_percentiles(self.response_times),

            # Throughput metrics
            'requests_per_second': self._calculate_throughput(),
            'peak_throughput': self._calculate_peak_throughput(),

            # Size metrics
            'avg_request_size': statistics.mean(self.request_sizes) if self.request_sizes else 0,
            'avg_response_size': statistics.mean(self.response_sizes) if self.response_sizes else 0,
            'total_data_transferred': sum(self.request_sizes) + sum(self.response_sizes),

            # Resource utilization
            'cpu_usage_stats': self._calculate_stats(self.cpu_usage),
            'memory_usage_stats': self._calculate_stats(self.memory_usage),
            'network_latency_stats': self._calculate_stats(self.network_latency),

            # Status code distribution
            'status_code_distribution': self._count_status_codes(),

            # Performance quality assessment
            'performance_grade': self._calculate_performance_grade()
        }

    def _calculate_stats(self, data: List[float]) -> Dict:
        """Calculate comprehensive statistics for a dataset"""
        if not data:
            return {}

        return {
            'min': min(data),
            'max': max(data),
            'mean': statistics.mean(data),
            'median': statistics.median(data),
            'std_dev': statistics.stdev(data) if len(data) > 1 else 0,
            'variance': statistics.variance(data) if len(data) > 1 else 0
        }

    def _calculate_percentiles(self, data: List[float]) -> Dict:
        """Calculate response time percentiles"""
        if not data:
            return {}

        sorted_data = sorted(data)
        return {
            'p50': np.percentile(sorted_data, 50),
            'p75': np.percentile(sorted_data, 75),
            'p90': np.percentile(sorted_data, 90),
            'p95': np.percentile(sorted_data, 95),
            'p99': np.percentile(sorted_data, 99),
            'p99.9': np.percentile(sorted_data, 99.9)
        }

    def _calculate_throughput(self) -> float:
        """Calculate average requests per second"""
        if len(self.timestamps) < 2:
            return 0

        duration = max(self.timestamps) - min(self.timestamps)
        return len(self.timestamps) / duration if duration > 0 else 0

    def _calculate_peak_throughput(self) -> float:
        """Calculate peak requests per second in any 1-second window"""
        if len(self.timestamps) < 2:
            return 0

        # Find the maximum number of requests in any 1-second window
        max_requests = 0
        for i, timestamp in enumerate(self.timestamps):
            count = sum(1 for t in self.timestamps if timestamp <= t <= timestamp + 1)
            max_requests = max(max_requests, count)

        return max_requests

    def _count_status_codes(self) -> Dict[int, int]:
        """Count occurrences of each status code"""
        counts = {}
        for code in self.status_codes:
            counts[code] = counts.get(code, 0) + 1
        return counts

    def _calculate_performance_grade(self) -> str:
        """Calculate overall performance grade based on multiple metrics"""
        if not self.response_times:
            return 'N/A'

        success_rate = sum(1 for code in self.status_codes if code in [200, 201, 202, 204]) / len(self.status_codes)
        avg_response_time = statistics.mean(self.response_times)
        p95_response_time = np.percentile(self.response_times, 95)

        score = 100

        # Deduct points for poor success rate
        if success_rate < 0.99:
            score -= (1 - success_rate) * 50

        # Deduct points for slow average response time
        if avg_response_time > 1.0:
            score -= min((avg_response_time - 1.0) * 20, 30)

        # Deduct points for slow P95 response time
        if p95_response_time > 2.0:
            score -= min((p95_response_time - 2.0) * 15, 20)

        if score >= 90:
            return 'A'
        elif score >= 80:
            return 'B'
        elif score >= 70:
            return 'C'
        elif score >= 60:
            return 'D'
        else:
            return 'F'


class TestBaselinePerformance:
    """Establish baseline performance metrics for all endpoints"""

    def test_search_endpoint_baseline(self, perf_config, perf_headers):
        """Establish baseline performance for search endpoint"""
        url = f"{perf_config['base_url']}/search"

        test_scenarios = [
            {'params': {'limit': 1}, 'description': 'minimal_search'},
            {'params': {'limit': 10}, 'description': 'standard_search'},
            {'params': {'limit': 50}, 'description': 'large_search'},
            {'params': {'q': '*', 'limit': 10}, 'description': 'wildcard_search'},
            {'params': {'q': '192.168.1.1', 'limit': 10}, 'description': 'ip_search'},
        ]

        baseline_results = {}

        for scenario in test_scenarios:
            print(f"Testing {scenario['description']} baseline performance")
            metrics = EnhancedPerformanceMetrics()

            for i in range(15):  # 15 samples for baseline
                start_time = time.time()
                cpu_before = psutil.cpu_percent()
                memory_before = psutil.virtual_memory().percent

                try:
                    response = requests.get(
                        url,
                        params=scenario['params'],
                        headers=perf_headers,
                        timeout=30
                    )
                    response_time = time.time() - start_time

                    cpu_after = psutil.cpu_percent()
                    memory_after = psutil.virtual_memory().percent

                    metrics.add_result(
                        response_time=response_time,
                        status_code=response.status_code,
                        request_size=len(json.dumps(scenario['params']).encode()),
                        response_size=len(response.content),
                        cpu_usage=(cpu_after - cpu_before),
                        memory_usage=(memory_after - memory_before)
                    )

                except requests.RequestException as e:
                    response_time = time.time() - start_time
                    metrics.add_result(response_time, 0, error_msg=str(e))

                time.sleep(0.2)  # Small delay between requests

            summary = metrics.get_comprehensive_summary()
            baseline_results[scenario['description']] = summary

            print(f"{scenario['description']} baseline: "
                  f"Avg: {summary['response_time_stats']['mean']:.3f}s, "
                  f"P95: {summary['response_time_percentiles']['p95']:.3f}s, "
                  f"Success: {summary['success_rate']:.2%}, "
                  f"Grade: {summary['performance_grade']}")

            # Baseline assertions
            assert summary['success_rate'] >= 0.8, f"Low success rate for {scenario['description']}: {summary['success_rate']:.2%}"

        return baseline_results

    def test_collect_endpoint_baseline(self, perf_config, perf_headers):
        """Establish baseline performance for collect endpoint"""
        url = f"{perf_config['base_url']}/collect"

        test_scenarios = [
            {
                'payload': {'sources': ['otx'], 'limit': 3},
                'description': 'small_otx_collection'
            },
            {
                'payload': {'sources': ['abuse_ch'], 'limit': 3},
                'description': 'small_abuse_ch_collection'
            },
            {
                'payload': {'sources': ['otx'], 'limit': 10},
                'description': 'medium_otx_collection'
            }
        ]

        baseline_results = {}

        for scenario in test_scenarios:
            print(f"Testing {scenario['description']} baseline performance")
            metrics = EnhancedPerformanceMetrics()

            for i in range(5):  # Fewer samples for collection (can be slow)
                start_time = time.time()

                try:
                    response = requests.post(
                        url,
                        json=scenario['payload'],
                        headers=perf_headers,
                        timeout=120  # Longer timeout for collection
                    )
                    response_time = time.time() - start_time

                    metrics.add_result(
                        response_time=response_time,
                        status_code=response.status_code,
                        request_size=len(json.dumps(scenario['payload']).encode()),
                        response_size=len(response.content)
                    )

                except requests.RequestException as e:
                    response_time = time.time() - start_time
                    metrics.add_result(response_time, 0, error_msg=str(e))

                time.sleep(2)  # Longer delay between collection requests

            summary = metrics.get_comprehensive_summary()
            baseline_results[scenario['description']] = summary

            print(f"{scenario['description']} baseline: "
                  f"Avg: {summary['response_time_stats']['mean']:.3f}s, "
                  f"Success: {summary['success_rate']:.2%}")

        return baseline_results

    def test_enrich_endpoint_baseline(self, perf_config, perf_headers):
        """Establish baseline performance for enrichment endpoint"""
        url = f"{perf_config['base_url']}/enrich"

        test_scenarios = [
            {
                'payload': {
                    'indicators': ['8.8.8.8'],
                    'enrichment_types': ['geolocation']
                },
                'description': 'single_ip_geolocation'
            },
            {
                'payload': {
                    'indicators': ['google.com'],
                    'enrichment_types': ['dns']
                },
                'description': 'single_domain_dns'
            },
            {
                'payload': {
                    'indicators': ['8.8.8.8', '1.1.1.1'],
                    'enrichment_types': ['geolocation', 'dns']
                },
                'description': 'multi_indicator_enrichment'
            }
        ]

        baseline_results = {}

        for scenario in test_scenarios:
            print(f"Testing {scenario['description']} baseline performance")
            metrics = EnhancedPerformanceMetrics()

            for i in range(10):
                start_time = time.time()

                try:
                    response = requests.post(
                        url,
                        json=scenario['payload'],
                        headers=perf_headers,
                        timeout=60
                    )
                    response_time = time.time() - start_time

                    metrics.add_result(
                        response_time=response_time,
                        status_code=response.status_code,
                        request_size=len(json.dumps(scenario['payload']).encode()),
                        response_size=len(response.content)
                    )

                except requests.RequestException as e:
                    response_time = time.time() - start_time
                    metrics.add_result(response_time, 0, error_msg=str(e))

                time.sleep(1)

            summary = metrics.get_comprehensive_summary()
            baseline_results[scenario['description']] = summary

            print(f"{scenario['description']} baseline: "
                  f"Avg: {summary['response_time_stats']['mean']:.3f}s, "
                  f"Success: {summary['success_rate']:.2%}")

        return baseline_results


class TestScalabilityAndLoad:
    """Test system scalability under increasing load"""

    def test_concurrent_search_requests(self, perf_config, perf_headers):
        """Test search endpoint under concurrent load"""
        url = f"{perf_config['base_url']}/search"
        params = {'limit': 10}

        concurrency_levels = [1, 2, 5, 10]

        for concurrency in concurrency_levels:
            print(f"Testing search with {concurrency} concurrent users")
            metrics = EnhancedPerformanceMetrics()

            def make_request():
                start_time = time.time()
                try:
                    response = requests.get(url, params=params, headers=perf_headers, timeout=30)
                    response_time = time.time() - start_time
                    return response_time, response.status_code, len(response.content)
                except requests.RequestException as e:
                    response_time = time.time() - start_time
                    return response_time, 0, 0

            # Execute concurrent requests
            with ThreadPoolExecutor(max_workers=concurrency) as executor:
                futures = [executor.submit(make_request) for _ in range(concurrency * 5)]

                for future in as_completed(futures):
                    response_time, status_code, response_size = future.result()
                    metrics.add_result(response_time, status_code, response_size=response_size)

            summary = metrics.get_comprehensive_summary()

            print(f"Concurrency {concurrency}: "
                  f"Avg: {summary['response_time_stats']['mean']:.3f}s, "
                  f"P95: {summary['response_time_percentiles']['p95']:.3f}s, "
                  f"Success: {summary['success_rate']:.2%}, "
                  f"RPS: {summary['requests_per_second']:.1f}")

            # Performance should degrade gracefully with increased concurrency
            assert summary['success_rate'] >= 0.7, f"Success rate too low at concurrency {concurrency}: {summary['success_rate']:.2%}"

    def test_sustained_load(self, perf_config, perf_headers):
        """Test system under sustained load"""
        url = f"{perf_config['base_url']}/search"
        params = {'limit': 5}

        duration = min(perf_config['load_test_duration'], 30)  # Cap at 30 seconds for testing
        concurrency = min(perf_config['concurrent_users'], 3)  # Cap at 3 users for testing

        print(f"Running sustained load test: {concurrency} users for {duration} seconds")

        metrics = EnhancedPerformanceMetrics()
        stop_time = time.time() + duration

        def sustained_requests():
            while time.time() < stop_time:
                start_time = time.time()
                try:
                    response = requests.get(url, params=params, headers=perf_headers, timeout=15)
                    response_time = time.time() - start_time
                    metrics.add_result(response_time, response.status_code, response_size=len(response.content))
                except requests.RequestException as e:
                    response_time = time.time() - start_time
                    metrics.add_result(response_time, 0, error_msg=str(e))

                time.sleep(1)  # 1 request per second per user

        # Run sustained load
        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = [executor.submit(sustained_requests) for _ in range(concurrency)]

            for future in as_completed(futures):
                future.result()

        summary = metrics.get_comprehensive_summary()

        print(f"Sustained load results: "
              f"Total requests: {summary['total_requests']}, "
              f"Success rate: {summary['success_rate']:.2%}, "
              f"Avg response time: {summary['response_time_stats']['mean']:.3f}s, "
              f"P95: {summary['response_time_percentiles']['p95']:.3f}s")

        # System should maintain performance under sustained load
        assert summary['success_rate'] >= perf_config['min_success_rate'], f"Success rate too low: {summary['success_rate']:.2%}"
        assert summary['response_time_stats']['mean'] < perf_config['max_response_time'], f"Average response time too high: {summary['response_time_stats']['mean']:.3f}s"

    def test_burst_traffic_handling(self, perf_config, perf_headers):
        """Test system handling of burst traffic"""
        url = f"{perf_config['base_url']}/search"
        params = {'limit': 1}

        print("Testing burst traffic handling")
        metrics = EnhancedPerformanceMetrics()

        # Simulate burst: 20 requests in rapid succession
        def make_burst_request():
            start_time = time.time()
            try:
                response = requests.get(url, params=params, headers=perf_headers, timeout=20)
                response_time = time.time() - start_time
                return response_time, response.status_code, len(response.content)
            except requests.RequestException as e:
                response_time = time.time() - start_time
                return response_time, 0, 0

        # Execute burst
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(make_burst_request) for _ in range(20)]

            for future in as_completed(futures):
                response_time, status_code, response_size = future.result()
                metrics.add_result(response_time, status_code, response_size=response_size)

        summary = metrics.get_comprehensive_summary()

        print(f"Burst traffic results: "
              f"Success rate: {summary['success_rate']:.2%}, "
              f"Max response time: {summary['response_time_stats']['max']:.3f}s, "
              f"P99: {summary['response_time_percentiles']['p99']:.3f}s")

        # System should handle burst traffic reasonably well
        assert summary['success_rate'] >= 0.6, f"Burst traffic success rate too low: {summary['success_rate']:.2%}"


class TestResourceUtilization:
    """Test resource utilization and efficiency"""

    def test_memory_usage_patterns(self, perf_config, perf_headers):
        """Test memory usage patterns during operations"""
        url = f"{perf_config['base_url']}/search"

        # Monitor memory usage during test
        memory_usage = []

        def monitor_memory():
            for _ in range(30):  # Monitor for 30 seconds
                memory_usage.append(psutil.virtual_memory().percent)
                time.sleep(1)

        # Start memory monitoring in background
        import threading
        monitor_thread = threading.Thread(target=monitor_memory)
        monitor_thread.start()

        # Perform requests while monitoring
        for i in range(20):
            try:
                requests.get(url, params={'limit': 10}, headers=perf_headers, timeout=10)
            except requests.RequestException:
                pass
            time.sleep(1)

        monitor_thread.join()

        if memory_usage:
            avg_memory = statistics.mean(memory_usage)
            max_memory = max(memory_usage)

            print(f"Memory usage - Average: {avg_memory:.1f}%, Peak: {max_memory:.1f}%")

            # Memory usage should be reasonable
            assert max_memory < 90, f"Memory usage too high: {max_memory:.1f}%"

    def test_response_size_efficiency(self, perf_config, perf_headers):
        """Test response size efficiency for different query types"""
        url = f"{perf_config['base_url']}/search"

        test_cases = [
            ({'limit': 1}, 'minimal'),
            ({'limit': 10}, 'standard'),
            ({'limit': 50}, 'large'),
            ({'q': '*', 'limit': 10}, 'wildcard')
        ]

        for params, description in test_cases:
            try:
                response = requests.get(url, params=params, headers=perf_headers, timeout=30)

                if response.status_code in [200, 204]:
                    response_size = len(response.content)

                    # Calculate efficiency (results per byte)
                    if response.status_code == 200:
                        data = response.json()
                        result_count = len(data.get('results', []))
                        efficiency = result_count / response_size if response_size > 0 else 0

                        print(f"{description} query: {response_size} bytes, {result_count} results, "
                              f"efficiency: {efficiency:.6f} results/byte")

                    # Response sizes should be reasonable
                    assert response_size < 1024 * 1024, f"Response size too large for {description}: {response_size} bytes"

            except requests.RequestException as e:
                print(f"Failed to test {description} query: {e}")


if __name__ == "__main__":
    # Run enhanced performance tests
    pytest.main([__file__, "-v", "--tb=short", "-s"])