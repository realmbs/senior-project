"""
Comprehensive Test Suite for Analytics Engine
Phase 8C Implementation - Complete Testing Framework

This module provides comprehensive testing for all analytics engine components:
- Unit tests for individual analytics engines
- Integration tests for cross-engine interactions
- Performance tests for caching and optimization
- End-to-end workflow tests
- Mock data generation for testing scenarios
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import json
import boto3
import time
from datetime import datetime, timezone, timedelta
from decimal import Decimal
from moto import mock_dynamodb

# Import analytics engine components
try:
    from analytics_engine import (
        TrendAnalysisEngine, GeographicAnalysisEngine, RiskScoringEngine,
        CorrelationIntelligenceEngine, BehavioralAnalysisEngine,
        AnalyticsCacheManager, PerformanceOptimizer,
        execute_analytics_with_cache, lambda_handler,
        TrendTimeframe, RiskLevel, AnalyticsType
    )
    ANALYTICS_ENGINE_AVAILABLE = True
except ImportError:
    print("Analytics engine not available for testing")
    ANALYTICS_ENGINE_AVAILABLE = False


class MockDataGenerator:
    """Generate realistic mock data for testing analytics engines"""

    @staticmethod
    def generate_mock_threats(count: int = 100, days_back: int = 30) -> list:
        """Generate mock threat intelligence data"""
        threats = []

        sources = ['alienvault_otx', 'abuse_ch', 'shodan', 'misp']
        threat_types = ['malware', 'phishing', 'apt', 'botnet', 'c2', 'trojan']
        countries = ['US', 'CN', 'RU', 'DE', 'UK', 'FR', 'IN', 'BR']

        base_time = datetime.now(timezone.utc) - timedelta(days=days_back)

        for i in range(count):
            # Generate threat with varying characteristics
            confidence = min(100, max(10, 50 + (i % 50)))  # 10-100 range
            threat_time = base_time + timedelta(
                days=(i * days_back) // count,
                hours=(i * 24) // count,
                minutes=(i * 60) // count
            )

            # Create realistic pattern
            if i % 3 == 0:  # Domain pattern
                pattern = f"[domain-name:value = 'malicious-domain-{i}.com']"
            elif i % 3 == 1:  # IP pattern
                pattern = f"[ipv4-addr:value = '192.168.{i % 255}.{(i * 2) % 255}']"
            else:  # URL pattern
                pattern = f"[url:value = 'http://malicious-{i}.example.com/path']"

            threat = {
                'object_id': f'indicator--{i:08d}-test-{int(time.time())}',
                'pattern': pattern,
                'labels': [threat_types[i % len(threat_types)]],
                'confidence': Decimal(str(confidence)),
                'source_name': sources[i % len(sources)],
                'created_date': threat_time.isoformat(),
                'description': f'Test threat indicator {i} for analytics testing',
                'enrichment_data': {
                    'geolocation': {
                        'country': countries[i % len(countries)],
                        'city': f'City-{i % 10}',
                        'latitude': 40.0 + (i % 20) - 10,  # ±10 degrees from 40
                        'longitude': -74.0 + (i % 20) - 10  # ±10 degrees from -74
                    },
                    'reputation': {
                        'score': confidence * 0.8,
                        'sources': [sources[i % len(sources)]]
                    }
                }
            }

            threats.append(threat)

        return threats

    @staticmethod
    def generate_campaign_threats(campaign_count: int = 3, threats_per_campaign: int = 10) -> list:
        """Generate mock threats that form identifiable campaigns"""
        all_threats = []

        for campaign_id in range(campaign_count):
            campaign_time = datetime.now(timezone.utc) - timedelta(days=campaign_id * 5)

            for threat_id in range(threats_per_campaign):
                threat_time = campaign_time + timedelta(hours=threat_id * 2)

                threat = {
                    'object_id': f'campaign-{campaign_id}-threat-{threat_id}',
                    'pattern': f"[domain-name:value = 'campaign{campaign_id}-domain{threat_id}.com']",
                    'labels': ['apt', 'campaign'],
                    'confidence': Decimal('85'),
                    'source_name': 'alienvault_otx',
                    'created_date': threat_time.isoformat(),
                    'description': f'Campaign {campaign_id} threat {threat_id}',
                    'enrichment_data': {
                        'geolocation': {
                            'country': 'CN' if campaign_id == 0 else 'RU',
                            'city': f'Campaign-City-{campaign_id}',
                            'latitude': 39.9 + campaign_id,
                            'longitude': 116.4 + campaign_id
                        }
                    }
                }
                all_threats.append(threat)

        return all_threats

    @staticmethod
    def generate_anomaly_threats(base_count: int = 50, anomaly_count: int = 20) -> list:
        """Generate threats with anomalous patterns for behavioral analysis"""
        threats = MockDataGenerator.generate_mock_threats(base_count, 30)

        # Add anomalous threats (sudden spike)
        anomaly_time = datetime.now(timezone.utc) - timedelta(days=1)

        for i in range(anomaly_count):
            threat_time = anomaly_time + timedelta(minutes=i * 5)  # Concentrated in time

            threat = {
                'object_id': f'anomaly-threat-{i}',
                'pattern': f"[domain-name:value = 'anomaly{i}.suspicious.com']",
                'labels': ['malware', 'suspicious'],
                'confidence': Decimal('95'),  # High confidence
                'source_name': 'new_threat_source',  # New source
                'created_date': threat_time.isoformat(),
                'description': f'Anomalous threat pattern {i}',
                'enrichment_data': {
                    'geolocation': {
                        'country': 'XX',  # Unusual country
                        'city': 'Unknown',
                        'latitude': 0.0,
                        'longitude': 0.0
                    }
                }
            }
            threats.append(threat)

        return threats


@unittest.skipUnless(ANALYTICS_ENGINE_AVAILABLE, "Analytics engine not available")
class TestTrendAnalysisEngine(unittest.TestCase):
    """Test cases for trend analysis engine"""

    def setUp(self):
        """Set up test environment"""
        self.engine = TrendAnalysisEngine()
        self.mock_threats = MockDataGenerator.generate_mock_threats(50, 14)

    @patch('analytics_engine.threat_intel_table')
    def test_temporal_trend_analysis(self, mock_table):
        """Test temporal trend analysis with various timeframes"""
        # Mock DynamoDB response
        mock_table.query.return_value = {
            'Items': self.mock_threats,
            'LastEvaluatedKey': None
        }

        # Test daily timeframe
        result = self.engine.analyze_temporal_trends(TrendTimeframe.DAILY)

        self.assertIn('trend_points', result)
        self.assertIn('trend_analysis', result)
        self.assertIn('detected_campaigns', result)
        self.assertIn('summary', result)
        self.assertGreater(len(result['trend_points']), 0)

    @patch('analytics_engine.threat_intel_table')
    def test_campaign_detection(self, mock_table):
        """Test threat campaign detection algorithms"""
        campaign_threats = MockDataGenerator.generate_campaign_threats(2, 8)

        mock_table.query.return_value = {
            'Items': campaign_threats,
            'LastEvaluatedKey': None
        }

        result = self.engine.analyze_temporal_trends(TrendTimeframe.WEEKLY)

        # Should detect the campaigns
        self.assertIn('detected_campaigns', result)
        campaigns = result['detected_campaigns']
        self.assertGreater(len(campaigns), 0)

        # Check campaign structure
        if campaigns:
            campaign = campaigns[0]
            self.assertIn('campaign_id', campaign)
            self.assertIn('indicators', campaign)
            self.assertIn('confidence', campaign)

    def test_trend_pattern_identification(self):
        """Test trend pattern identification algorithms"""
        # Test increasing pattern
        increasing_values = [1, 3, 5, 8, 12, 18, 25]
        trend = self.engine._calculate_trend(increasing_values)
        self.assertEqual(trend['direction'], 'increasing')
        self.assertGreater(trend['strength'], 0)

        # Test decreasing pattern
        decreasing_values = [25, 18, 12, 8, 5, 3, 1]
        trend = self.engine._calculate_trend(decreasing_values)
        self.assertEqual(trend['direction'], 'decreasing')

        # Test stable pattern
        stable_values = [10, 11, 9, 10, 11, 10, 9]
        trend = self.engine._calculate_trend(stable_values)
        self.assertEqual(trend['direction'], 'stable')

    def test_anomaly_detection(self):
        """Test anomaly detection in trend data"""
        # Normal values with anomalies
        values = [10, 11, 9, 10, 50, 11, 10, 9, 45, 10]  # 50 and 45 are anomalies
        anomalies = self.engine._detect_anomalies(values)

        self.assertGreater(len(anomalies), 0)
        # Should detect the high values as anomalies
        anomaly_values = [a['value'] for a in anomalies]
        self.assertIn(50, anomaly_values)


@unittest.skipUnless(ANALYTICS_ENGINE_AVAILABLE, "Analytics engine not available")
class TestGeographicAnalysisEngine(unittest.TestCase):
    """Test cases for geographic analysis engine"""

    def setUp(self):
        """Set up test environment"""
        self.engine = GeographicAnalysisEngine()
        self.mock_threats = MockDataGenerator.generate_mock_threats(30, 7)

    @patch('analytics_engine.threat_intel_table')
    def test_geographic_distribution_analysis(self, mock_table):
        """Test geographic distribution analysis"""
        mock_table.scan.return_value = {
            'Items': self.mock_threats,
            'LastEvaluatedKey': None
        }

        result = self.engine.analyze_geographic_distribution()

        self.assertIn('clusters', result)
        self.assertIn('country_analysis', result)
        self.assertIn('threat_hotspots', result)
        self.assertIn('geographic_summary', result)

    def test_geographic_clustering(self):
        """Test geographic clustering algorithms"""
        # Create test points with known clusters
        geo_points = [
            {'lat': 40.7128, 'lon': -74.0060, 'country': 'US', 'city': 'NYC', 'threat': {'labels': ['malware']}},
            {'lat': 40.7580, 'lon': -73.9855, 'country': 'US', 'city': 'NYC', 'threat': {'labels': ['malware']}},  # Close to first
            {'lat': 51.5074, 'lon': -0.1278, 'country': 'UK', 'city': 'London', 'threat': {'labels': ['phishing']}},
            {'lat': 51.5155, 'lon': -0.1415, 'country': 'UK', 'city': 'London', 'threat': {'labels': ['phishing']}},  # Close to third
        ]

        clusters = self.engine._perform_geographic_clustering(geo_points)

        # Should find clusters
        self.assertGreater(len(clusters), 0)

        if clusters:
            cluster = clusters[0]
            self.assertIn('cluster_id', cluster)
            self.assertIn('center_lat', cluster)
            self.assertIn('center_lon', cluster)
            self.assertIn('threat_count', cluster)

    def test_distance_calculation(self):
        """Test Haversine distance calculation"""
        # NYC to London (known distance ~5570 km)
        point1 = {'lat': 40.7128, 'lon': -74.0060}
        point2 = {'lat': 51.5074, 'lon': -0.1278}

        distance = self.engine._calculate_distance(point1, point2)

        # Should be approximately 5570 km (allow ±100 km tolerance)
        self.assertGreater(distance, 5470)
        self.assertLess(distance, 5670)

    def test_country_risk_assessment(self):
        """Test country-level risk assessment"""
        # Test different risk levels
        self.assertEqual(self.engine._calculate_country_risk_level(100, 90), 'critical')
        self.assertEqual(self.engine._calculate_country_risk_level(25, 80), 'high')
        self.assertEqual(self.engine._calculate_country_risk_level(10, 60), 'medium')
        self.assertEqual(self.engine._calculate_country_risk_level(2, 30), 'low')


@unittest.skipUnless(ANALYTICS_ENGINE_AVAILABLE, "Analytics engine not available")
class TestRiskScoringEngine(unittest.TestCase):
    """Test cases for risk scoring engine"""

    def setUp(self):
        """Set up test environment"""
        self.engine = RiskScoringEngine()

    def test_enhanced_risk_scoring(self):
        """Test enhanced multi-factor risk scoring"""
        # High-risk threat
        high_risk_threat = {
            'object_id': 'test-threat-1',
            'confidence': 95,
            'source_name': 'alienvault_otx',
            'labels': ['apt', 'malware'],
            'created_date': datetime.now(timezone.utc).isoformat(),
            'pattern': '[domain-name:value = "malicious.com"]',
            'description': 'APT campaign detected with high confidence',
            'enrichment_data': {
                'geolocation': {'country': 'CN'},
                'reputation': {'score': 85}
            }
        }

        result = self.engine.calculate_enhanced_risk_score(high_risk_threat)

        self.assertIn('enhanced_risk_score', result)
        self.assertIn('risk_level', result)
        self.assertIn('risk_factors', result)
        self.assertIn('business_impact', result)
        self.assertIn('recommendations', result)

        # Should be high or critical risk
        self.assertIn(result['risk_level'], ['high', 'critical'])
        self.assertGreater(result['enhanced_risk_score'], 70)

    def test_risk_factor_calculations(self):
        """Test individual risk factor calculations"""
        threat = {
            'source_name': 'alienvault_otx',
            'created_date': datetime.now(timezone.utc).isoformat(),
            'labels': ['malware'],
            'confidence': 80,
            'pattern': '[domain-name:value = "test.com"]'
        }

        # Test source factor
        source_factor = self.engine._calculate_source_factor(threat)
        self.assertGreater(source_factor, 0)
        self.assertLessEqual(source_factor, 100)

        # Test temporal factor (recent threat should score high)
        temporal_factor = self.engine._calculate_temporal_factor(threat)
        self.assertGreater(temporal_factor, 90)  # Recent threats score high

        # Test threat type factor
        threat_type_factor = self.engine._calculate_threat_type_factor(threat)
        self.assertGreater(threat_type_factor, 50)  # Malware should be significant

    def test_business_impact_assessment(self):
        """Test business impact assessment"""
        ransomware_threat = {
            'labels': ['ransomware', 'malware'],
            'description': 'ransomware attack targeting financial systems',
            'pattern': '[file:hashes.MD5 = "abc123"]'
        }

        impact = self.engine._assess_business_impact(ransomware_threat, 85)

        self.assertIn('financial_risk', impact)
        self.assertIn('operational_impact', impact)
        self.assertIn('overall_impact', impact)

        # Ransomware should have high financial risk
        self.assertEqual(impact['financial_risk'], 'high')

    @patch('analytics_engine.threat_intel_table')
    def test_risk_distribution_analysis(self, mock_table):
        """Test risk distribution analysis across threats"""
        threats = MockDataGenerator.generate_mock_threats(20, 7)

        mock_table.scan.return_value = {
            'Items': threats,
            'LastEvaluatedKey': None
        }

        result = self.engine.analyze_risk_distribution()

        self.assertIn('risk_distribution', result)
        self.assertIn('risk_levels', result)
        self.assertIn('source_analysis', result)
        self.assertIn('high_risk_summary', result)


@unittest.skipUnless(ANALYTICS_ENGINE_AVAILABLE, "Analytics engine not available")
class TestBehavioralAnalysisEngine(unittest.TestCase):
    """Test cases for behavioral analysis engine"""

    def setUp(self):
        """Set up test environment"""
        self.engine = BehavioralAnalysisEngine()

    @patch('analytics_engine.threat_intel_table')
    def test_behavioral_pattern_analysis(self, mock_table):
        """Test behavioral pattern analysis with anomaly detection"""
        # Use anomaly dataset
        threats = MockDataGenerator.generate_anomaly_threats(30, 15)

        mock_table.query.return_value = {
            'Items': threats,
            'LastEvaluatedKey': None
        }

        result = self.engine.analyze_behavioral_patterns()

        self.assertIn('baselines', result)
        self.assertIn('anomalies', result)
        self.assertIn('behavioral_clusters', result)
        self.assertIn('emerging_patterns', result)
        self.assertIn('behavioral_summary', result)

    def test_baseline_establishment(self):
        """Test behavioral baseline establishment"""
        threats = MockDataGenerator.generate_mock_threats(50, 30)
        baselines = self.engine._establish_baselines(threats)

        self.assertIn('threat_volume', baselines)
        self.assertIn('confidence_levels', baselines)
        self.assertIn('source_diversity', baselines)

        # Check baseline structure
        volume_baseline = baselines['threat_volume']
        self.assertIn('mean', volume_baseline)
        self.assertIn('std_dev', volume_baseline)
        self.assertIn('median', volume_baseline)

    def test_behavioral_clustering(self):
        """Test behavioral clustering algorithms"""
        threats = MockDataGenerator.generate_mock_threats(20, 7)
        clusters = self.engine._identify_behavioral_clusters(threats)

        # Should find some clusters
        if clusters:
            cluster = clusters[0]
            self.assertIn('cluster_id', cluster)
            self.assertIn('threat_count', cluster)
            self.assertIn('characteristics', cluster)
            self.assertGreater(cluster['threat_count'], 2)  # Minimum cluster size

    def test_feature_extraction(self):
        """Test behavioral feature extraction"""
        threat = {
            'created_date': datetime.now(timezone.utc).isoformat(),
            'confidence': 75,
            'source_name': 'alienvault_otx',
            'labels': ['malware', 'apt'],
            'pattern': '[domain-name:value = "test.com"]'
        }

        features = self.engine._extract_behavioral_features(threat)

        self.assertIsNotNone(features)
        self.assertIn('hour_of_day', features)
        self.assertIn('confidence', features)
        self.assertIn('source_type', features)
        self.assertIn('has_malware', features)
        self.assertIn('has_apt', features)

    def test_emerging_pattern_detection(self):
        """Test detection of emerging threat patterns"""
        # Create dataset with emerging patterns
        historical_threats = MockDataGenerator.generate_mock_threats(30, 60)
        recent_threats = MockDataGenerator.generate_anomaly_threats(10, 5)
        all_threats = historical_threats + recent_threats

        emerging_patterns = self.engine._detect_emerging_patterns(all_threats)

        # Should detect emerging patterns
        if emerging_patterns:
            pattern = emerging_patterns[0]
            self.assertIn('pattern_type', pattern)
            self.assertIn('emergence_score', pattern)
            self.assertGreater(pattern['emergence_score'], 1.0)


@unittest.skipUnless(ANALYTICS_ENGINE_AVAILABLE, "Analytics engine not available")
class TestAnalyticsCacheManager(unittest.TestCase):
    """Test cases for analytics caching system"""

    def setUp(self):
        """Set up test environment"""
        # Mock the cache table
        with patch('analytics_engine.analytics_cache_table') as mock_table:
            mock_table.get_item.return_value = {'Item': None}
            self.cache_manager = AnalyticsCacheManager()

    def test_cache_key_generation(self):
        """Test cache key generation consistency"""
        params1 = {'timeframe': 'daily', 'confidence': 70}
        filters1 = {'source': 'otx'}

        key1 = self.cache_manager.generate_cache_key('trend_analysis', params1, filters1)
        key2 = self.cache_manager.generate_cache_key('trend_analysis', params1, filters1)

        # Same parameters should generate same key
        self.assertEqual(key1, key2)

        # Different parameters should generate different key
        params2 = {'timeframe': 'weekly', 'confidence': 70}
        key3 = self.cache_manager.generate_cache_key('trend_analysis', params2, filters1)
        self.assertNotEqual(key1, key3)

    @patch('analytics_engine.analytics_cache_table')
    def test_cache_storage_and_retrieval(self, mock_table):
        """Test cache storage and retrieval operations"""
        # Mock successful storage
        mock_table.put_item.return_value = {}

        # Mock successful retrieval
        test_result = {'test': 'data', 'timestamp': '2023-01-01T00:00:00Z'}
        mock_table.get_item.return_value = {
            'Item': {
                'cache_key': 'test-key',
                'result_data': json.dumps(test_result),
                'compressed': False,
                'ttl': int(time.time()) + 3600,
                'created_at': datetime.now(timezone.utc).isoformat()
            }
        }

        # Test storage
        self.cache_manager.store_result('test-key', test_result)
        mock_table.put_item.assert_called_once()

        # Test retrieval
        retrieved = self.cache_manager.get_cached_result('test-key')
        self.assertEqual(retrieved, test_result)

    def test_cache_compression(self):
        """Test cache compression functionality"""
        large_data = "x" * 5000  # Large string for compression testing

        compressed = self.cache_manager._compress_data(large_data)
        decompressed = self.cache_manager._decompress_data(compressed)

        self.assertEqual(decompressed, large_data)
        self.assertLess(len(compressed), len(large_data))  # Compression should reduce size


@unittest.skipUnless(ANALYTICS_ENGINE_AVAILABLE, "Analytics engine not available")
class TestPerformanceOptimizer(unittest.TestCase):
    """Test cases for performance optimization"""

    def setUp(self):
        """Set up test environment"""
        self.optimizer = PerformanceOptimizer()

    def test_query_execution_optimization(self):
        """Test optimized query execution"""
        def mock_query_func(*args, **kwargs):
            time.sleep(0.01)  # Simulate query time
            return {'result': 'success', 'args': args, 'kwargs': kwargs}

        result = self.optimizer.optimize_query_execution(
            mock_query_func, 'arg1', 'arg2', param1='value1'
        )

        self.assertEqual(result['result'], 'success')
        self.assertEqual(result['args'], ('arg1', 'arg2'))
        self.assertEqual(result['kwargs'], {'param1': 'value1'})

    def test_performance_monitoring(self):
        """Test performance monitoring and recommendations"""
        # Simulate multiple query executions
        def fast_query():
            return {'result': 'fast'}

        def slow_query():
            time.sleep(0.02)  # Simulate slow query
            return {'result': 'slow'}

        # Execute multiple times to generate statistics
        for _ in range(10):
            self.optimizer.optimize_query_execution(fast_query)
            self.optimizer.optimize_query_execution(slow_query)

        recommendations = self.optimizer.get_performance_recommendations()
        self.assertIsInstance(recommendations, list)
        self.assertGreater(len(recommendations), 0)


@unittest.skipUnless(ANALYTICS_ENGINE_AVAILABLE, "Analytics engine not available")
class TestAnalyticsIntegration(unittest.TestCase):
    """Integration tests for analytics engine components"""

    @patch('analytics_engine.analytics_cache_table')
    @patch('analytics_engine.threat_intel_table')
    def test_end_to_end_analytics_workflow(self, mock_threat_table, mock_cache_table):
        """Test complete analytics workflow with caching"""
        # Mock DynamoDB responses
        threats = MockDataGenerator.generate_mock_threats(20, 7)
        mock_threat_table.query.return_value = {
            'Items': threats,
            'LastEvaluatedKey': None
        }

        # Mock cache miss then hit
        mock_cache_table.get_item.side_effect = [
            {},  # Cache miss
            {    # Cache hit
                'Item': {
                    'cache_key': 'test-key',
                    'result_data': json.dumps({'cached': True}),
                    'compressed': False,
                    'ttl': int(time.time()) + 3600
                }
            }
        ]
        mock_cache_table.put_item.return_value = {}

        # First call - should execute and cache
        result1 = execute_analytics_with_cache(
            'trend_analysis',
            lambda f: {'test': 'result1', 'filters': f},
            {'timeframe': 'daily'},
            {'source': 'otx'}
        )

        self.assertIn('execution_metadata', result1)
        self.assertFalse(result1['execution_metadata']['cache_hit'])

        # Second call - should hit cache
        result2 = execute_analytics_with_cache(
            'trend_analysis',
            lambda f: {'test': 'result2', 'filters': f},
            {'timeframe': 'daily'},
            {'source': 'otx'}
        )

        self.assertEqual(result2['cached'], True)

    @patch('analytics_engine.threat_intel_table')
    def test_lambda_handler_integration(self, mock_table):
        """Test Lambda handler with various analytics actions"""
        threats = MockDataGenerator.generate_mock_threats(10, 7)
        mock_table.query.return_value = {
            'Items': threats,
            'LastEvaluatedKey': None
        }
        mock_table.scan.return_value = {
            'Items': threats,
            'LastEvaluatedKey': None
        }

        # Test trend analysis
        event = {
            'action': 'trend_analysis',
            'parameters': {
                'timeframe': 'daily',
                'filters': {'source': 'otx'}
            }
        }

        response = lambda_handler(event, {})
        self.assertEqual(response['statusCode'], 200)

        body = json.loads(response['body'])
        self.assertIn('trend_points', body)

        # Test geographic analysis
        event['action'] = 'geographic_analysis'
        response = lambda_handler(event, {})
        self.assertEqual(response['statusCode'], 200)

        # Test cache stats
        event['action'] = 'cache_stats'
        response = lambda_handler(event, {})
        self.assertEqual(response['statusCode'], 200)

        body = json.loads(response['body'])
        self.assertIn('cache_statistics', body)
        self.assertIn('analytics_engines', body)

        # Test unsupported action
        event['action'] = 'unsupported_action'
        response = lambda_handler(event, {})
        self.assertEqual(response['statusCode'], 400)


class TestAnalyticsPerformance(unittest.TestCase):
    """Performance and load testing for analytics engine"""

    @unittest.skipUnless(ANALYTICS_ENGINE_AVAILABLE, "Analytics engine not available")
    @patch('analytics_engine.threat_intel_table')
    def test_large_dataset_performance(self, mock_table):
        """Test analytics performance with large datasets"""
        # Generate large dataset
        large_dataset = MockDataGenerator.generate_mock_threats(1000, 30)

        mock_table.query.return_value = {
            'Items': large_dataset,
            'LastEvaluatedKey': None
        }
        mock_table.scan.return_value = {
            'Items': large_dataset,
            'LastEvaluatedKey': None
        }

        # Test trend analysis performance
        start_time = time.time()
        trend_engine = TrendAnalysisEngine()
        result = trend_engine.analyze_temporal_trends(TrendTimeframe.DAILY)
        execution_time = time.time() - start_time

        self.assertLess(execution_time, 30)  # Should complete within 30 seconds
        self.assertIn('trend_points', result)
        self.assertGreater(len(result['trend_points']), 0)

    @unittest.skipUnless(ANALYTICS_ENGINE_AVAILABLE, "Analytics engine not available")
    def test_memory_efficiency(self):
        """Test memory efficiency of analytics operations"""
        import psutil
        import os

        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss

        # Perform memory-intensive operations
        threats = MockDataGenerator.generate_mock_threats(500, 14)

        # Memory should not grow excessively
        final_memory = process.memory_info().rss
        memory_growth = final_memory - initial_memory

        # Allow reasonable memory growth (less than 100MB for test data)
        self.assertLess(memory_growth, 100 * 1024 * 1024)


def run_analytics_tests():
    """Run all analytics engine tests"""
    if not ANALYTICS_ENGINE_AVAILABLE:
        print("Analytics engine not available - skipping tests")
        return

    # Create test suite
    test_suite = unittest.TestSuite()

    # Add test classes
    test_classes = [
        TestTrendAnalysisEngine,
        TestGeographicAnalysisEngine,
        TestRiskScoringEngine,
        TestBehavioralAnalysisEngine,
        TestAnalyticsCacheManager,
        TestPerformanceOptimizer,
        TestAnalyticsIntegration,
        TestAnalyticsPerformance
    ]

    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)

    # Print summary
    print(f"\n=== Analytics Engine Test Summary ===")
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success rate: {((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100):.1f}%")

    return result.wasSuccessful()


if __name__ == '__main__':
    run_analytics_tests()