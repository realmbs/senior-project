"""
Threat Intelligence Analytics Engine
Phase 8C Implementation - Advanced Analytics for Intelligence Value Generation

This module provides comprehensive threat intelligence analytics including:
- Trend Analysis Engine: Temporal threat pattern detection and campaign identification
- Geographic Threat Mapping: IP geolocation clustering and country-level analysis
- Risk Scoring Algorithms: Multi-factor risk assessment and threat severity classification
- Correlation Intelligence: Cross-source indicator relationships and attribution analysis
- Behavioral Analysis: Anomaly detection and baseline behavior establishment

Features:
- Real-time analytics with caching optimization
- Integration with existing event-driven architecture
- STIX 2.1 compliant analytics results
- Machine learning-ready data structures
- Scalable analysis algorithms
"""

import json
import boto3
import logging
import os
import re
import hashlib
import math
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Tuple, Union
from decimal import Decimal
from dataclasses import dataclass, asdict
from enum import Enum
from collections import defaultdict, Counter
import ipaddress
from urllib.parse import urlparse
from botocore.exceptions import ClientError
import time
import difflib

# Import existing search capabilities
try:
    from search_engine import (
        AdvancedSearchEngine, SearchQuery, SearchType, SortOrder,
        search_engine as global_search_engine
    )
    SEARCH_ENGINE_AVAILABLE = True
except ImportError:
    logger.warning("Search engine not available - analytics will use basic queries")
    SEARCH_ENGINE_AVAILABLE = False

# Import event utilities for integration
try:
    from event_utils import (
        EventEmitter, EventType, ThreatAnalyzer, WorkflowTracker
    )
    EVENT_INTEGRATION_AVAILABLE = True
except ImportError:
    logger.warning("Event utilities not available - analytics will run standalone")
    EVENT_INTEGRATION_AVAILABLE = False

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# AWS Service Clients
dynamodb = boto3.resource('dynamodb')
s3_client = boto3.client('s3')
cloudwatch = boto3.client('cloudwatch')

# Environment Variables
ENVIRONMENT = os.environ.get('ENVIRONMENT', 'dev')
THREAT_INTEL_TABLE = os.environ['THREAT_INTEL_TABLE']
ENRICHMENT_CACHE_TABLE = os.environ['ENRICHMENT_CACHE_TABLE']
ANALYTICS_CACHE_TABLE = os.environ.get('ANALYTICS_CACHE_TABLE', f'threat-intel-analytics-cache-{ENVIRONMENT}')
PROCESSED_DATA_BUCKET = os.environ['PROCESSED_DATA_BUCKET']

# Performance and Caching Configuration
ENABLE_ANALYTICS_CACHE = os.environ.get('ENABLE_ANALYTICS_CACHE', 'true').lower() == 'true'
CACHE_COMPRESSION_ENABLED = os.environ.get('CACHE_COMPRESSION_ENABLED', 'true').lower() == 'true'
QUERY_CACHE_SIZE_LIMIT_MB = int(os.environ.get('QUERY_CACHE_SIZE_LIMIT_MB', '50'))
RESULT_CACHE_TTL_MINUTES = int(os.environ.get('RESULT_CACHE_TTL_MINUTES', '30'))
MAX_CACHE_ENTRIES = int(os.environ.get('MAX_CACHE_ENTRIES', '1000'))

# DynamoDB Tables
threat_intel_table = dynamodb.Table(THREAT_INTEL_TABLE)
enrichment_cache_table = dynamodb.Table(ENRICHMENT_CACHE_TABLE)

# Try to initialize analytics cache table (may not exist in all environments)
try:
    analytics_cache_table = dynamodb.Table(ANALYTICS_CACHE_TABLE)
except Exception:
    analytics_cache_table = None
    logger.warning(f"Analytics cache table {ANALYTICS_CACHE_TABLE} not available - caching disabled")

# Analytics Configuration
ANALYTICS_CACHE_TTL_HOURS = 24
TREND_ANALYSIS_WINDOW_DAYS = 30
GEOGRAPHIC_CLUSTERING_RADIUS_KM = 100
ANOMALY_DETECTION_SENSITIVITY = 2.0  # Standard deviations
MIN_CORRELATION_CONFIDENCE = 0.6
MAX_ANALYTICS_RESULTS = 10000


class AnalyticsType(Enum):
    """Enumeration of analytics types"""
    TREND_ANALYSIS = "trend_analysis"
    GEOGRAPHIC_MAPPING = "geographic_mapping"
    RISK_SCORING = "risk_scoring"
    CORRELATION_INTELLIGENCE = "correlation_intelligence"
    BEHAVIORAL_ANALYSIS = "behavioral_analysis"
    CAMPAIGN_DETECTION = "campaign_detection"
    THREAT_LANDSCAPE = "threat_landscape"


class TrendTimeframe(Enum):
    """Time frame options for trend analysis"""
    HOURLY = "1h"
    DAILY = "24h"
    WEEKLY = "7d"
    MONTHLY = "30d"
    QUARTERLY = "90d"


class RiskLevel(Enum):
    """Risk level classification"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


@dataclass
class AnalyticsQuery:
    """Structured analytics query object"""
    analytics_type: AnalyticsType
    timeframe: Optional[TrendTimeframe] = None
    filters: Optional[Dict[str, Any]] = None
    parameters: Optional[Dict[str, Any]] = None
    cache_enabled: bool = True
    max_results: int = 1000


@dataclass
class TrendPoint:
    """Individual data point in trend analysis"""
    timestamp: datetime
    count: int
    confidence_avg: float
    threat_types: List[str]
    sources: List[str]
    risk_score: float


@dataclass
class ThreatCampaign:
    """Identified threat campaign"""
    campaign_id: str
    name: Optional[str]
    start_date: datetime
    end_date: Optional[datetime]
    indicators: List[str]
    confidence: float
    attribution: Optional[str]
    techniques: List[str]
    geographic_scope: List[str]


@dataclass
class GeographicCluster:
    """Geographic threat cluster"""
    cluster_id: str
    center_lat: float
    center_lon: float
    radius_km: float
    threat_count: int
    primary_threat_types: List[str]
    countries: List[str]
    confidence: float


@dataclass
class CorrelationResult:
    """Cross-source correlation result"""
    correlation_id: str
    indicator_pairs: List[Tuple[str, str]]
    correlation_type: str
    confidence: float
    evidence: List[str]
    timeline: List[datetime]
    shared_attributes: Dict[str, Any]


class TrendAnalysisEngine:
    """Advanced trend analysis for threat intelligence"""

    def __init__(self):
        self.cache_ttl = timedelta(hours=ANALYTICS_CACHE_TTL_HOURS)

    def analyze_temporal_trends(self, timeframe: TrendTimeframe,
                              filters: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Analyze temporal patterns in threat intelligence data

        Args:
            timeframe: Time window for analysis
            filters: Optional filters for specific threat types, sources, etc.

        Returns:
            Dictionary containing trend analysis results
        """
        try:
            logger.info(f"Starting temporal trend analysis for timeframe: {timeframe.value}")

            # Calculate time window
            end_time = datetime.now(timezone.utc)
            if timeframe == TrendTimeframe.HOURLY:
                start_time = end_time - timedelta(hours=24)
                bucket_size = timedelta(hours=1)
            elif timeframe == TrendTimeframe.DAILY:
                start_time = end_time - timedelta(days=30)
                bucket_size = timedelta(days=1)
            elif timeframe == TrendTimeframe.WEEKLY:
                start_time = end_time - timedelta(weeks=12)
                bucket_size = timedelta(weeks=1)
            elif timeframe == TrendTimeframe.MONTHLY:
                start_time = end_time - timedelta(days=365)
                bucket_size = timedelta(days=30)
            else:  # QUARTERLY
                start_time = end_time - timedelta(days=1095)  # 3 years
                bucket_size = timedelta(days=90)

            # Query threat intelligence data using time-index GSI
            query_params = {
                'IndexName': 'time-index',
                'KeyConditionExpression': 'created_date BETWEEN :start AND :end',
                'ExpressionAttributeValues': {
                    ':start': start_time.isoformat(),
                    ':end': end_time.isoformat()
                }
            }

            # Apply filters if provided
            if filters:
                filter_expressions = []
                for key, value in filters.items():
                    if key == 'source':
                        filter_expressions.append(f"source_name = :{key}")
                        query_params['ExpressionAttributeValues'][f':{key}'] = value
                    elif key == 'threat_type':
                        filter_expressions.append(f"contains(labels, :{key})")
                        query_params['ExpressionAttributeValues'][f':{key}'] = value
                    elif key == 'min_confidence':
                        filter_expressions.append(f"confidence >= :{key}")
                        query_params['ExpressionAttributeValues'][f':{key}'] = Decimal(str(value))

                if filter_expressions:
                    query_params['FilterExpression'] = ' AND '.join(filter_expressions)

            # Execute query with pagination
            threats = []
            response = threat_intel_table.query(**query_params)
            threats.extend(response.get('Items', []))

            while 'LastEvaluatedKey' in response:
                query_params['ExclusiveStartKey'] = response['LastEvaluatedKey']
                response = threat_intel_table.query(**query_params)
                threats.extend(response.get('Items', []))

            logger.info(f"Retrieved {len(threats)} threats for trend analysis")

            # Process threats into time buckets
            trend_buckets = defaultdict(list)
            for threat in threats:
                threat_time = datetime.fromisoformat(threat['created_date'].replace('Z', '+00:00'))
                bucket_key = self._get_time_bucket(threat_time, start_time, bucket_size)
                trend_buckets[bucket_key].append(threat)

            # Generate trend points
            trend_points = []
            for bucket_time, bucket_threats in sorted(trend_buckets.items()):
                if bucket_threats:
                    trend_point = self._create_trend_point(bucket_time, bucket_threats)
                    trend_points.append(trend_point)

            # Perform trend analysis
            trend_analysis = self._analyze_trend_patterns(trend_points)

            # Detect campaigns
            campaigns = self._detect_threat_campaigns(threats, timeframe)

            result = {
                'timeframe': timeframe.value,
                'analysis_window': {
                    'start_time': start_time.isoformat(),
                    'end_time': end_time.isoformat()
                },
                'total_threats': len(threats),
                'trend_points': [asdict(tp) for tp in trend_points],
                'trend_analysis': trend_analysis,
                'detected_campaigns': [asdict(c) for c in campaigns],
                'summary': self._generate_trend_summary(trend_points, trend_analysis),
                'generated_at': datetime.now(timezone.utc).isoformat()
            }

            logger.info(f"Trend analysis completed: {len(trend_points)} points, {len(campaigns)} campaigns")
            return result

        except Exception as e:
            logger.error(f"Error in temporal trend analysis: {str(e)}")
            raise

    def _get_time_bucket(self, timestamp: datetime, start_time: datetime,
                        bucket_size: timedelta) -> datetime:
        """Calculate which time bucket a timestamp belongs to"""
        time_diff = timestamp - start_time
        bucket_number = int(time_diff.total_seconds() // bucket_size.total_seconds())
        return start_time + (bucket_size * bucket_number)

    def _create_trend_point(self, timestamp: datetime, threats: List[Dict]) -> TrendPoint:
        """Create a trend point from a bucket of threats"""
        confidences = [float(t.get('confidence', 0)) for t in threats]
        avg_confidence = sum(confidences) / len(confidences) if confidences else 0

        # Extract threat types from labels
        threat_types = set()
        sources = set()
        for threat in threats:
            if 'labels' in threat:
                threat_types.update(threat['labels'])
            if 'source_name' in threat:
                sources.add(threat['source_name'])

        # Calculate risk score based on count, confidence, and threat types
        risk_multiplier = 1.0
        if 'apt' in str(threat_types).lower():
            risk_multiplier = 2.0
        elif 'malware' in str(threat_types).lower():
            risk_multiplier = 1.5

        risk_score = min(100.0, (len(threats) * avg_confidence * risk_multiplier) / 10)

        return TrendPoint(
            timestamp=timestamp,
            count=len(threats),
            confidence_avg=avg_confidence,
            threat_types=list(threat_types),
            sources=list(sources),
            risk_score=risk_score
        )

    def _analyze_trend_patterns(self, trend_points: List[TrendPoint]) -> Dict[str, Any]:
        """Analyze patterns in trend data"""
        if len(trend_points) < 2:
            return {'pattern': 'insufficient_data', 'confidence': 0.0}

        counts = [tp.count for tp in trend_points]
        confidences = [tp.confidence_avg for tp in trend_points]
        risk_scores = [tp.risk_score for tp in trend_points]

        # Calculate trends
        count_trend = self._calculate_trend(counts)
        confidence_trend = self._calculate_trend(confidences)
        risk_trend = self._calculate_trend(risk_scores)

        # Detect anomalies
        anomalies = self._detect_anomalies(counts)

        # Identify patterns
        pattern = self._identify_pattern(counts)

        # Calculate volatility
        volatility = self._calculate_volatility(counts)

        return {
            'count_trend': count_trend,
            'confidence_trend': confidence_trend,
            'risk_trend': risk_trend,
            'pattern': pattern,
            'volatility': volatility,
            'anomalies': anomalies,
            'peak_activity': self._find_peak_activity(trend_points),
            'threat_evolution': self._analyze_threat_evolution(trend_points)
        }

    def _calculate_trend(self, values: List[float]) -> Dict[str, Any]:
        """Calculate trend direction and strength"""
        if len(values) < 2:
            return {'direction': 'stable', 'strength': 0.0, 'change_percent': 0.0}

        # Simple linear regression
        n = len(values)
        x_vals = list(range(n))

        sum_x = sum(x_vals)
        sum_y = sum(values)
        sum_xy = sum(x * y for x, y in zip(x_vals, values))
        sum_x2 = sum(x * x for x in x_vals)

        if n * sum_x2 - sum_x * sum_x == 0:
            slope = 0
        else:
            slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x * sum_x)

        # Determine direction
        if abs(slope) < 0.1:
            direction = 'stable'
        elif slope > 0:
            direction = 'increasing'
        else:
            direction = 'decreasing'

        # Calculate change percentage
        if values[0] != 0:
            change_percent = ((values[-1] - values[0]) / values[0]) * 100
        else:
            change_percent = 0.0

        return {
            'direction': direction,
            'strength': abs(slope),
            'change_percent': change_percent,
            'slope': slope
        }

    def _detect_anomalies(self, values: List[float]) -> List[Dict[str, Any]]:
        """Detect anomalies using statistical methods"""
        if len(values) < 3:
            return []

        mean_val = sum(values) / len(values)
        variance = sum((x - mean_val) ** 2 for x in values) / len(values)
        std_dev = math.sqrt(variance)

        anomalies = []
        threshold = ANOMALY_DETECTION_SENSITIVITY * std_dev

        for i, value in enumerate(values):
            if abs(value - mean_val) > threshold:
                anomalies.append({
                    'index': i,
                    'value': value,
                    'expected': mean_val,
                    'deviation': abs(value - mean_val),
                    'severity': 'high' if abs(value - mean_val) > 2 * threshold else 'medium'
                })

        return anomalies

    def _identify_pattern(self, values: List[float]) -> str:
        """Identify overall pattern in the data"""
        if len(values) < 3:
            return 'insufficient_data'

        # Check for cycles
        if self._is_cyclical(values):
            return 'cyclical'

        # Check for exponential growth
        if self._is_exponential(values):
            return 'exponential'

        # Check for linear trend
        trend = self._calculate_trend(values)
        if abs(trend['slope']) > 0.5:
            return 'linear_trend'

        # Check for spike pattern
        if self._has_spikes(values):
            return 'spiky'

        return 'stable'

    def _is_cyclical(self, values: List[float]) -> bool:
        """Check if data shows cyclical pattern"""
        # Simple cyclical detection - look for alternating high/low periods
        if len(values) < 6:
            return False

        peaks = []
        valleys = []

        for i in range(1, len(values) - 1):
            if values[i] > values[i-1] and values[i] > values[i+1]:
                peaks.append(i)
            elif values[i] < values[i-1] and values[i] < values[i+1]:
                valleys.append(i)

        # Cyclical if we have multiple peaks and valleys
        return len(peaks) >= 2 and len(valleys) >= 2

    def _is_exponential(self, values: List[float]) -> bool:
        """Check if data shows exponential growth pattern"""
        if len(values) < 3 or min(values) <= 0:
            return False

        # Check if log(values) shows linear trend
        try:
            log_values = [math.log(max(v, 0.1)) for v in values]
            trend = self._calculate_trend(log_values)
            return abs(trend['slope']) > 0.3
        except (ValueError, OverflowError):
            return False

    def _has_spikes(self, values: List[float]) -> bool:
        """Check if data has spike pattern"""
        if len(values) < 3:
            return False

        mean_val = sum(values) / len(values)
        std_dev = math.sqrt(sum((x - mean_val) ** 2 for x in values) / len(values))

        spikes = sum(1 for v in values if abs(v - mean_val) > 2 * std_dev)
        return spikes / len(values) > 0.1  # More than 10% are spikes

    def _calculate_volatility(self, values: List[float]) -> float:
        """Calculate volatility (coefficient of variation)"""
        if len(values) < 2:
            return 0.0

        mean_val = sum(values) / len(values)
        if mean_val == 0:
            return 0.0

        variance = sum((x - mean_val) ** 2 for x in values) / len(values)
        std_dev = math.sqrt(variance)

        return std_dev / mean_val

    def _find_peak_activity(self, trend_points: List[TrendPoint]) -> Dict[str, Any]:
        """Find periods of peak threat activity"""
        if not trend_points:
            return {}

        max_count = max(tp.count for tp in trend_points)
        max_risk = max(tp.risk_score for tp in trend_points)

        peak_count_point = next(tp for tp in trend_points if tp.count == max_count)
        peak_risk_point = next(tp for tp in trend_points if tp.risk_score == max_risk)

        return {
            'peak_count': {
                'timestamp': peak_count_point.timestamp.isoformat(),
                'count': max_count,
                'threat_types': peak_count_point.threat_types
            },
            'peak_risk': {
                'timestamp': peak_risk_point.timestamp.isoformat(),
                'risk_score': max_risk,
                'threat_types': peak_risk_point.threat_types
            }
        }

    def _analyze_threat_evolution(self, trend_points: List[TrendPoint]) -> Dict[str, Any]:
        """Analyze how threat landscape evolves over time"""
        if len(trend_points) < 2:
            return {}

        # Track threat type evolution
        early_types = set()
        late_types = set()

        mid_point = len(trend_points) // 2

        for tp in trend_points[:mid_point]:
            early_types.update(tp.threat_types)

        for tp in trend_points[mid_point:]:
            late_types.update(tp.threat_types)

        emerging_types = late_types - early_types
        declining_types = early_types - late_types
        persistent_types = early_types & late_types

        # Track source evolution
        early_sources = set()
        late_sources = set()

        for tp in trend_points[:mid_point]:
            early_sources.update(tp.sources)

        for tp in trend_points[mid_point:]:
            late_sources.update(tp.sources)

        return {
            'threat_types': {
                'emerging': list(emerging_types),
                'declining': list(declining_types),
                'persistent': list(persistent_types)
            },
            'sources': {
                'early_period': list(early_sources),
                'late_period': list(late_sources)
            },
            'confidence_evolution': {
                'early_avg': sum(tp.confidence_avg for tp in trend_points[:mid_point]) / mid_point if mid_point > 0 else 0,
                'late_avg': sum(tp.confidence_avg for tp in trend_points[mid_point:]) / (len(trend_points) - mid_point) if len(trend_points) > mid_point else 0
            }
        }

    def _detect_threat_campaigns(self, threats: List[Dict],
                               timeframe: TrendTimeframe) -> List[ThreatCampaign]:
        """Detect potential threat campaigns from clustered threats"""
        campaigns = []

        # Group threats by similar patterns
        pattern_groups = defaultdict(list)

        for threat in threats:
            # Create a pattern signature based on threat characteristics
            pattern_elements = []

            if 'labels' in threat:
                pattern_elements.extend(sorted(threat['labels']))

            if 'source_name' in threat:
                pattern_elements.append(threat['source_name'])

            # Extract domain/IP patterns from indicators
            if 'pattern' in threat:
                pattern_text = threat['pattern']
                domains = re.findall(r"domain-name:value\s*=\s*'([^']+)'", pattern_text)
                ips = re.findall(r"ipv4-addr:value\s*=\s*'([^']+)'", pattern_text)

                # Add domain patterns (TLD, length, etc.)
                for domain in domains:
                    parts = domain.split('.')
                    if len(parts) > 1:
                        pattern_elements.append(f"tld:{parts[-1]}")
                        pattern_elements.append(f"domain_parts:{len(parts)}")

                # Add IP patterns (subnet, etc.)
                for ip in ips:
                    try:
                        ip_obj = ipaddress.ip_address(ip)
                        if ip_obj.is_private:
                            pattern_elements.append("ip:private")
                        else:
                            pattern_elements.append("ip:public")
                            # Add /24 subnet pattern
                            if isinstance(ip_obj, ipaddress.IPv4Address):
                                subnet = str(ipaddress.ip_network(f"{ip}/24", strict=False))
                                pattern_elements.append(f"subnet:{subnet}")
                    except ValueError:
                        pass

            pattern_signature = "|".join(sorted(pattern_elements))
            pattern_groups[pattern_signature].append(threat)

        # Identify campaigns from groups with sufficient size and time span
        for pattern_sig, group_threats in pattern_groups.items():
            if len(group_threats) < 3:  # Minimum threats for a campaign
                continue

            # Sort by time
            group_threats.sort(key=lambda x: x['created_date'])

            start_time = datetime.fromisoformat(group_threats[0]['created_date'].replace('Z', '+00:00'))
            end_time = datetime.fromisoformat(group_threats[-1]['created_date'].replace('Z', '+00:00'))

            # Campaign must span reasonable time period
            duration = end_time - start_time
            if timeframe == TrendTimeframe.HOURLY and duration < timedelta(hours=2):
                continue
            elif timeframe == TrendTimeframe.DAILY and duration < timedelta(days=2):
                continue
            elif timeframe in [TrendTimeframe.WEEKLY, TrendTimeframe.MONTHLY] and duration < timedelta(days=3):
                continue

            # Calculate campaign confidence based on consistency
            confidences = [float(t.get('confidence', 0)) for t in group_threats]
            avg_confidence = sum(confidences) / len(confidences)
            confidence_std = math.sqrt(sum((c - avg_confidence) ** 2 for c in confidences) / len(confidences))

            # High confidence if threats are consistent and high-confidence
            campaign_confidence = avg_confidence * (1 - min(0.5, confidence_std / 50))

            if campaign_confidence < 50:  # Minimum confidence threshold
                continue

            # Extract indicators
            indicators = []
            techniques = set()
            attribution_hints = set()

            for threat in group_threats:
                indicators.append(threat.get('object_id', ''))

                # Extract techniques from labels
                if 'labels' in threat:
                    for label in threat['labels']:
                        if 'attack' in label.lower() or 'technique' in label.lower():
                            techniques.add(label)

                # Look for attribution hints
                if 'description' in threat:
                    desc = threat['description'].lower()
                    for hint in ['apt', 'group', 'actor', 'campaign']:
                        if hint in desc:
                            attribution_hints.add(hint)

            # Generate campaign name
            threat_types = set()
            for threat in group_threats:
                if 'labels' in threat:
                    threat_types.update(threat['labels'])

            campaign_name = f"Campaign-{start_time.strftime('%Y%m%d')}-{'-'.join(list(threat_types)[:2])}"

            campaign = ThreatCampaign(
                campaign_id=hashlib.sha256(pattern_sig.encode()).hexdigest()[:16],
                name=campaign_name,
                start_date=start_time,
                end_date=end_time,
                indicators=indicators,
                confidence=campaign_confidence,
                attribution=list(attribution_hints)[0] if attribution_hints else None,
                techniques=list(techniques),
                geographic_scope=[]  # Will be filled by geographic analysis
            )

            campaigns.append(campaign)

        logger.info(f"Detected {len(campaigns)} potential threat campaigns")
        return campaigns

    def _generate_trend_summary(self, trend_points: List[TrendPoint],
                              analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary of trend analysis"""
        if not trend_points:
            return {'status': 'no_data'}

        total_threats = sum(tp.count for tp in trend_points)
        avg_confidence = sum(tp.confidence_avg for tp in trend_points) / len(trend_points)
        max_risk = max(tp.risk_score for tp in trend_points)

        # Determine overall threat level
        if max_risk > 80:
            threat_level = 'critical'
        elif max_risk > 60:
            threat_level = 'high'
        elif max_risk > 40:
            threat_level = 'medium'
        else:
            threat_level = 'low'

        # Key insights
        insights = []

        if analysis.get('count_trend', {}).get('direction') == 'increasing':
            insights.append("Threat activity is increasing over the analyzed period")

        if analysis.get('volatility', 0) > 0.5:
            insights.append("High volatility detected in threat patterns")

        if analysis.get('anomalies'):
            insights.append(f"{len(analysis['anomalies'])} anomalous periods detected")

        if analysis.get('pattern') == 'cyclical':
            insights.append("Cyclical threat pattern suggests coordinated campaigns")

        return {
            'threat_level': threat_level,
            'total_threats': total_threats,
            'average_confidence': round(avg_confidence, 2),
            'max_risk_score': round(max_risk, 2),
            'primary_pattern': analysis.get('pattern', 'unknown'),
            'key_insights': insights,
            'recommendation': self._generate_recommendation(threat_level, analysis)
        }

    def _generate_recommendation(self, threat_level: str, analysis: Dict[str, Any]) -> str:
        """Generate actionable recommendations based on analysis"""
        if threat_level == 'critical':
            return "Immediate security review recommended. Deploy additional monitoring and countermeasures."
        elif threat_level == 'high':
            return "Increased vigilance recommended. Review and update security policies."
        elif analysis.get('count_trend', {}).get('direction') == 'increasing':
            return "Monitor trend closely. Consider proactive security measures."
        elif analysis.get('pattern') == 'cyclical':
            return "Investigate potential coordinated campaigns. Implement threat hunting protocols."
        else:
            return "Continue standard monitoring procedures. Regular review recommended."


class GeographicAnalysisEngine:
    """Advanced geographic threat analysis and clustering"""

    def __init__(self):
        self.cache_ttl = timedelta(hours=ANALYTICS_CACHE_TTL_HOURS)

    def analyze_geographic_distribution(self, filters: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Analyze geographic distribution of threats

        Args:
            filters: Optional filters for specific threat types, sources, etc.

        Returns:
            Dictionary containing geographic analysis results
        """
        try:
            logger.info("Starting geographic threat distribution analysis")

            # Query threat intelligence data with geographic information
            scan_params = {
                'FilterExpression': 'attribute_exists(enrichment_data.geolocation)'
            }

            # Apply additional filters if provided
            if filters:
                filter_expressions = ['attribute_exists(enrichment_data.geolocation)']
                expression_values = {}

                for key, value in filters.items():
                    if key == 'source':
                        filter_expressions.append(f"source_name = :{key}")
                        expression_values[f':{key}'] = value
                    elif key == 'threat_type':
                        filter_expressions.append(f"contains(labels, :{key})")
                        expression_values[f':{key}'] = value
                    elif key == 'min_confidence':
                        filter_expressions.append(f"confidence >= :{key}")
                        expression_values[f':{key}'] = Decimal(str(value))

                if expression_values:
                    scan_params['FilterExpression'] = ' AND '.join(filter_expressions)
                    scan_params['ExpressionAttributeValues'] = expression_values

            # Execute scan with pagination
            threats_with_geo = []
            response = threat_intel_table.scan(**scan_params)
            threats_with_geo.extend(response.get('Items', []))

            while 'LastEvaluatedKey' in response:
                scan_params['ExclusiveStartKey'] = response['LastEvaluatedKey']
                response = threat_intel_table.scan(**scan_params)
                threats_with_geo.extend(response.get('Items', []))

            logger.info(f"Retrieved {len(threats_with_geo)} threats with geographic data")

            if not threats_with_geo:
                return {
                    'error': 'No threats with geographic data found',
                    'total_threats': 0
                }

            # Extract geographic coordinates
            geo_points = []
            for threat in threats_with_geo:
                geo_data = threat.get('enrichment_data', {}).get('geolocation', {})
                if geo_data and 'latitude' in geo_data and 'longitude' in geo_data:
                    geo_points.append({
                        'lat': float(geo_data['latitude']),
                        'lon': float(geo_data['longitude']),
                        'country': geo_data.get('country', 'Unknown'),
                        'city': geo_data.get('city', 'Unknown'),
                        'threat': threat
                    })

            # Perform clustering analysis
            clusters = self._perform_geographic_clustering(geo_points)

            # Analyze country-level distribution
            country_analysis = self._analyze_country_distribution(geo_points)

            # Detect geographic migration patterns
            migration_patterns = self._detect_migration_patterns(geo_points)

            # Generate threat hotspots
            hotspots = self._identify_threat_hotspots(geo_points, clusters)

            result = {
                'total_threats_with_geo': len(threats_with_geo),
                'total_geo_points': len(geo_points),
                'clusters': [asdict(c) for c in clusters],
                'country_analysis': country_analysis,
                'migration_patterns': migration_patterns,
                'threat_hotspots': hotspots,
                'geographic_summary': self._generate_geographic_summary(geo_points, clusters),
                'generated_at': datetime.now(timezone.utc).isoformat()
            }

            logger.info(f"Geographic analysis completed: {len(clusters)} clusters, {len(country_analysis)} countries")
            return result

        except Exception as e:
            logger.error(f"Error in geographic analysis: {str(e)}")
            raise

    def _perform_geographic_clustering(self, geo_points: List[Dict]) -> List[GeographicCluster]:
        """Perform geographic clustering using distance-based algorithm"""
        if not geo_points:
            return []

        clusters = []
        unassigned_points = geo_points.copy()
        cluster_id = 0

        while unassigned_points:
            # Start new cluster with first unassigned point
            seed_point = unassigned_points[0]
            cluster_points = [seed_point]
            unassigned_points.remove(seed_point)

            # Find all points within clustering radius
            points_to_check = unassigned_points.copy()
            for point in points_to_check:
                if self._calculate_distance(seed_point, point) <= GEOGRAPHIC_CLUSTERING_RADIUS_KM:
                    cluster_points.append(point)
                    unassigned_points.remove(point)

            # Create cluster if it has enough points
            if len(cluster_points) >= 2:
                cluster = self._create_geographic_cluster(cluster_id, cluster_points)
                clusters.append(cluster)
                cluster_id += 1

        return clusters

    def _calculate_distance(self, point1: Dict, point2: Dict) -> float:
        """Calculate distance between two geographic points using Haversine formula"""
        R = 6371  # Earth's radius in kilometers

        lat1_rad = math.radians(point1['lat'])
        lat2_rad = math.radians(point2['lat'])
        delta_lat = math.radians(point2['lat'] - point1['lat'])
        delta_lon = math.radians(point2['lon'] - point1['lon'])

        a = (math.sin(delta_lat / 2) ** 2 +
             math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(delta_lon / 2) ** 2)
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

        return R * c

    def _create_geographic_cluster(self, cluster_id: int, points: List[Dict]) -> GeographicCluster:
        """Create a geographic cluster from a set of points"""
        # Calculate cluster center
        center_lat = sum(p['lat'] for p in points) / len(points)
        center_lon = sum(p['lon'] for p in points) / len(points)

        # Calculate radius (maximum distance from center)
        max_distance = 0
        center_point = {'lat': center_lat, 'lon': center_lon}
        for point in points:
            distance = self._calculate_distance(center_point, point)
            max_distance = max(max_distance, distance)

        # Extract threat characteristics
        threat_types = set()
        countries = set()
        confidences = []

        for point in points:
            threat = point['threat']
            if 'labels' in threat:
                threat_types.update(threat['labels'])
            countries.add(point['country'])
            confidences.append(float(threat.get('confidence', 0)))

        avg_confidence = sum(confidences) / len(confidences) if confidences else 0

        return GeographicCluster(
            cluster_id=f"geo-cluster-{cluster_id}",
            center_lat=center_lat,
            center_lon=center_lon,
            radius_km=max_distance,
            threat_count=len(points),
            primary_threat_types=list(threat_types)[:5],  # Top 5 threat types
            countries=list(countries),
            confidence=avg_confidence
        )

    def _analyze_country_distribution(self, geo_points: List[Dict]) -> Dict[str, Any]:
        """Analyze threat distribution by country"""
        country_stats = defaultdict(lambda: {
            'count': 0,
            'threat_types': set(),
            'confidences': [],
            'cities': set()
        })

        for point in geo_points:
            country = point['country']
            threat = point['threat']

            country_stats[country]['count'] += 1
            country_stats[country]['cities'].add(point['city'])
            country_stats[country]['confidences'].append(float(threat.get('confidence', 0)))

            if 'labels' in threat:
                country_stats[country]['threat_types'].update(threat['labels'])

        # Convert to final format and calculate statistics
        country_analysis = {}
        for country, stats in country_stats.items():
            avg_confidence = sum(stats['confidences']) / len(stats['confidences'])

            country_analysis[country] = {
                'threat_count': stats['count'],
                'average_confidence': round(avg_confidence, 2),
                'threat_types': list(stats['threat_types']),
                'cities_affected': list(stats['cities']),
                'risk_level': self._calculate_country_risk_level(stats['count'], avg_confidence)
            }

        # Sort by threat count
        sorted_countries = sorted(country_analysis.items(), key=lambda x: x[1]['threat_count'], reverse=True)

        return {
            'total_countries': len(country_analysis),
            'by_country': dict(sorted_countries),
            'top_threat_countries': [country for country, _ in sorted_countries[:10]],
            'distribution_analysis': self._analyze_geographic_distribution_pattern(country_analysis)
        }

    def _calculate_country_risk_level(self, threat_count: int, avg_confidence: float) -> str:
        """Calculate risk level for a country based on threat count and confidence"""
        risk_score = threat_count * (avg_confidence / 100)

        if risk_score > 50:
            return 'critical'
        elif risk_score > 20:
            return 'high'
        elif risk_score > 5:
            return 'medium'
        else:
            return 'low'

    def _analyze_geographic_distribution_pattern(self, country_analysis: Dict) -> Dict[str, Any]:
        """Analyze overall geographic distribution patterns"""
        threat_counts = [data['threat_count'] for data in country_analysis.values()]

        if not threat_counts:
            return {'pattern': 'no_data'}

        total_threats = sum(threat_counts)
        max_threats = max(threat_counts)

        # Calculate concentration ratio (top 3 countries)
        sorted_counts = sorted(threat_counts, reverse=True)
        top_3_sum = sum(sorted_counts[:3]) if len(sorted_counts) >= 3 else sum(sorted_counts)
        concentration_ratio = top_3_sum / total_threats if total_threats > 0 else 0

        # Determine distribution pattern
        if concentration_ratio > 0.8:
            pattern = 'highly_concentrated'
        elif concentration_ratio > 0.6:
            pattern = 'concentrated'
        elif concentration_ratio > 0.4:
            pattern = 'moderately_distributed'
        else:
            pattern = 'widely_distributed'

        return {
            'pattern': pattern,
            'concentration_ratio': round(concentration_ratio, 3),
            'gini_coefficient': self._calculate_gini_coefficient(threat_counts),
            'countries_with_threats': len(country_analysis),
            'average_threats_per_country': round(total_threats / len(country_analysis), 2)
        }

    def _calculate_gini_coefficient(self, values: List[float]) -> float:
        """Calculate Gini coefficient to measure inequality in distribution"""
        if not values:
            return 0.0

        sorted_values = sorted(values)
        n = len(sorted_values)
        cumsum = sum(sorted_values)

        if cumsum == 0:
            return 0.0

        cumulative = 0
        gini_sum = 0

        for i, value in enumerate(sorted_values):
            cumulative += value
            gini_sum += (2 * (i + 1) - n - 1) * value

        return gini_sum / (n * cumsum)

    def _detect_migration_patterns(self, geo_points: List[Dict]) -> Dict[str, Any]:
        """Detect threat migration patterns over time"""
        if not geo_points:
            return {}

        # Group threats by time periods
        time_periods = defaultdict(list)

        for point in geo_points:
            threat = point['threat']
            threat_time = datetime.fromisoformat(threat['created_date'].replace('Z', '+00:00'))

            # Group by week
            week_start = threat_time - timedelta(days=threat_time.weekday())
            week_key = week_start.strftime('%Y-W%U')

            time_periods[week_key].append(point)

        # Analyze geographic evolution over time
        migration_analysis = []
        sorted_periods = sorted(time_periods.items())

        for i in range(1, len(sorted_periods)):
            prev_period = sorted_periods[i-1][1]
            curr_period = sorted_periods[i][1]

            prev_countries = set(p['country'] for p in prev_period)
            curr_countries = set(p['country'] for p in curr_period)

            new_countries = curr_countries - prev_countries
            disappeared_countries = prev_countries - curr_countries
            persistent_countries = prev_countries & curr_countries

            if new_countries or disappeared_countries:
                migration_analysis.append({
                    'period': sorted_periods[i][0],
                    'new_countries': list(new_countries),
                    'disappeared_countries': list(disappeared_countries),
                    'persistent_countries': list(persistent_countries),
                    'expansion_rate': len(new_countries) / len(prev_countries) if prev_countries else 0
                })

        return {
            'time_periods_analyzed': len(sorted_periods),
            'migration_events': migration_analysis,
            'summary': {
                'highly_mobile_threats': len([m for m in migration_analysis if len(m['new_countries']) > 2]),
                'geographic_expansion_detected': any(m['expansion_rate'] > 0.5 for m in migration_analysis),
                'most_active_period': max(migration_analysis, key=lambda x: len(x['new_countries']))['period'] if migration_analysis else None
            }
        }

    def _identify_threat_hotspots(self, geo_points: List[Dict], clusters: List[GeographicCluster]) -> List[Dict[str, Any]]:
        """Identify geographic threat hotspots"""
        hotspots = []

        # Cluster-based hotspots
        for cluster in clusters:
            if cluster.threat_count >= 5:  # Minimum threats for hotspot
                hotspot = {
                    'type': 'cluster',
                    'id': cluster.cluster_id,
                    'center_lat': cluster.center_lat,
                    'center_lon': cluster.center_lon,
                    'threat_count': cluster.threat_count,
                    'primary_threats': cluster.primary_threat_types,
                    'countries': cluster.countries,
                    'confidence': cluster.confidence,
                    'severity': self._calculate_hotspot_severity(cluster.threat_count, cluster.confidence)
                }
                hotspots.append(hotspot)

        # City-based hotspots
        city_stats = defaultdict(lambda: {'count': 0, 'confidences': [], 'threat_types': set()})

        for point in geo_points:
            city_key = f"{point['city']}, {point['country']}"
            threat = point['threat']

            city_stats[city_key]['count'] += 1
            city_stats[city_key]['confidences'].append(float(threat.get('confidence', 0)))

            if 'labels' in threat:
                city_stats[city_key]['threat_types'].update(threat['labels'])

        for city, stats in city_stats.items():
            if stats['count'] >= 3:  # Minimum threats for city hotspot
                avg_confidence = sum(stats['confidences']) / len(stats['confidences'])

                hotspot = {
                    'type': 'city',
                    'id': f"city-{hashlib.md5(city.encode()).hexdigest()[:8]}",
                    'location': city,
                    'threat_count': stats['count'],
                    'primary_threats': list(stats['threat_types'])[:3],
                    'confidence': avg_confidence,
                    'severity': self._calculate_hotspot_severity(stats['count'], avg_confidence)
                }
                hotspots.append(hotspot)

        # Sort by severity
        hotspots.sort(key=lambda x: x['threat_count'] * x['confidence'], reverse=True)

        return hotspots[:20]  # Top 20 hotspots

    def _calculate_hotspot_severity(self, threat_count: int, confidence: float) -> str:
        """Calculate severity level for threat hotspot"""
        severity_score = threat_count * (confidence / 100)

        if severity_score > 20:
            return 'critical'
        elif severity_score > 10:
            return 'high'
        elif severity_score > 5:
            return 'medium'
        else:
            return 'low'

    def _generate_geographic_summary(self, geo_points: List[Dict], clusters: List[GeographicCluster]) -> Dict[str, Any]:
        """Generate executive summary of geographic analysis"""
        if not geo_points:
            return {'status': 'no_data'}

        countries = set(p['country'] for p in geo_points)
        cities = set(f"{p['city']}, {p['country']}" for p in geo_points)

        # Calculate geographic spread
        if len(geo_points) > 1:
            lats = [p['lat'] for p in geo_points]
            lons = [p['lon'] for p in geo_points]

            lat_range = max(lats) - min(lats)
            lon_range = max(lons) - min(lons)

            # Rough geographic spread in km
            geographic_spread = max(lat_range, lon_range) * 111  # 1 degree ≈ 111 km
        else:
            geographic_spread = 0

        # Determine geographic pattern
        if len(countries) == 1:
            pattern = 'localized'
        elif len(countries) <= 3:
            pattern = 'regional'
        elif len(countries) <= 10:
            pattern = 'multi-regional'
        else:
            pattern = 'global'

        return {
            'countries_affected': len(countries),
            'cities_affected': len(cities),
            'clusters_detected': len(clusters),
            'geographic_spread_km': round(geographic_spread, 2),
            'distribution_pattern': pattern,
            'clustering_efficiency': len(clusters) / len(geo_points) if geo_points else 0,
            'top_countries': list(Counter(p['country'] for p in geo_points).most_common(5)),
            'recommendation': self._generate_geographic_recommendation(pattern, len(clusters), len(countries))
        }

    def _generate_geographic_recommendation(self, pattern: str, clusters: int, countries: int) -> str:
        """Generate recommendations based on geographic analysis"""
        if pattern == 'global' and clusters > 5:
            return "Global threat distribution with multiple clusters detected. Implement coordinated international response."
        elif pattern == 'multi-regional' and clusters > 3:
            return "Multi-regional threat activity suggests organized campaign. Enhanced regional cooperation recommended."
        elif pattern == 'regional':
            return "Regional threat concentration detected. Focus defensive resources on affected region."
        elif pattern == 'localized':
            return "Localized threat activity. Targeted response and monitoring recommended."
        else:
            return "Continue geographic monitoring. Regular pattern analysis recommended."


class RiskScoringEngine:
    """Advanced multi-factor risk assessment for threat intelligence"""

    def __init__(self):
        self.cache_ttl = timedelta(hours=ANALYTICS_CACHE_TTL_HOURS)

        # Source reliability weights (0.0 - 1.0)
        self.source_weights = {
            'alienvault_otx': 0.85,
            'abuse_ch': 0.90,
            'shodan': 0.80,
            'misp': 0.85,
            'virustotal': 0.75,
            'hybrid_analysis': 0.80,
            'unknown': 0.50
        }

        # Threat type severity multipliers
        self.threat_severity = {
            'apt': 2.0,
            'advanced-persistent-threat': 2.0,
            'campaign': 1.8,
            'backdoor': 1.7,
            'trojan': 1.5,
            'ransomware': 1.8,
            'botnet': 1.6,
            'phishing': 1.3,
            'malware': 1.4,
            'suspicious': 1.1,
            'anomalous-activity': 1.2,
            'malicious-activity': 1.5,
            'benign': 0.3,
            'unknown': 1.0
        }

        # Geographic risk multipliers based on common threat origin regions
        self.geographic_risk = {
            'high_risk': 1.5,     # Known high-risk countries
            'medium_risk': 1.2,   # Moderate risk countries
            'low_risk': 1.0,      # Low risk countries
            'unknown': 1.1        # Unknown locations
        }

    def calculate_enhanced_risk_score(self, threat: Dict[str, Any],
                                    context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Calculate enhanced risk score using multi-factor assessment

        Args:
            threat: Threat intelligence object
            context: Additional context (correlations, trends, etc.)

        Returns:
            Dictionary with risk score and factors breakdown
        """
        try:
            logger.info(f"Calculating enhanced risk score for threat: {threat.get('object_id', 'unknown')}")

            # Base confidence score
            base_confidence = float(threat.get('confidence', 0))

            # Calculate individual risk factors
            source_factor = self._calculate_source_factor(threat)
            temporal_factor = self._calculate_temporal_factor(threat)
            geographic_factor = self._calculate_geographic_factor(threat)
            threat_type_factor = self._calculate_threat_type_factor(threat)
            correlation_factor = self._calculate_correlation_factor(threat, context)
            consistency_factor = self._calculate_consistency_factor(threat)
            urgency_factor = self._calculate_urgency_factor(threat)

            # Weighted risk score calculation
            weighted_score = (
                base_confidence * 0.25 +
                source_factor * 0.15 +
                temporal_factor * 0.10 +
                geographic_factor * 0.10 +
                threat_type_factor * 0.20 +
                correlation_factor * 0.10 +
                consistency_factor * 0.05 +
                urgency_factor * 0.05
            )

            # Normalize to 0-100 scale
            risk_score = min(100.0, max(0.0, weighted_score))

            # Determine risk level
            risk_level = self._determine_risk_level(risk_score)

            # Calculate business impact
            business_impact = self._assess_business_impact(threat, risk_score)

            # Generate recommendations
            recommendations = self._generate_risk_recommendations(risk_level, threat, context)

            result = {
                'threat_id': threat.get('object_id', 'unknown'),
                'enhanced_risk_score': round(risk_score, 2),
                'risk_level': risk_level,
                'base_confidence': base_confidence,
                'risk_factors': {
                    'source_reliability': round(source_factor, 2),
                    'temporal_relevance': round(temporal_factor, 2),
                    'geographic_risk': round(geographic_factor, 2),
                    'threat_severity': round(threat_type_factor, 2),
                    'cross_correlation': round(correlation_factor, 2),
                    'data_consistency': round(consistency_factor, 2),
                    'urgency_level': round(urgency_factor, 2)
                },
                'business_impact': business_impact,
                'recommendations': recommendations,
                'calculated_at': datetime.now(timezone.utc).isoformat()
            }

            logger.info(f"Risk score calculated: {risk_score:.2f} ({risk_level})")
            return result

        except Exception as e:
            logger.error(f"Error calculating risk score: {str(e)}")
            raise

    def _calculate_source_factor(self, threat: Dict[str, Any]) -> float:
        """Calculate source reliability factor"""
        source_name = threat.get('source_name', 'unknown').lower()

        # Find matching source weight
        source_weight = self.source_weights.get('unknown', 0.50)
        for source_key, weight in self.source_weights.items():
            if source_key in source_name:
                source_weight = weight
                break

        return source_weight * 100

    def _calculate_temporal_factor(self, threat: Dict[str, Any]) -> float:
        """Calculate temporal relevance factor"""
        try:
            created_date = datetime.fromisoformat(threat['created_date'].replace('Z', '+00:00'))
            now = datetime.now(timezone.utc)
            age_hours = (now - created_date).total_seconds() / 3600

            # Recent threats are more relevant
            if age_hours <= 1:
                return 100.0  # Very fresh
            elif age_hours <= 24:
                return 95.0   # Fresh
            elif age_hours <= 168:  # 1 week
                return 85.0   # Recent
            elif age_hours <= 720:  # 30 days
                return 70.0   # Moderately recent
            elif age_hours <= 2160:  # 90 days
                return 50.0   # Aging
            else:
                return 30.0   # Old
        except (KeyError, ValueError):
            return 50.0  # Unknown age

    def _calculate_geographic_factor(self, threat: Dict[str, Any]) -> float:
        """Calculate geographic risk factor"""
        try:
            enrichment_data = threat.get('enrichment_data', {})
            geolocation = enrichment_data.get('geolocation', {})

            if not geolocation:
                return 60.0  # Unknown location

            country = geolocation.get('country', '').lower()

            # High-risk countries (based on common threat origins)
            high_risk_countries = {
                'china', 'russia', 'north korea', 'iran', 'belarus',
                'syria', 'pakistan', 'ukraine', 'romania', 'brazil'
            }

            # Medium-risk countries
            medium_risk_countries = {
                'india', 'vietnam', 'turkey', 'egypt', 'indonesia',
                'nigeria', 'bangladesh', 'philippines', 'thailand'
            }

            if country in high_risk_countries:
                return 85.0
            elif country in medium_risk_countries:
                return 70.0
            else:
                return 50.0  # Low risk or unknown

        except Exception:
            return 60.0  # Default for unknown

    def _calculate_threat_type_factor(self, threat: Dict[str, Any]) -> float:
        """Calculate threat type severity factor"""
        labels = threat.get('labels', [])
        if not labels:
            return 50.0  # Unknown threat type

        max_severity = 1.0
        for label in labels:
            label_lower = label.lower()
            for threat_type, multiplier in self.threat_severity.items():
                if threat_type in label_lower:
                    max_severity = max(max_severity, multiplier)

        # Convert multiplier to 0-100 scale
        return min(100.0, max_severity * 50.0)

    def _calculate_correlation_factor(self, threat: Dict[str, Any],
                                    context: Optional[Dict[str, Any]]) -> float:
        """Calculate cross-source correlation factor"""
        if not context:
            return 50.0  # No correlation data

        correlations = context.get('correlations', [])
        if not correlations:
            return 50.0

        # Higher confidence if threat is correlated across multiple sources
        correlation_count = len(correlations)
        unique_sources = len(set(c.get('source', 'unknown') for c in correlations))

        if correlation_count >= 3 and unique_sources >= 2:
            return 95.0  # High correlation
        elif correlation_count >= 2:
            return 80.0  # Moderate correlation
        elif correlation_count >= 1:
            return 65.0  # Some correlation
        else:
            return 50.0  # No correlation

    def _calculate_consistency_factor(self, threat: Dict[str, Any]) -> float:
        """Calculate data consistency factor"""
        consistency_score = 100.0

        # Check for required fields
        required_fields = ['object_id', 'pattern', 'labels', 'confidence', 'created_date']
        missing_fields = sum(1 for field in required_fields if not threat.get(field))
        consistency_score -= missing_fields * 10

        # Check pattern validity
        pattern = threat.get('pattern', '')
        if pattern:
            # Basic STIX pattern validation
            if not (pattern.startswith('[') and pattern.endswith(']')):
                consistency_score -= 15

            # Check for valid observable types
            valid_patterns = ['domain-name:', 'ipv4-addr:', 'ipv6-addr:', 'url:', 'file:']
            if not any(vp in pattern for vp in valid_patterns):
                consistency_score -= 10

        # Check confidence value validity
        confidence = threat.get('confidence', 0)
        if not (0 <= confidence <= 100):
            consistency_score -= 20

        return max(0.0, min(100.0, consistency_score))

    def _calculate_urgency_factor(self, threat: Dict[str, Any]) -> float:
        """Calculate urgency factor based on threat characteristics"""
        urgency_score = 50.0  # Base urgency

        labels = threat.get('labels', [])
        description = threat.get('description', '').lower()

        # High urgency indicators
        high_urgency_terms = [
            'active', 'ongoing', 'current', 'live', 'zero-day',
            'exploit', 'breach', 'compromise', 'attack'
        ]

        # Check labels
        for label in labels:
            if any(term in label.lower() for term in high_urgency_terms):
                urgency_score += 20
                break

        # Check description
        if any(term in description for term in high_urgency_terms):
            urgency_score += 15

        # Recent creation indicates higher urgency
        try:
            created_date = datetime.fromisoformat(threat['created_date'].replace('Z', '+00:00'))
            age_hours = (datetime.now(timezone.utc) - created_date).total_seconds() / 3600
            if age_hours <= 6:
                urgency_score += 25
            elif age_hours <= 24:
                urgency_score += 15
        except Exception:
            pass

        return min(100.0, urgency_score)

    def _determine_risk_level(self, risk_score: float) -> str:
        """Determine risk level from numeric score"""
        if risk_score >= 85:
            return 'critical'
        elif risk_score >= 70:
            return 'high'
        elif risk_score >= 50:
            return 'medium'
        elif risk_score >= 30:
            return 'low'
        else:
            return 'minimal'

    def _assess_business_impact(self, threat: Dict[str, Any], risk_score: float) -> Dict[str, Any]:
        """Assess potential business impact"""
        impact_assessment = {
            'financial_risk': 'unknown',
            'operational_impact': 'unknown',
            'data_confidentiality': 'unknown',
            'reputation_risk': 'unknown',
            'compliance_impact': 'unknown',
            'overall_impact': 'unknown'
        }

        labels = threat.get('labels', [])
        pattern = threat.get('pattern', '').lower()
        description = threat.get('description', '').lower()

        # Assess financial risk
        financial_indicators = ['ransomware', 'cryptolocker', 'financial', 'banking', 'payment']
        if any(indicator in ' '.join(labels).lower() for indicator in financial_indicators):
            impact_assessment['financial_risk'] = 'high' if risk_score > 70 else 'medium'

        # Assess operational impact
        operational_indicators = ['backdoor', 'trojan', 'botnet', 'ddos', 'disruption']
        if any(indicator in ' '.join(labels).lower() for indicator in operational_indicators):
            impact_assessment['operational_impact'] = 'high' if risk_score > 70 else 'medium'

        # Assess data confidentiality
        data_indicators = ['exfiltration', 'data-theft', 'credential', 'personal', 'confidential']
        if any(indicator in description for indicator in data_indicators):
            impact_assessment['data_confidentiality'] = 'high' if risk_score > 70 else 'medium'

        # Assess reputation risk
        reputation_indicators = ['public', 'exposure', 'leak', 'breach', 'disclosure']
        if any(indicator in description for indicator in reputation_indicators):
            impact_assessment['reputation_risk'] = 'high' if risk_score > 70 else 'medium'

        # Overall impact based on risk score
        if risk_score >= 85:
            impact_assessment['overall_impact'] = 'critical'
        elif risk_score >= 70:
            impact_assessment['overall_impact'] = 'high'
        elif risk_score >= 50:
            impact_assessment['overall_impact'] = 'medium'
        else:
            impact_assessment['overall_impact'] = 'low'

        return impact_assessment

    def _generate_risk_recommendations(self, risk_level: str, threat: Dict[str, Any],
                                     context: Optional[Dict[str, Any]]) -> List[str]:
        """Generate actionable risk-based recommendations"""
        recommendations = []

        if risk_level == 'critical':
            recommendations.extend([
                "Immediate incident response activation required",
                "Deploy emergency countermeasures and monitoring",
                "Notify security team and stakeholders immediately",
                "Consider isolating affected systems",
                "Implement emergency threat hunting procedures"
            ])
        elif risk_level == 'high':
            recommendations.extend([
                "Urgent security review and enhanced monitoring required",
                "Deploy additional security controls and alerts",
                "Notify security team within 4 hours",
                "Review and update security policies",
                "Implement targeted threat hunting"
            ])
        elif risk_level == 'medium':
            recommendations.extend([
                "Enhanced monitoring and regular review recommended",
                "Update security signatures and rules",
                "Schedule security assessment within 48 hours",
                "Review related threats and patterns"
            ])
        elif risk_level == 'low':
            recommendations.extend([
                "Standard monitoring procedures sufficient",
                "Include in routine security reviews",
                "Update threat intelligence feeds"
            ])
        else:  # minimal
            recommendations.extend([
                "Low priority - routine monitoring only",
                "Include in periodic security reports"
            ])

        # Add specific recommendations based on threat characteristics
        labels = threat.get('labels', [])

        if 'phishing' in ' '.join(labels).lower():
            recommendations.append("Implement anti-phishing training and email security controls")

        if 'malware' in ' '.join(labels).lower():
            recommendations.append("Update antivirus signatures and endpoint protection")

        if 'backdoor' in ' '.join(labels).lower():
            recommendations.append("Conduct network segmentation review and access control audit")

        return recommendations

    def analyze_risk_distribution(self, filters: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Analyze risk distribution across threat intelligence data

        Args:
            filters: Optional filters for analysis scope

        Returns:
            Dictionary containing risk distribution analysis
        """
        try:
            logger.info("Starting risk distribution analysis")

            # Query threat intelligence data
            scan_params = {}

            # Apply filters if provided
            if filters:
                filter_expressions = []
                expression_values = {}

                for key, value in filters.items():
                    if key == 'source':
                        filter_expressions.append(f"source_name = :{key}")
                        expression_values[f':{key}'] = value
                    elif key == 'threat_type':
                        filter_expressions.append(f"contains(labels, :{key})")
                        expression_values[f':{key}'] = value
                    elif key == 'min_confidence':
                        filter_expressions.append(f"confidence >= :{key}")
                        expression_values[f':{key}'] = Decimal(str(value))

                if filter_expressions:
                    scan_params['FilterExpression'] = ' AND '.join(filter_expressions)
                    scan_params['ExpressionAttributeValues'] = expression_values

            # Execute scan with pagination
            threats = []
            response = threat_intel_table.scan(**scan_params)
            threats.extend(response.get('Items', []))

            while 'LastEvaluatedKey' in response and len(threats) < MAX_ANALYTICS_RESULTS:
                scan_params['ExclusiveStartKey'] = response['LastEvaluatedKey']
                response = threat_intel_table.scan(**scan_params)
                threats.extend(response.get('Items', []))

            logger.info(f"Analyzing risk distribution for {len(threats)} threats")

            # Calculate enhanced risk scores for all threats
            risk_scores = []
            risk_levels = defaultdict(int)
            source_risks = defaultdict(list)
            threat_type_risks = defaultdict(list)

            for threat in threats:
                risk_result = self.calculate_enhanced_risk_score(threat)

                risk_score = risk_result['enhanced_risk_score']
                risk_level = risk_result['risk_level']

                risk_scores.append(risk_score)
                risk_levels[risk_level] += 1

                source = threat.get('source_name', 'unknown')
                source_risks[source].append(risk_score)

                for label in threat.get('labels', []):
                    threat_type_risks[label].append(risk_score)

            # Calculate distribution statistics
            if risk_scores:
                avg_risk = sum(risk_scores) / len(risk_scores)
                median_risk = sorted(risk_scores)[len(risk_scores) // 2]
                max_risk = max(risk_scores)
                min_risk = min(risk_scores)

                # Calculate percentiles
                sorted_scores = sorted(risk_scores)
                p95 = sorted_scores[int(0.95 * len(sorted_scores))]
                p75 = sorted_scores[int(0.75 * len(sorted_scores))]
                p25 = sorted_scores[int(0.25 * len(sorted_scores))]
            else:
                avg_risk = median_risk = max_risk = min_risk = p95 = p75 = p25 = 0

            # Analyze source risk patterns
            source_analysis = {}
            for source, scores in source_risks.items():
                if scores:
                    source_analysis[source] = {
                        'threat_count': len(scores),
                        'average_risk': round(sum(scores) / len(scores), 2),
                        'max_risk': round(max(scores), 2),
                        'high_risk_count': sum(1 for s in scores if s >= 70)
                    }

            # Analyze threat type risk patterns
            threat_type_analysis = {}
            for threat_type, scores in threat_type_risks.items():
                if scores:
                    threat_type_analysis[threat_type] = {
                        'threat_count': len(scores),
                        'average_risk': round(sum(scores) / len(scores), 2),
                        'max_risk': round(max(scores), 2),
                        'high_risk_count': sum(1 for s in scores if s >= 70)
                    }

            result = {
                'total_threats_analyzed': len(threats),
                'risk_distribution': {
                    'average_risk': round(avg_risk, 2),
                    'median_risk': round(median_risk, 2),
                    'maximum_risk': round(max_risk, 2),
                    'minimum_risk': round(min_risk, 2),
                    'percentiles': {
                        'p95': round(p95, 2),
                        'p75': round(p75, 2),
                        'p25': round(p25, 2)
                    }
                },
                'risk_levels': dict(risk_levels),
                'source_analysis': dict(sorted(source_analysis.items(),
                                             key=lambda x: x[1]['average_risk'], reverse=True)),
                'threat_type_analysis': dict(sorted(threat_type_analysis.items(),
                                                  key=lambda x: x[1]['average_risk'], reverse=True)[:20]),
                'high_risk_summary': {
                    'critical_threats': risk_levels['critical'],
                    'high_risk_threats': risk_levels['high'],
                    'percentage_high_risk': round((risk_levels['critical'] + risk_levels['high']) / len(threats) * 100, 2) if threats else 0
                },
                'generated_at': datetime.now(timezone.utc).isoformat()
            }

            logger.info(f"Risk distribution analysis completed: {avg_risk:.2f} average risk")
            return result

        except Exception as e:
            logger.error(f"Error in risk distribution analysis: {str(e)}")
            raise


class CorrelationIntelligenceEngine:
    """Advanced cross-source correlation and threat relationship analysis"""

    def __init__(self):
        self.cache_ttl = timedelta(hours=ANALYTICS_CACHE_TTL_HOURS)

        # Correlation type weights for confidence calculation
        self.correlation_weights = {
            'exact_match': 1.0,
            'infrastructure_overlap': 0.9,
            'temporal_correlation': 0.7,
            'pattern_similarity': 0.8,
            'behavioral_similarity': 0.85,
            'attribution_link': 0.9,
            'semantic_similarity': 0.6
        }

        # Minimum confidence threshold for correlation results
        self.min_correlation_confidence = MIN_CORRELATION_CONFIDENCE

    def analyze_cross_source_correlations(self, filters: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Analyze correlations between threats from different sources

        Args:
            filters: Optional filters for analysis scope

        Returns:
            Dictionary containing correlation analysis results
        """
        try:
            logger.info("Starting cross-source correlation analysis")

            # Query threat intelligence data
            scan_params = {}

            # Apply filters if provided
            if filters:
                filter_expressions = []
                expression_values = {}

                for key, value in filters.items():
                    if key == 'source':
                        filter_expressions.append(f"source_name = :{key}")
                        expression_values[f':{key}'] = value
                    elif key == 'threat_type':
                        filter_expressions.append(f"contains(labels, :{key})")
                        expression_values[f':{key}'] = value
                    elif key == 'min_confidence':
                        filter_expressions.append(f"confidence >= :{key}")
                        expression_values[f':{key}'] = Decimal(str(value))

                if filter_expressions:
                    scan_params['FilterExpression'] = ' AND '.join(filter_expressions)
                    scan_params['ExpressionAttributeValues'] = expression_values

            # Execute scan with pagination
            threats = []
            response = threat_intel_table.scan(**scan_params)
            threats.extend(response.get('Items', []))

            while 'LastEvaluatedKey' in response and len(threats) < MAX_ANALYTICS_RESULTS:
                scan_params['ExclusiveStartKey'] = response['LastEvaluatedKey']
                response = threat_intel_table.scan(**scan_params)
                threats.extend(response.get('Items', []))

            logger.info(f"Analyzing correlations for {len(threats)} threats")

            # Group threats by source for cross-source analysis
            threats_by_source = defaultdict(list)
            for threat in threats:
                source = threat.get('source_name', 'unknown')
                threats_by_source[source].append(threat)

            # Find correlations between different sources
            correlations = []
            source_pairs = []

            sources = list(threats_by_source.keys())
            for i in range(len(sources)):
                for j in range(i + 1, len(sources)):
                    source_pairs.append((sources[i], sources[j]))

            for source1, source2 in source_pairs:
                threats1 = threats_by_source[source1]
                threats2 = threats_by_source[source2]

                pair_correlations = self._find_correlations_between_sources(
                    threats1, threats2, source1, source2
                )
                correlations.extend(pair_correlations)

            # Analyze correlation patterns
            correlation_analysis = self._analyze_correlation_patterns(correlations)

            # Identify threat campaigns
            campaigns = self._identify_correlated_campaigns(correlations, threats)

            # Build relationship graph
            relationship_graph = self._build_relationship_graph(correlations)

            result = {
                'total_threats_analyzed': len(threats),
                'total_correlations_found': len(correlations),
                'source_pairs_analyzed': len(source_pairs),
                'correlations': [asdict(c) for c in correlations[:100]],  # Top 100 correlations
                'correlation_analysis': correlation_analysis,
                'identified_campaigns': [asdict(c) for c in campaigns],
                'relationship_graph': relationship_graph,
                'cross_source_summary': self._generate_correlation_summary(correlations, threats_by_source),
                'generated_at': datetime.now(timezone.utc).isoformat()
            }

            logger.info(f"Correlation analysis completed: {len(correlations)} correlations found")
            return result

        except Exception as e:
            logger.error(f"Error in correlation analysis: {str(e)}")
            raise

    def _find_correlations_between_sources(self, threats1: List[Dict], threats2: List[Dict],
                                          source1: str, source2: str) -> List[CorrelationResult]:
        """Find correlations between threats from two different sources"""
        correlations = []

        for threat1 in threats1:
            for threat2 in threats2:
                correlation = self._analyze_threat_pair(threat1, threat2, source1, source2)
                if correlation and correlation.confidence >= self.min_correlation_confidence:
                    correlations.append(correlation)

        return correlations

    def _analyze_threat_pair(self, threat1: Dict, threat2: Dict,
                           source1: str, source2: str) -> Optional[CorrelationResult]:
        """Analyze correlation between two specific threats"""
        correlation_factors = []
        evidence = []
        shared_attributes = {}

        # Extract observables from patterns
        observables1 = self._extract_observables(threat1.get('pattern', ''))
        observables2 = self._extract_observables(threat2.get('pattern', ''))

        # 1. Exact observable match
        exact_matches = observables1 & observables2
        if exact_matches:
            correlation_factors.append(('exact_match', len(exact_matches) / max(len(observables1), len(observables2))))
            evidence.extend([f"Exact observable match: {obs}" for obs in list(exact_matches)[:3]])
            shared_attributes['exact_observables'] = list(exact_matches)

        # 2. Infrastructure overlap (IP subnets, domain patterns)
        infra_overlap = self._detect_infrastructure_overlap(observables1, observables2)
        if infra_overlap['score'] > 0:
            correlation_factors.append(('infrastructure_overlap', infra_overlap['score']))
            evidence.extend(infra_overlap['evidence'])
            shared_attributes.update(infra_overlap['attributes'])

        # 3. Temporal correlation
        temporal_score = self._calculate_temporal_correlation(threat1, threat2)
        if temporal_score > 0.3:
            correlation_factors.append(('temporal_correlation', temporal_score))
            evidence.append(f"Temporal correlation score: {temporal_score:.2f}")

        # 4. Pattern similarity
        pattern_similarity = self._calculate_pattern_similarity(
            threat1.get('pattern', ''), threat2.get('pattern', '')
        )
        if pattern_similarity > 0.5:
            correlation_factors.append(('pattern_similarity', pattern_similarity))
            evidence.append(f"Pattern similarity: {pattern_similarity:.2f}")

        # 5. Behavioral similarity (labels/techniques)
        behavioral_score = self._calculate_behavioral_similarity(threat1, threat2)
        if behavioral_score > 0.4:
            correlation_factors.append(('behavioral_similarity', behavioral_score))
            evidence.append(f"Behavioral similarity: {behavioral_score:.2f}")
            shared_attributes['shared_behaviors'] = self._get_shared_labels(threat1, threat2)

        # 6. Attribution links
        attribution_score = self._detect_attribution_links(threat1, threat2)
        if attribution_score > 0.3:
            correlation_factors.append(('attribution_link', attribution_score))
            evidence.append(f"Attribution link detected: {attribution_score:.2f}")

        # 7. Semantic similarity (descriptions)
        semantic_score = self._calculate_semantic_similarity(threat1, threat2)
        if semantic_score > 0.4:
            correlation_factors.append(('semantic_similarity', semantic_score))
            evidence.append(f"Semantic similarity: {semantic_score:.2f}")

        # Calculate overall correlation confidence
        if not correlation_factors:
            return None

        weighted_confidence = sum(
            score * self.correlation_weights[factor_type]
            for factor_type, score in correlation_factors
        ) / len(correlation_factors)

        if weighted_confidence < self.min_correlation_confidence:
            return None

        # Determine correlation type
        correlation_type = self._determine_correlation_type(correlation_factors)

        # Create timeline
        timeline = []
        try:
            time1 = datetime.fromisoformat(threat1['created_date'].replace('Z', '+00:00'))
            time2 = datetime.fromisoformat(threat2['created_date'].replace('Z', '+00:00'))
            timeline = sorted([time1, time2])
        except Exception:
            pass

        return CorrelationResult(
            correlation_id=hashlib.sha256(
                f"{threat1.get('object_id', '')}-{threat2.get('object_id', '')}".encode()
            ).hexdigest()[:16],
            indicator_pairs=[(threat1.get('object_id', 'unknown'), threat2.get('object_id', 'unknown'))],
            correlation_type=correlation_type,
            confidence=round(weighted_confidence, 3),
            evidence=evidence,
            timeline=timeline,
            shared_attributes=shared_attributes
        )

    def _extract_observables(self, pattern: str) -> set:
        """Extract observables from STIX pattern"""
        observables = set()

        if not pattern:
            return observables

        # Extract domains
        domain_matches = re.findall(r"domain-name:value\s*=\s*'([^']+)'", pattern)
        observables.update(domain_matches)

        # Extract IPs
        ip_matches = re.findall(r"ipv[46]?-addr:value\s*=\s*'([^']+)'", pattern)
        observables.update(ip_matches)

        # Extract URLs
        url_matches = re.findall(r"url:value\s*=\s*'([^']+)'", pattern)
        observables.update(url_matches)

        # Extract file hashes
        hash_matches = re.findall(r"file:hashes\.(?:MD5|SHA-1|SHA-256)\s*=\s*'([^']+)'", pattern)
        observables.update(hash_matches)

        # Extract email addresses
        email_matches = re.findall(r"email-addr:value\s*=\s*'([^']+)'", pattern)
        observables.update(email_matches)

        return observables

    def _detect_infrastructure_overlap(self, observables1: set, observables2: set) -> Dict[str, Any]:
        """Detect infrastructure overlap between observable sets"""
        overlap_score = 0.0
        evidence = []
        attributes = {}

        # Direct overlap
        direct_overlap = observables1 & observables2
        if direct_overlap:
            overlap_score += 0.8
            evidence.extend([f"Direct infrastructure overlap: {obs}" for obs in list(direct_overlap)[:3]])

        # IP subnet overlap
        ips1 = {obs for obs in observables1 if self._is_ip_address(obs)}
        ips2 = {obs for obs in observables2 if self._is_ip_address(obs)}

        subnet_overlap = self._find_subnet_overlap(ips1, ips2)
        if subnet_overlap:
            overlap_score += 0.6
            evidence.append(f"IP subnet overlap detected: {len(subnet_overlap)} subnets")
            attributes['shared_subnets'] = subnet_overlap

        # Domain pattern overlap
        domains1 = {obs for obs in observables1 if self._is_domain(obs)}
        domains2 = {obs for obs in observables2 if self._is_domain(obs)}

        domain_patterns = self._find_domain_patterns(domains1, domains2)
        if domain_patterns:
            overlap_score += 0.5
            evidence.append(f"Domain pattern overlap: {len(domain_patterns)} patterns")
            attributes['shared_domain_patterns'] = domain_patterns

        return {
            'score': min(1.0, overlap_score),
            'evidence': evidence,
            'attributes': attributes
        }

    def _is_ip_address(self, value: str) -> bool:
        """Check if value is an IP address"""
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    def _is_domain(self, value: str) -> bool:
        """Check if value is a domain name"""
        domain_pattern = re.compile(
            r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        )
        return bool(domain_pattern.match(value)) and '.' in value

    def _find_subnet_overlap(self, ips1: set, ips2: set) -> List[str]:
        """Find overlapping IP subnets"""
        subnets = []

        for ip1 in ips1:
            for ip2 in ips2:
                try:
                    addr1 = ipaddress.ip_address(ip1)
                    addr2 = ipaddress.ip_address(ip2)

                    # Check /24 subnet overlap
                    if isinstance(addr1, ipaddress.IPv4Address) and isinstance(addr2, ipaddress.IPv4Address):
                        subnet1 = ipaddress.ip_network(f"{ip1}/24", strict=False)
                        subnet2 = ipaddress.ip_network(f"{ip2}/24", strict=False)

                        if subnet1 == subnet2:
                            subnets.append(str(subnet1))
                except ValueError:
                    continue

        return list(set(subnets))

    def _find_domain_patterns(self, domains1: set, domains2: set) -> List[str]:
        """Find shared domain patterns"""
        patterns = []

        # Extract TLDs
        tlds1 = {domain.split('.')[-1] for domain in domains1 if '.' in domain}
        tlds2 = {domain.split('.')[-1] for domain in domains2 if '.' in domain}
        shared_tlds = tlds1 & tlds2
        patterns.extend([f"TLD: .{tld}" for tld in shared_tlds])

        # Extract domain patterns (length, character patterns)
        for domain1 in domains1:
            for domain2 in domains2:
                if self._similar_domain_pattern(domain1, domain2):
                    patterns.append(f"Similar pattern: {domain1} ~ {domain2}")

        return list(set(patterns))

    def _similar_domain_pattern(self, domain1: str, domain2: str) -> bool:
        """Check if two domains have similar patterns"""
        # Check if domains have similar length and character patterns
        if abs(len(domain1) - len(domain2)) > 5:
            return False

        # Check for similar character patterns (letters, numbers, hyphens)
        pattern1 = re.sub(r'[a-z]', 'L', re.sub(r'[0-9]', 'N', domain1.lower()))
        pattern2 = re.sub(r'[a-z]', 'L', re.sub(r'[0-9]', 'N', domain2.lower()))

        # Calculate pattern similarity
        return self._calculate_string_similarity(pattern1, pattern2) > 0.7

    def _calculate_temporal_correlation(self, threat1: Dict, threat2: Dict) -> float:
        """Calculate temporal correlation between two threats"""
        try:
            time1 = datetime.fromisoformat(threat1['created_date'].replace('Z', '+00:00'))
            time2 = datetime.fromisoformat(threat2['created_date'].replace('Z', '+00:00'))

            time_diff = abs((time1 - time2).total_seconds())

            # Correlation score based on time proximity
            if time_diff <= 3600:  # 1 hour
                return 1.0
            elif time_diff <= 86400:  # 1 day
                return 0.9
            elif time_diff <= 604800:  # 1 week
                return 0.7
            elif time_diff <= 2592000:  # 30 days
                return 0.5
            elif time_diff <= 7776000:  # 90 days
                return 0.3
            else:
                return 0.1

        except Exception:
            return 0.0

    def _calculate_pattern_similarity(self, pattern1: str, pattern2: str) -> float:
        """Calculate similarity between STIX patterns"""
        if not pattern1 or not pattern2:
            return 0.0

        # Extract pattern components
        components1 = self._extract_pattern_components(pattern1)
        components2 = self._extract_pattern_components(pattern2)

        if not components1 or not components2:
            return 0.0

        # Calculate Jaccard similarity
        intersection = len(components1 & components2)
        union = len(components1 | components2)

        return intersection / union if union > 0 else 0.0

    def _extract_pattern_components(self, pattern: str) -> set:
        """Extract components from STIX pattern for comparison"""
        components = set()

        # Extract observable types
        observable_types = re.findall(r'([a-z-]+):(?:value|hashes)', pattern)
        components.update([f"type:{otype}" for otype in observable_types])

        # Extract operators
        operators = re.findall(r'\s(AND|OR|NOT)\s', pattern)
        components.update([f"op:{op}" for op in operators])

        # Extract value patterns (generalized)
        values = re.findall(r"'([^']+)'", pattern)
        for value in values:
            # Generalize values to patterns
            if self._is_ip_address(value):
                components.add("pattern:ip")
            elif self._is_domain(value):
                components.add("pattern:domain")
            elif '@' in value:
                components.add("pattern:email")
            elif len(value) == 32 and all(c in '0123456789abcdef' for c in value.lower()):
                components.add("pattern:md5")
            elif len(value) == 64 and all(c in '0123456789abcdef' for c in value.lower()):
                components.add("pattern:sha256")

        return components

    def _calculate_behavioral_similarity(self, threat1: Dict, threat2: Dict) -> float:
        """Calculate behavioral similarity based on labels and techniques"""
        labels1 = set(threat1.get('labels', []))
        labels2 = set(threat2.get('labels', []))

        if not labels1 or not labels2:
            return 0.0

        # Calculate Jaccard similarity for labels
        intersection = len(labels1 & labels2)
        union = len(labels1 | labels2)

        return intersection / union if union > 0 else 0.0

    def _get_shared_labels(self, threat1: Dict, threat2: Dict) -> List[str]:
        """Get shared labels between two threats"""
        labels1 = set(threat1.get('labels', []))
        labels2 = set(threat2.get('labels', []))
        return list(labels1 & labels2)

    def _detect_attribution_links(self, threat1: Dict, threat2: Dict) -> float:
        """Detect potential attribution links between threats"""
        attribution_score = 0.0

        # Check descriptions for attribution indicators
        desc1 = threat1.get('description', '').lower()
        desc2 = threat2.get('description', '').lower()

        attribution_keywords = [
            'apt', 'group', 'actor', 'campaign', 'operation', 'team',
            'lazarus', 'fancy bear', 'cozy bear', 'equation', 'carbanak'
        ]

        for keyword in attribution_keywords:
            if keyword in desc1 and keyword in desc2:
                attribution_score += 0.3

        # Check for shared tactics/techniques references
        technique_patterns = [
            r't\d{4}',  # MITRE ATT&CK technique IDs
            r'ta\d{4}', # MITRE ATT&CK tactic IDs
        ]

        for pattern in technique_patterns:
            techniques1 = set(re.findall(pattern, desc1))
            techniques2 = set(re.findall(pattern, desc2))

            if techniques1 & techniques2:
                attribution_score += 0.4

        return min(1.0, attribution_score)

    def _calculate_semantic_similarity(self, threat1: Dict, threat2: Dict) -> float:
        """Calculate semantic similarity between threat descriptions"""
        desc1 = threat1.get('description', '').lower()
        desc2 = threat2.get('description', '').lower()

        if not desc1 or not desc2:
            return 0.0

        # Simple word-based similarity (would be enhanced with NLP in production)
        words1 = set(re.findall(r'\b\w+\b', desc1))
        words2 = set(re.findall(r'\b\w+\b', desc2))

        # Remove common words
        stop_words = {'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by'}
        words1 -= stop_words
        words2 -= stop_words

        if not words1 or not words2:
            return 0.0

        # Calculate Jaccard similarity
        intersection = len(words1 & words2)
        union = len(words1 | words2)

        return intersection / union if union > 0 else 0.0

    def _calculate_string_similarity(self, str1: str, str2: str) -> float:
        """Calculate string similarity using difflib"""
        return difflib.SequenceMatcher(None, str1, str2).ratio()

    def _determine_correlation_type(self, correlation_factors: List[Tuple[str, float]]) -> str:
        """Determine the primary correlation type"""
        if not correlation_factors:
            return 'unknown'

        # Find the strongest correlation factor
        strongest_factor = max(correlation_factors, key=lambda x: x[1])
        return strongest_factor[0]

    def _analyze_correlation_patterns(self, correlations: List[CorrelationResult]) -> Dict[str, Any]:
        """Analyze patterns in correlation results"""
        if not correlations:
            return {'pattern': 'no_correlations'}

        # Count correlation types
        correlation_types = Counter(c.correlation_type for c in correlations)

        # Calculate average confidence by type
        type_confidences = defaultdict(list)
        for correlation in correlations:
            type_confidences[correlation.correlation_type].append(correlation.confidence)

        avg_confidences = {
            ctype: sum(confidences) / len(confidences)
            for ctype, confidences in type_confidences.items()
        }

        # Find high-confidence correlations
        high_confidence_correlations = [c for c in correlations if c.confidence >= 0.8]

        # Identify correlation clusters
        clusters = self._identify_correlation_clusters(correlations)

        return {
            'total_correlations': len(correlations),
            'correlation_types': dict(correlation_types),
            'average_confidence_by_type': {k: round(v, 3) for k, v in avg_confidences.items()},
            'high_confidence_correlations': len(high_confidence_correlations),
            'correlation_clusters': len(clusters),
            'strongest_correlation_type': correlation_types.most_common(1)[0][0] if correlation_types else 'none',
            'overall_average_confidence': round(sum(c.confidence for c in correlations) / len(correlations), 3)
        }

    def _identify_correlation_clusters(self, correlations: List[CorrelationResult]) -> List[Dict[str, Any]]:
        """Identify clusters of highly correlated threats"""
        # Group correlations by shared indicators
        threat_connections = defaultdict(set)

        for correlation in correlations:
            for pair in correlation.indicator_pairs:
                threat_connections[pair[0]].add(pair[1])
                threat_connections[pair[1]].add(pair[0])

        # Find connected components (clusters)
        clusters = []
        visited = set()

        for threat_id in threat_connections:
            if threat_id not in visited:
                cluster = self._find_connected_threats(threat_id, threat_connections, visited)
                if len(cluster) >= 3:  # Minimum cluster size
                    clusters.append({
                        'cluster_id': f"cluster-{len(clusters)}",
                        'threat_count': len(cluster),
                        'threats': list(cluster),
                        'internal_correlations': sum(1 for c in correlations
                                                   if all(t in cluster for pair in c.indicator_pairs for t in pair))
                    })

        return clusters

    def _find_connected_threats(self, start_threat: str, connections: Dict,
                              visited: set) -> set:
        """Find all threats connected to a starting threat"""
        cluster = set()
        stack = [start_threat]

        while stack:
            current = stack.pop()
            if current not in visited:
                visited.add(current)
                cluster.add(current)
                stack.extend(connections[current] - visited)

        return cluster

    def _identify_correlated_campaigns(self, correlations: List[CorrelationResult],
                                     threats: List[Dict]) -> List[ThreatCampaign]:
        """Identify potential threat campaigns from correlation data"""
        campaigns = []

        # Find high-confidence correlation clusters
        clusters = self._identify_correlation_clusters([c for c in correlations if c.confidence >= 0.7])

        for i, cluster in enumerate(clusters):
            if cluster['threat_count'] >= 5:  # Minimum threats for campaign
                # Get threat details for cluster
                cluster_threats = []
                for threat in threats:
                    if threat.get('object_id') in cluster['threats']:
                        cluster_threats.append(threat)

                if len(cluster_threats) >= 5:
                    # Analyze campaign characteristics
                    start_times = []
                    end_times = []
                    techniques = set()
                    sources = set()

                    for threat in cluster_threats:
                        try:
                            time = datetime.fromisoformat(threat['created_date'].replace('Z', '+00:00'))
                            start_times.append(time)
                            end_times.append(time)
                        except Exception:
                            pass

                        if 'labels' in threat:
                            techniques.update(threat['labels'])

                        sources.add(threat.get('source_name', 'unknown'))

                    if start_times:
                        campaign = ThreatCampaign(
                            campaign_id=f"corr-campaign-{i}",
                            name=f"Correlated-Campaign-{i}",
                            start_date=min(start_times),
                            end_date=max(end_times),
                            indicators=[t.get('object_id', '') for t in cluster_threats],
                            confidence=cluster['internal_correlations'] / cluster['threat_count'] * 100,
                            attribution=None,
                            techniques=list(techniques)[:10],
                            geographic_scope=[]  # Would be filled by geographic analysis
                        )
                        campaigns.append(campaign)

        return campaigns

    def _build_relationship_graph(self, correlations: List[CorrelationResult]) -> Dict[str, Any]:
        """Build a relationship graph from correlation data"""
        nodes = set()
        edges = []

        for correlation in correlations:
            for pair in correlation.indicator_pairs:
                nodes.add(pair[0])
                nodes.add(pair[1])
                edges.append({
                    'source': pair[0],
                    'target': pair[1],
                    'correlation_type': correlation.correlation_type,
                    'confidence': correlation.confidence,
                    'correlation_id': correlation.correlation_id
                })

        return {
            'node_count': len(nodes),
            'edge_count': len(edges),
            'nodes': list(nodes)[:100],  # Limit for performance
            'edges': edges[:200],  # Limit for performance
            'density': len(edges) / (len(nodes) * (len(nodes) - 1) / 2) if len(nodes) > 1 else 0,
            'avg_connections_per_node': len(edges) * 2 / len(nodes) if nodes else 0
        }

    def _generate_correlation_summary(self, correlations: List[CorrelationResult],
                                    threats_by_source: Dict[str, List[Dict]]) -> Dict[str, Any]:
        """Generate executive summary of correlation analysis"""
        if not correlations:
            return {'status': 'no_correlations'}

        # Source correlation matrix
        source_pairs = defaultdict(int)
        for correlation in correlations:
            # Infer sources from correlation (would be enhanced with source tracking)
            source_pairs['cross_source'] += 1

        # High-confidence correlations
        high_conf_count = sum(1 for c in correlations if c.confidence >= 0.8)
        medium_conf_count = sum(1 for c in correlations if 0.6 <= c.confidence < 0.8)

        # Most common correlation types
        correlation_types = Counter(c.correlation_type for c in correlations)

        return {
            'total_sources_analyzed': len(threats_by_source),
            'correlation_strength': {
                'high_confidence': high_conf_count,
                'medium_confidence': medium_conf_count,
                'total_correlations': len(correlations)
            },
            'primary_correlation_types': dict(correlation_types.most_common(5)),
            'cross_source_coverage': len([s for s in threats_by_source.values() if len(s) > 0]),
            'recommendation': self._generate_correlation_recommendation(correlations, correlation_types)
        }

    def _generate_correlation_recommendation(self, correlations: List[CorrelationResult],
                                           correlation_types: Counter) -> str:
        """Generate recommendations based on correlation analysis"""
        high_conf_count = sum(1 for c in correlations if c.confidence >= 0.8)

        if high_conf_count >= 10:
            return "Strong cross-source correlations detected. Investigate potential coordinated campaigns."
        elif high_conf_count >= 5:
            return "Moderate correlations found. Monitor for developing threat patterns."
        elif correlation_types.get('infrastructure_overlap', 0) > 5:
            return "Infrastructure overlap detected. Review shared threat infrastructure."
        elif correlation_types.get('temporal_correlation', 0) > 5:
            return "Temporal clustering detected. Investigate time-based threat patterns."
        else:
            return "Limited correlations found. Continue standard monitoring and analysis."


class AnalyticsCacheManager:
    """Intelligent caching system for analytics results"""

    def __init__(self):
        self.cache_enabled = ENABLE_ANALYTICS_CACHE and analytics_cache_table is not None
        self.compression_enabled = CACHE_COMPRESSION_ENABLED
        self.ttl_seconds = RESULT_CACHE_TTL_MINUTES * 60
        self.max_entries = MAX_CACHE_ENTRIES

    def get_cached_result(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Retrieve cached analytics result"""
        if not self.cache_enabled:
            return None

        try:
            start_time = time.time()

            response = analytics_cache_table.get_item(
                Key={'cache_key': cache_key}
            )

            if 'Item' not in response:
                return None

            item = response['Item']

            # Check TTL
            if 'ttl' in item and item['ttl'] < int(time.time()):
                # Expired - delete and return None
                self._delete_cache_entry(cache_key)
                return None

            # Decompress if needed
            cached_data = item['result_data']
            if self.compression_enabled and item.get('compressed', False):
                cached_data = self._decompress_data(cached_data)

            retrieval_time = (time.time() - start_time) * 1000
            logger.info(f"Cache hit for key {cache_key[:20]}... (retrieval: {retrieval_time:.2f}ms)")

            return json.loads(cached_data) if isinstance(cached_data, str) else cached_data

        except Exception as e:
            logger.warning(f"Error retrieving from cache: {str(e)}")
            return None

    def store_result(self, cache_key: str, result: Dict[str, Any], custom_ttl_minutes: Optional[int] = None) -> None:
        """Store analytics result in cache"""
        if not self.cache_enabled:
            return

        try:
            start_time = time.time()

            # Serialize result
            result_data = json.dumps(result, default=str)

            # Check size limit
            size_mb = len(result_data) / (1024 * 1024)
            if size_mb > QUERY_CACHE_SIZE_LIMIT_MB:
                logger.warning(f"Result too large for cache: {size_mb:.2f}MB > {QUERY_CACHE_SIZE_LIMIT_MB}MB")
                return

            # Compress if enabled and beneficial
            compressed = False
            if self.compression_enabled and len(result_data) > 1024:  # Only compress if > 1KB
                compressed_data = self._compress_data(result_data)
                if len(compressed_data) < len(result_data) * 0.8:  # Only use if 20%+ compression
                    result_data = compressed_data
                    compressed = True

            # Calculate TTL
            ttl_seconds = (custom_ttl_minutes or RESULT_CACHE_TTL_MINUTES) * 60
            ttl_timestamp = int(time.time()) + ttl_seconds

            # Store in cache
            analytics_cache_table.put_item(
                Item={
                    'cache_key': cache_key,
                    'result_data': result_data,
                    'compressed': compressed,
                    'ttl': ttl_timestamp,
                    'created_at': datetime.now(timezone.utc).isoformat(),
                    'size_bytes': len(result_data),
                    'original_size_bytes': len(json.dumps(result, default=str))
                }
            )

            storage_time = (time.time() - start_time) * 1000
            compression_ratio = len(result_data) / len(json.dumps(result, default=str)) if compressed else 1.0

            logger.info(f"Cached result for key {cache_key[:20]}... "
                       f"(storage: {storage_time:.2f}ms, compression: {compression_ratio:.2f})")

            # Cleanup old entries if needed
            self._cleanup_cache_if_needed()

        except Exception as e:
            logger.warning(f"Error storing to cache: {str(e)}")

    def generate_cache_key(self, analytics_type: str, parameters: Dict[str, Any],
                          filters: Optional[Dict[str, Any]] = None) -> str:
        """Generate consistent cache key for analytics query"""
        # Create deterministic key from parameters
        key_components = [
            analytics_type,
            str(sorted(parameters.items()) if parameters else ''),
            str(sorted(filters.items()) if filters else '')
        ]

        key_string = '|'.join(key_components)
        cache_key = hashlib.sha256(key_string.encode()).hexdigest()

        return f"analytics:{analytics_type}:{cache_key[:16]}"

    def invalidate_cache_pattern(self, pattern: str) -> int:
        """Invalidate cache entries matching pattern"""
        if not self.cache_enabled:
            return 0

        try:
            # Scan for matching keys (limited implementation)
            response = analytics_cache_table.scan(
                FilterExpression='begins_with(cache_key, :pattern)',
                ExpressionAttributeValues={':pattern': pattern},
                ProjectionExpression='cache_key'
            )

            deleted_count = 0
            for item in response.get('Items', []):
                self._delete_cache_entry(item['cache_key'])
                deleted_count += 1

            logger.info(f"Invalidated {deleted_count} cache entries matching pattern: {pattern}")
            return deleted_count

        except Exception as e:
            logger.warning(f"Error invalidating cache pattern {pattern}: {str(e)}")
            return 0

    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache performance statistics"""
        if not self.cache_enabled:
            return {'cache_enabled': False}

        try:
            # Get basic table statistics
            table_info = analytics_cache_table.describe()

            return {
                'cache_enabled': True,
                'table_status': table_info['Table']['TableStatus'],
                'item_count': table_info['Table']['ItemCount'],
                'table_size_bytes': table_info['Table']['TableSizeBytes'],
                'compression_enabled': self.compression_enabled,
                'ttl_minutes': RESULT_CACHE_TTL_MINUTES,
                'max_entries': self.max_entries
            }

        except Exception as e:
            logger.warning(f"Error getting cache stats: {str(e)}")
            return {'cache_enabled': True, 'error': str(e)}

    def _compress_data(self, data: str) -> bytes:
        """Compress data using gzip"""
        import gzip
        return gzip.compress(data.encode('utf-8'))

    def _decompress_data(self, data: bytes) -> str:
        """Decompress gzipped data"""
        import gzip
        return gzip.decompress(data).decode('utf-8')

    def _delete_cache_entry(self, cache_key: str) -> None:
        """Delete specific cache entry"""
        try:
            analytics_cache_table.delete_item(Key={'cache_key': cache_key})
        except Exception as e:
            logger.warning(f"Error deleting cache entry {cache_key}: {str(e)}")

    def _cleanup_cache_if_needed(self) -> None:
        """Cleanup old cache entries if approaching limits"""
        try:
            # Simple cleanup: let DynamoDB TTL handle most cleanup
            # This could be enhanced with more sophisticated eviction policies
            pass
        except Exception as e:
            logger.warning(f"Error during cache cleanup: {str(e)}")


class PerformanceOptimizer:
    """Performance optimization utilities for analytics processing"""

    def __init__(self):
        self.query_stats = defaultdict(list)
        self.optimization_enabled = True

    def optimize_query_execution(self, query_func, *args, **kwargs) -> Any:
        """Execute query with performance optimizations"""
        start_time = time.time()

        try:
            # Execute the query
            result = query_func(*args, **kwargs)

            # Record performance metrics
            execution_time = (time.time() - start_time) * 1000
            self._record_query_performance(query_func.__name__, execution_time, len(args) + len(kwargs))

            return result

        except Exception as e:
            execution_time = (time.time() - start_time) * 1000
            logger.error(f"Query {query_func.__name__} failed after {execution_time:.2f}ms: {str(e)}")
            raise

    def batch_optimize_queries(self, queries: List[Tuple[callable, tuple, dict]]) -> List[Any]:
        """Execute multiple queries with batch optimizations"""
        results = []
        start_time = time.time()

        # Group similar queries for potential optimization
        query_groups = self._group_similar_queries(queries)

        for group in query_groups:
            for query_func, args, kwargs in group:
                try:
                    result = self.optimize_query_execution(query_func, *args, **kwargs)
                    results.append(result)
                except Exception as e:
                    logger.error(f"Batch query failed: {str(e)}")
                    results.append(None)

        total_time = (time.time() - start_time) * 1000
        logger.info(f"Batch executed {len(queries)} queries in {total_time:.2f}ms")

        return results

    def get_performance_recommendations(self) -> List[str]:
        """Generate performance recommendations based on query patterns"""
        recommendations = []

        # Analyze query performance patterns
        for query_name, times in self.query_stats.items():
            if len(times) >= 5:
                avg_time = sum(times) / len(times)
                max_time = max(times)

                if avg_time > 5000:  # 5 seconds
                    recommendations.append(f"Query {query_name} is slow (avg: {avg_time:.0f}ms) - consider optimization")

                if max_time > 30000:  # 30 seconds
                    recommendations.append(f"Query {query_name} has timeouts (max: {max_time:.0f}ms) - implement pagination")

        # General recommendations
        if not recommendations:
            recommendations.append("Query performance is within acceptable limits")

        return recommendations

    def _record_query_performance(self, query_name: str, execution_time_ms: float, param_count: int) -> None:
        """Record query performance metrics"""
        self.query_stats[query_name].append(execution_time_ms)

        # Keep only recent performance data (last 100 executions per query)
        if len(self.query_stats[query_name]) > 100:
            self.query_stats[query_name] = self.query_stats[query_name][-100:]

        # Log slow queries
        if execution_time_ms > 10000:  # 10 seconds
            logger.warning(f"Slow query detected: {query_name} took {execution_time_ms:.2f}ms")

    def _group_similar_queries(self, queries: List[Tuple[callable, tuple, dict]]) -> List[List[Tuple[callable, tuple, dict]]]:
        """Group similar queries for potential batch optimization"""
        # Simple grouping by function name
        groups = defaultdict(list)
        for query in queries:
            func_name = query[0].__name__
            groups[func_name].append(query)

        return list(groups.values())


class BehavioralAnalysisEngine:
    """Advanced behavioral analysis with anomaly detection for threat intelligence"""

    def __init__(self):
        self.cache_ttl = timedelta(hours=ANALYTICS_CACHE_TTL_HOURS)

        # Anomaly detection sensitivity (standard deviations)
        self.anomaly_sensitivity = ANOMALY_DETECTION_SENSITIVITY

        # Baseline calculation window (days)
        self.baseline_window_days = 30

        # Minimum data points for reliable analysis
        self.min_data_points = 10

    def analyze_behavioral_patterns(self, filters: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Analyze behavioral patterns and detect anomalies in threat intelligence data

        Args:
            filters: Optional filters for analysis scope

        Returns:
            Dictionary containing behavioral analysis results
        """
        try:
            logger.info("Starting behavioral pattern analysis")

            # Query historical threat intelligence data
            threats = self._query_historical_threats(filters)

            if len(threats) < self.min_data_points:
                return {
                    'error': f'Insufficient data for behavioral analysis (minimum {self.min_data_points} threats required)',
                    'total_threats': len(threats)
                }

            logger.info(f"Analyzing behavioral patterns for {len(threats)} threats")

            # Establish baselines
            baselines = self._establish_baselines(threats)

            # Detect anomalies
            anomalies = self._detect_behavioral_anomalies(threats, baselines)

            # Analyze threat evolution patterns
            evolution_patterns = self._analyze_threat_evolution(threats)

            # Identify behavioral clusters
            behavioral_clusters = self._identify_behavioral_clusters(threats)

            # Detect emerging threat patterns
            emerging_patterns = self._detect_emerging_patterns(threats)

            # Generate adaptive thresholds
            adaptive_thresholds = self._generate_adaptive_thresholds(threats, baselines)

            result = {
                'total_threats_analyzed': len(threats),
                'analysis_period': {
                    'start_date': min(threats, key=lambda x: x['created_date'])['created_date'] if threats else None,
                    'end_date': max(threats, key=lambda x: x['created_date'])['created_date'] if threats else None
                },
                'baselines': baselines,
                'anomalies': anomalies,
                'evolution_patterns': evolution_patterns,
                'behavioral_clusters': behavioral_clusters,
                'emerging_patterns': emerging_patterns,
                'adaptive_thresholds': adaptive_thresholds,
                'behavioral_summary': self._generate_behavioral_summary(threats, anomalies, baselines),
                'generated_at': datetime.now(timezone.utc).isoformat()
            }

            logger.info(f"Behavioral analysis completed: {len(anomalies)} anomalies detected")
            return result

        except Exception as e:
            logger.error(f"Error in behavioral analysis: {str(e)}")
            raise

    def _query_historical_threats(self, filters: Optional[Dict[str, Any]]) -> List[Dict]:
        """Query historical threat data for behavioral analysis"""
        # Calculate time window for baseline
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=self.baseline_window_days * 2)  # Extended window for patterns

        query_params = {
            'IndexName': 'time-index',
            'KeyConditionExpression': 'created_date BETWEEN :start AND :end',
            'ExpressionAttributeValues': {
                ':start': start_time.isoformat(),
                ':end': end_time.isoformat()
            }
        }

        # Apply additional filters if provided
        if filters:
            filter_expressions = []
            for key, value in filters.items():
                if key == 'source':
                    filter_expressions.append(f"source_name = :{key}")
                    query_params['ExpressionAttributeValues'][f':{key}'] = value
                elif key == 'threat_type':
                    filter_expressions.append(f"contains(labels, :{key})")
                    query_params['ExpressionAttributeValues'][f':{key}'] = value

            if filter_expressions:
                query_params['FilterExpression'] = ' AND '.join(filter_expressions)

        # Execute query with pagination
        threats = []
        response = threat_intel_table.query(**query_params)
        threats.extend(response.get('Items', []))

        while 'LastEvaluatedKey' in response and len(threats) < MAX_ANALYTICS_RESULTS:
            query_params['ExclusiveStartKey'] = response['LastEvaluatedKey']
            response = threat_intel_table.query(**query_params)
            threats.extend(response.get('Items', []))

        return threats

    def _establish_baselines(self, threats: List[Dict]) -> Dict[str, Any]:
        """Establish behavioral baselines from historical data"""
        baselines = {}

        # Group threats by time buckets (daily)
        daily_counts = defaultdict(int)
        daily_confidences = defaultdict(list)
        daily_sources = defaultdict(set)
        daily_threat_types = defaultdict(set)

        for threat in threats:
            try:
                threat_date = datetime.fromisoformat(threat['created_date'].replace('Z', '+00:00')).date()

                daily_counts[threat_date] += 1
                daily_confidences[threat_date].append(float(threat.get('confidence', 0)))
                daily_sources[threat_date].add(threat.get('source_name', 'unknown'))

                if 'labels' in threat:
                    daily_threat_types[threat_date].update(threat['labels'])
            except Exception:
                continue

        # Calculate baseline statistics
        count_values = list(daily_counts.values())
        confidence_values = [conf for day_confs in daily_confidences.values() for conf in day_confs]
        source_diversity = [len(sources) for sources in daily_sources.values()]
        type_diversity = [len(types) for types in daily_threat_types.values()]

        if count_values:
            baselines['threat_volume'] = {
                'mean': sum(count_values) / len(count_values),
                'std_dev': self._calculate_std_dev(count_values),
                'median': sorted(count_values)[len(count_values) // 2],
                'percentile_95': sorted(count_values)[int(0.95 * len(count_values))],
                'min': min(count_values),
                'max': max(count_values)
            }

        if confidence_values:
            baselines['confidence_levels'] = {
                'mean': sum(confidence_values) / len(confidence_values),
                'std_dev': self._calculate_std_dev(confidence_values),
                'median': sorted(confidence_values)[len(confidence_values) // 2]
            }

        if source_diversity:
            baselines['source_diversity'] = {
                'mean': sum(source_diversity) / len(source_diversity),
                'std_dev': self._calculate_std_dev(source_diversity)
            }

        if type_diversity:
            baselines['threat_type_diversity'] = {
                'mean': sum(type_diversity) / len(type_diversity),
                'std_dev': self._calculate_std_dev(type_diversity)
            }

        # Calculate temporal patterns
        baselines['temporal_patterns'] = self._analyze_temporal_patterns(daily_counts)

        return baselines

    def _calculate_std_dev(self, values: List[float]) -> float:
        """Calculate standard deviation"""
        if len(values) < 2:
            return 0.0

        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        return math.sqrt(variance)

    def _analyze_temporal_patterns(self, daily_counts: Dict) -> Dict[str, Any]:
        """Analyze temporal patterns in threat data"""
        if not daily_counts:
            return {}

        # Convert to time series
        sorted_dates = sorted(daily_counts.keys())
        counts = [daily_counts[date] for date in sorted_dates]

        patterns = {}

        # Weekly patterns
        weekly_counts = defaultdict(list)
        for date in sorted_dates:
            weekday = date.weekday()  # 0=Monday, 6=Sunday
            weekly_counts[weekday].append(daily_counts[date])

        if weekly_counts:
            weekly_averages = {day: sum(counts) / len(counts) for day, counts in weekly_counts.items()}
            patterns['weekly_pattern'] = {
                'averages': weekly_averages,
                'peak_day': max(weekly_averages, key=weekly_averages.get),
                'lowest_day': min(weekly_averages, key=weekly_averages.get)
            }

        # Monthly patterns (if enough data)
        if len(sorted_dates) > 30:
            monthly_counts = defaultdict(list)
            for date in sorted_dates:
                day_of_month = date.day
                monthly_counts[day_of_month].append(daily_counts[date])

            monthly_averages = {day: sum(counts) / len(counts) for day, counts in monthly_counts.items()}
            patterns['monthly_pattern'] = {
                'averages': monthly_averages,
                'peak_day': max(monthly_averages, key=monthly_averages.get),
                'lowest_day': min(monthly_averages, key=monthly_averages.get)
            }

        return patterns

    def _detect_behavioral_anomalies(self, threats: List[Dict], baselines: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect behavioral anomalies using statistical methods"""
        anomalies = []

        # Group recent threats (last 7 days) for anomaly detection
        recent_cutoff = datetime.now(timezone.utc) - timedelta(days=7)
        recent_threats = []

        for threat in threats:
            try:
                threat_time = datetime.fromisoformat(threat['created_date'].replace('Z', '+00:00'))
                if threat_time >= recent_cutoff:
                    recent_threats.append(threat)
            except Exception:
                continue

        if not recent_threats:
            return anomalies

        # Group recent threats by day
        recent_daily_counts = defaultdict(int)
        recent_daily_confidences = defaultdict(list)
        recent_daily_sources = defaultdict(set)
        recent_daily_types = defaultdict(set)

        for threat in recent_threats:
            try:
                threat_date = datetime.fromisoformat(threat['created_date'].replace('Z', '+00:00')).date()

                recent_daily_counts[threat_date] += 1
                recent_daily_confidences[threat_date].append(float(threat.get('confidence', 0)))
                recent_daily_sources[threat_date].add(threat.get('source_name', 'unknown'))

                if 'labels' in threat:
                    recent_daily_types[threat_date].update(threat['labels'])
            except Exception:
                continue

        # Detect volume anomalies
        volume_baseline = baselines.get('threat_volume', {})
        if volume_baseline:
            mean_volume = volume_baseline['mean']
            std_volume = volume_baseline['std_dev']
            threshold = mean_volume + (self.anomaly_sensitivity * std_volume)

            for date, count in recent_daily_counts.items():
                if count > threshold and std_volume > 0:
                    severity = 'high' if count > mean_volume + (3 * std_volume) else 'medium'
                    anomalies.append({
                        'type': 'volume_spike',
                        'date': date.isoformat(),
                        'value': count,
                        'baseline_mean': mean_volume,
                        'threshold': threshold,
                        'severity': severity,
                        'description': f"Threat volume spike: {count} threats (baseline: {mean_volume:.1f})"
                    })

        # Detect confidence anomalies
        confidence_baseline = baselines.get('confidence_levels', {})
        if confidence_baseline:
            mean_confidence = confidence_baseline['mean']
            std_confidence = confidence_baseline['std_dev']

            for date, confidences in recent_daily_confidences.items():
                if confidences:
                    avg_confidence = sum(confidences) / len(confidences)

                    # Detect unusually low confidence
                    low_threshold = mean_confidence - (self.anomaly_sensitivity * std_confidence)
                    if avg_confidence < low_threshold and std_confidence > 0:
                        anomalies.append({
                            'type': 'confidence_drop',
                            'date': date.isoformat(),
                            'value': avg_confidence,
                            'baseline_mean': mean_confidence,
                            'threshold': low_threshold,
                            'severity': 'medium',
                            'description': f"Confidence drop: {avg_confidence:.1f}% (baseline: {mean_confidence:.1f}%)"
                        })

                    # Detect unusually high confidence
                    high_threshold = mean_confidence + (self.anomaly_sensitivity * std_confidence)
                    if avg_confidence > high_threshold and std_confidence > 0:
                        anomalies.append({
                            'type': 'confidence_spike',
                            'date': date.isoformat(),
                            'value': avg_confidence,
                            'baseline_mean': mean_confidence,
                            'threshold': high_threshold,
                            'severity': 'low',
                            'description': f"Confidence spike: {avg_confidence:.1f}% (baseline: {mean_confidence:.1f}%)"
                        })

        # Detect source diversity anomalies
        source_baseline = baselines.get('source_diversity', {})
        if source_baseline:
            mean_sources = source_baseline['mean']
            std_sources = source_baseline['std_dev']

            for date, sources in recent_daily_sources.items():
                source_count = len(sources)

                # Detect unusual source concentration (too few sources)
                low_threshold = mean_sources - (self.anomaly_sensitivity * std_sources)
                if source_count < low_threshold and std_sources > 0:
                    anomalies.append({
                        'type': 'source_concentration',
                        'date': date.isoformat(),
                        'value': source_count,
                        'baseline_mean': mean_sources,
                        'threshold': low_threshold,
                        'severity': 'medium',
                        'description': f"Source concentration: {source_count} sources (baseline: {mean_sources:.1f})"
                    })

        # Detect new threat types
        known_types = set()
        for threat in threats[:-len(recent_threats)]:  # Historical threats only
            if 'labels' in threat:
                known_types.update(threat['labels'])

        for date, types in recent_daily_types.items():
            new_types = types - known_types
            if new_types:
                anomalies.append({
                    'type': 'new_threat_types',
                    'date': date.isoformat(),
                    'value': list(new_types),
                    'count': len(new_types),
                    'severity': 'high' if len(new_types) > 3 else 'medium',
                    'description': f"New threat types detected: {', '.join(list(new_types)[:3])}"
                })

        return sorted(anomalies, key=lambda x: x['date'], reverse=True)

    def _analyze_threat_evolution(self, threats: List[Dict]) -> Dict[str, Any]:
        """Analyze how threat patterns evolve over time"""
        if not threats:
            return {}

        # Sort threats by time
        sorted_threats = sorted(threats, key=lambda x: x['created_date'])

        # Divide into time periods (weekly)
        time_periods = []
        current_period = []
        current_week = None

        for threat in sorted_threats:
            try:
                threat_time = datetime.fromisoformat(threat['created_date'].replace('Z', '+00:00'))
                week = threat_time.isocalendar()[1]  # ISO week number

                if current_week is None:
                    current_week = week

                if week == current_week:
                    current_period.append(threat)
                else:
                    if current_period:
                        time_periods.append({
                            'week': current_week,
                            'threats': current_period
                        })
                    current_period = [threat]
                    current_week = week
            except Exception:
                continue

        # Add the last period
        if current_period:
            time_periods.append({
                'week': current_week,
                'threats': current_period
            })

        if len(time_periods) < 2:
            return {'error': 'Insufficient time periods for evolution analysis'}

        # Analyze evolution patterns
        evolution = {
            'time_periods': len(time_periods),
            'threat_type_evolution': self._analyze_type_evolution(time_periods),
            'source_evolution': self._analyze_source_evolution(time_periods),
            'confidence_evolution': self._analyze_confidence_evolution(time_periods),
            'volume_trends': self._analyze_volume_trends(time_periods)
        }

        return evolution

    def _analyze_type_evolution(self, time_periods: List[Dict]) -> Dict[str, Any]:
        """Analyze how threat types evolve over time"""
        type_evolution = []

        for period in time_periods:
            threat_types = Counter()
            for threat in period['threats']:
                if 'labels' in threat:
                    threat_types.update(threat['labels'])

            type_evolution.append({
                'week': period['week'],
                'top_types': dict(threat_types.most_common(5)),
                'total_types': len(threat_types),
                'threat_count': len(period['threats'])
            })

        # Identify trending types
        if len(type_evolution) >= 2:
            recent_types = set(type_evolution[-1]['top_types'].keys())
            previous_types = set(type_evolution[-2]['top_types'].keys())

            emerging_types = recent_types - previous_types
            declining_types = previous_types - recent_types
        else:
            emerging_types = set()
            declining_types = set()

        return {
            'timeline': type_evolution,
            'emerging_types': list(emerging_types),
            'declining_types': list(declining_types)
        }

    def _analyze_source_evolution(self, time_periods: List[Dict]) -> Dict[str, Any]:
        """Analyze how threat sources evolve over time"""
        source_evolution = []

        for period in time_periods:
            sources = Counter()
            for threat in period['threats']:
                source = threat.get('source_name', 'unknown')
                sources[source] += 1

            source_evolution.append({
                'week': period['week'],
                'sources': dict(sources),
                'dominant_source': sources.most_common(1)[0][0] if sources else None,
                'source_diversity': len(sources)
            })

        return {
            'timeline': source_evolution,
            'diversity_trend': [p['source_diversity'] for p in source_evolution]
        }

    def _analyze_confidence_evolution(self, time_periods: List[Dict]) -> Dict[str, Any]:
        """Analyze how confidence levels evolve over time"""
        confidence_evolution = []

        for period in time_periods:
            confidences = []
            for threat in period['threats']:
                confidence = float(threat.get('confidence', 0))
                confidences.append(confidence)

            if confidences:
                avg_confidence = sum(confidences) / len(confidences)
                confidence_evolution.append({
                    'week': period['week'],
                    'average_confidence': avg_confidence,
                    'confidence_std': self._calculate_std_dev(confidences),
                    'threat_count': len(confidences)
                })

        return {
            'timeline': confidence_evolution,
            'trend': self._calculate_trend([p['average_confidence'] for p in confidence_evolution])
        }

    def _analyze_volume_trends(self, time_periods: List[Dict]) -> Dict[str, Any]:
        """Analyze volume trends over time"""
        volumes = [len(period['threats']) for period in time_periods]

        return {
            'weekly_volumes': volumes,
            'trend': self._calculate_trend(volumes),
            'volatility': self._calculate_std_dev(volumes) / (sum(volumes) / len(volumes)) if volumes else 0
        }

    def _calculate_trend(self, values: List[float]) -> Dict[str, Any]:
        """Calculate trend direction and strength"""
        if len(values) < 2:
            return {'direction': 'stable', 'strength': 0.0}

        # Simple linear regression
        n = len(values)
        x_vals = list(range(n))

        sum_x = sum(x_vals)
        sum_y = sum(values)
        sum_xy = sum(x * y for x, y in zip(x_vals, values))
        sum_x2 = sum(x * x for x in x_vals)

        if n * sum_x2 - sum_x * sum_x == 0:
            slope = 0
        else:
            slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x * sum_x)

        # Determine direction
        if abs(slope) < 0.1:
            direction = 'stable'
        elif slope > 0:
            direction = 'increasing'
        else:
            direction = 'decreasing'

        return {
            'direction': direction,
            'strength': abs(slope),
            'slope': slope
        }

    def _identify_behavioral_clusters(self, threats: List[Dict]) -> List[Dict[str, Any]]:
        """Identify clusters of threats with similar behavioral patterns"""
        if not threats:
            return []

        # Create feature vectors for threats
        threat_features = []
        for threat in threats:
            features = self._extract_behavioral_features(threat)
            if features:
                threat_features.append({
                    'threat_id': threat.get('object_id', 'unknown'),
                    'features': features,
                    'threat': threat
                })

        if len(threat_features) < 3:
            return []

        # Simple clustering based on feature similarity
        clusters = []
        unassigned = threat_features.copy()
        cluster_id = 0

        while unassigned:
            # Start new cluster with first unassigned threat
            seed = unassigned[0]
            cluster = [seed]
            unassigned.remove(seed)

            # Find similar threats
            to_remove = []
            for threat_feature in unassigned:
                similarity = self._calculate_feature_similarity(seed['features'], threat_feature['features'])
                if similarity > 0.7:  # Similarity threshold
                    cluster.append(threat_feature)
                    to_remove.append(threat_feature)

            # Remove assigned threats
            for item in to_remove:
                unassigned.remove(item)

            # Create cluster if it has enough members
            if len(cluster) >= 3:
                cluster_characteristics = self._analyze_cluster_characteristics(cluster)
                clusters.append({
                    'cluster_id': f"behavioral-cluster-{cluster_id}",
                    'threat_count': len(cluster),
                    'threat_ids': [t['threat_id'] for t in cluster],
                    'characteristics': cluster_characteristics,
                    'similarity_score': sum(
                        self._calculate_feature_similarity(cluster[0]['features'], t['features'])
                        for t in cluster[1:]
                    ) / (len(cluster) - 1) if len(cluster) > 1 else 1.0
                })
                cluster_id += 1

        return clusters

    def _extract_behavioral_features(self, threat: Dict) -> Optional[Dict[str, float]]:
        """Extract behavioral features from a threat"""
        features = {}

        try:
            # Temporal features
            threat_time = datetime.fromisoformat(threat['created_date'].replace('Z', '+00:00'))
            features['hour_of_day'] = threat_time.hour / 24.0
            features['day_of_week'] = threat_time.weekday() / 7.0

            # Confidence feature
            features['confidence'] = float(threat.get('confidence', 0)) / 100.0

            # Source feature (encoded)
            source = threat.get('source_name', 'unknown').lower()
            source_encoding = {
                'alienvault_otx': 0.2,
                'abuse_ch': 0.4,
                'shodan': 0.6,
                'misp': 0.8,
                'unknown': 0.0
            }
            features['source_type'] = source_encoding.get(source, 0.0)

            # Threat type features
            labels = threat.get('labels', [])
            features['threat_type_count'] = len(labels) / 10.0  # Normalize

            # Specific threat type indicators
            threat_indicators = {
                'malware': any('malware' in label.lower() for label in labels),
                'phishing': any('phishing' in label.lower() for label in labels),
                'apt': any('apt' in label.lower() for label in labels),
                'botnet': any('botnet' in label.lower() for label in labels)
            }

            for indicator, present in threat_indicators.items():
                features[f'has_{indicator}'] = 1.0 if present else 0.0

            # Pattern complexity (rough estimate)
            pattern = threat.get('pattern', '')
            features['pattern_complexity'] = min(len(pattern) / 1000.0, 1.0)  # Normalize

            return features

        except Exception:
            return None

    def _calculate_feature_similarity(self, features1: Dict[str, float], features2: Dict[str, float]) -> float:
        """Calculate similarity between two feature vectors"""
        common_keys = set(features1.keys()) & set(features2.keys())
        if not common_keys:
            return 0.0

        # Calculate cosine similarity
        dot_product = sum(features1[key] * features2[key] for key in common_keys)
        norm1 = math.sqrt(sum(features1[key] ** 2 for key in common_keys))
        norm2 = math.sqrt(sum(features2[key] ** 2 for key in common_keys))

        if norm1 == 0 or norm2 == 0:
            return 0.0

        return dot_product / (norm1 * norm2)

    def _analyze_cluster_characteristics(self, cluster: List[Dict]) -> Dict[str, Any]:
        """Analyze characteristics of a behavioral cluster"""
        threats = [item['threat'] for item in cluster]

        # Common sources
        sources = Counter(threat.get('source_name', 'unknown') for threat in threats)

        # Common threat types
        all_labels = []
        for threat in threats:
            all_labels.extend(threat.get('labels', []))
        threat_types = Counter(all_labels)

        # Temporal patterns
        hours = []
        days = []
        for threat in threats:
            try:
                threat_time = datetime.fromisoformat(threat['created_date'].replace('Z', '+00:00'))
                hours.append(threat_time.hour)
                days.append(threat_time.weekday())
            except Exception:
                continue

        # Confidence levels
        confidences = [float(threat.get('confidence', 0)) for threat in threats]

        return {
            'dominant_sources': dict(sources.most_common(3)),
            'common_threat_types': dict(threat_types.most_common(5)),
            'temporal_pattern': {
                'common_hours': Counter(hours).most_common(3),
                'common_days': Counter(days).most_common(3)
            },
            'confidence_stats': {
                'average': sum(confidences) / len(confidences) if confidences else 0,
                'std_dev': self._calculate_std_dev(confidences)
            }
        }

    def _detect_emerging_patterns(self, threats: List[Dict]) -> List[Dict[str, Any]]:
        """Detect emerging threat patterns"""
        if not threats:
            return []

        # Sort threats by time
        sorted_threats = sorted(threats, key=lambda x: x['created_date'])

        # Split into recent and historical
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=14)  # Last 2 weeks
        recent_threats = []
        historical_threats = []

        for threat in sorted_threats:
            try:
                threat_time = datetime.fromisoformat(threat['created_date'].replace('Z', '+00:00'))
                if threat_time >= cutoff_date:
                    recent_threats.append(threat)
                else:
                    historical_threats.append(threat)
            except Exception:
                continue

        if len(recent_threats) < 5 or len(historical_threats) < 10:
            return []

        emerging_patterns = []

        # Detect emerging threat types
        historical_types = Counter()
        recent_types = Counter()

        for threat in historical_threats:
            if 'labels' in threat:
                historical_types.update(threat['labels'])

        for threat in recent_threats:
            if 'labels' in threat:
                recent_types.update(threat['labels'])

        # Calculate emergence scores
        for threat_type, recent_count in recent_types.items():
            historical_count = historical_types.get(threat_type, 0)

            # Calculate emergence score
            if historical_count == 0:
                emergence_score = 1.0  # Completely new
            else:
                # Compare recent frequency to historical frequency
                recent_freq = recent_count / len(recent_threats)
                historical_freq = historical_count / len(historical_threats)
                emergence_score = min(recent_freq / (historical_freq + 0.01), 10.0)

            if emergence_score > 2.0:  # Significant emergence
                emerging_patterns.append({
                    'pattern_type': 'threat_type_emergence',
                    'pattern_value': threat_type,
                    'emergence_score': round(emergence_score, 2),
                    'recent_count': recent_count,
                    'historical_count': historical_count,
                    'description': f"Emerging threat type: {threat_type} (score: {emergence_score:.2f})"
                })

        # Detect emerging sources
        historical_sources = Counter(threat.get('source_name', 'unknown') for threat in historical_threats)
        recent_sources = Counter(threat.get('source_name', 'unknown') for threat in recent_threats)

        for source, recent_count in recent_sources.items():
            historical_count = historical_sources.get(source, 0)

            if historical_count == 0 and recent_count >= 3:
                emerging_patterns.append({
                    'pattern_type': 'new_source',
                    'pattern_value': source,
                    'emergence_score': 1.0,
                    'recent_count': recent_count,
                    'historical_count': 0,
                    'description': f"New threat source detected: {source}"
                })

        return sorted(emerging_patterns, key=lambda x: x['emergence_score'], reverse=True)

    def _generate_adaptive_thresholds(self, threats: List[Dict], baselines: Dict[str, Any]) -> Dict[str, Any]:
        """Generate adaptive thresholds based on recent behavior"""
        adaptive_thresholds = {}

        # Recent data (last 7 days)
        recent_cutoff = datetime.now(timezone.utc) - timedelta(days=7)
        recent_threats = []

        for threat in threats:
            try:
                threat_time = datetime.fromisoformat(threat['created_date'].replace('Z', '+00:00'))
                if threat_time >= recent_cutoff:
                    recent_threats.append(threat)
            except Exception:
                continue

        if not recent_threats:
            return adaptive_thresholds

        # Adaptive volume threshold
        volume_baseline = baselines.get('threat_volume', {})
        if volume_baseline:
            baseline_mean = volume_baseline['mean']
            baseline_std = volume_baseline['std_dev']

            # Calculate recent daily volumes
            recent_daily_counts = defaultdict(int)
            for threat in recent_threats:
                try:
                    threat_date = datetime.fromisoformat(threat['created_date'].replace('Z', '+00:00')).date()
                    recent_daily_counts[threat_date] += 1
                except Exception:
                    continue

            if recent_daily_counts:
                recent_volumes = list(recent_daily_counts.values())
                recent_mean = sum(recent_volumes) / len(recent_volumes)
                recent_std = self._calculate_std_dev(recent_volumes)

                # Adaptive threshold combines baseline and recent behavior
                adaptive_mean = (baseline_mean + recent_mean) / 2
                adaptive_std = max(baseline_std, recent_std)

                adaptive_thresholds['volume_threshold'] = {
                    'warning': adaptive_mean + adaptive_std,
                    'critical': adaptive_mean + (2 * adaptive_std),
                    'baseline_mean': baseline_mean,
                    'recent_mean': recent_mean,
                    'adaptive_mean': adaptive_mean
                }

        # Adaptive confidence threshold
        confidence_baseline = baselines.get('confidence_levels', {})
        if confidence_baseline:
            baseline_conf_mean = confidence_baseline['mean']

            recent_confidences = [float(threat.get('confidence', 0)) for threat in recent_threats]
            if recent_confidences:
                recent_conf_mean = sum(recent_confidences) / len(recent_confidences)
                recent_conf_std = self._calculate_std_dev(recent_confidences)

                adaptive_thresholds['confidence_threshold'] = {
                    'low_warning': max(recent_conf_mean - recent_conf_std, 30.0),
                    'high_quality': recent_conf_mean + recent_conf_std,
                    'baseline_mean': baseline_conf_mean,
                    'recent_mean': recent_conf_mean
                }

        return adaptive_thresholds

    def _generate_behavioral_summary(self, threats: List[Dict], anomalies: List[Dict],
                                   baselines: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary of behavioral analysis"""
        if not threats:
            return {'status': 'no_data'}

        # Categorize anomalies by severity
        high_severity = [a for a in anomalies if a.get('severity') == 'high']
        medium_severity = [a for a in anomalies if a.get('severity') == 'medium']

        # Determine overall behavioral status
        if len(high_severity) >= 3:
            status = 'critical'
        elif len(high_severity) >= 1 or len(medium_severity) >= 3:
            status = 'concerning'
        elif len(anomalies) > 0:
            status = 'monitoring'
        else:
            status = 'normal'

        # Key insights
        insights = []

        if high_severity:
            insights.append(f"{len(high_severity)} high-severity behavioral anomalies detected")

        volume_anomalies = [a for a in anomalies if a['type'] == 'volume_spike']
        if volume_anomalies:
            insights.append(f"Threat volume spikes detected on {len(volume_anomalies)} days")

        new_type_anomalies = [a for a in anomalies if a['type'] == 'new_threat_types']
        if new_type_anomalies:
            insights.append("New threat types emerging in recent activity")

        confidence_anomalies = [a for a in anomalies if a['type'] in ['confidence_drop', 'confidence_spike']]
        if confidence_anomalies:
            insights.append("Unusual confidence level patterns detected")

        return {
            'behavioral_status': status,
            'total_anomalies': len(anomalies),
            'anomaly_breakdown': {
                'high_severity': len(high_severity),
                'medium_severity': len(medium_severity),
                'low_severity': len(anomalies) - len(high_severity) - len(medium_severity)
            },
            'key_insights': insights,
            'recommendation': self._generate_behavioral_recommendation(status, anomalies),
            'baseline_stability': self._assess_baseline_stability(baselines)
        }

    def _assess_baseline_stability(self, baselines: Dict[str, Any]) -> str:
        """Assess the stability of established baselines"""
        if not baselines:
            return 'unknown'

        # Check if we have sufficient baseline data
        volume_baseline = baselines.get('threat_volume', {})
        if volume_baseline:
            std_dev = volume_baseline.get('std_dev', 0)
            mean = volume_baseline.get('mean', 0)

            if mean > 0:
                coefficient_of_variation = std_dev / mean
                if coefficient_of_variation < 0.3:
                    return 'stable'
                elif coefficient_of_variation < 0.6:
                    return 'moderate'
                else:
                    return 'volatile'

        return 'insufficient_data'

    def _generate_behavioral_recommendation(self, status: str, anomalies: List[Dict]) -> str:
        """Generate recommendations based on behavioral analysis"""
        if status == 'critical':
            return "Critical behavioral anomalies detected. Immediate investigation and enhanced monitoring required."
        elif status == 'concerning':
            return "Concerning behavioral patterns identified. Increase monitoring and review threat response procedures."
        elif status == 'monitoring':
            return "Minor behavioral anomalies detected. Continue monitoring with standard procedures."
        else:
            return "Behavioral patterns within normal parameters. Maintain current monitoring level."


# Initialize performance optimization components
cache_manager = AnalyticsCacheManager()
performance_optimizer = PerformanceOptimizer()

# Global analytics engine instances with caching integration
trend_analytics = TrendAnalysisEngine()
geographic_analytics = GeographicAnalysisEngine()
risk_analytics = RiskScoringEngine()
correlation_analytics = CorrelationIntelligenceEngine()
behavioral_analytics = BehavioralAnalysisEngine()


def execute_analytics_with_cache(analytics_type: str, analytics_func: callable,
                                parameters: Dict[str, Any], filters: Optional[Dict[str, Any]] = None,
                                custom_ttl_minutes: Optional[int] = None) -> Dict[str, Any]:
    """Execute analytics function with intelligent caching"""
    try:
        # Generate cache key
        cache_key = cache_manager.generate_cache_key(analytics_type, parameters, filters)

        # Try to get cached result
        cached_result = cache_manager.get_cached_result(cache_key)
        if cached_result is not None:
            cached_result['_cache_hit'] = True
            cached_result['_cache_key'] = cache_key[:20] + '...'
            return cached_result

        # Execute analytics with performance optimization
        start_time = time.time()
        result = performance_optimizer.optimize_query_execution(analytics_func, filters)

        # Add execution metadata
        execution_time = (time.time() - start_time) * 1000
        result['execution_metadata'] = {
            'execution_time_ms': round(execution_time, 2),
            'cache_hit': False,
            'analytics_type': analytics_type,
            'performance_optimized': True
        }

        # Store result in cache
        cache_manager.store_result(cache_key, result, custom_ttl_minutes)

        logger.info(f"Analytics {analytics_type} completed in {execution_time:.2f}ms")
        return result

    except Exception as e:
        logger.error(f"Error executing analytics {analytics_type}: {str(e)}")
        return {
            'error': str(e),
            'analytics_type': analytics_type,
            'execution_metadata': {
                'execution_time_ms': 0,
                'cache_hit': False,
                'error': True
            }
        }


def lambda_handler(event, context):
    """
    AWS Lambda handler for analytics engine

    Expected event structure:
    {
        "action": "trend_analysis" | "geographic_analysis",
        "parameters": {
            "timeframe": "daily",    # For trend analysis
            "filters": {...}
        }
    }
    """
    try:
        logger.info(f"Analytics engine invoked with event: {json.dumps(event, default=str)}")

        action = event.get('action', 'trend_analysis')
        parameters = event.get('parameters', {})

        if action == 'trend_analysis':
            timeframe_str = parameters.get('timeframe', 'daily')
            try:
                timeframe = TrendTimeframe(timeframe_str)
            except ValueError:
                timeframe = TrendTimeframe.DAILY

            filters = parameters.get('filters')

            # Execute with caching
            result = execute_analytics_with_cache(
                'trend_analysis',
                lambda f: trend_analytics.analyze_temporal_trends(timeframe, f),
                {'timeframe': timeframe_str},
                filters,
                custom_ttl_minutes=parameters.get('cache_ttl_minutes')
            )

            return {
                'statusCode': 200,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                'body': json.dumps(result, default=str)
            }

        elif action == 'geographic_analysis':
            filters = parameters.get('filters')

            # Execute with caching
            result = execute_analytics_with_cache(
                'geographic_analysis',
                geographic_analytics.analyze_geographic_distribution,
                {},
                filters,
                custom_ttl_minutes=parameters.get('cache_ttl_minutes')
            )

            return {
                'statusCode': 200,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                'body': json.dumps(result, default=str)
            }

        elif action == 'risk_scoring':
            threat_data = parameters.get('threat')
            context_data = parameters.get('context')

            if not threat_data:
                return {
                    'statusCode': 400,
                    'headers': {
                        'Content-Type': 'application/json',
                        'Access-Control-Allow-Origin': '*'
                    },
                    'body': json.dumps({
                        'error': 'threat parameter is required for risk scoring'
                    })
                }

            # Risk scoring typically not cached as it's per-threat
            result = risk_analytics.calculate_enhanced_risk_score(threat_data, context_data)

            return {
                'statusCode': 200,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                'body': json.dumps(result, default=str)
            }

        elif action == 'risk_distribution':
            filters = parameters.get('filters')

            # Execute with caching
            result = execute_analytics_with_cache(
                'risk_distribution',
                risk_analytics.analyze_risk_distribution,
                {},
                filters,
                custom_ttl_minutes=parameters.get('cache_ttl_minutes')
            )

            return {
                'statusCode': 200,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                'body': json.dumps(result, default=str)
            }

        elif action == 'correlation_analysis':
            filters = parameters.get('filters')

            # Execute with caching (longer TTL for expensive correlation analysis)
            result = execute_analytics_with_cache(
                'correlation_analysis',
                correlation_analytics.analyze_cross_source_correlations,
                {},
                filters,
                custom_ttl_minutes=parameters.get('cache_ttl_minutes', 60)  # 1 hour default
            )

            return {
                'statusCode': 200,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                'body': json.dumps(result, default=str)
            }

        elif action == 'behavioral_analysis':
            filters = parameters.get('filters')

            # Execute with caching
            result = execute_analytics_with_cache(
                'behavioral_analysis',
                behavioral_analytics.analyze_behavioral_patterns,
                {},
                filters,
                custom_ttl_minutes=parameters.get('cache_ttl_minutes')
            )

            return {
                'statusCode': 200,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                'body': json.dumps(result, default=str)
            }

        elif action == 'cache_stats':
            # Return cache performance statistics
            cache_stats = cache_manager.get_cache_stats()
            performance_recommendations = performance_optimizer.get_performance_recommendations()

            result = {
                'cache_statistics': cache_stats,
                'performance_recommendations': performance_recommendations,
                'analytics_engines': {
                    'trend_analysis': 'available',
                    'geographic_analysis': 'available',
                    'risk_scoring': 'available',
                    'risk_distribution': 'available',
                    'correlation_analysis': 'available',
                    'behavioral_analysis': 'available'
                }
            }

            return {
                'statusCode': 200,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                'body': json.dumps(result, default=str)
            }

        elif action == 'invalidate_cache':
            # Invalidate cache entries matching pattern
            pattern = parameters.get('pattern', 'analytics:')
            invalidated_count = cache_manager.invalidate_cache_pattern(pattern)

            result = {
                'pattern': pattern,
                'invalidated_entries': invalidated_count,
                'status': 'completed'
            }

            return {
                'statusCode': 200,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                'body': json.dumps(result, default=str)
            }

        else:
            return {
                'statusCode': 400,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                'body': json.dumps({
                    'error': f'Unsupported action: {action}',
                    'supported_actions': [
                        'trend_analysis', 'geographic_analysis', 'risk_scoring',
                        'risk_distribution', 'correlation_analysis', 'behavioral_analysis',
                        'cache_stats', 'invalidate_cache'
                    ]
                })
            }

    except Exception as e:
        logger.error(f"Error in analytics engine: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({
                'error': 'Internal server error',
                'message': str(e)
            })
        }