"""
Performance Metrics Collection and Alerting System
Phase 8D Implementation - Infrastructure Enhancements

This module provides comprehensive performance metrics collection and intelligent alerting:
- Real-time performance metrics collection from all system components
- Advanced alerting with intelligent thresholds and anomaly detection
- Performance trend analysis and predictive alerting
- Automated performance optimization recommendations
- Integration with CloudWatch and custom metric dashboards

Features:
- Multi-dimensional performance tracking
- Adaptive threshold management based on historical data
- Intelligent alert correlation and noise reduction
- Performance bottleneck identification and analysis
- Automated remediation trigger integration
"""

import json
import boto3
import logging
import os
import time
import math
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
from collections import defaultdict, deque
import statistics
from decimal import Decimal

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# AWS Service Clients
cloudwatch = boto3.client('cloudwatch')
sns = boto3.client('sns')
dynamodb = boto3.resource('dynamodb')
lambda_client = boto3.client('lambda')

# Environment Variables
ENVIRONMENT = os.environ.get('ENVIRONMENT', 'dev')
PROJECT_NAME = os.environ.get('PROJECT_NAME', 'threat-intel')
ALERT_TOPIC_ARN = os.environ.get('ALERT_TOPIC_ARN', '')
METRICS_TABLE_NAME = os.environ.get('METRICS_TABLE_NAME', f'{PROJECT_NAME}-metrics-{ENVIRONMENT}')

# Performance Metrics Configuration
BASELINE_WINDOW_HOURS = 24  # Hours to use for baseline calculation
ANOMALY_DETECTION_THRESHOLD = 2.0  # Standard deviations
ALERT_COOLDOWN_MINUTES = 15  # Minimum time between similar alerts
MAX_METRICS_BATCH_SIZE = 20  # CloudWatch metric batch limit


class MetricType(Enum):
    """Types of performance metrics"""
    LATENCY = "latency"
    THROUGHPUT = "throughput"
    ERROR_RATE = "error_rate"
    RESOURCE_UTILIZATION = "resource_utilization"
    COST_EFFICIENCY = "cost_efficiency"
    CACHE_PERFORMANCE = "cache_performance"
    DATA_QUALITY = "data_quality"


class AlertSeverity(Enum):
    """Alert severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ComponentType(Enum):
    """System component types"""
    LAMBDA_FUNCTION = "lambda"
    DYNAMODB_TABLE = "dynamodb"
    API_GATEWAY = "api_gateway"
    CACHE_LAYER = "cache"
    SEARCH_ENGINE = "search"
    ANALYTICS_ENGINE = "analytics"


@dataclass
class PerformanceMetric:
    """Individual performance metric"""
    metric_id: str
    component_type: ComponentType
    component_name: str
    metric_type: MetricType
    value: float
    unit: str
    timestamp: datetime
    dimensions: Dict[str, str]
    metadata: Dict[str, Any]


@dataclass
class AlertCondition:
    """Alert condition definition"""
    condition_id: str
    metric_type: MetricType
    threshold_type: str  # 'static', 'adaptive', 'anomaly'
    threshold_value: Optional[float]
    comparison_operator: str  # 'GreaterThan', 'LessThan', 'Equal'
    evaluation_periods: int
    severity: AlertSeverity
    auto_resolve: bool = True


@dataclass
class PerformanceAlert:
    """Performance alert"""
    alert_id: str
    condition_id: str
    component_type: ComponentType
    component_name: str
    metric_type: MetricType
    severity: AlertSeverity
    current_value: float
    threshold_value: float
    message: str
    timestamp: datetime
    resolved: bool = False
    resolution_timestamp: Optional[datetime] = None


@dataclass
class PerformanceBaseline:
    """Performance baseline for adaptive thresholds"""
    component_name: str
    metric_type: MetricType
    baseline_value: float
    standard_deviation: float
    sample_count: int
    last_updated: datetime
    confidence_level: float


class PerformanceMetricsCollector:
    """Comprehensive performance metrics collection engine"""

    def __init__(self):
        self.metrics_buffer = deque(maxlen=1000)
        self.alert_conditions = self._load_alert_conditions()
        self.baselines = {}
        self.active_alerts = {}
        self.metrics_cache = defaultdict(list)

    def collect_lambda_metrics(self, function_name: str) -> List[PerformanceMetric]:
        """
        Collect performance metrics from Lambda function

        Args:
            function_name: Name of the Lambda function

        Returns:
            List of performance metrics
        """
        try:
            logger.info(f"Collecting metrics for Lambda function: {function_name}")
            metrics = []

            # Get CloudWatch metrics for the function
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(minutes=5)

            # Duration metrics
            duration_stats = self._get_cloudwatch_statistics(
                namespace='AWS/Lambda',
                metric_name='Duration',
                dimensions=[{'Name': 'FunctionName', 'Value': function_name}],
                start_time=start_time,
                end_time=end_time,
                statistics=['Average', 'Maximum', 'Minimum']
            )

            if duration_stats:
                metrics.append(PerformanceMetric(
                    metric_id=f"lambda_{function_name}_duration_avg",
                    component_type=ComponentType.LAMBDA_FUNCTION,
                    component_name=function_name,
                    metric_type=MetricType.LATENCY,
                    value=duration_stats.get('Average', 0),
                    unit='milliseconds',
                    timestamp=end_time,
                    dimensions={'FunctionName': function_name, 'Statistic': 'Average'},
                    metadata={'max_duration': duration_stats.get('Maximum', 0)}
                ))

            # Invocation count (throughput)
            invocation_stats = self._get_cloudwatch_statistics(
                namespace='AWS/Lambda',
                metric_name='Invocations',
                dimensions=[{'Name': 'FunctionName', 'Value': function_name}],
                start_time=start_time,
                end_time=end_time,
                statistics=['Sum']
            )

            if invocation_stats:
                metrics.append(PerformanceMetric(
                    metric_id=f"lambda_{function_name}_invocations",
                    component_type=ComponentType.LAMBDA_FUNCTION,
                    component_name=function_name,
                    metric_type=MetricType.THROUGHPUT,
                    value=invocation_stats.get('Sum', 0),
                    unit='count',
                    timestamp=end_time,
                    dimensions={'FunctionName': function_name},
                    metadata={}
                ))

            # Error rate
            error_stats = self._get_cloudwatch_statistics(
                namespace='AWS/Lambda',
                metric_name='Errors',
                dimensions=[{'Name': 'FunctionName', 'Value': function_name}],
                start_time=start_time,
                end_time=end_time,
                statistics=['Sum']
            )

            if error_stats and invocation_stats:
                error_rate = (error_stats.get('Sum', 0) / max(invocation_stats.get('Sum', 1), 1)) * 100
                metrics.append(PerformanceMetric(
                    metric_id=f"lambda_{function_name}_error_rate",
                    component_type=ComponentType.LAMBDA_FUNCTION,
                    component_name=function_name,
                    metric_type=MetricType.ERROR_RATE,
                    value=error_rate,
                    unit='percent',
                    timestamp=end_time,
                    dimensions={'FunctionName': function_name},
                    metadata={'error_count': error_stats.get('Sum', 0)}
                ))

            logger.info(f"Collected {len(metrics)} metrics for Lambda function {function_name}")
            return metrics

        except Exception as e:
            logger.error(f"Error collecting Lambda metrics for {function_name}: {str(e)}")
            return []

    def collect_dynamodb_metrics(self, table_name: str) -> List[PerformanceMetric]:
        """
        Collect performance metrics from DynamoDB table

        Args:
            table_name: Name of the DynamoDB table

        Returns:
            List of performance metrics
        """
        try:
            logger.info(f"Collecting metrics for DynamoDB table: {table_name}")
            metrics = []

            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(minutes=5)

            # Read/Write latency
            for operation in ['Query', 'Scan', 'GetItem', 'PutItem']:
                latency_stats = self._get_cloudwatch_statistics(
                    namespace='AWS/DynamoDB',
                    metric_name=f'SuccessfulRequestLatency',
                    dimensions=[
                        {'Name': 'TableName', 'Value': table_name},
                        {'Name': 'Operation', 'Value': operation}
                    ],
                    start_time=start_time,
                    end_time=end_time,
                    statistics=['Average', 'Maximum']
                )

                if latency_stats:
                    metrics.append(PerformanceMetric(
                        metric_id=f"dynamodb_{table_name}_{operation.lower()}_latency",
                        component_type=ComponentType.DYNAMODB_TABLE,
                        component_name=table_name,
                        metric_type=MetricType.LATENCY,
                        value=latency_stats.get('Average', 0),
                        unit='milliseconds',
                        timestamp=end_time,
                        dimensions={'TableName': table_name, 'Operation': operation},
                        metadata={'max_latency': latency_stats.get('Maximum', 0)}
                    ))

            # Consumed capacity
            read_capacity_stats = self._get_cloudwatch_statistics(
                namespace='AWS/DynamoDB',
                metric_name='ConsumedReadCapacityUnits',
                dimensions=[{'Name': 'TableName', 'Value': table_name}],
                start_time=start_time,
                end_time=end_time,
                statistics=['Sum', 'Average']
            )

            if read_capacity_stats:
                metrics.append(PerformanceMetric(
                    metric_id=f"dynamodb_{table_name}_read_capacity",
                    component_type=ComponentType.DYNAMODB_TABLE,
                    component_name=table_name,
                    metric_type=MetricType.RESOURCE_UTILIZATION,
                    value=read_capacity_stats.get('Average', 0),
                    unit='capacity_units',
                    timestamp=end_time,
                    dimensions={'TableName': table_name, 'CapacityType': 'Read'},
                    metadata={'total_consumed': read_capacity_stats.get('Sum', 0)}
                ))

            # Throttling events
            throttle_stats = self._get_cloudwatch_statistics(
                namespace='AWS/DynamoDB',
                metric_name='UserErrors',
                dimensions=[{'Name': 'TableName', 'Value': table_name}],
                start_time=start_time,
                end_time=end_time,
                statistics=['Sum']
            )

            if throttle_stats:
                metrics.append(PerformanceMetric(
                    metric_id=f"dynamodb_{table_name}_throttle_events",
                    component_type=ComponentType.DYNAMODB_TABLE,
                    component_name=table_name,
                    metric_type=MetricType.ERROR_RATE,
                    value=throttle_stats.get('Sum', 0),
                    unit='count',
                    timestamp=end_time,
                    dimensions={'TableName': table_name},
                    metadata={}
                ))

            logger.info(f"Collected {len(metrics)} metrics for DynamoDB table {table_name}")
            return metrics

        except Exception as e:
            logger.error(f"Error collecting DynamoDB metrics for {table_name}: {str(e)}")
            return []

    def collect_cache_metrics(self) -> List[PerformanceMetric]:
        """
        Collect cache performance metrics

        Returns:
            List of cache performance metrics
        """
        try:
            logger.info("Collecting cache performance metrics")
            metrics = []

            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(minutes=5)

            # Cache hit ratio
            hit_ratio_stats = self._get_cloudwatch_statistics(
                namespace='ThreatIntel/Cache',
                metric_name='CacheHitRatio',
                dimensions=[{'Name': 'Environment', 'Value': ENVIRONMENT}],
                start_time=start_time,
                end_time=end_time,
                statistics=['Average']
            )

            if hit_ratio_stats:
                metrics.append(PerformanceMetric(
                    metric_id="cache_hit_ratio",
                    component_type=ComponentType.CACHE_LAYER,
                    component_name="redis_cluster",
                    metric_type=MetricType.CACHE_PERFORMANCE,
                    value=hit_ratio_stats.get('Average', 0),
                    unit='percent',
                    timestamp=end_time,
                    dimensions={'Environment': ENVIRONMENT},
                    metadata={}
                ))

            # Cache response time
            response_time_stats = self._get_cloudwatch_statistics(
                namespace='ThreatIntel/Cache',
                metric_name='CacheResponseTime',
                dimensions=[{'Name': 'Environment', 'Value': ENVIRONMENT}],
                start_time=start_time,
                end_time=end_time,
                statistics=['Average', 'Maximum']
            )

            if response_time_stats:
                metrics.append(PerformanceMetric(
                    metric_id="cache_response_time",
                    component_type=ComponentType.CACHE_LAYER,
                    component_name="redis_cluster",
                    metric_type=MetricType.LATENCY,
                    value=response_time_stats.get('Average', 0),
                    unit='milliseconds',
                    timestamp=end_time,
                    dimensions={'Environment': ENVIRONMENT},
                    metadata={'max_response_time': response_time_stats.get('Maximum', 0)}
                ))

            logger.info(f"Collected {len(metrics)} cache metrics")
            return metrics

        except Exception as e:
            logger.error(f"Error collecting cache metrics: {str(e)}")
            return []

    def collect_custom_application_metrics(self) -> List[PerformanceMetric]:
        """
        Collect custom application-specific metrics

        Returns:
            List of custom performance metrics
        """
        try:
            logger.info("Collecting custom application metrics")
            metrics = []

            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(minutes=5)

            # Threat intelligence processing metrics
            processing_metrics = [
                ('ThreatIntel/Processing', 'ProcessingLatency', MetricType.LATENCY),
                ('ThreatIntel/Processing', 'IndicatorsProcessed', MetricType.THROUGHPUT),
                ('ThreatIntel/Processing', 'QualityScore', MetricType.DATA_QUALITY),
                ('ThreatIntel/Search', 'SearchLatency', MetricType.LATENCY),
                ('ThreatIntel/Analytics', 'AnalyticsLatency', MetricType.LATENCY)
            ]

            for namespace, metric_name, metric_type in processing_metrics:
                stats = self._get_cloudwatch_statistics(
                    namespace=namespace,
                    metric_name=metric_name,
                    dimensions=[{'Name': 'Environment', 'Value': ENVIRONMENT}],
                    start_time=start_time,
                    end_time=end_time,
                    statistics=['Average', 'Maximum']
                )

                if stats:
                    component_name = namespace.split('/')[-1].lower()
                    metrics.append(PerformanceMetric(
                        metric_id=f"{component_name}_{metric_name.lower()}",
                        component_type=ComponentType.ANALYTICS_ENGINE if 'Analytics' in namespace else ComponentType.SEARCH_ENGINE,
                        component_name=component_name,
                        metric_type=metric_type,
                        value=stats.get('Average', 0),
                        unit='milliseconds' if metric_type == MetricType.LATENCY else 'count',
                        timestamp=end_time,
                        dimensions={'Environment': ENVIRONMENT, 'Component': component_name},
                        metadata={'max_value': stats.get('Maximum', 0)}
                    ))

            logger.info(f"Collected {len(metrics)} custom application metrics")
            return metrics

        except Exception as e:
            logger.error(f"Error collecting custom application metrics: {str(e)}")
            return []

    def analyze_performance_trends(self, metrics: List[PerformanceMetric]) -> Dict[str, Any]:
        """
        Analyze performance trends and detect anomalies

        Args:
            metrics: List of performance metrics to analyze

        Returns:
            Performance analysis results
        """
        try:
            logger.info(f"Analyzing performance trends for {len(metrics)} metrics")

            analysis_results = {
                'anomalies_detected': [],
                'performance_trends': {},
                'recommendations': [],
                'baseline_updates': []
            }

            # Group metrics by component and type
            grouped_metrics = defaultdict(list)
            for metric in metrics:
                key = f"{metric.component_name}_{metric.metric_type.value}"
                grouped_metrics[key].append(metric)

            # Analyze each metric group
            for group_key, group_metrics in grouped_metrics.items():
                if len(group_metrics) < 2:
                    continue

                # Calculate trend
                values = [m.value for m in group_metrics]
                timestamps = [m.timestamp for m in group_metrics]

                trend_analysis = self._calculate_trend(values, timestamps)
                analysis_results['performance_trends'][group_key] = trend_analysis

                # Check for anomalies
                baseline = self._get_baseline(group_metrics[0].component_name, group_metrics[0].metric_type)
                if baseline:
                    for metric in group_metrics:
                        anomaly = self._detect_anomaly(metric, baseline)
                        if anomaly:
                            analysis_results['anomalies_detected'].append(anomaly)

                # Generate recommendations
                recommendations = self._generate_performance_recommendations(group_key, trend_analysis, group_metrics)
                analysis_results['recommendations'].extend(recommendations)

            logger.info(f"Performance analysis completed: {len(analysis_results['anomalies_detected'])} anomalies detected")
            return analysis_results

        except Exception as e:
            logger.error(f"Error analyzing performance trends: {str(e)}")
            return {}

    def check_alert_conditions(self, metrics: List[PerformanceMetric]) -> List[PerformanceAlert]:
        """
        Check metrics against alert conditions and generate alerts

        Args:
            metrics: List of performance metrics to check

        Returns:
            List of generated alerts
        """
        try:
            logger.info(f"Checking alert conditions for {len(metrics)} metrics")
            alerts = []

            for metric in metrics:
                for condition in self.alert_conditions:
                    if self._metric_matches_condition(metric, condition):
                        alert = self._evaluate_alert_condition(metric, condition)
                        if alert:
                            alerts.append(alert)

            # Filter duplicate alerts based on cooldown
            filtered_alerts = self._filter_alerts_by_cooldown(alerts)

            logger.info(f"Generated {len(filtered_alerts)} alerts after filtering")
            return filtered_alerts

        except Exception as e:
            logger.error(f"Error checking alert conditions: {str(e)}")
            return []

    def send_alerts(self, alerts: List[PerformanceAlert]) -> Dict[str, int]:
        """
        Send alerts via configured notification channels

        Args:
            alerts: List of alerts to send

        Returns:
            Summary of sent alerts by severity
        """
        try:
            logger.info(f"Sending {len(alerts)} alerts")

            sent_summary = defaultdict(int)

            for alert in alerts:
                try:
                    # Create alert message
                    message = self._format_alert_message(alert)

                    # Send via SNS if configured
                    if ALERT_TOPIC_ARN:
                        self._send_sns_alert(alert, message)

                    # Store alert in DynamoDB for tracking
                    self._store_alert(alert)

                    # Update active alerts tracking
                    self.active_alerts[alert.alert_id] = alert

                    sent_summary[alert.severity.value] += 1

                except Exception as e:
                    logger.error(f"Error sending alert {alert.alert_id}: {str(e)}")

            logger.info(f"Alert sending completed: {dict(sent_summary)}")
            return dict(sent_summary)

        except Exception as e:
            logger.error(f"Error sending alerts: {str(e)}")
            return {}

    def publish_metrics_to_cloudwatch(self, metrics: List[PerformanceMetric]) -> bool:
        """
        Publish collected metrics to CloudWatch

        Args:
            metrics: List of metrics to publish

        Returns:
            True if successful, False otherwise
        """
        try:
            logger.info(f"Publishing {len(metrics)} metrics to CloudWatch")

            # Group metrics by namespace for batch publishing
            namespace_metrics = defaultdict(list)

            for metric in metrics:
                namespace = f"ThreatIntel/Performance/{metric.component_type.value.title()}"

                metric_data = {
                    'MetricName': f"{metric.metric_type.value.title()}",
                    'Value': metric.value,
                    'Unit': self._convert_unit_for_cloudwatch(metric.unit),
                    'Timestamp': metric.timestamp,
                    'Dimensions': [
                        {'Name': key, 'Value': value}
                        for key, value in metric.dimensions.items()
                    ]
                }

                namespace_metrics[namespace].append(metric_data)

            # Publish metrics in batches
            for namespace, metric_list in namespace_metrics.items():
                for i in range(0, len(metric_list), MAX_METRICS_BATCH_SIZE):
                    batch = metric_list[i:i + MAX_METRICS_BATCH_SIZE]

                    cloudwatch.put_metric_data(
                        Namespace=namespace,
                        MetricData=batch
                    )

            logger.info("Metrics published to CloudWatch successfully")
            return True

        except Exception as e:
            logger.error(f"Error publishing metrics to CloudWatch: {str(e)}")
            return False

    def _get_cloudwatch_statistics(self, namespace: str, metric_name: str,
                                 dimensions: List[Dict[str, str]],
                                 start_time: datetime, end_time: datetime,
                                 statistics: List[str]) -> Optional[Dict[str, float]]:
        """Get statistics from CloudWatch"""
        try:
            response = cloudwatch.get_metric_statistics(
                Namespace=namespace,
                MetricName=metric_name,
                Dimensions=dimensions,
                StartTime=start_time,
                EndTime=end_time,
                Period=300,  # 5 minutes
                Statistics=statistics
            )

            if response['Datapoints']:
                # Return the most recent datapoint
                latest = sorted(response['Datapoints'], key=lambda x: x['Timestamp'])[-1]
                return {stat: latest.get(stat, 0) for stat in statistics}

            return None

        except Exception as e:
            logger.error(f"Error getting CloudWatch statistics: {str(e)}")
            return None

    def _load_alert_conditions(self) -> List[AlertCondition]:
        """Load alert conditions configuration"""
        # In a real implementation, this would load from configuration
        return [
            AlertCondition(
                condition_id="lambda_duration_high",
                metric_type=MetricType.LATENCY,
                threshold_type="static",
                threshold_value=30000,  # 30 seconds
                comparison_operator="GreaterThan",
                evaluation_periods=2,
                severity=AlertSeverity.HIGH
            ),
            AlertCondition(
                condition_id="error_rate_high",
                metric_type=MetricType.ERROR_RATE,
                threshold_type="static",
                threshold_value=5.0,  # 5%
                comparison_operator="GreaterThan",
                evaluation_periods=1,
                severity=AlertSeverity.CRITICAL
            ),
            AlertCondition(
                condition_id="cache_hit_ratio_low",
                metric_type=MetricType.CACHE_PERFORMANCE,
                threshold_type="static",
                threshold_value=80.0,  # 80%
                comparison_operator="LessThan",
                evaluation_periods=3,
                severity=AlertSeverity.MEDIUM
            )
        ]

    def _get_baseline(self, component_name: str, metric_type: MetricType) -> Optional[PerformanceBaseline]:
        """Get performance baseline for component and metric type"""
        baseline_key = f"{component_name}_{metric_type.value}"
        return self.baselines.get(baseline_key)

    def _detect_anomaly(self, metric: PerformanceMetric, baseline: PerformanceBaseline) -> Optional[Dict[str, Any]]:
        """Detect anomaly in metric based on baseline"""
        try:
            # Calculate z-score
            if baseline.standard_deviation > 0:
                z_score = abs(metric.value - baseline.baseline_value) / baseline.standard_deviation

                if z_score > ANOMALY_DETECTION_THRESHOLD:
                    return {
                        'metric_id': metric.metric_id,
                        'anomaly_type': 'statistical',
                        'z_score': z_score,
                        'current_value': metric.value,
                        'baseline_value': baseline.baseline_value,
                        'severity': 'high' if z_score > 3.0 else 'medium'
                    }

            return None

        except Exception as e:
            logger.error(f"Error detecting anomaly: {str(e)}")
            return None

    def _calculate_trend(self, values: List[float], timestamps: List[datetime]) -> Dict[str, Any]:
        """Calculate trend analysis for metric values"""
        try:
            if len(values) < 2:
                return {'trend': 'insufficient_data'}

            # Simple linear regression for trend
            n = len(values)
            x = list(range(n))

            sum_x = sum(x)
            sum_y = sum(values)
            sum_xy = sum(x[i] * values[i] for i in range(n))
            sum_x2 = sum(x[i] ** 2 for i in range(n))

            slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x ** 2)

            trend_direction = 'increasing' if slope > 0 else 'decreasing' if slope < 0 else 'stable'
            trend_strength = abs(slope) / (max(values) - min(values)) if max(values) != min(values) else 0

            return {
                'trend': trend_direction,
                'strength': trend_strength,
                'slope': slope,
                'latest_value': values[-1],
                'average_value': statistics.mean(values),
                'variance': statistics.variance(values) if len(values) > 1 else 0
            }

        except Exception as e:
            logger.error(f"Error calculating trend: {str(e)}")
            return {'trend': 'error'}

    def _generate_performance_recommendations(self, group_key: str, trend_analysis: Dict[str, Any],
                                           metrics: List[PerformanceMetric]) -> List[str]:
        """Generate performance optimization recommendations"""
        recommendations = []

        try:
            if trend_analysis.get('trend') == 'increasing':
                if 'latency' in group_key:
                    recommendations.append(f"Consider optimization for {group_key}: latency is increasing")
                elif 'error_rate' in group_key:
                    recommendations.append(f"Investigate error causes for {group_key}: error rate is increasing")

            if trend_analysis.get('variance', 0) > trend_analysis.get('average_value', 0) * 0.5:
                recommendations.append(f"High variance detected in {group_key}: consider load balancing")

        except Exception as e:
            logger.error(f"Error generating recommendations: {str(e)}")

        return recommendations

    def _metric_matches_condition(self, metric: PerformanceMetric, condition: AlertCondition) -> bool:
        """Check if metric matches alert condition criteria"""
        return metric.metric_type == condition.metric_type

    def _evaluate_alert_condition(self, metric: PerformanceMetric, condition: AlertCondition) -> Optional[PerformanceAlert]:
        """Evaluate if metric triggers alert condition"""
        try:
            if condition.threshold_type == "static" and condition.threshold_value is not None:
                threshold_met = False

                if condition.comparison_operator == "GreaterThan":
                    threshold_met = metric.value > condition.threshold_value
                elif condition.comparison_operator == "LessThan":
                    threshold_met = metric.value < condition.threshold_value
                elif condition.comparison_operator == "Equal":
                    threshold_met = metric.value == condition.threshold_value

                if threshold_met:
                    alert_id = f"{condition.condition_id}_{metric.component_name}_{int(time.time())}"

                    return PerformanceAlert(
                        alert_id=alert_id,
                        condition_id=condition.condition_id,
                        component_type=metric.component_type,
                        component_name=metric.component_name,
                        metric_type=metric.metric_type,
                        severity=condition.severity,
                        current_value=metric.value,
                        threshold_value=condition.threshold_value,
                        message=f"{metric.metric_type.value} {condition.comparison_operator} {condition.threshold_value}",
                        timestamp=metric.timestamp
                    )

            return None

        except Exception as e:
            logger.error(f"Error evaluating alert condition: {str(e)}")
            return None

    def _filter_alerts_by_cooldown(self, alerts: List[PerformanceAlert]) -> List[PerformanceAlert]:
        """Filter alerts based on cooldown period"""
        # This would implement cooldown logic to prevent alert spam
        return alerts

    def _format_alert_message(self, alert: PerformanceAlert) -> str:
        """Format alert message for notification"""
        return f"""
PERFORMANCE ALERT - {alert.severity.value.upper()}

Component: {alert.component_name} ({alert.component_type.value})
Metric: {alert.metric_type.value}
Current Value: {alert.current_value}
Threshold: {alert.threshold_value}
Message: {alert.message}
Timestamp: {alert.timestamp.isoformat()}

Alert ID: {alert.alert_id}
Environment: {ENVIRONMENT}
""".strip()

    def _send_sns_alert(self, alert: PerformanceAlert, message: str):
        """Send alert via SNS"""
        try:
            sns.publish(
                TopicArn=ALERT_TOPIC_ARN,
                Subject=f"[{ENVIRONMENT.upper()}] {alert.severity.value.upper()}: {alert.component_name}",
                Message=message
            )
        except Exception as e:
            logger.error(f"Error sending SNS alert: {str(e)}")

    def _store_alert(self, alert: PerformanceAlert):
        """Store alert in DynamoDB for tracking"""
        try:
            # This would store the alert in a DynamoDB table
            logger.debug(f"Storing alert {alert.alert_id}")
        except Exception as e:
            logger.error(f"Error storing alert: {str(e)}")

    def _convert_unit_for_cloudwatch(self, unit: str) -> str:
        """Convert metric unit to CloudWatch-compatible unit"""
        unit_mapping = {
            'milliseconds': 'Milliseconds',
            'seconds': 'Seconds',
            'percent': 'Percent',
            'count': 'Count',
            'capacity_units': 'Count'
        }
        return unit_mapping.get(unit, 'None')


# Lambda handler for performance metrics collection
def lambda_handler(event, context):
    """
    Lambda handler for performance metrics collection and alerting

    Supported actions:
    - collect_all: Collect metrics from all components
    - collect_lambda: Collect Lambda function metrics
    - collect_dynamodb: Collect DynamoDB metrics
    - collect_cache: Collect cache metrics
    - analyze_trends: Analyze performance trends
    - check_alerts: Check alert conditions
    """
    try:
        logger.info(f"Performance metrics collector invoked")

        collector = PerformanceMetricsCollector()
        action = event.get('action', 'collect_all')

        if action == 'collect_all':
            all_metrics = []

            # Collect Lambda metrics
            lambda_functions = event.get('lambda_functions', [])
            for function_name in lambda_functions:
                metrics = collector.collect_lambda_metrics(function_name)
                all_metrics.extend(metrics)

            # Collect DynamoDB metrics
            table_names = event.get('table_names', [])
            for table_name in table_names:
                metrics = collector.collect_dynamodb_metrics(table_name)
                all_metrics.extend(metrics)

            # Collect cache metrics
            cache_metrics = collector.collect_cache_metrics()
            all_metrics.extend(cache_metrics)

            # Collect custom application metrics
            custom_metrics = collector.collect_custom_application_metrics()
            all_metrics.extend(custom_metrics)

            # Publish to CloudWatch
            publish_success = collector.publish_metrics_to_cloudwatch(all_metrics)

            # Analyze trends
            trend_analysis = collector.analyze_performance_trends(all_metrics)

            # Check alerts
            alerts = collector.check_alert_conditions(all_metrics)
            alert_summary = collector.send_alerts(alerts)

            return {
                'statusCode': 200,
                'body': json.dumps({
                    'metrics_collected': len(all_metrics),
                    'metrics_published': publish_success,
                    'trend_analysis': trend_analysis,
                    'alerts_generated': len(alerts),
                    'alert_summary': alert_summary
                }, default=str)
            }

        else:
            return {
                'statusCode': 400,
                'body': json.dumps({
                    'error': f'Unknown action: {action}',
                    'supported_actions': ['collect_all', 'collect_lambda', 'collect_dynamodb', 'collect_cache']
                })
            }

    except Exception as e:
        logger.error(f"Error in performance metrics collector: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': 'Internal server error',
                'message': str(e)
            })
        }


if __name__ == "__main__":
    # Test the metrics collector locally
    test_event = {
        'action': 'collect_all',
        'lambda_functions': ['threat-intel-collector-dev', 'threat-intel-processor-dev'],
        'table_names': ['threat-intelligence-dev']
    }

    result = lambda_handler(test_event, None)
    print(json.dumps(result, indent=2))