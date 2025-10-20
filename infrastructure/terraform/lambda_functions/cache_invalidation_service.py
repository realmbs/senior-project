"""
Intelligent Cache Invalidation Service
Phase 8D Implementation - Infrastructure Enhancements

This module provides intelligent cache invalidation strategies for the threat intelligence platform:
- Event-driven cache invalidation based on data changes
- Smart invalidation patterns and dependency tracking
- Batch invalidation for related data updates
- Cache warming strategies after invalidation
- Performance-optimized invalidation scheduling

Features:
- Automatic invalidation triggers based on DynamoDB streams
- Intelligent dependency graph for cascade invalidation
- Batch processing for high-volume invalidations
- Cache warming priority queues
- Real-time invalidation metrics and monitoring
"""

import json
import boto3
import logging
import os
import time
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
from collections import defaultdict, deque
import re
import fnmatch

# Import cache manager
from cache_manager import get_cache_manager, IntelligentCacheManager

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# AWS Service Clients
dynamodb = boto3.resource('dynamodb')
sqs = boto3.client('sqs')
sns = boto3.client('sns')
cloudwatch = boto3.client('cloudwatch')

# Environment Variables
ENVIRONMENT = os.environ.get('ENVIRONMENT', 'dev')
PROJECT_NAME = os.environ.get('PROJECT_NAME', 'threat-intel')
INVALIDATION_QUEUE_URL = os.environ.get('INVALIDATION_QUEUE_URL', '')
CACHE_WARMING_QUEUE_URL = os.environ.get('CACHE_WARMING_QUEUE_URL', '')

# Invalidation Configuration
MAX_BATCH_SIZE = 25  # SQS batch limit
INVALIDATION_DELAY_SECONDS = 5  # Delay before processing invalidation
MAX_DEPENDENCY_DEPTH = 3  # Maximum depth for dependency cascading
CACHE_WARMING_DELAY_SECONDS = 10  # Delay before warming cache


class InvalidationType(Enum):
    """Types of cache invalidation"""
    IMMEDIATE = "immediate"
    DELAYED = "delayed"
    BATCH = "batch"
    CASCADE = "cascade"
    SMART = "smart"


class InvalidationTrigger(Enum):
    """Triggers for cache invalidation"""
    DATA_UPDATE = "data_update"
    DATA_DELETE = "data_delete"
    SCHEMA_CHANGE = "schema_change"
    MANUAL = "manual"
    SCHEDULED = "scheduled"
    TTL_EXPIRY = "ttl_expiry"


class CacheNamespace(Enum):
    """Cache namespaces for organized invalidation"""
    THREAT_INTEL = "threat_intel"
    SEARCH_RESULTS = "search_results"
    ANALYTICS = "analytics"
    ENRICHMENT = "enrichment"
    EXPORT = "export"
    CORRELATION = "correlation"


@dataclass
class InvalidationRequest:
    """Cache invalidation request"""
    request_id: str
    invalidation_type: InvalidationType
    trigger: InvalidationTrigger
    namespace: CacheNamespace
    patterns: List[str]
    priority: int  # 1-5, 1 being highest
    dependencies: List[str]
    metadata: Dict[str, Any]
    created_at: datetime
    scheduled_for: Optional[datetime] = None


@dataclass
class InvalidationResult:
    """Result of cache invalidation operation"""
    request_id: str
    patterns_processed: List[str]
    keys_invalidated: int
    dependencies_processed: int
    execution_time_ms: int
    success: bool
    errors: List[str]
    cache_warming_triggered: bool


@dataclass
class CacheDependency:
    """Cache dependency relationship"""
    parent_pattern: str
    child_patterns: List[str]
    invalidation_type: InvalidationType
    namespace: CacheNamespace


class InvalidationEngine:
    """Intelligent cache invalidation engine"""

    def __init__(self):
        self.cache_manager = get_cache_manager()
        self.dependency_graph = self._build_dependency_graph()
        self.invalidation_queue = deque()
        self.metrics = defaultdict(int)

    def invalidate_cache(self, request: InvalidationRequest) -> InvalidationResult:
        """
        Execute cache invalidation request

        Args:
            request: Invalidation request details

        Returns:
            Invalidation result with metrics
        """
        start_time = time.time()
        logger.info(f"Processing invalidation request: {request.request_id}")

        try:
            # Check if scheduled for future
            if request.scheduled_for and request.scheduled_for > datetime.now(timezone.utc):
                self._schedule_invalidation(request)
                return InvalidationResult(
                    request_id=request.request_id,
                    patterns_processed=[],
                    keys_invalidated=0,
                    dependencies_processed=0,
                    execution_time_ms=0,
                    success=True,
                    errors=[],
                    cache_warming_triggered=False
                )

            # Process based on invalidation type
            result = self._process_invalidation(request)

            # Update metrics
            self.metrics['total_invalidations'] += 1
            self.metrics['keys_invalidated'] += result.keys_invalidated
            self.metrics[f'namespace_{request.namespace.value}'] += 1

            # Send metrics to CloudWatch
            self._send_invalidation_metrics(request, result)

            logger.info(f"Invalidation completed: {request.request_id}, Keys: {result.keys_invalidated}")
            return result

        except Exception as e:
            logger.error(f"Error processing invalidation: {str(e)}")
            return InvalidationResult(
                request_id=request.request_id,
                patterns_processed=[],
                keys_invalidated=0,
                dependencies_processed=0,
                execution_time_ms=int((time.time() - start_time) * 1000),
                success=False,
                errors=[str(e)],
                cache_warming_triggered=False
            )

    def invalidate_by_data_change(self, table_name: str, record: Dict[str, Any],
                                event_name: str) -> List[InvalidationResult]:
        """
        Intelligent invalidation based on DynamoDB data changes

        Args:
            table_name: DynamoDB table name
            record: Changed record data
            event_name: DynamoDB stream event name

        Returns:
            List of invalidation results
        """
        try:
            logger.info(f"Processing data change invalidation: {table_name}, Event: {event_name}")

            # Determine affected cache patterns
            patterns = self._analyze_data_change_impact(table_name, record, event_name)

            if not patterns:
                logger.debug("No cache patterns affected by data change")
                return []

            # Create invalidation requests
            requests = []
            for namespace, pattern_list in patterns.items():
                request = InvalidationRequest(
                    request_id=f"data_change_{int(time.time() * 1000)}_{namespace.value}",
                    invalidation_type=InvalidationType.SMART,
                    trigger=InvalidationTrigger.DATA_UPDATE if event_name != 'REMOVE' else InvalidationTrigger.DATA_DELETE,
                    namespace=namespace,
                    patterns=pattern_list,
                    priority=self._calculate_priority(namespace, event_name),
                    dependencies=self._find_dependencies(pattern_list),
                    metadata={
                        'table_name': table_name,
                        'event_name': event_name,
                        'record_keys': self._extract_record_keys(record)
                    },
                    created_at=datetime.now(timezone.utc)
                )
                requests.append(request)

            # Execute invalidation requests
            results = []
            for request in requests:
                result = self.invalidate_cache(request)
                results.append(result)

                # Trigger cache warming if needed
                if result.success and event_name != 'REMOVE':
                    self._trigger_cache_warming(request.namespace, request.patterns)

            return results

        except Exception as e:
            logger.error(f"Error in data change invalidation: {str(e)}")
            return []

    def batch_invalidate(self, requests: List[InvalidationRequest]) -> List[InvalidationResult]:
        """
        Process multiple invalidation requests in batch

        Args:
            requests: List of invalidation requests

        Returns:
            List of invalidation results
        """
        try:
            logger.info(f"Processing batch invalidation: {len(requests)} requests")

            # Sort by priority and group by namespace
            sorted_requests = sorted(requests, key=lambda r: r.priority)
            grouped_requests = defaultdict(list)

            for request in sorted_requests:
                grouped_requests[request.namespace].append(request)

            # Process by namespace to optimize cache operations
            results = []
            for namespace, namespace_requests in grouped_requests.items():
                namespace_results = self._process_namespace_batch(namespace, namespace_requests)
                results.extend(namespace_results)

            logger.info(f"Batch invalidation completed: {len(results)} results")
            return results

        except Exception as e:
            logger.error(f"Error in batch invalidation: {str(e)}")
            return []

    def warm_cache_after_invalidation(self, namespace: CacheNamespace,
                                    patterns: List[str], priority: int = 3) -> bool:
        """
        Warm cache after invalidation with intelligent preloading

        Args:
            namespace: Cache namespace
            patterns: Patterns that were invalidated
            priority: Warming priority (1-5)

        Returns:
            True if warming was triggered successfully
        """
        try:
            logger.info(f"Warming cache for namespace {namespace.value}: {len(patterns)} patterns")

            # Determine what to warm based on usage patterns
            warming_keys = self._determine_warming_keys(namespace, patterns)

            if not warming_keys:
                logger.debug("No keys identified for cache warming")
                return True

            # Create warming functions based on namespace
            warming_functions = self._create_warming_functions(namespace, warming_keys)

            # Execute cache warming
            if warming_functions:
                warm_result = self.cache_manager.warm_cache(warming_functions, ttl=1800)
                successful_count = sum(warm_result.values())

                logger.info(f"Cache warming completed: {successful_count}/{len(warming_functions)} successful")

                # Update metrics
                self.metrics['cache_warming_operations'] += 1
                self.metrics['cache_warming_keys'] += successful_count

                return successful_count > 0

            return True

        except Exception as e:
            logger.error(f"Error in cache warming: {str(e)}")
            return False

    def _process_invalidation(self, request: InvalidationRequest) -> InvalidationResult:
        """Process individual invalidation request"""
        start_time = time.time()
        keys_invalidated = 0
        dependencies_processed = 0
        errors = []
        cache_warming_triggered = False

        try:
            # Process main patterns
            for pattern in request.patterns:
                try:
                    count = self.cache_manager.invalidate_pattern(pattern)
                    keys_invalidated += count
                    logger.debug(f"Invalidated pattern {pattern}: {count} keys")
                except Exception as e:
                    errors.append(f"Pattern {pattern}: {str(e)}")

            # Process dependencies if cascade invalidation
            if request.invalidation_type == InvalidationType.CASCADE:
                dependencies_processed = self._process_dependencies(request.patterns, request.namespace)

            # Trigger cache warming for non-delete operations
            if (request.trigger != InvalidationTrigger.DATA_DELETE and
                request.invalidation_type in [InvalidationType.SMART, InvalidationType.CASCADE]):

                warming_success = self.warm_cache_after_invalidation(
                    request.namespace, request.patterns, request.priority
                )
                cache_warming_triggered = warming_success

        except Exception as e:
            errors.append(f"General error: {str(e)}")

        execution_time = int((time.time() - start_time) * 1000)

        return InvalidationResult(
            request_id=request.request_id,
            patterns_processed=request.patterns,
            keys_invalidated=keys_invalidated,
            dependencies_processed=dependencies_processed,
            execution_time_ms=execution_time,
            success=len(errors) == 0,
            errors=errors,
            cache_warming_triggered=cache_warming_triggered
        )

    def _analyze_data_change_impact(self, table_name: str, record: Dict[str, Any],
                                  event_name: str) -> Dict[CacheNamespace, List[str]]:
        """Analyze what cache patterns are affected by data change"""
        patterns = defaultdict(list)

        try:
            # Extract key information from record
            object_id = record.get('Keys', {}).get('object_id', {}).get('S', '')
            object_type = record.get('Keys', {}).get('object_type', {}).get('S', '')

            # Threat intelligence table changes
            if 'threat-intelligence' in table_name:
                # Invalidate specific object cache
                if object_id:
                    patterns[CacheNamespace.THREAT_INTEL].extend([
                        f"threat_intel:object:{object_id}",
                        f"threat_intel:object:{object_id}:*"
                    ])

                # Invalidate type-based caches
                if object_type:
                    patterns[CacheNamespace.THREAT_INTEL].extend([
                        f"threat_intel:type:{object_type}",
                        f"threat_intel:type:{object_type}:*"
                    ])

                # Invalidate search results that might include this object
                patterns[CacheNamespace.SEARCH_RESULTS].extend([
                    f"search:*:{object_type}:*",
                    "search:recent:*",
                    "search:popular:*"
                ])

                # Invalidate analytics that might be affected
                patterns[CacheNamespace.ANALYTICS].extend([
                    "analytics:trend:*",
                    "analytics:geographic:*",
                    f"analytics:risk:{object_type}:*"
                ])

                # Extract additional attributes for specific invalidations
                image = record.get('NewImage', {}) or record.get('OldImage', {})
                if image:
                    # Source-based invalidation
                    source = image.get('source_name', {}).get('S', '')
                    if source:
                        patterns[CacheNamespace.THREAT_INTEL].append(f"threat_intel:source:{source}:*")
                        patterns[CacheNamespace.ANALYTICS].append(f"analytics:source:{source}:*")

                    # Geographic invalidation
                    geo_region = image.get('geographic_region', {}).get('S', '')
                    if geo_region:
                        patterns[CacheNamespace.ANALYTICS].append(f"analytics:geo:{geo_region}:*")

                    # Pattern hash invalidation
                    pattern_hash = image.get('pattern_hash', {}).get('S', '')
                    if pattern_hash:
                        patterns[CacheNamespace.THREAT_INTEL].append(f"threat_intel:pattern:{pattern_hash}")

            # Enrichment cache changes
            elif 'enrichment-cache' in table_name:
                observable_value = record.get('Keys', {}).get('observable_value', {}).get('S', '')
                enrichment_type = record.get('Keys', {}).get('enrichment_type', {}).get('S', '')

                if observable_value and enrichment_type:
                    patterns[CacheNamespace.ENRICHMENT].extend([
                        f"enrichment:{enrichment_type}:{observable_value}",
                        f"enrichment:{enrichment_type}:*",
                        f"enrichment:*:{observable_value}"
                    ])

            # Deduplication table changes
            elif 'dedup' in table_name:
                content_hash = record.get('Keys', {}).get('content_hash', {}).get('S', '')
                if content_hash:
                    patterns[CacheNamespace.THREAT_INTEL].append(f"dedup:{content_hash}")

        except Exception as e:
            logger.error(f"Error analyzing data change impact: {str(e)}")

        return dict(patterns)

    def _calculate_priority(self, namespace: CacheNamespace, event_name: str) -> int:
        """Calculate invalidation priority based on namespace and event type"""
        # Base priority by namespace
        namespace_priority = {
            CacheNamespace.THREAT_INTEL: 1,  # Highest priority
            CacheNamespace.SEARCH_RESULTS: 2,
            CacheNamespace.ANALYTICS: 3,
            CacheNamespace.ENRICHMENT: 3,
            CacheNamespace.EXPORT: 4,
            CacheNamespace.CORRELATION: 4
        }

        priority = namespace_priority.get(namespace, 3)

        # Increase priority for deletions
        if event_name == 'REMOVE':
            priority = max(1, priority - 1)

        return priority

    def _find_dependencies(self, patterns: List[str]) -> List[str]:
        """Find cache dependencies for given patterns"""
        dependencies = []

        for pattern in patterns:
            for dependency in self.dependency_graph:
                if fnmatch.fnmatch(pattern, dependency.parent_pattern):
                    dependencies.extend(dependency.child_patterns)

        return list(set(dependencies))

    def _extract_record_keys(self, record: Dict[str, Any]) -> Dict[str, str]:
        """Extract key fields from DynamoDB record"""
        keys = {}

        try:
            # Extract from Keys field
            record_keys = record.get('Keys', {})
            for key, value_obj in record_keys.items():
                if isinstance(value_obj, dict):
                    # Get the actual value from the DynamoDB attribute value format
                    for data_type, data_value in value_obj.items():
                        keys[key] = str(data_value)
                        break

        except Exception as e:
            logger.error(f"Error extracting record keys: {str(e)}")

        return keys

    def _schedule_invalidation(self, request: InvalidationRequest):
        """Schedule invalidation for future execution"""
        try:
            # Send to SQS with delay
            delay_seconds = max(0, int((request.scheduled_for - datetime.now(timezone.utc)).total_seconds()))

            if INVALIDATION_QUEUE_URL:
                sqs.send_message(
                    QueueUrl=INVALIDATION_QUEUE_URL,
                    MessageBody=json.dumps(asdict(request), default=str),
                    DelaySeconds=min(delay_seconds, 900)  # SQS max delay is 15 minutes
                )

            logger.info(f"Scheduled invalidation request {request.request_id} for {request.scheduled_for}")

        except Exception as e:
            logger.error(f"Error scheduling invalidation: {str(e)}")

    def _process_dependencies(self, patterns: List[str], namespace: CacheNamespace) -> int:
        """Process dependency invalidations"""
        dependencies_processed = 0

        try:
            for pattern in patterns:
                for dependency in self.dependency_graph:
                    if (dependency.namespace == namespace and
                        fnmatch.fnmatch(pattern, dependency.parent_pattern)):

                        for child_pattern in dependency.child_patterns:
                            count = self.cache_manager.invalidate_pattern(child_pattern)
                            dependencies_processed += count

        except Exception as e:
            logger.error(f"Error processing dependencies: {str(e)}")

        return dependencies_processed

    def _process_namespace_batch(self, namespace: CacheNamespace,
                                requests: List[InvalidationRequest]) -> List[InvalidationResult]:
        """Process batch of requests for specific namespace"""
        results = []

        try:
            # Collect all patterns for batch processing
            all_patterns = []
            for request in requests:
                all_patterns.extend(request.patterns)

            # Remove duplicates while preserving order
            unique_patterns = list(dict.fromkeys(all_patterns))

            # Process patterns in batch
            total_invalidated = 0
            for pattern in unique_patterns:
                count = self.cache_manager.invalidate_pattern(pattern)
                total_invalidated += count

            # Create results for each request
            for request in requests:
                result = InvalidationResult(
                    request_id=request.request_id,
                    patterns_processed=request.patterns,
                    keys_invalidated=total_invalidated // len(requests),  # Approximate distribution
                    dependencies_processed=0,
                    execution_time_ms=0,
                    success=True,
                    errors=[],
                    cache_warming_triggered=False
                )
                results.append(result)

        except Exception as e:
            logger.error(f"Error processing namespace batch: {str(e)}")

        return results

    def _determine_warming_keys(self, namespace: CacheNamespace, patterns: List[str]) -> List[str]:
        """Determine which keys to warm based on usage patterns"""
        warming_keys = []

        try:
            # This would typically analyze usage statistics
            # For now, return a subset of common patterns
            if namespace == CacheNamespace.THREAT_INTEL:
                warming_keys.extend([
                    "threat_intel:recent:indicators",
                    "threat_intel:high_confidence:all",
                    "threat_intel:sources:summary"
                ])
            elif namespace == CacheNamespace.SEARCH_RESULTS:
                warming_keys.extend([
                    "search:popular:queries",
                    "search:recent:results"
                ])
            elif namespace == CacheNamespace.ANALYTICS:
                warming_keys.extend([
                    "analytics:trend:daily",
                    "analytics:risk:summary"
                ])

        except Exception as e:
            logger.error(f"Error determining warming keys: {str(e)}")

        return warming_keys

    def _create_warming_functions(self, namespace: CacheNamespace,
                                warming_keys: List[str]) -> Dict[str, callable]:
        """Create functions to warm specific cache keys"""
        warming_functions = {}

        try:
            # This would create actual fetch functions based on the keys
            # For now, return mock functions
            for key in warming_keys:
                warming_functions[key] = lambda: {"warmed": True, "timestamp": datetime.now().isoformat()}

        except Exception as e:
            logger.error(f"Error creating warming functions: {str(e)}")

        return warming_functions

    def _build_dependency_graph(self) -> List[CacheDependency]:
        """Build cache dependency graph"""
        dependencies = [
            # Threat intelligence dependencies
            CacheDependency(
                parent_pattern="threat_intel:object:*",
                child_patterns=["search:*", "analytics:trend:*"],
                invalidation_type=InvalidationType.CASCADE,
                namespace=CacheNamespace.THREAT_INTEL
            ),

            # Search result dependencies
            CacheDependency(
                parent_pattern="search:query:*",
                child_patterns=["search:popular:*", "search:recent:*"],
                invalidation_type=InvalidationType.CASCADE,
                namespace=CacheNamespace.SEARCH_RESULTS
            ),

            # Analytics dependencies
            CacheDependency(
                parent_pattern="analytics:trend:*",
                child_patterns=["analytics:summary:*", "analytics:dashboard:*"],
                invalidation_type=InvalidationType.CASCADE,
                namespace=CacheNamespace.ANALYTICS
            )
        ]

        return dependencies

    def _send_invalidation_metrics(self, request: InvalidationRequest, result: InvalidationResult):
        """Send invalidation metrics to CloudWatch"""
        try:
            metric_data = [
                {
                    'MetricName': 'CacheInvalidations',
                    'Value': 1,
                    'Unit': 'Count',
                    'Dimensions': [
                        {'Name': 'Environment', 'Value': ENVIRONMENT},
                        {'Name': 'Namespace', 'Value': request.namespace.value},
                        {'Name': 'InvalidationType', 'Value': request.invalidation_type.value}
                    ]
                },
                {
                    'MetricName': 'CacheKeysInvalidated',
                    'Value': result.keys_invalidated,
                    'Unit': 'Count',
                    'Dimensions': [
                        {'Name': 'Environment', 'Value': ENVIRONMENT},
                        {'Name': 'Namespace', 'Value': request.namespace.value}
                    ]
                },
                {
                    'MetricName': 'InvalidationExecutionTime',
                    'Value': result.execution_time_ms,
                    'Unit': 'Milliseconds',
                    'Dimensions': [
                        {'Name': 'Environment', 'Value': ENVIRONMENT}
                    ]
                }
            ]

            cloudwatch.put_metric_data(
                Namespace='ThreatIntel/CacheInvalidation',
                MetricData=metric_data
            )

        except Exception as e:
            logger.error(f"Error sending invalidation metrics: {str(e)}")


# Global invalidation engine instance
invalidation_engine = None

def get_invalidation_engine() -> InvalidationEngine:
    """Get global invalidation engine instance"""
    global invalidation_engine
    if invalidation_engine is None:
        invalidation_engine = InvalidationEngine()
    return invalidation_engine


# Lambda handler for cache invalidation operations
def lambda_handler(event, context):
    """
    Lambda handler for cache invalidation operations

    Supported event sources:
    - DynamoDB Streams: Automatic invalidation on data changes
    - SQS: Scheduled invalidation requests
    - API Gateway: Manual invalidation requests
    """
    try:
        logger.info(f"Cache invalidation service invoked")
        engine = get_invalidation_engine()

        # Handle DynamoDB Stream events
        if 'Records' in event and event['Records']:
            results = []
            for record in event['Records']:
                if record.get('eventSource') == 'aws:dynamodb':
                    table_name = record.get('eventSourceARN', '').split('/')[-1]
                    event_name = record.get('eventName', '')
                    dynamodb_record = record.get('dynamodb', {})

                    invalidation_results = engine.invalidate_by_data_change(
                        table_name, dynamodb_record, event_name
                    )
                    results.extend(invalidation_results)

            return {
                'statusCode': 200,
                'body': json.dumps({
                    'message': f'Processed {len(event["Records"])} DynamoDB records',
                    'invalidation_results': len(results),
                    'total_keys_invalidated': sum(r.keys_invalidated for r in results)
                }, default=str)
            }

        # Handle SQS messages (scheduled invalidations)
        elif event.get('Records') and event['Records'][0].get('eventSource') == 'aws:sqs':
            results = []
            for record in event['Records']:
                try:
                    message_body = json.loads(record['body'])
                    request = InvalidationRequest(**message_body)
                    result = engine.invalidate_cache(request)
                    results.append(result)
                except Exception as e:
                    logger.error(f"Error processing SQS message: {str(e)}")

            return {
                'statusCode': 200,
                'body': json.dumps({
                    'message': f'Processed {len(event["Records"])} SQS messages',
                    'results': [asdict(r) for r in results]
                }, default=str)
            }

        # Handle direct API calls
        else:
            action = event.get('action', 'invalidate')

            if action == 'invalidate':
                request_data = event.get('request', {})
                request = InvalidationRequest(**request_data)
                result = engine.invalidate_cache(request)

                return {
                    'statusCode': 200,
                    'body': json.dumps({
                        'result': asdict(result)
                    }, default=str)
                }

            elif action == 'batch_invalidate':
                requests_data = event.get('requests', [])
                requests = [InvalidationRequest(**req) for req in requests_data]
                results = engine.batch_invalidate(requests)

                return {
                    'statusCode': 200,
                    'body': json.dumps({
                        'results': [asdict(r) for r in results]
                    }, default=str)
                }

            elif action == 'warm_cache':
                namespace = CacheNamespace(event.get('namespace', 'threat_intel'))
                patterns = event.get('patterns', [])
                priority = event.get('priority', 3)

                success = engine.warm_cache_after_invalidation(namespace, patterns, priority)

                return {
                    'statusCode': 200,
                    'body': json.dumps({
                        'success': success,
                        'message': 'Cache warming completed'
                    })
                }

            else:
                return {
                    'statusCode': 400,
                    'body': json.dumps({
                        'error': f'Unknown action: {action}',
                        'supported_actions': ['invalidate', 'batch_invalidate', 'warm_cache']
                    })
                }

    except Exception as e:
        logger.error(f"Error in cache invalidation service: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': 'Internal server error',
                'message': str(e)
            })
        }


if __name__ == "__main__":
    # Test the invalidation service locally
    test_event = {
        'action': 'invalidate',
        'request': {
            'request_id': 'test_001',
            'invalidation_type': 'smart',
            'trigger': 'manual',
            'namespace': 'threat_intel',
            'patterns': ['threat_intel:test:*'],
            'priority': 1,
            'dependencies': [],
            'metadata': {},
            'created_at': datetime.now(timezone.utc).isoformat()
        }
    }

    result = lambda_handler(test_event, None)
    print(json.dumps(result, indent=2))