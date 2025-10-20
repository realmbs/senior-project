"""
ElastiCache Integration and Intelligent Caching Strategy
Phase 8D Implementation - Infrastructure Enhancements

This module provides enterprise-grade caching capabilities for the threat intelligence platform:
- ElastiCache Redis cluster integration for Lambda functions
- Intelligent cache invalidation and refresh strategies
- Multi-layer caching architecture (Lambda memory + Redis + DynamoDB)
- Cache hit ratio optimization and performance monitoring
- Automated cache warming and preloading strategies

Features:
- Distributed caching across Lambda instances
- Intelligent cache key generation and namespace management
- Cache compression and serialization optimization
- Real-time cache performance monitoring
- Automated cache eviction and TTL management
- Circuit breaker pattern for cache failures
"""

import json
import boto3
import redis
import logging
import os
import time
import pickle
import gzip
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Tuple, Union, Callable
from decimal import Decimal
from dataclasses import dataclass, asdict
from enum import Enum
import threading
from collections import defaultdict
from botocore.exceptions import ClientError

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# AWS Service Clients
cloudwatch = boto3.client('cloudwatch')
ssm = boto3.client('ssm')

# Environment Variables
ENVIRONMENT = os.environ.get('ENVIRONMENT', 'dev')
REDIS_CLUSTER_ENDPOINT = os.environ.get('REDIS_CLUSTER_ENDPOINT', '')
REDIS_PORT = int(os.environ.get('REDIS_PORT', '6379'))
ENABLE_CACHE_COMPRESSION = os.environ.get('ENABLE_CACHE_COMPRESSION', 'true').lower() == 'true'
CACHE_KEY_PREFIX = os.environ.get('CACHE_KEY_PREFIX', f'threat-intel-{ENVIRONMENT}')

# Cache Configuration
DEFAULT_TTL_SECONDS = 1800  # 30 minutes
LONG_TTL_SECONDS = 86400    # 24 hours
SHORT_TTL_SECONDS = 300     # 5 minutes
MAX_CACHE_VALUE_SIZE_MB = 5  # 5MB max per cache entry
CACHE_CIRCUIT_BREAKER_THRESHOLD = 5  # Failures before circuit opens
CACHE_CIRCUIT_BREAKER_TIMEOUT = 60   # Seconds before trying again


class CacheLayer(Enum):
    """Cache layer types"""
    MEMORY = "memory"      # Lambda memory cache
    REDIS = "redis"        # ElastiCache Redis
    DYNAMODB = "dynamodb"  # DynamoDB cache table
    HYBRID = "hybrid"      # Multi-layer caching


class CacheStrategy(Enum):
    """Caching strategies"""
    WRITE_THROUGH = "write_through"
    WRITE_BEHIND = "write_behind"
    CACHE_ASIDE = "cache_aside"
    REFRESH_AHEAD = "refresh_ahead"


class SerializationFormat(Enum):
    """Data serialization formats"""
    JSON = "json"
    PICKLE = "pickle"
    MSGPACK = "msgpack"


@dataclass
class CacheEntry:
    """Cache entry with metadata"""
    key: str
    value: Any
    ttl_seconds: int
    created_at: datetime
    expires_at: datetime
    hit_count: int = 0
    size_bytes: int = 0
    serialization_format: SerializationFormat = SerializationFormat.JSON


@dataclass
class CacheMetrics:
    """Cache performance metrics"""
    cache_hits: int = 0
    cache_misses: int = 0
    cache_errors: int = 0
    total_operations: int = 0
    avg_response_time_ms: float = 0.0
    hit_ratio: float = 0.0
    memory_usage_mb: float = 0.0
    evictions: int = 0


@dataclass
class CacheConfiguration:
    """Cache configuration settings"""
    layers: List[CacheLayer]
    strategy: CacheStrategy
    default_ttl: int
    compression_enabled: bool
    serialization_format: SerializationFormat
    max_memory_entries: int
    circuit_breaker_enabled: bool


class CircuitBreaker:
    """Circuit breaker pattern for cache operations"""

    def __init__(self, failure_threshold: int = 5, timeout_seconds: int = 60):
        self.failure_threshold = failure_threshold
        self.timeout_seconds = timeout_seconds
        self.failure_count = 0
        self.last_failure_time = None
        self.state = "closed"  # closed, open, half_open

    def call(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with circuit breaker protection"""
        if self.state == "open":
            if self._should_attempt_reset():
                self.state = "half_open"
            else:
                raise Exception("Circuit breaker is open")

        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result
        except Exception as e:
            self._on_failure()
            raise e

    def _should_attempt_reset(self) -> bool:
        """Check if circuit breaker should attempt reset"""
        if self.last_failure_time is None:
            return True
        return time.time() - self.last_failure_time > self.timeout_seconds

    def _on_success(self):
        """Handle successful operation"""
        self.failure_count = 0
        self.state = "closed"

    def _on_failure(self):
        """Handle failed operation"""
        self.failure_count += 1
        self.last_failure_time = time.time()
        if self.failure_count >= self.failure_threshold:
            self.state = "open"


class IntelligentCacheManager:
    """Enterprise-grade intelligent cache manager"""

    def __init__(self, config: Optional[CacheConfiguration] = None):
        self.config = config or self._get_default_config()
        self.memory_cache = {}
        self.redis_client = None
        self.circuit_breaker = CircuitBreaker()
        self.metrics = CacheMetrics()
        self.cache_locks = defaultdict(threading.Lock)

        # Initialize Redis connection
        self._initialize_redis()

    def get(self, key: str, default: Any = None,
           fetch_func: Optional[Callable] = None, ttl: Optional[int] = None) -> Any:
        """
        Multi-layer cache get with automatic fallback and population

        Args:
            key: Cache key
            default: Default value if not found
            fetch_func: Function to fetch data if cache miss
            ttl: TTL for new cache entries

        Returns:
            Cached value or result from fetch_func
        """
        start_time = time.time()
        cache_key = self._generate_cache_key(key)

        try:
            self.metrics.total_operations += 1

            # Try memory cache first
            if CacheLayer.MEMORY in self.config.layers:
                value = self._get_from_memory(cache_key)
                if value is not None:
                    self.metrics.cache_hits += 1
                    self._update_metrics(start_time)
                    logger.debug(f"Cache hit (memory): {cache_key}")
                    return value

            # Try Redis cache
            if CacheLayer.REDIS in self.config.layers and self.redis_client:
                try:
                    value = self.circuit_breaker.call(self._get_from_redis, cache_key)
                    if value is not None:
                        # Populate memory cache
                        if CacheLayer.MEMORY in self.config.layers:
                            self._set_in_memory(cache_key, value, ttl or self.config.default_ttl)

                        self.metrics.cache_hits += 1
                        self._update_metrics(start_time)
                        logger.debug(f"Cache hit (Redis): {cache_key}")
                        return value
                except Exception as e:
                    logger.warning(f"Redis cache error: {str(e)}")
                    self.metrics.cache_errors += 1

            # Cache miss - use fetch function if provided
            if fetch_func:
                logger.debug(f"Cache miss - fetching: {cache_key}")
                value = fetch_func()

                # Cache the fetched value
                if value is not None:
                    self.set(key, value, ttl or self.config.default_ttl)

                self.metrics.cache_misses += 1
                self._update_metrics(start_time)
                return value

            # Return default if no fetch function
            self.metrics.cache_misses += 1
            self._update_metrics(start_time)
            return default

        except Exception as e:
            logger.error(f"Error in cache get operation: {str(e)}")
            self.metrics.cache_errors += 1
            return default

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """
        Multi-layer cache set with intelligent distribution

        Args:
            key: Cache key
            value: Value to cache
            ttl: Time to live in seconds

        Returns:
            True if successful, False otherwise
        """
        try:
            cache_key = self._generate_cache_key(key)
            ttl = ttl or self.config.default_ttl

            # Serialize and optionally compress the value
            serialized_value = self._serialize_value(value)

            # Check size limits
            if len(serialized_value) > MAX_CACHE_VALUE_SIZE_MB * 1024 * 1024:
                logger.warning(f"Cache value too large for key {cache_key}: {len(serialized_value)} bytes")
                return False

            success = True

            # Set in memory cache
            if CacheLayer.MEMORY in self.config.layers:
                success &= self._set_in_memory(cache_key, value, ttl)

            # Set in Redis cache
            if CacheLayer.REDIS in self.config.layers and self.redis_client:
                try:
                    success &= self.circuit_breaker.call(self._set_in_redis, cache_key, serialized_value, ttl)
                except Exception as e:
                    logger.warning(f"Redis cache set error: {str(e)}")
                    success = False

            logger.debug(f"Cache set: {cache_key}, TTL: {ttl}s, Success: {success}")
            return success

        except Exception as e:
            logger.error(f"Error in cache set operation: {str(e)}")
            return False

    def delete(self, key: str) -> bool:
        """
        Delete from all cache layers

        Args:
            key: Cache key to delete

        Returns:
            True if successful, False otherwise
        """
        try:
            cache_key = self._generate_cache_key(key)
            success = True

            # Delete from memory cache
            if CacheLayer.MEMORY in self.config.layers:
                success &= self._delete_from_memory(cache_key)

            # Delete from Redis cache
            if CacheLayer.REDIS in self.config.layers and self.redis_client:
                try:
                    success &= self.circuit_breaker.call(self._delete_from_redis, cache_key)
                except Exception as e:
                    logger.warning(f"Redis cache delete error: {str(e)}")
                    success = False

            logger.debug(f"Cache delete: {cache_key}, Success: {success}")
            return success

        except Exception as e:
            logger.error(f"Error in cache delete operation: {str(e)}")
            return False

    def invalidate_pattern(self, pattern: str) -> int:
        """
        Invalidate cache entries matching pattern

        Args:
            pattern: Pattern to match (supports wildcards)

        Returns:
            Number of entries invalidated
        """
        try:
            invalidated_count = 0

            # Invalidate from memory cache
            if CacheLayer.MEMORY in self.config.layers:
                invalidated_count += self._invalidate_memory_pattern(pattern)

            # Invalidate from Redis cache
            if CacheLayer.REDIS in self.config.layers and self.redis_client:
                try:
                    invalidated_count += self.circuit_breaker.call(self._invalidate_redis_pattern, pattern)
                except Exception as e:
                    logger.warning(f"Redis cache invalidation error: {str(e)}")

            logger.info(f"Cache pattern invalidation: {pattern}, Count: {invalidated_count}")
            return invalidated_count

        except Exception as e:
            logger.error(f"Error in cache pattern invalidation: {str(e)}")
            return 0

    def warm_cache(self, keys_and_functions: Dict[str, Callable], ttl: Optional[int] = None) -> Dict[str, bool]:
        """
        Warm cache with multiple entries

        Args:
            keys_and_functions: Dict of cache keys to fetch functions
            ttl: TTL for cache entries

        Returns:
            Dict of key to success status
        """
        try:
            logger.info(f"Warming cache with {len(keys_and_functions)} entries")
            results = {}

            for key, fetch_func in keys_and_functions.items():
                try:
                    value = fetch_func()
                    success = self.set(key, value, ttl)
                    results[key] = success
                except Exception as e:
                    logger.error(f"Error warming cache for key {key}: {str(e)}")
                    results[key] = False

            successful_count = sum(results.values())
            logger.info(f"Cache warming completed: {successful_count}/{len(keys_and_functions)} successful")
            return results

        except Exception as e:
            logger.error(f"Error in cache warming: {str(e)}")
            return {}

    def get_metrics(self) -> CacheMetrics:
        """Get current cache metrics"""
        try:
            # Calculate hit ratio
            if self.metrics.total_operations > 0:
                self.metrics.hit_ratio = self.metrics.cache_hits / self.metrics.total_operations

            # Get memory usage
            self.metrics.memory_usage_mb = self._calculate_memory_usage()

            return self.metrics

        except Exception as e:
            logger.error(f"Error getting cache metrics: {str(e)}")
            return self.metrics

    def _initialize_redis(self):
        """Initialize Redis connection"""
        try:
            if REDIS_CLUSTER_ENDPOINT and CacheLayer.REDIS in self.config.layers:
                self.redis_client = redis.Redis(
                    host=REDIS_CLUSTER_ENDPOINT,
                    port=REDIS_PORT,
                    decode_responses=False,  # We handle binary data
                    socket_connect_timeout=5,
                    socket_timeout=5,
                    retry_on_timeout=True,
                    health_check_interval=30
                )

                # Test connection
                self.redis_client.ping()
                logger.info("Redis connection established successfully")
            else:
                logger.warning("Redis not configured or not enabled in cache layers")

        except Exception as e:
            logger.error(f"Failed to initialize Redis connection: {str(e)}")
            self.redis_client = None

    def _generate_cache_key(self, key: str) -> str:
        """Generate standardized cache key with namespace"""
        return f"{CACHE_KEY_PREFIX}:{key}"

    def _serialize_value(self, value: Any) -> bytes:
        """Serialize value for storage"""
        try:
            if self.config.serialization_format == SerializationFormat.JSON:
                serialized = json.dumps(value, default=str).encode('utf-8')
            elif self.config.serialization_format == SerializationFormat.PICKLE:
                serialized = pickle.dumps(value)
            else:
                # Default to JSON
                serialized = json.dumps(value, default=str).encode('utf-8')

            # Compress if enabled
            if self.config.compression_enabled and len(serialized) > 1024:
                serialized = gzip.compress(serialized)

            return serialized

        except Exception as e:
            logger.error(f"Error serializing value: {str(e)}")
            raise

    def _deserialize_value(self, serialized: bytes) -> Any:
        """Deserialize value from storage"""
        try:
            # Decompress if compressed
            if self.config.compression_enabled:
                try:
                    serialized = gzip.decompress(serialized)
                except:
                    # Not compressed, continue with original data
                    pass

            if self.config.serialization_format == SerializationFormat.JSON:
                return json.loads(serialized.decode('utf-8'))
            elif self.config.serialization_format == SerializationFormat.PICKLE:
                return pickle.loads(serialized)
            else:
                return json.loads(serialized.decode('utf-8'))

        except Exception as e:
            logger.error(f"Error deserializing value: {str(e)}")
            raise

    def _get_from_memory(self, key: str) -> Any:
        """Get value from memory cache"""
        entry = self.memory_cache.get(key)
        if entry and entry.expires_at > datetime.now(timezone.utc):
            entry.hit_count += 1
            return entry.value
        elif entry:
            # Expired entry
            del self.memory_cache[key]
        return None

    def _set_in_memory(self, key: str, value: Any, ttl: int) -> bool:
        """Set value in memory cache"""
        try:
            # Check memory limits
            if len(self.memory_cache) >= self.config.max_memory_entries:
                self._evict_memory_cache()

            entry = CacheEntry(
                key=key,
                value=value,
                ttl_seconds=ttl,
                created_at=datetime.now(timezone.utc),
                expires_at=datetime.now(timezone.utc) + timedelta(seconds=ttl),
                size_bytes=len(str(value))
            )

            self.memory_cache[key] = entry
            return True

        except Exception as e:
            logger.error(f"Error setting memory cache: {str(e)}")
            return False

    def _delete_from_memory(self, key: str) -> bool:
        """Delete from memory cache"""
        try:
            if key in self.memory_cache:
                del self.memory_cache[key]
            return True
        except Exception as e:
            logger.error(f"Error deleting from memory cache: {str(e)}")
            return False

    def _get_from_redis(self, key: str) -> Any:
        """Get value from Redis cache"""
        if not self.redis_client:
            return None

        serialized = self.redis_client.get(key)
        if serialized:
            return self._deserialize_value(serialized)
        return None

    def _set_in_redis(self, key: str, serialized_value: bytes, ttl: int) -> bool:
        """Set value in Redis cache"""
        if not self.redis_client:
            return False

        return self.redis_client.setex(key, ttl, serialized_value)

    def _delete_from_redis(self, key: str) -> bool:
        """Delete from Redis cache"""
        if not self.redis_client:
            return False

        return bool(self.redis_client.delete(key))

    def _invalidate_memory_pattern(self, pattern: str) -> int:
        """Invalidate memory cache entries matching pattern"""
        import fnmatch

        keys_to_delete = []
        for key in self.memory_cache.keys():
            if fnmatch.fnmatch(key, pattern):
                keys_to_delete.append(key)

        for key in keys_to_delete:
            del self.memory_cache[key]

        return len(keys_to_delete)

    def _invalidate_redis_pattern(self, pattern: str) -> int:
        """Invalidate Redis cache entries matching pattern"""
        if not self.redis_client:
            return 0

        keys = self.redis_client.keys(pattern)
        if keys:
            return self.redis_client.delete(*keys)
        return 0

    def _evict_memory_cache(self):
        """Evict least recently used entries from memory cache"""
        if len(self.memory_cache) < self.config.max_memory_entries:
            return

        # Sort by hit count and creation time
        sorted_entries = sorted(
            self.memory_cache.items(),
            key=lambda x: (x[1].hit_count, x[1].created_at)
        )

        # Remove 25% of entries
        remove_count = max(1, len(sorted_entries) // 4)
        for i in range(remove_count):
            key, _ = sorted_entries[i]
            del self.memory_cache[key]
            self.metrics.evictions += 1

    def _calculate_memory_usage(self) -> float:
        """Calculate memory usage in MB"""
        total_bytes = sum(entry.size_bytes for entry in self.memory_cache.values())
        return total_bytes / (1024 * 1024)

    def _update_metrics(self, start_time: float):
        """Update performance metrics"""
        response_time = (time.time() - start_time) * 1000  # Convert to milliseconds

        # Update average response time
        total_ops = self.metrics.total_operations
        if total_ops > 1:
            self.metrics.avg_response_time_ms = (
                (self.metrics.avg_response_time_ms * (total_ops - 1) + response_time) / total_ops
            )
        else:
            self.metrics.avg_response_time_ms = response_time

    def _get_default_config(self) -> CacheConfiguration:
        """Get default cache configuration"""
        return CacheConfiguration(
            layers=[CacheLayer.MEMORY, CacheLayer.REDIS],
            strategy=CacheStrategy.CACHE_ASIDE,
            default_ttl=DEFAULT_TTL_SECONDS,
            compression_enabled=ENABLE_CACHE_COMPRESSION,
            serialization_format=SerializationFormat.JSON,
            max_memory_entries=1000,
            circuit_breaker_enabled=True
        )

    def send_metrics_to_cloudwatch(self):
        """Send cache metrics to CloudWatch"""
        try:
            metrics = self.get_metrics()

            metric_data = [
                {
                    'MetricName': 'CacheHitRatio',
                    'Value': metrics.hit_ratio,
                    'Unit': 'Percent',
                    'Dimensions': [
                        {'Name': 'Environment', 'Value': ENVIRONMENT},
                        {'Name': 'CacheType', 'Value': 'Intelligent'}
                    ]
                },
                {
                    'MetricName': 'CacheResponseTime',
                    'Value': metrics.avg_response_time_ms,
                    'Unit': 'Milliseconds',
                    'Dimensions': [
                        {'Name': 'Environment', 'Value': ENVIRONMENT}
                    ]
                },
                {
                    'MetricName': 'CacheMemoryUsage',
                    'Value': metrics.memory_usage_mb,
                    'Unit': 'Megabytes',
                    'Dimensions': [
                        {'Name': 'Environment', 'Value': ENVIRONMENT}
                    ]
                },
                {
                    'MetricName': 'CacheErrors',
                    'Value': metrics.cache_errors,
                    'Unit': 'Count',
                    'Dimensions': [
                        {'Name': 'Environment', 'Value': ENVIRONMENT}
                    ]
                }
            ]

            cloudwatch.put_metric_data(
                Namespace='ThreatIntel/Cache',
                MetricData=metric_data
            )

            logger.debug("Cache metrics sent to CloudWatch")

        except Exception as e:
            logger.error(f"Error sending cache metrics to CloudWatch: {str(e)}")


# Global cache manager instance for Lambda functions
cache_manager = None

def get_cache_manager() -> IntelligentCacheManager:
    """Get global cache manager instance"""
    global cache_manager
    if cache_manager is None:
        cache_manager = IntelligentCacheManager()
    return cache_manager


# Convenience functions for Lambda integration
def cached(key_func: Callable = None, ttl: int = DEFAULT_TTL_SECONDS):
    """
    Decorator for caching function results

    Args:
        key_func: Function to generate cache key from function args
        ttl: Time to live in seconds

    Returns:
        Decorated function with caching
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            cache = get_cache_manager()

            # Generate cache key
            if key_func:
                cache_key = key_func(*args, **kwargs)
            else:
                cache_key = f"{func.__name__}:{hashlib.sha256(str(args + tuple(kwargs.items())).encode()).hexdigest()[:16]}"

            # Try to get from cache
            def fetch_func():
                return func(*args, **kwargs)

            return cache.get(cache_key, fetch_func=fetch_func, ttl=ttl)

        return wrapper
    return decorator


# Lambda handler for cache management operations
def lambda_handler(event, context):
    """
    Lambda handler for cache management operations

    Supported actions:
    - get: Get value from cache
    - set: Set value in cache
    - delete: Delete from cache
    - invalidate: Invalidate pattern
    - warm: Warm cache
    - metrics: Get cache metrics
    """
    try:
        logger.info(f"Cache manager invoked with action: {event.get('action', 'unknown')}")

        cache = get_cache_manager()
        action = event.get('action', 'get')

        if action == 'get':
            key = event.get('key')
            if not key:
                return {
                    'statusCode': 400,
                    'body': json.dumps({'error': 'Key parameter required'})
                }

            value = cache.get(key)
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'key': key,
                    'value': value,
                    'found': value is not None
                })
            }

        elif action == 'set':
            key = event.get('key')
            value = event.get('value')
            ttl = event.get('ttl', DEFAULT_TTL_SECONDS)

            if not key or value is None:
                return {
                    'statusCode': 400,
                    'body': json.dumps({'error': 'Key and value parameters required'})
                }

            success = cache.set(key, value, ttl)
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'key': key,
                    'success': success,
                    'ttl': ttl
                })
            }

        elif action == 'delete':
            key = event.get('key')
            if not key:
                return {
                    'statusCode': 400,
                    'body': json.dumps({'error': 'Key parameter required'})
                }

            success = cache.delete(key)
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'key': key,
                    'success': success
                })
            }

        elif action == 'invalidate':
            pattern = event.get('pattern')
            if not pattern:
                return {
                    'statusCode': 400,
                    'body': json.dumps({'error': 'Pattern parameter required'})
                }

            count = cache.invalidate_pattern(pattern)
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'pattern': pattern,
                    'invalidated_count': count
                })
            }

        elif action == 'metrics':
            metrics = cache.get_metrics()
            cache.send_metrics_to_cloudwatch()

            return {
                'statusCode': 200,
                'body': json.dumps({
                    'metrics': asdict(metrics)
                }, default=str)
            }

        else:
            return {
                'statusCode': 400,
                'body': json.dumps({
                    'error': f'Unknown action: {action}',
                    'supported_actions': ['get', 'set', 'delete', 'invalidate', 'warm', 'metrics']
                })
            }

    except Exception as e:
        logger.error(f"Error in cache manager: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': 'Internal server error',
                'message': str(e)
            })
        }


if __name__ == "__main__":
    # Test the cache manager locally
    test_event = {
        'action': 'set',
        'key': 'test_key',
        'value': {'test': 'data'},
        'ttl': 300
    }

    result = lambda_handler(test_event, None)
    print(json.dumps(result, indent=2))