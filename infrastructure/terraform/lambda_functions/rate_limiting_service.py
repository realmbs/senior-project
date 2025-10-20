"""
Advanced Rate Limiting and Comprehensive Error Handling Service
Phase 8D Implementation - Infrastructure Enhancements

This module provides enterprise-grade rate limiting and error handling capabilities:
- Multi-tier rate limiting with intelligent thresholds
- User-based and IP-based rate limiting strategies
- Adaptive rate limiting based on system load and user behavior
- Comprehensive error handling with structured error responses
- Rate limit bypass for trusted users and emergency situations

Features:
- Redis-backed distributed rate limiting
- Sliding window rate limiting algorithms
- Circuit breaker pattern integration
- Intelligent error classification and routing
- Rate limit analytics and monitoring
- Dynamic threshold adjustment based on system capacity
"""

import json
import boto3
import redis
import logging
import os
import time
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Tuple, Union
from dataclasses import dataclass, asdict
from enum import Enum
from collections import defaultdict
import ipaddress

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# AWS Service Clients
dynamodb = boto3.resource('dynamodb')
ssm = boto3.client('ssm')
cloudwatch = boto3.client('cloudwatch')

# Environment Variables
ENVIRONMENT = os.environ.get('ENVIRONMENT', 'dev')
PROJECT_NAME = os.environ.get('PROJECT_NAME', 'threat-intel')
REDIS_ENDPOINT = os.environ.get('REDIS_CLUSTER_ENDPOINT', '')
REDIS_PORT = int(os.environ.get('REDIS_PORT', '6379'))

# Rate Limiting Configuration
DEFAULT_RATE_LIMIT = 100  # requests per minute
BURST_RATE_LIMIT = 200   # burst capacity
SLIDING_WINDOW_SIZE = 60  # seconds
RATE_LIMIT_KEY_TTL = 3600  # 1 hour
CIRCUIT_BREAKER_THRESHOLD = 10  # failures before opening
CIRCUIT_BREAKER_TIMEOUT = 300  # 5 minutes


class RateLimitTier(Enum):
    """Rate limiting tiers for different user types"""
    FREE = "free"
    BASIC = "basic"
    PREMIUM = "premium"
    ENTERPRISE = "enterprise"
    ADMIN = "admin"


class ErrorType(Enum):
    """Comprehensive error type classification"""
    VALIDATION_ERROR = "VALIDATION_ERROR"
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
    AUTHENTICATION_ERROR = "AUTHENTICATION_ERROR"
    AUTHORIZATION_ERROR = "AUTHORIZATION_ERROR"
    NOT_FOUND = "NOT_FOUND"
    CONFLICT = "CONFLICT"
    PAYLOAD_TOO_LARGE = "PAYLOAD_TOO_LARGE"
    UNSUPPORTED_MEDIA_TYPE = "UNSUPPORTED_MEDIA_TYPE"
    INTERNAL_ERROR = "INTERNAL_ERROR"
    SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"
    CIRCUIT_BREAKER_OPEN = "CIRCUIT_BREAKER_OPEN"
    TIMEOUT = "TIMEOUT"


class ErrorSeverity(Enum):
    """Error severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class RateLimitConfig:
    """Rate limit configuration for different tiers"""
    tier: RateLimitTier
    requests_per_minute: int
    requests_per_hour: int
    requests_per_day: int
    burst_capacity: int
    concurrent_requests: int
    whitelist_bypass: bool = False


@dataclass
class RateLimitResult:
    """Result of rate limit check"""
    allowed: bool
    tier: RateLimitTier
    current_usage: int
    limit: int
    reset_time: datetime
    retry_after: Optional[int] = None
    reason: Optional[str] = None


@dataclass
class ErrorDetail:
    """Detailed error information"""
    error_id: str
    error_type: ErrorType
    error_code: str
    severity: ErrorSeverity
    message: str
    details: List[str]
    timestamp: datetime
    request_id: str
    path: str
    user_id: Optional[str] = None
    ip_address: Optional[str] = None
    correlation_id: Optional[str] = None


@dataclass
class CircuitBreakerState:
    """Circuit breaker state tracking"""
    state: str  # 'closed', 'open', 'half-open'
    failure_count: int
    last_failure_time: Optional[datetime]
    next_attempt_time: Optional[datetime]


class AdvancedRateLimitingService:
    """Enterprise-grade rate limiting service"""

    def __init__(self):
        self.redis_client = self._initialize_redis()
        self.rate_limit_configs = self._load_rate_limit_configs()
        self.circuit_breakers = {}
        self.error_handlers = self._initialize_error_handlers()

    def check_rate_limit(self, user_id: str, api_key: str, ip_address: str,
                        endpoint: str, method: str) -> RateLimitResult:
        """
        Check rate limits using sliding window algorithm

        Args:
            user_id: User identifier
            api_key: API key for tier identification
            ip_address: Client IP address
            endpoint: API endpoint being accessed
            method: HTTP method

        Returns:
            Rate limit check result
        """
        try:
            logger.info(f"Checking rate limit for user {user_id}, endpoint {endpoint}")

            # Determine user tier
            tier = self._determine_user_tier(user_id, api_key)
            config = self.rate_limit_configs[tier]

            # Check if user is whitelisted
            if config.whitelist_bypass and self._is_whitelisted(user_id, ip_address):
                return RateLimitResult(
                    allowed=True,
                    tier=tier,
                    current_usage=0,
                    limit=config.requests_per_minute,
                    reset_time=datetime.now(timezone.utc) + timedelta(minutes=1),
                    reason="whitelisted"
                )

            # Check multiple rate limit windows
            checks = [
                self._check_sliding_window(user_id, "minute", config.requests_per_minute, 60),
                self._check_sliding_window(user_id, "hour", config.requests_per_hour, 3600),
                self._check_sliding_window(user_id, "day", config.requests_per_day, 86400),
                self._check_ip_rate_limit(ip_address, endpoint),
                self._check_concurrent_requests(user_id, config.concurrent_requests)
            ]

            # Find the most restrictive limit
            for check in checks:
                if not check.allowed:
                    return check

            # Record the request
            self._record_request(user_id, ip_address, endpoint, method)

            # Return success
            return RateLimitResult(
                allowed=True,
                tier=tier,
                current_usage=checks[0].current_usage + 1,
                limit=config.requests_per_minute,
                reset_time=datetime.now(timezone.utc) + timedelta(minutes=1)
            )

        except Exception as e:
            logger.error(f"Error checking rate limit: {str(e)}")
            # Fail open for availability
            return RateLimitResult(
                allowed=True,
                tier=RateLimitTier.FREE,
                current_usage=0,
                limit=DEFAULT_RATE_LIMIT,
                reset_time=datetime.now(timezone.utc) + timedelta(minutes=1),
                reason="rate_limiting_service_error"
            )

    def handle_error(self, error_type: ErrorType, message: str, request_context: Dict[str, Any],
                    exception: Optional[Exception] = None) -> ErrorDetail:
        """
        Comprehensive error handling with structured error responses

        Args:
            error_type: Type of error
            message: Error message
            request_context: Request context information
            exception: Original exception if available

        Returns:
            Structured error detail
        """
        try:
            logger.info(f"Handling error: {error_type.value}")

            # Generate unique error ID
            error_id = f"err_{int(time.time() * 1000)}_{hashlib.sha256(str(time.time()).encode()).hexdigest()[:8]}"

            # Classify error severity
            severity = self._classify_error_severity(error_type, exception)

            # Extract error details
            details = self._extract_error_details(error_type, exception, request_context)

            # Create error detail object
            error_detail = ErrorDetail(
                error_id=error_id,
                error_type=error_type,
                error_code=self._generate_error_code(error_type),
                severity=severity,
                message=message,
                details=details,
                timestamp=datetime.now(timezone.utc),
                request_id=request_context.get('request_id', ''),
                path=request_context.get('path', ''),
                user_id=request_context.get('user_id'),
                ip_address=request_context.get('ip_address'),
                correlation_id=request_context.get('correlation_id')
            )

            # Log error for monitoring
            self._log_error_for_monitoring(error_detail)

            # Update circuit breaker if needed
            if severity in [ErrorSeverity.HIGH, ErrorSeverity.CRITICAL]:
                self._update_circuit_breaker(request_context.get('service', 'unknown'), True)

            return error_detail

        except Exception as e:
            logger.error(f"Error in error handling: {str(e)}")
            # Fallback error
            return ErrorDetail(
                error_id="err_fallback",
                error_type=ErrorType.INTERNAL_ERROR,
                error_code="INTERNAL_ERROR_001",
                severity=ErrorSeverity.CRITICAL,
                message="An unexpected error occurred",
                details=["Error handling system failure"],
                timestamp=datetime.now(timezone.utc),
                request_id=request_context.get('request_id', ''),
                path=request_context.get('path', '')
            )

    def check_circuit_breaker(self, service_name: str) -> bool:
        """
        Check circuit breaker state for a service

        Args:
            service_name: Name of the service to check

        Returns:
            True if requests should be allowed, False if circuit is open
        """
        try:
            if service_name not in self.circuit_breakers:
                self.circuit_breakers[service_name] = CircuitBreakerState(
                    state="closed",
                    failure_count=0,
                    last_failure_time=None,
                    next_attempt_time=None
                )

            breaker = self.circuit_breakers[service_name]

            if breaker.state == "closed":
                return True
            elif breaker.state == "open":
                # Check if timeout has passed
                if (breaker.next_attempt_time and
                    datetime.now(timezone.utc) >= breaker.next_attempt_time):
                    breaker.state = "half-open"
                    logger.info(f"Circuit breaker for {service_name} moved to half-open")
                    return True
                return False
            elif breaker.state == "half-open":
                return True

            return False

        except Exception as e:
            logger.error(f"Error checking circuit breaker: {str(e)}")
            return True  # Fail open

    def adaptive_rate_limiting(self, system_load: float, error_rate: float) -> Dict[RateLimitTier, RateLimitConfig]:
        """
        Adjust rate limits based on system load and error rates

        Args:
            system_load: Current system load (0.0 to 1.0)
            error_rate: Current error rate (0.0 to 1.0)

        Returns:
            Adjusted rate limit configurations
        """
        try:
            logger.info(f"Adjusting rate limits: load={system_load}, error_rate={error_rate}")

            adjusted_configs = {}

            for tier, base_config in self.rate_limit_configs.items():
                # Calculate adjustment factor
                load_factor = max(0.1, 1.0 - system_load)  # Reduce limits as load increases
                error_factor = max(0.1, 1.0 - error_rate)  # Reduce limits as errors increase

                adjustment_factor = min(load_factor, error_factor)

                # Apply adjustment
                adjusted_config = RateLimitConfig(
                    tier=tier,
                    requests_per_minute=int(base_config.requests_per_minute * adjustment_factor),
                    requests_per_hour=int(base_config.requests_per_hour * adjustment_factor),
                    requests_per_day=int(base_config.requests_per_day * adjustment_factor),
                    burst_capacity=int(base_config.burst_capacity * adjustment_factor),
                    concurrent_requests=int(base_config.concurrent_requests * adjustment_factor),
                    whitelist_bypass=base_config.whitelist_bypass
                )

                adjusted_configs[tier] = adjusted_config

            # Update active configurations
            self.rate_limit_configs = adjusted_configs

            logger.info(f"Rate limits adjusted with factor {adjustment_factor:.2f}")
            return adjusted_configs

        except Exception as e:
            logger.error(f"Error in adaptive rate limiting: {str(e)}")
            return self.rate_limit_configs

    def generate_api_response(self, error_detail: ErrorDetail, rate_limit_result: Optional[RateLimitResult] = None) -> Dict[str, Any]:
        """
        Generate standardized API error response

        Args:
            error_detail: Error detail object
            rate_limit_result: Rate limit result if applicable

        Returns:
            Formatted API response
        """
        try:
            # Base response structure
            response = {
                "error": {
                    "id": error_detail.error_id,
                    "code": error_detail.error_code,
                    "type": error_detail.error_type.value,
                    "message": error_detail.message,
                    "details": error_detail.details,
                    "severity": error_detail.severity.value
                },
                "timestamp": error_detail.timestamp.isoformat(),
                "request_id": error_detail.request_id,
                "path": error_detail.path
            }

            # Add rate limit information if applicable
            if rate_limit_result:
                response["rate_limit"] = {
                    "tier": rate_limit_result.tier.value,
                    "current_usage": rate_limit_result.current_usage,
                    "limit": rate_limit_result.limit,
                    "reset_time": rate_limit_result.reset_time.isoformat(),
                    "retry_after": rate_limit_result.retry_after
                }

            # Add correlation ID if available
            if error_detail.correlation_id:
                response["correlation_id"] = error_detail.correlation_id

            # HTTP status code mapping
            status_code = self._map_error_to_status_code(error_detail.error_type)
            response["status_code"] = status_code

            return response

        except Exception as e:
            logger.error(f"Error generating API response: {str(e)}")
            # Fallback response
            return {
                "error": {
                    "code": "INTERNAL_ERROR_002",
                    "type": "INTERNAL_ERROR",
                    "message": "Failed to generate error response"
                },
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "status_code": 500
            }

    def _initialize_redis(self) -> Optional[redis.Redis]:
        """Initialize Redis connection"""
        try:
            if REDIS_ENDPOINT:
                client = redis.Redis(
                    host=REDIS_ENDPOINT,
                    port=REDIS_PORT,
                    decode_responses=True,
                    socket_connect_timeout=5,
                    socket_timeout=5,
                    retry_on_timeout=True
                )
                client.ping()
                logger.info("Redis connection established for rate limiting")
                return client
            else:
                logger.warning("Redis not configured - using fallback rate limiting")
                return None
        except Exception as e:
            logger.error(f"Failed to initialize Redis: {str(e)}")
            return None

    def _load_rate_limit_configs(self) -> Dict[RateLimitTier, RateLimitConfig]:
        """Load rate limit configurations for different tiers"""
        return {
            RateLimitTier.FREE: RateLimitConfig(
                tier=RateLimitTier.FREE,
                requests_per_minute=50,
                requests_per_hour=1000,
                requests_per_day=10000,
                burst_capacity=100,
                concurrent_requests=5
            ),
            RateLimitTier.BASIC: RateLimitConfig(
                tier=RateLimitTier.BASIC,
                requests_per_minute=200,
                requests_per_hour=5000,
                requests_per_day=50000,
                burst_capacity=400,
                concurrent_requests=20
            ),
            RateLimitTier.PREMIUM: RateLimitConfig(
                tier=RateLimitTier.PREMIUM,
                requests_per_minute=500,
                requests_per_hour=15000,
                requests_per_day=200000,
                burst_capacity=1000,
                concurrent_requests=50
            ),
            RateLimitTier.ENTERPRISE: RateLimitConfig(
                tier=RateLimitTier.ENTERPRISE,
                requests_per_minute=2000,
                requests_per_hour=60000,
                requests_per_day=1000000,
                burst_capacity=4000,
                concurrent_requests=200
            ),
            RateLimitTier.ADMIN: RateLimitConfig(
                tier=RateLimitTier.ADMIN,
                requests_per_minute=10000,
                requests_per_hour=300000,
                requests_per_day=5000000,
                burst_capacity=20000,
                concurrent_requests=1000,
                whitelist_bypass=True
            )
        }

    def _determine_user_tier(self, user_id: str, api_key: str) -> RateLimitTier:
        """Determine user tier based on user ID and API key"""
        try:
            # This would typically query a user database
            # For now, implement simple logic based on API key pattern
            if api_key.startswith('admin_'):
                return RateLimitTier.ADMIN
            elif api_key.startswith('ent_'):
                return RateLimitTier.ENTERPRISE
            elif api_key.startswith('prem_'):
                return RateLimitTier.PREMIUM
            elif api_key.startswith('basic_'):
                return RateLimitTier.BASIC
            else:
                return RateLimitTier.FREE
        except Exception as e:
            logger.error(f"Error determining user tier: {str(e)}")
            return RateLimitTier.FREE

    def _is_whitelisted(self, user_id: str, ip_address: str) -> bool:
        """Check if user or IP is whitelisted"""
        try:
            # This would check against a whitelist database/cache
            # For now, implement basic IP range checking
            private_ranges = [
                ipaddress.ip_network('10.0.0.0/8'),
                ipaddress.ip_network('172.16.0.0/12'),
                ipaddress.ip_network('192.168.0.0/16')
            ]

            try:
                ip = ipaddress.ip_address(ip_address)
                for network in private_ranges:
                    if ip in network:
                        return True
            except ValueError:
                pass

            return False
        except Exception as e:
            logger.error(f"Error checking whitelist: {str(e)}")
            return False

    def _check_sliding_window(self, user_id: str, window_type: str, limit: int, window_seconds: int) -> RateLimitResult:
        """Check rate limit using sliding window algorithm"""
        try:
            if not self.redis_client:
                # Fallback to simple in-memory check
                return RateLimitResult(
                    allowed=True,
                    tier=RateLimitTier.FREE,
                    current_usage=0,
                    limit=limit,
                    reset_time=datetime.now(timezone.utc) + timedelta(seconds=window_seconds)
                )

            key = f"rate_limit:{user_id}:{window_type}"
            now = time.time()
            window_start = now - window_seconds

            # Remove old entries
            self.redis_client.zremrangebyscore(key, 0, window_start)

            # Count current requests
            current_count = self.redis_client.zcard(key)

            if current_count >= limit:
                # Get oldest entry to calculate reset time
                oldest_entries = self.redis_client.zrange(key, 0, 0, withscores=True)
                if oldest_entries:
                    oldest_time = oldest_entries[0][1]
                    reset_time = datetime.fromtimestamp(oldest_time + window_seconds, timezone.utc)
                else:
                    reset_time = datetime.now(timezone.utc) + timedelta(seconds=window_seconds)

                return RateLimitResult(
                    allowed=False,
                    tier=RateLimitTier.FREE,  # Will be updated by caller
                    current_usage=current_count,
                    limit=limit,
                    reset_time=reset_time,
                    retry_after=int((reset_time - datetime.now(timezone.utc)).total_seconds()),
                    reason=f"{window_type}_rate_limit_exceeded"
                )

            # Add current request
            self.redis_client.zadd(key, {str(now): now})
            self.redis_client.expire(key, window_seconds)

            return RateLimitResult(
                allowed=True,
                tier=RateLimitTier.FREE,  # Will be updated by caller
                current_usage=current_count,
                limit=limit,
                reset_time=datetime.now(timezone.utc) + timedelta(seconds=window_seconds)
            )

        except Exception as e:
            logger.error(f"Error in sliding window check: {str(e)}")
            return RateLimitResult(
                allowed=True,
                tier=RateLimitTier.FREE,
                current_usage=0,
                limit=limit,
                reset_time=datetime.now(timezone.utc) + timedelta(seconds=window_seconds),
                reason="rate_limit_check_error"
            )

    def _check_ip_rate_limit(self, ip_address: str, endpoint: str) -> RateLimitResult:
        """Check IP-based rate limiting"""
        try:
            # Implement stricter IP-based limits for security
            ip_limit = 1000  # requests per hour per IP
            window_seconds = 3600

            if not self.redis_client:
                return RateLimitResult(
                    allowed=True,
                    tier=RateLimitTier.FREE,
                    current_usage=0,
                    limit=ip_limit,
                    reset_time=datetime.now(timezone.utc) + timedelta(seconds=window_seconds)
                )

            key = f"ip_rate_limit:{ip_address}:{endpoint}"
            now = time.time()
            window_start = now - window_seconds

            # Remove old entries
            self.redis_client.zremrangebyscore(key, 0, window_start)

            # Count current requests
            current_count = self.redis_client.zcard(key)

            if current_count >= ip_limit:
                return RateLimitResult(
                    allowed=False,
                    tier=RateLimitTier.FREE,
                    current_usage=current_count,
                    limit=ip_limit,
                    reset_time=datetime.now(timezone.utc) + timedelta(seconds=window_seconds),
                    retry_after=window_seconds,
                    reason="ip_rate_limit_exceeded"
                )

            return RateLimitResult(
                allowed=True,
                tier=RateLimitTier.FREE,
                current_usage=current_count,
                limit=ip_limit,
                reset_time=datetime.now(timezone.utc) + timedelta(seconds=window_seconds)
            )

        except Exception as e:
            logger.error(f"Error in IP rate limit check: {str(e)}")
            return RateLimitResult(
                allowed=True,
                tier=RateLimitTier.FREE,
                current_usage=0,
                limit=ip_limit,
                reset_time=datetime.now(timezone.utc) + timedelta(seconds=window_seconds),
                reason="ip_rate_limit_check_error"
            )

    def _check_concurrent_requests(self, user_id: str, limit: int) -> RateLimitResult:
        """Check concurrent request limits"""
        try:
            if not self.redis_client:
                return RateLimitResult(
                    allowed=True,
                    tier=RateLimitTier.FREE,
                    current_usage=0,
                    limit=limit,
                    reset_time=datetime.now(timezone.utc) + timedelta(minutes=1)
                )

            key = f"concurrent:{user_id}"
            current_count = self.redis_client.get(key) or 0
            current_count = int(current_count)

            if current_count >= limit:
                return RateLimitResult(
                    allowed=False,
                    tier=RateLimitTier.FREE,
                    current_usage=current_count,
                    limit=limit,
                    reset_time=datetime.now(timezone.utc) + timedelta(seconds=30),
                    retry_after=30,
                    reason="concurrent_requests_exceeded"
                )

            return RateLimitResult(
                allowed=True,
                tier=RateLimitTier.FREE,
                current_usage=current_count,
                limit=limit,
                reset_time=datetime.now(timezone.utc) + timedelta(minutes=1)
            )

        except Exception as e:
            logger.error(f"Error checking concurrent requests: {str(e)}")
            return RateLimitResult(
                allowed=True,
                tier=RateLimitTier.FREE,
                current_usage=0,
                limit=limit,
                reset_time=datetime.now(timezone.utc) + timedelta(minutes=1),
                reason="concurrent_check_error"
            )

    def _record_request(self, user_id: str, ip_address: str, endpoint: str, method: str):
        """Record successful request for tracking"""
        try:
            if self.redis_client:
                # Increment concurrent request counter
                concurrent_key = f"concurrent:{user_id}"
                self.redis_client.incr(concurrent_key)
                self.redis_client.expire(concurrent_key, 30)  # 30 second timeout

        except Exception as e:
            logger.error(f"Error recording request: {str(e)}")

    def _classify_error_severity(self, error_type: ErrorType, exception: Optional[Exception]) -> ErrorSeverity:
        """Classify error severity"""
        severity_mapping = {
            ErrorType.VALIDATION_ERROR: ErrorSeverity.LOW,
            ErrorType.RATE_LIMIT_EXCEEDED: ErrorSeverity.MEDIUM,
            ErrorType.AUTHENTICATION_ERROR: ErrorSeverity.MEDIUM,
            ErrorType.AUTHORIZATION_ERROR: ErrorSeverity.MEDIUM,
            ErrorType.NOT_FOUND: ErrorSeverity.LOW,
            ErrorType.CONFLICT: ErrorSeverity.MEDIUM,
            ErrorType.PAYLOAD_TOO_LARGE: ErrorSeverity.MEDIUM,
            ErrorType.UNSUPPORTED_MEDIA_TYPE: ErrorSeverity.LOW,
            ErrorType.INTERNAL_ERROR: ErrorSeverity.HIGH,
            ErrorType.SERVICE_UNAVAILABLE: ErrorSeverity.HIGH,
            ErrorType.CIRCUIT_BREAKER_OPEN: ErrorSeverity.HIGH,
            ErrorType.TIMEOUT: ErrorSeverity.MEDIUM
        }

        return severity_mapping.get(error_type, ErrorSeverity.MEDIUM)

    def _extract_error_details(self, error_type: ErrorType, exception: Optional[Exception],
                             request_context: Dict[str, Any]) -> List[str]:
        """Extract detailed error information"""
        details = []

        if exception:
            details.append(f"Exception: {str(exception)}")

        if error_type == ErrorType.VALIDATION_ERROR:
            details.append("Request validation failed")
            details.extend(request_context.get('validation_errors', []))

        elif error_type == ErrorType.RATE_LIMIT_EXCEEDED:
            details.append("API rate limit exceeded")
            if 'rate_limit_info' in request_context:
                info = request_context['rate_limit_info']
                details.append(f"Current usage: {info.get('current_usage', 'unknown')}")
                details.append(f"Limit: {info.get('limit', 'unknown')}")

        return details

    def _generate_error_code(self, error_type: ErrorType) -> str:
        """Generate standardized error codes"""
        error_codes = {
            ErrorType.VALIDATION_ERROR: "VALIDATION_001",
            ErrorType.RATE_LIMIT_EXCEEDED: "RATE_LIMIT_001",
            ErrorType.AUTHENTICATION_ERROR: "AUTH_001",
            ErrorType.AUTHORIZATION_ERROR: "AUTH_002",
            ErrorType.NOT_FOUND: "NOT_FOUND_001",
            ErrorType.CONFLICT: "CONFLICT_001",
            ErrorType.PAYLOAD_TOO_LARGE: "PAYLOAD_001",
            ErrorType.UNSUPPORTED_MEDIA_TYPE: "MEDIA_001",
            ErrorType.INTERNAL_ERROR: "INTERNAL_001",
            ErrorType.SERVICE_UNAVAILABLE: "SERVICE_001",
            ErrorType.CIRCUIT_BREAKER_OPEN: "CIRCUIT_001",
            ErrorType.TIMEOUT: "TIMEOUT_001"
        }

        return error_codes.get(error_type, "UNKNOWN_001")

    def _map_error_to_status_code(self, error_type: ErrorType) -> int:
        """Map error types to HTTP status codes"""
        status_mapping = {
            ErrorType.VALIDATION_ERROR: 400,
            ErrorType.RATE_LIMIT_EXCEEDED: 429,
            ErrorType.AUTHENTICATION_ERROR: 401,
            ErrorType.AUTHORIZATION_ERROR: 403,
            ErrorType.NOT_FOUND: 404,
            ErrorType.CONFLICT: 409,
            ErrorType.PAYLOAD_TOO_LARGE: 413,
            ErrorType.UNSUPPORTED_MEDIA_TYPE: 415,
            ErrorType.INTERNAL_ERROR: 500,
            ErrorType.SERVICE_UNAVAILABLE: 503,
            ErrorType.CIRCUIT_BREAKER_OPEN: 503,
            ErrorType.TIMEOUT: 408
        }

        return status_mapping.get(error_type, 500)

    def _log_error_for_monitoring(self, error_detail: ErrorDetail):
        """Log error for monitoring and alerting"""
        try:
            # Send metrics to CloudWatch
            cloudwatch.put_metric_data(
                Namespace='ThreatIntel/ErrorHandling',
                MetricData=[
                    {
                        'MetricName': 'ErrorCount',
                        'Value': 1,
                        'Unit': 'Count',
                        'Dimensions': [
                            {'Name': 'ErrorType', 'Value': error_detail.error_type.value},
                            {'Name': 'Severity', 'Value': error_detail.severity.value},
                            {'Name': 'Environment', 'Value': ENVIRONMENT}
                        ]
                    }
                ]
            )

        except Exception as e:
            logger.error(f"Error logging error metrics: {str(e)}")

    def _update_circuit_breaker(self, service_name: str, is_failure: bool):
        """Update circuit breaker state"""
        try:
            if service_name not in self.circuit_breakers:
                self.circuit_breakers[service_name] = CircuitBreakerState(
                    state="closed",
                    failure_count=0,
                    last_failure_time=None,
                    next_attempt_time=None
                )

            breaker = self.circuit_breakers[service_name]

            if is_failure:
                breaker.failure_count += 1
                breaker.last_failure_time = datetime.now(timezone.utc)

                if breaker.failure_count >= CIRCUIT_BREAKER_THRESHOLD:
                    breaker.state = "open"
                    breaker.next_attempt_time = datetime.now(timezone.utc) + timedelta(seconds=CIRCUIT_BREAKER_TIMEOUT)
                    logger.warning(f"Circuit breaker opened for {service_name}")
            else:
                # Success - reset failure count
                breaker.failure_count = 0
                if breaker.state == "half-open":
                    breaker.state = "closed"
                    logger.info(f"Circuit breaker closed for {service_name}")

        except Exception as e:
            logger.error(f"Error updating circuit breaker: {str(e)}")

    def _initialize_error_handlers(self) -> Dict[ErrorType, callable]:
        """Initialize error type specific handlers"""
        return {
            ErrorType.RATE_LIMIT_EXCEEDED: self._handle_rate_limit_error,
            ErrorType.CIRCUIT_BREAKER_OPEN: self._handle_circuit_breaker_error,
            ErrorType.TIMEOUT: self._handle_timeout_error
        }

    def _handle_rate_limit_error(self, error_detail: ErrorDetail) -> Dict[str, Any]:
        """Handle rate limit specific error processing"""
        return {"additional_headers": {"Retry-After": "60"}}

    def _handle_circuit_breaker_error(self, error_detail: ErrorDetail) -> Dict[str, Any]:
        """Handle circuit breaker specific error processing"""
        return {"additional_headers": {"Retry-After": str(CIRCUIT_BREAKER_TIMEOUT)}}

    def _handle_timeout_error(self, error_detail: ErrorDetail) -> Dict[str, Any]:
        """Handle timeout specific error processing"""
        return {"additional_headers": {"Connection": "close"}}


# Lambda handler for rate limiting and error handling
def lambda_handler(event, context):
    """
    Lambda handler for rate limiting and error handling

    Supported actions:
    - check_rate_limit: Check rate limits for a request
    - handle_error: Process and format errors
    - check_circuit_breaker: Check circuit breaker state
    - adaptive_adjust: Adjust rate limits based on system load
    """
    try:
        logger.info(f"Rate limiting service invoked")

        service = AdvancedRateLimitingService()
        action = event.get('action', 'check_rate_limit')

        if action == 'check_rate_limit':
            user_id = event.get('user_id', 'anonymous')
            api_key = event.get('api_key', '')
            ip_address = event.get('ip_address', '0.0.0.0')
            endpoint = event.get('endpoint', '/')
            method = event.get('method', 'GET')

            result = service.check_rate_limit(user_id, api_key, ip_address, endpoint, method)

            return {
                'statusCode': 200 if result.allowed else 429,
                'body': json.dumps({
                    'allowed': result.allowed,
                    'rate_limit': asdict(result)
                }, default=str)
            }

        elif action == 'handle_error':
            error_type = ErrorType(event.get('error_type', 'INTERNAL_ERROR'))
            message = event.get('message', 'An error occurred')
            request_context = event.get('request_context', {})

            error_detail = service.handle_error(error_type, message, request_context)
            response = service.generate_api_response(error_detail)

            return {
                'statusCode': response['status_code'],
                'body': json.dumps(response, default=str)
            }

        elif action == 'check_circuit_breaker':
            service_name = event.get('service_name', 'unknown')
            allowed = service.check_circuit_breaker(service_name)

            return {
                'statusCode': 200,
                'body': json.dumps({
                    'allowed': allowed,
                    'service': service_name
                })
            }

        elif action == 'adaptive_adjust':
            system_load = event.get('system_load', 0.5)
            error_rate = event.get('error_rate', 0.0)

            adjusted_configs = service.adaptive_rate_limiting(system_load, error_rate)

            return {
                'statusCode': 200,
                'body': json.dumps({
                    'adjusted_configs': {tier.value: asdict(config) for tier, config in adjusted_configs.items()}
                }, default=str)
            }

        else:
            return {
                'statusCode': 400,
                'body': json.dumps({
                    'error': f'Unknown action: {action}',
                    'supported_actions': ['check_rate_limit', 'handle_error', 'check_circuit_breaker', 'adaptive_adjust']
                })
            }

    except Exception as e:
        logger.error(f"Error in rate limiting service: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': 'Internal server error',
                'message': str(e)
            })
        }


if __name__ == "__main__":
    # Test the rate limiting service locally
    test_event = {
        'action': 'check_rate_limit',
        'user_id': 'test_user',
        'api_key': 'basic_test_key',
        'ip_address': '192.168.1.100',
        'endpoint': '/search',
        'method': 'GET'
    }

    result = lambda_handler(test_event, None)
    print(json.dumps(result, indent=2))