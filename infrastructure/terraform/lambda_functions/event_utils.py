"""
Event Utilities for Threat Intelligence Platform
Phase 8B - Shared utilities for EventBridge integration

This module provides shared utilities for event emission and handling across
all Lambda functions in the threat intelligence platform.
"""

import json
import boto3
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from enum import Enum

# Configure logging
logger = logging.getLogger()

# AWS Service Clients
eventbridge = boto3.client('events')

# Environment Variables
ENVIRONMENT = os.environ.get('ENVIRONMENT', 'dev')
EVENT_BUS_NAME = os.environ.get('EVENT_BUS_NAME', f'threat-intel-{ENVIRONMENT}')


class EventType(Enum):
    """Event types for threat intelligence pipeline"""
    COLLECTION_STARTED = "collection.started"
    COLLECTION_COMPLETED = "collection.completed"
    COLLECTION_FAILED = "collection.failed"
    PROCESSING_STARTED = "processing.started"
    PROCESSING_COMPLETED = "processing.completed"
    PROCESSING_FAILED = "processing.failed"
    ENRICHMENT_STARTED = "enrichment.started"
    ENRICHMENT_COMPLETED = "enrichment.completed"
    ENRICHMENT_FAILED = "enrichment.failed"
    THREAT_CRITICAL = "threat.critical"
    THREAT_HIGH_PRIORITY = "threat.high_priority"
    SYSTEM_ERROR = "system.error"
    WORKFLOW_COMPLETED = "workflow.completed"


class ProcessingPriority(Enum):
    """Processing priority levels"""
    CRITICAL = "critical"
    HIGH = "high"
    STANDARD = "standard"
    LOW = "low"


class EventEmitter:
    """Utility class for emitting events to EventBridge"""

    @staticmethod
    def emit_event(
        event_type: EventType,
        source: str,
        data: Dict[str, Any],
        correlation_id: Optional[str] = None,
        priority: ProcessingPriority = ProcessingPriority.STANDARD,
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Emit an event to EventBridge

        Args:
            event_type: Type of event to emit
            source: Source system emitting the event
            data: Event data payload
            correlation_id: Optional correlation ID for workflow tracking
            priority: Processing priority for the event
            metadata: Optional metadata

        Returns:
            True if event was successfully emitted, False otherwise
        """
        try:
            event_detail = {
                'event_type': event_type.value,
                'event_id': str(uuid.uuid4()),
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'source': source,
                'data': data,
                'correlation_id': correlation_id,
                'priority': priority.value,
                'metadata': metadata or {},
                'environment': ENVIRONMENT
            }

            response = eventbridge.put_events(
                Entries=[
                    {
                        'Source': f'threat-intel.{source}',
                        'DetailType': f'Threat Intelligence {event_type.value.title().replace(".", " ")}',
                        'Detail': json.dumps(event_detail, default=str),
                        'EventBusName': EVENT_BUS_NAME
                    }
                ]
            )

            # Check if event was successfully published
            failed_entries = response.get('FailedEntryCount', 0)
            if failed_entries > 0:
                logger.error(f"Failed to emit event: {response.get('Entries', [])}")
                return False

            logger.info(f"Successfully emitted event: {event_type.value} from {source}")
            return True

        except Exception as e:
            logger.error(f"Error emitting event {event_type.value}: {e}", exc_info=True)
            return False

    @staticmethod
    def emit_collection_completed(
        source: str,
        indicators_collected: int,
        new_indicators: int,
        duplicates_filtered: int,
        collection_stats: Dict[str, Any],
        correlation_id: Optional[str] = None
    ) -> bool:
        """Emit collection completed event"""
        data = {
            'source': source,
            'indicators_collected': indicators_collected,
            'new_indicators': new_indicators,
            'duplicates_filtered': duplicates_filtered,
            'collection_stats': collection_stats,
            'indicators': collection_stats.get('indicators', [])  # Include actual indicators for processing
        }

        return EventEmitter.emit_event(
            event_type=EventType.COLLECTION_COMPLETED,
            source=source,
            data=data,
            correlation_id=correlation_id,
            priority=ProcessingPriority.HIGH if new_indicators > 0 else ProcessingPriority.LOW
        )

    @staticmethod
    def emit_processing_completed(
        processed_count: int,
        valid_count: int,
        invalid_count: int,
        enriched_count: int,
        high_confidence_indicators: List[Dict[str, Any]],
        workflow_id: Optional[str] = None,
        correlation_id: Optional[str] = None
    ) -> bool:
        """Emit processing completed event"""
        data = {
            'processed_indicators': processed_count,
            'valid_indicators': valid_count,
            'invalid_indicators': invalid_count,
            'enriched_indicators': enriched_count,
            'high_confidence_indicators': high_confidence_indicators,
            'workflow_id': workflow_id
        }

        return EventEmitter.emit_event(
            event_type=EventType.PROCESSING_COMPLETED,
            source='processor',
            data=data,
            correlation_id=correlation_id,
            priority=ProcessingPriority.HIGH if high_confidence_indicators else ProcessingPriority.STANDARD
        )

    @staticmethod
    def emit_enrichment_completed(
        enriched_count: int,
        enrichment_results: List[Dict[str, Any]],
        workflow_id: Optional[str] = None,
        correlation_id: Optional[str] = None
    ) -> bool:
        """Emit enrichment completed event"""
        data = {
            'enriched_indicators': enriched_count,
            'enrichment_results': enrichment_results,
            'workflow_id': workflow_id
        }

        return EventEmitter.emit_event(
            event_type=EventType.ENRICHMENT_COMPLETED,
            source='enrichment',
            data=data,
            correlation_id=correlation_id,
            priority=ProcessingPriority.STANDARD
        )

    @staticmethod
    def emit_critical_threat(
        threat_indicators: List[Dict[str, Any]],
        threat_analysis: Dict[str, Any],
        correlation_id: Optional[str] = None
    ) -> bool:
        """Emit critical threat detected event"""
        data = {
            'indicators': threat_indicators,
            'threat_analysis': threat_analysis,
            'alert_level': 'critical',
            'immediate_action_required': True
        }

        return EventEmitter.emit_event(
            event_type=EventType.THREAT_CRITICAL,
            source='threat-detection',
            data=data,
            correlation_id=correlation_id,
            priority=ProcessingPriority.CRITICAL
        )

    @staticmethod
    def emit_system_error(
        error_message: str,
        error_context: Dict[str, Any],
        workflow_id: Optional[str] = None,
        correlation_id: Optional[str] = None
    ) -> bool:
        """Emit system error event"""
        data = {
            'error_message': error_message,
            'error_context': error_context,
            'workflow_id': workflow_id,
            'error_type': EventEmitter._classify_error(error_message)
        }

        return EventEmitter.emit_event(
            event_type=EventType.SYSTEM_ERROR,
            source='error-handler',
            data=data,
            correlation_id=correlation_id,
            priority=ProcessingPriority.HIGH
        )

    @staticmethod
    def _classify_error(error_message: str) -> str:
        """Classify error type based on message"""
        error_message_lower = error_message.lower()

        if 'timeout' in error_message_lower:
            return 'processing_timeout'
        elif 'rate limit' in error_message_lower:
            return 'api_rate_limit'
        elif 'connection' in error_message_lower:
            return 'dependency_failure'
        elif 'memory' in error_message_lower:
            return 'memory_error'
        elif 'permission' in error_message_lower:
            return 'permission_error'
        else:
            return 'unknown_error'


class ThreatAnalyzer:
    """Utility class for threat analysis and priority determination"""

    @staticmethod
    def analyze_threat_priority(indicator: Dict[str, Any]) -> ProcessingPriority:
        """Analyze indicator and determine processing priority"""
        confidence = indicator.get('confidence', 50)
        threat_type = indicator.get('threat_type', '')
        source = indicator.get('source_name', '')
        labels = indicator.get('labels', [])

        # Critical indicators
        if (confidence >= 90 or
            threat_type in ['malware', 'c2_infrastructure', 'apt'] or
            source in ['government', 'law-enforcement'] or
            any(label in ['malicious-activity', 'attribution'] for label in labels)):
            return ProcessingPriority.CRITICAL

        # High priority indicators
        if (confidence >= 75 or
            threat_type in ['phishing', 'suspicious-activity'] or
            source in ['commercial', 'trusted-source'] or
            'campaign' in str(indicator).lower()):
            return ProcessingPriority.HIGH

        # Standard priority
        if confidence >= 50 or threat_type in ['unknown', 'suspicious']:
            return ProcessingPriority.STANDARD

        # Low priority
        return ProcessingPriority.LOW

    @staticmethod
    def identify_critical_threats(indicators: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify indicators that require immediate attention"""
        critical_threats = []

        for indicator in indicators:
            priority = ThreatAnalyzer.analyze_threat_priority(indicator)

            if priority == ProcessingPriority.CRITICAL:
                critical_threats.append(indicator)

        return critical_threats

    @staticmethod
    def analyze_threat_campaign(indicators: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze indicators for potential threat campaign"""
        analysis = {
            'campaign_indicators': 0,
            'related_patterns': [],
            'confidence_scores': [],
            'threat_types': [],
            'sources': [],
            'geographic_distribution': {},
            'temporal_clustering': {}
        }

        for indicator in indicators:
            analysis['confidence_scores'].append(indicator.get('confidence', 0))

            threat_type = indicator.get('threat_type')
            if threat_type:
                analysis['threat_types'].append(threat_type)

            source = indicator.get('source_name')
            if source:
                analysis['sources'].append(source)

            # Look for campaign indicators in labels or description
            labels = indicator.get('labels', [])
            description = indicator.get('description', '')

            if ('campaign' in description.lower() or
                any('campaign' in label.lower() for label in labels)):
                analysis['campaign_indicators'] += 1

        # Calculate statistics
        if analysis['confidence_scores']:
            analysis['avg_confidence'] = sum(analysis['confidence_scores']) / len(analysis['confidence_scores'])
            analysis['max_confidence'] = max(analysis['confidence_scores'])

        analysis['unique_threat_types'] = list(set(analysis['threat_types']))
        analysis['unique_sources'] = list(set(analysis['sources']))

        return analysis


class WorkflowTracker:
    """Utility class for workflow correlation and tracking"""

    @staticmethod
    def generate_correlation_id() -> str:
        """Generate a new correlation ID for workflow tracking"""
        return f"workflow-{uuid.uuid4()}"

    @staticmethod
    def extract_correlation_id(event: Dict[str, Any]) -> Optional[str]:
        """Extract correlation ID from event"""
        # Try different possible locations for correlation ID
        correlation_id = event.get('correlation_id')

        if not correlation_id and 'detail' in event:
            correlation_id = event['detail'].get('correlation_id')

        if not correlation_id and 'metadata' in event:
            correlation_id = event['metadata'].get('correlation_id')

        return correlation_id

    @staticmethod
    def create_workflow_metadata(
        step: str,
        source_event_id: Optional[str] = None,
        additional_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Create workflow metadata for event tracking"""
        metadata = {
            'workflow_step': step,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'environment': ENVIRONMENT
        }

        if source_event_id:
            metadata['source_event_id'] = source_event_id

        if additional_data:
            metadata.update(additional_data)

        return metadata


class EventValidator:
    """Utility class for event validation"""

    @staticmethod
    def validate_event_structure(event: Dict[str, Any]) -> bool:
        """Validate basic event structure"""
        required_fields = ['event_type', 'source', 'data']

        return all(field in event for field in required_fields)

    @staticmethod
    def validate_indicator_data(indicator: Dict[str, Any]) -> bool:
        """Validate indicator data structure"""
        required_fields = ['object_id', 'pattern', 'labels']

        return all(field in indicator for field in required_fields)

    @staticmethod
    def sanitize_event_data(data: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize event data for safe transmission"""
        # Remove any sensitive fields
        sensitive_fields = ['api_key', 'secret', 'password', 'token']

        sanitized = data.copy()

        def remove_sensitive(obj):
            if isinstance(obj, dict):
                return {k: remove_sensitive(v) for k, v in obj.items()
                       if k.lower() not in sensitive_fields}
            elif isinstance(obj, list):
                return [remove_sensitive(item) for item in obj]
            else:
                return obj

        return remove_sensitive(sanitized)


# Convenience functions for easy import
def emit_collection_completed(source: str, stats: Dict[str, Any], correlation_id: Optional[str] = None) -> bool:
    """Convenience function for emitting collection completed events"""
    return EventEmitter.emit_collection_completed(
        source=source,
        indicators_collected=stats.get('indicators_collected', 0),
        new_indicators=stats.get('new_indicators', 0),
        duplicates_filtered=stats.get('duplicates_filtered', 0),
        collection_stats=stats,
        correlation_id=correlation_id
    )


def emit_processing_completed(stats: Dict[str, Any], workflow_id: Optional[str] = None, correlation_id: Optional[str] = None) -> bool:
    """Convenience function for emitting processing completed events"""
    return EventEmitter.emit_processing_completed(
        processed_count=stats.get('indicators_processed', 0),
        valid_count=stats.get('valid_indicators', 0),
        invalid_count=stats.get('invalid_indicators', 0),
        enriched_count=stats.get('enriched_indicators', 0),
        high_confidence_indicators=stats.get('high_confidence_indicators', []),
        workflow_id=workflow_id,
        correlation_id=correlation_id
    )


def emit_critical_threat(indicators: List[Dict[str, Any]], correlation_id: Optional[str] = None) -> bool:
    """Convenience function for emitting critical threat events"""
    threat_analysis = ThreatAnalyzer.analyze_threat_campaign(indicators)

    return EventEmitter.emit_critical_threat(
        threat_indicators=indicators,
        threat_analysis=threat_analysis,
        correlation_id=correlation_id
    )


def analyze_processing_priority(indicator: Dict[str, Any]) -> ProcessingPriority:
    """Convenience function for analyzing processing priority"""
    return ThreatAnalyzer.analyze_threat_priority(indicator)