"""
Event-Driven Orchestration Engine
Phase 8B Implementation - EventBridge Integration for Threat Intelligence Pipeline

This module provides comprehensive event-driven orchestration including:
- EventBridge integration for cross-service communication
- Workflow orchestration (Collection → Processing → Enrichment → Analysis)
- Priority-based processing with real-time threat detection
- Intelligent batch processing and optimization
- Comprehensive error handling and retry mechanisms
- Processing state management and monitoring
- Automated response triggering for critical threats
"""

import json
import boto3
import logging
import os
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, asdict
from enum import Enum
import uuid
from botocore.exceptions import ClientError

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# AWS Service Clients
eventbridge = boto3.client('events')
lambda_client = boto3.client('lambda')
dynamodb = boto3.resource('dynamodb')
cloudwatch = boto3.client('cloudwatch')

# Environment Variables
ENVIRONMENT = os.environ.get('ENVIRONMENT', 'dev')
EVENT_BUS_NAME = os.environ.get('EVENT_BUS_NAME', f'threat-intel-{ENVIRONMENT}')
PROCESSING_STATE_TABLE = os.environ.get('PROCESSING_STATE_TABLE', f'threat-intel-processing-state-{ENVIRONMENT}')
THREAT_INTEL_TABLE = os.environ['THREAT_INTEL_TABLE']

# Lambda Function Names
COLLECTOR_FUNCTION = os.environ.get('COLLECTOR_FUNCTION', f'threat-intel-collector-{ENVIRONMENT}')
PROCESSOR_FUNCTION = os.environ.get('PROCESSOR_FUNCTION', f'threat-intel-processor-{ENVIRONMENT}')
ENRICHMENT_FUNCTION = os.environ.get('ENRICHMENT_FUNCTION', f'threat-intel-enrichment-{ENVIRONMENT}')
ANALYTICS_FUNCTION = os.environ.get('ANALYTICS_FUNCTION', f'threat-intel-analytics-{ENVIRONMENT}')

# Processing Configuration
REAL_TIME_CONFIDENCE_THRESHOLD = int(os.environ.get('REAL_TIME_CONFIDENCE_THRESHOLD', '85'))
HIGH_PRIORITY_BATCH_SIZE = int(os.environ.get('HIGH_PRIORITY_BATCH_SIZE', '10'))
STANDARD_BATCH_SIZE = int(os.environ.get('STANDARD_BATCH_SIZE', '50'))
MAX_RETRY_ATTEMPTS = int(os.environ.get('MAX_RETRY_ATTEMPTS', '3'))

# DynamoDB Tables
processing_state_table = dynamodb.Table(PROCESSING_STATE_TABLE)


class EventType(Enum):
    """Enumeration of event types in the threat intelligence pipeline"""
    COLLECTION_STARTED = "collection.started"
    COLLECTION_COMPLETED = "collection.completed"
    COLLECTION_FAILED = "collection.failed"
    PROCESSING_STARTED = "processing.started"
    PROCESSING_COMPLETED = "processing.completed"
    PROCESSING_FAILED = "processing.failed"
    ENRICHMENT_STARTED = "enrichment.started"
    ENRICHMENT_COMPLETED = "enrichment.completed"
    ENRICHMENT_FAILED = "enrichment.failed"
    ANALYTICS_STARTED = "analytics.started"
    ANALYTICS_COMPLETED = "analytics.completed"
    ANALYTICS_FAILED = "analytics.failed"
    THREAT_CRITICAL = "threat.critical"
    THREAT_HIGH_PRIORITY = "threat.high_priority"
    ANOMALY_DETECTED = "analytics.anomaly_detected"
    CAMPAIGN_DETECTED = "analytics.campaign_detected"
    RISK_THRESHOLD_EXCEEDED = "analytics.risk_threshold_exceeded"
    SYSTEM_ERROR = "system.error"
    WORKFLOW_COMPLETED = "workflow.completed"


class ProcessingPriority(Enum):
    """Processing priority levels"""
    CRITICAL = "critical"      # Immediate processing
    HIGH = "high"             # Priority batch processing
    STANDARD = "standard"     # Normal batch processing
    LOW = "low"              # Background processing


class WorkflowStatus(Enum):
    """Workflow execution status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    RETRY = "retry"


@dataclass
class ThreatIntelEvent:
    """Structured event object for threat intelligence pipeline"""
    event_type: EventType
    source: str
    event_id: str
    timestamp: str
    data: Dict[str, Any]
    metadata: Dict[str, Any]
    correlation_id: Optional[str] = None
    retry_count: int = 0
    priority: ProcessingPriority = ProcessingPriority.STANDARD


@dataclass
class WorkflowExecution:
    """Workflow execution tracking object"""
    workflow_id: str
    correlation_id: str
    status: WorkflowStatus
    started_at: str
    updated_at: str
    steps_completed: List[str]
    current_step: Optional[str]
    error_details: Optional[Dict[str, Any]]
    metadata: Dict[str, Any]


@dataclass
class ProcessingBatch:
    """Intelligent processing batch with priority and optimization"""
    batch_id: str
    priority: ProcessingPriority
    indicators: List[Dict[str, Any]]
    estimated_processing_time: int
    memory_requirements: int
    created_at: str
    metadata: Dict[str, Any]


class EventOrchestrator:
    """Advanced event-driven orchestration engine"""

    def __init__(self):
        self.event_handlers = {
            EventType.COLLECTION_COMPLETED: self._handle_collection_completed,
            EventType.PROCESSING_COMPLETED: self._handle_processing_completed,
            EventType.ENRICHMENT_COMPLETED: self._handle_enrichment_completed,
            EventType.ANALYTICS_COMPLETED: self._handle_analytics_completed,
            EventType.ANALYTICS_FAILED: self._handle_analytics_failed,
            EventType.THREAT_CRITICAL: self._handle_critical_threat,
            EventType.ANOMALY_DETECTED: self._handle_anomaly_detected,
            EventType.CAMPAIGN_DETECTED: self._handle_campaign_detected,
            EventType.RISK_THRESHOLD_EXCEEDED: self._handle_risk_threshold_exceeded,
            EventType.SYSTEM_ERROR: self._handle_system_error,
        }
        self.workflow_manager = WorkflowManager()
        self.batch_processor = IntelligentBatchProcessor()
        self.error_handler = ErrorHandler()

    def process_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process incoming EventBridge event

        Args:
            event: EventBridge event payload

        Returns:
            Processing result
        """
        try:
            # Parse EventBridge event
            detail = event.get('detail', {})
            source = event.get('source', 'unknown')
            event_type_str = detail.get('event_type')

            if not event_type_str:
                raise ValueError("Missing event_type in event detail")

            event_type = EventType(event_type_str)

            # Create structured event object
            threat_event = ThreatIntelEvent(
                event_type=event_type,
                source=source,
                event_id=detail.get('event_id', str(uuid.uuid4())),
                timestamp=detail.get('timestamp', datetime.now(timezone.utc).isoformat()),
                data=detail.get('data', {}),
                metadata=detail.get('metadata', {}),
                correlation_id=detail.get('correlation_id'),
                retry_count=detail.get('retry_count', 0),
                priority=ProcessingPriority(detail.get('priority', 'standard'))
            )

            logger.info(f"Processing event: {event_type.value} from {source}")

            # Route to appropriate handler
            handler = self.event_handlers.get(event_type)
            if handler:
                result = handler(threat_event)
            else:
                logger.warning(f"No handler for event type: {event_type.value}")
                result = {'status': 'ignored', 'reason': f'No handler for {event_type.value}'}

            # Update metrics
            self._update_metrics(event_type, 'success')

            return result

        except Exception as e:
            logger.error(f"Error processing event: {e}", exc_info=True)
            self._update_metrics(EventType.SYSTEM_ERROR, 'error')

            # Trigger error handling
            self.error_handler.handle_event_error(event, str(e))

            return {'status': 'error', 'message': str(e)}

    def _handle_collection_completed(self, event: ThreatIntelEvent) -> Dict[str, Any]:
        """Handle collection completion events"""
        try:
            collection_data = event.data
            source = collection_data.get('source')
            indicators_count = collection_data.get('new_indicators', 0)

            logger.info(f"Collection completed: {source}, {indicators_count} new indicators")

            # Start workflow tracking
            workflow = self.workflow_manager.start_workflow(
                event_type='collection_to_processing',
                correlation_id=event.correlation_id or str(uuid.uuid4()),
                metadata={
                    'source': source,
                    'indicators_count': indicators_count,
                    'collection_event_id': event.event_id
                }
            )

            # Determine processing strategy
            if indicators_count == 0:
                logger.info("No new indicators to process")
                return {'status': 'completed', 'reason': 'no_new_indicators'}

            # Check for high-priority indicators
            high_priority_indicators = self._identify_high_priority_indicators(collection_data)

            if high_priority_indicators:
                # Trigger real-time processing for critical threats
                self._trigger_real_time_processing(high_priority_indicators, workflow.workflow_id)

            # Trigger batch processing for remaining indicators
            self._trigger_batch_processing(
                source=source,
                workflow_id=workflow.workflow_id,
                correlation_id=workflow.correlation_id
            )

            return {
                'status': 'processing_triggered',
                'workflow_id': workflow.workflow_id,
                'high_priority_count': len(high_priority_indicators),
                'total_indicators': indicators_count
            }

        except Exception as e:
            logger.error(f"Error handling collection completed: {e}")
            raise

    def _handle_processing_completed(self, event: ThreatIntelEvent) -> Dict[str, Any]:
        """Handle processing completion events"""
        try:
            processing_data = event.data
            workflow_id = processing_data.get('workflow_id')
            processed_count = processing_data.get('processed_indicators', 0)
            high_confidence_indicators = processing_data.get('high_confidence_indicators', [])

            logger.info(f"Processing completed: {processed_count} indicators processed")

            # Update workflow
            if workflow_id:
                self.workflow_manager.update_workflow_step(
                    workflow_id, 'processing_completed', {'processed_count': processed_count}
                )

            # Trigger enrichment for high-confidence indicators
            if high_confidence_indicators:
                self._trigger_selective_enrichment(
                    high_confidence_indicators,
                    workflow_id,
                    event.correlation_id
                )

            # Check for critical threats
            critical_threats = self._identify_critical_threats(processing_data.get('processed_indicators', []))
            if critical_threats:
                self._emit_critical_threat_events(critical_threats, workflow_id)

            return {
                'status': 'enrichment_triggered',
                'workflow_id': workflow_id,
                'enrichment_count': len(high_confidence_indicators),
                'critical_threats': len(critical_threats)
            }

        except Exception as e:
            logger.error(f"Error handling processing completed: {e}")
            raise

    def _handle_enrichment_completed(self, event: ThreatIntelEvent) -> Dict[str, Any]:
        """Handle enrichment completion events"""
        try:
            enrichment_data = event.data
            workflow_id = enrichment_data.get('workflow_id')
            enriched_count = enrichment_data.get('enriched_indicators', 0)

            logger.info(f"Enrichment completed: {enriched_count} indicators enriched")

            # Update workflow
            if workflow_id:
                self.workflow_manager.update_workflow_step(
                    workflow_id, 'enrichment_completed', {'enriched_count': enriched_count}
                )

                # Complete workflow
                self.workflow_manager.complete_workflow(workflow_id)

            # Check if analytics should be triggered
            should_run_analytics = self._should_trigger_analytics(enrichment_data)

            if should_run_analytics:
                logger.info(f"Triggering analytics for workflow {workflow_id}")
                self._trigger_analytics_processing(enrichment_data, workflow_id, event.correlation_id)
            else:
                # Trigger final analysis or alerting if needed
                self._trigger_final_analysis(enrichment_data, workflow_id)

            return {
                'status': 'workflow_completed',
                'workflow_id': workflow_id,
                'enriched_count': enriched_count
            }

        except Exception as e:
            logger.error(f"Error handling enrichment completed: {e}")
            raise

    def _handle_critical_threat(self, event: ThreatIntelEvent) -> Dict[str, Any]:
        """Handle critical threat detection events"""
        try:
            threat_data = event.data
            threat_indicators = threat_data.get('indicators', [])

            logger.critical(f"Critical threat detected: {len(threat_indicators)} indicators")

            # Immediate processing and alerting
            results = []
            for indicator in threat_indicators:
                # Trigger immediate enrichment
                enrichment_result = self._trigger_immediate_enrichment(indicator, event.correlation_id)

                # Send alerts
                alert_result = self._send_critical_threat_alert(indicator, enrichment_result)

                results.append({
                    'indicator_id': indicator.get('object_id'),
                    'enrichment_status': enrichment_result.get('status'),
                    'alert_status': alert_result.get('status')
                })

            return {
                'status': 'critical_threat_processed',
                'threat_count': len(threat_indicators),
                'results': results
            }

        except Exception as e:
            logger.error(f"Error handling critical threat: {e}")
            raise

    def _handle_system_error(self, event: ThreatIntelEvent) -> Dict[str, Any]:
        """Handle system error events"""
        try:
            error_data = event.data
            workflow_id = error_data.get('workflow_id')

            logger.error(f"System error event: {error_data}")

            # Update workflow if applicable
            if workflow_id:
                self.workflow_manager.mark_workflow_failed(
                    workflow_id, error_data
                )

            # Trigger error recovery if possible
            recovery_result = self.error_handler.attempt_recovery(error_data)

            return {
                'status': 'error_handled',
                'recovery_attempted': recovery_result.get('attempted', False),
                'recovery_status': recovery_result.get('status')
            }

        except Exception as e:
            logger.error(f"Error handling system error: {e}")
            raise

    def _identify_high_priority_indicators(self, collection_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify indicators requiring immediate processing"""
        high_priority = []

        indicators = collection_data.get('indicators', [])
        for indicator in indicators:
            confidence = indicator.get('confidence', 0)
            threat_type = indicator.get('threat_type', '')
            source = indicator.get('source_name', '')

            # High priority criteria
            if (confidence >= REAL_TIME_CONFIDENCE_THRESHOLD or
                threat_type in ['malware', 'c2_infrastructure'] or
                source in ['government', 'commercial']):

                high_priority.append(indicator)

        return high_priority

    def _trigger_real_time_processing(self, indicators: List[Dict[str, Any]], workflow_id: str) -> None:
        """Trigger immediate processing for high-priority threats"""
        try:
            # Process each critical indicator immediately
            for indicator in indicators:
                event_payload = {
                    'action': 'process',
                    'data': [indicator],
                    'priority': 'critical',
                    'workflow_id': workflow_id,
                    'real_time': True
                }

                lambda_client.invoke(
                    FunctionName=PROCESSOR_FUNCTION,
                    InvocationType='Event',  # Asynchronous
                    Payload=json.dumps(event_payload)
                )

            logger.info(f"Triggered real-time processing for {len(indicators)} critical indicators")

        except Exception as e:
            logger.error(f"Error triggering real-time processing: {e}")
            raise

    def _trigger_batch_processing(self, source: str, workflow_id: str, correlation_id: str) -> None:
        """Trigger intelligent batch processing"""
        try:
            # Create processing event
            processing_event = ThreatIntelEvent(
                event_type=EventType.PROCESSING_STARTED,
                source='orchestrator',
                event_id=str(uuid.uuid4()),
                timestamp=datetime.now(timezone.utc).isoformat(),
                data={
                    'source': source,
                    'workflow_id': workflow_id,
                    'batch_mode': True
                },
                metadata={'correlation_id': correlation_id},
                correlation_id=correlation_id
            )

            self._emit_event(processing_event)

            # Also trigger processor directly
            lambda_client.invoke(
                FunctionName=PROCESSOR_FUNCTION,
                InvocationType='Event',
                Payload=json.dumps({
                    'action': 'process',
                    'workflow_id': workflow_id,
                    'correlation_id': correlation_id,
                    'batch_mode': True
                })
            )

        except Exception as e:
            logger.error(f"Error triggering batch processing: {e}")
            raise

    def _emit_event(self, event: ThreatIntelEvent) -> None:
        """Emit event to EventBridge"""
        try:
            event_detail = asdict(event)
            # Convert enum values to strings
            event_detail['event_type'] = event.event_type.value
            event_detail['priority'] = event.priority.value

            eventbridge.put_events(
                Entries=[
                    {
                        'Source': 'threat-intel.orchestrator',
                        'DetailType': f'Threat Intelligence {event.event_type.value.title()}',
                        'Detail': json.dumps(event_detail),
                        'EventBusName': EVENT_BUS_NAME
                    }
                ]
            )

        except Exception as e:
            logger.error(f"Error emitting event: {e}")
            raise

    def _update_metrics(self, event_type: EventType, status: str) -> None:
        """Update CloudWatch metrics"""
        try:
            cloudwatch.put_metric_data(
                Namespace='ThreatIntel/Orchestration',
                MetricData=[
                    {
                        'MetricName': 'EventsProcessed',
                        'Dimensions': [
                            {'Name': 'EventType', 'Value': event_type.value},
                            {'Name': 'Status', 'Value': status},
                            {'Name': 'Environment', 'Value': ENVIRONMENT}
                        ],
                        'Value': 1,
                        'Unit': 'Count'
                    }
                ]
            )
        except Exception as e:
            logger.warning(f"Error updating metrics: {e}")


class WorkflowManager:
    """Manages workflow execution and state"""

    def start_workflow(self, event_type: str, correlation_id: str, metadata: Dict[str, Any]) -> WorkflowExecution:
        """Start a new workflow execution"""
        workflow = WorkflowExecution(
            workflow_id=str(uuid.uuid4()),
            correlation_id=correlation_id,
            status=WorkflowStatus.RUNNING,
            started_at=datetime.now(timezone.utc).isoformat(),
            updated_at=datetime.now(timezone.utc).isoformat(),
            steps_completed=[],
            current_step=event_type,
            error_details=None,
            metadata=metadata
        )

        # Store in DynamoDB
        self._store_workflow_state(workflow)

        return workflow

    def update_workflow_step(self, workflow_id: str, step: str, data: Dict[str, Any]) -> None:
        """Update workflow with completed step"""
        try:
            processing_state_table.update_item(
                Key={'workflow_id': workflow_id},
                UpdateExpression='SET steps_completed = list_append(steps_completed, :step), updated_at = :timestamp, current_step = :current',
                ExpressionAttributeValues={
                    ':step': [step],
                    ':timestamp': datetime.now(timezone.utc).isoformat(),
                    ':current': step
                }
            )
        except Exception as e:
            logger.error(f"Error updating workflow step: {e}")

    def complete_workflow(self, workflow_id: str) -> None:
        """Mark workflow as completed"""
        try:
            processing_state_table.update_item(
                Key={'workflow_id': workflow_id},
                UpdateExpression='SET #status = :status, updated_at = :timestamp, current_step = :step',
                ExpressionAttributeNames={'#status': 'status'},
                ExpressionAttributeValues={
                    ':status': WorkflowStatus.COMPLETED.value,
                    ':timestamp': datetime.now(timezone.utc).isoformat(),
                    ':step': 'completed'
                }
            )
        except Exception as e:
            logger.error(f"Error completing workflow: {e}")

    def mark_workflow_failed(self, workflow_id: str, error_details: Dict[str, Any]) -> None:
        """Mark workflow as failed"""
        try:
            processing_state_table.update_item(
                Key={'workflow_id': workflow_id},
                UpdateExpression='SET #status = :status, updated_at = :timestamp, error_details = :error',
                ExpressionAttributeNames={'#status': 'status'},
                ExpressionAttributeValues={
                    ':status': WorkflowStatus.FAILED.value,
                    ':timestamp': datetime.now(timezone.utc).isoformat(),
                    ':error': error_details
                }
            )
        except Exception as e:
            logger.error(f"Error marking workflow failed: {e}")

    def _store_workflow_state(self, workflow: WorkflowExecution) -> None:
        """Store workflow state in DynamoDB"""
        try:
            item = asdict(workflow)
            item['status'] = workflow.status.value

            processing_state_table.put_item(Item=item)
        except Exception as e:
            logger.error(f"Error storing workflow state: {e}")


class IntelligentBatchProcessor:
    """Intelligent batch processing with optimization"""

    def create_optimized_batches(self, indicators: List[Dict[str, Any]]) -> List[ProcessingBatch]:
        """Create optimized processing batches"""
        batches = []

        # Group by priority
        priority_groups = self._group_by_priority(indicators)

        for priority, group_indicators in priority_groups.items():
            # Create batches based on priority
            batch_size = self._get_batch_size_for_priority(priority)

            for i in range(0, len(group_indicators), batch_size):
                batch_indicators = group_indicators[i:i + batch_size]

                batch = ProcessingBatch(
                    batch_id=str(uuid.uuid4()),
                    priority=priority,
                    indicators=batch_indicators,
                    estimated_processing_time=self._estimate_processing_time(batch_indicators),
                    memory_requirements=self._estimate_memory_requirements(batch_indicators),
                    created_at=datetime.now(timezone.utc).isoformat(),
                    metadata={
                        'indicator_count': len(batch_indicators),
                        'avg_confidence': sum(i.get('confidence', 50) for i in batch_indicators) / len(batch_indicators)
                    }
                )

                batches.append(batch)

        return batches

    def _group_by_priority(self, indicators: List[Dict[str, Any]]) -> Dict[ProcessingPriority, List[Dict[str, Any]]]:
        """Group indicators by processing priority"""
        groups = {priority: [] for priority in ProcessingPriority}

        for indicator in indicators:
            priority = self._determine_priority(indicator)
            groups[priority].append(indicator)

        return {k: v for k, v in groups.items() if v}  # Remove empty groups

    def _determine_priority(self, indicator: Dict[str, Any]) -> ProcessingPriority:
        """Determine processing priority for indicator"""
        confidence = indicator.get('confidence', 50)
        threat_type = indicator.get('threat_type', '')
        source = indicator.get('source_name', '')

        if confidence >= 90 or threat_type in ['malware', 'c2_infrastructure']:
            return ProcessingPriority.CRITICAL
        elif confidence >= 70 or source in ['government', 'commercial']:
            return ProcessingPriority.HIGH
        elif confidence >= 50:
            return ProcessingPriority.STANDARD
        else:
            return ProcessingPriority.LOW

    def _get_batch_size_for_priority(self, priority: ProcessingPriority) -> int:
        """Get optimal batch size for priority level"""
        batch_sizes = {
            ProcessingPriority.CRITICAL: 5,   # Small batches for immediate processing
            ProcessingPriority.HIGH: HIGH_PRIORITY_BATCH_SIZE,
            ProcessingPriority.STANDARD: STANDARD_BATCH_SIZE,
            ProcessingPriority.LOW: STANDARD_BATCH_SIZE * 2  # Larger batches for efficiency
        }
        return batch_sizes.get(priority, STANDARD_BATCH_SIZE)

    def _estimate_processing_time(self, indicators: List[Dict[str, Any]]) -> int:
        """Estimate processing time in seconds"""
        # Base time per indicator + complexity factors
        base_time = len(indicators) * 2  # 2 seconds per indicator

        # Add time for complex patterns
        complex_patterns = sum(1 for i in indicators if len(i.get('pattern', '')) > 100)
        base_time += complex_patterns * 5

        return base_time

    def _estimate_memory_requirements(self, indicators: List[Dict[str, Any]]) -> int:
        """Estimate memory requirements in MB"""
        # Base memory + size of indicator data
        base_memory = 64  # 64MB base

        # Estimate data size
        data_size = sum(len(json.dumps(i)) for i in indicators) / (1024 * 1024)  # Convert to MB

        return int(base_memory + data_size * 2)  # 2x factor for processing overhead

    def _should_trigger_analytics(self, enrichment_data: Dict[str, Any]) -> bool:
        """Determine if analytics should be triggered based on enrichment data"""
        # Trigger analytics for high-confidence threats or specific types
        confidence = enrichment_data.get('confidence', 0)
        threat_types = enrichment_data.get('labels', [])

        # High confidence threats
        if confidence >= 70:
            return True

        # Specific threat types that warrant analysis
        critical_types = ['apt', 'malware', 'c2', 'campaign', 'backdoor', 'trojan']
        if any(threat_type.lower() in ' '.join(threat_types).lower() for threat_type in critical_types):
            return True

        # Geographic enrichment present (for geographic analysis)
        if enrichment_data.get('geolocation'):
            return True

        return False

    def _trigger_analytics_processing(self, enrichment_data: Dict[str, Any], workflow_id: str, correlation_id: str) -> None:
        """Trigger analytics processing via Lambda invocation"""
        try:
            # Prepare analytics payload
            analytics_payload = {
                'action': 'behavioral_analysis',
                'parameters': {
                    'workflow_id': workflow_id,
                    'correlation_id': correlation_id,
                    'enrichment_data': enrichment_data,
                    'trigger_timestamp': datetime.now(timezone.utc).isoformat()
                }
            }

            # Invoke analytics Lambda function
            response = lambda_client.invoke(
                FunctionName=ANALYTICS_FUNCTION,
                InvocationType='Event',  # Asynchronous invocation
                Payload=json.dumps(analytics_payload)
            )

            logger.info(f"Analytics triggered for workflow {workflow_id}, response: {response['StatusCode']}")

            # Emit analytics started event
            analytics_event = ThreatIntelEvent(
                event_type=EventType.ANALYTICS_STARTED,
                source='event_orchestrator',
                event_id=str(uuid.uuid4()),
                timestamp=datetime.now(timezone.utc).isoformat(),
                data={
                    'workflow_id': workflow_id,
                    'correlation_id': correlation_id,
                    'analytics_types': ['behavioral_analysis', 'risk_scoring'],
                    'enrichment_data': enrichment_data
                },
                metadata={'trigger_reason': 'enrichment_completed'},
                correlation_id=correlation_id
            )

            # Emit event for tracking
            event_emitter = EventEmitter()
            event_emitter.emit_event(analytics_event)

        except Exception as e:
            logger.error(f"Error triggering analytics processing: {str(e)}")
            # Continue without analytics - not critical for workflow completion

    def _handle_analytics_completed(self, event: ThreatIntelEvent) -> Dict[str, Any]:
        """Handle analytics completion events"""
        try:
            analytics_data = event.data
            workflow_id = analytics_data.get('workflow_id')
            analytics_results = analytics_data.get('analytics_results', {})

            logger.info(f"Analytics completed for workflow {workflow_id}")

            # Process analytics findings
            self._process_analytics_findings(analytics_results, event.correlation_id)

            # Complete workflow
            if workflow_id:
                self.workflow_manager.complete_workflow(workflow_id)

            return {
                'status': 'analytics_completed',
                'workflow_id': workflow_id,
                'findings_processed': True
            }

        except Exception as e:
            logger.error(f"Error handling analytics completed: {e}")
            raise

    def _handle_analytics_failed(self, event: ThreatIntelEvent) -> Dict[str, Any]:
        """Handle analytics processing failures"""
        try:
            analytics_data = event.data
            workflow_id = analytics_data.get('workflow_id')
            error_details = analytics_data.get('error_details', {})

            logger.warning(f"Analytics failed for workflow {workflow_id}: {error_details}")

            # Analytics failure is not critical - complete workflow without analytics
            if workflow_id:
                self.workflow_manager.complete_workflow(workflow_id)

            # Store analytics failure for monitoring
            self._store_analytics_failure(workflow_id, error_details)

            return {
                'status': 'analytics_failed',
                'workflow_id': workflow_id,
                'workflow_completed': True
            }

        except Exception as e:
            logger.error(f"Error handling analytics failure: {e}")
            raise

    def _handle_anomaly_detected(self, event: ThreatIntelEvent) -> Dict[str, Any]:
        """Handle anomaly detection events"""
        try:
            anomaly_data = event.data
            anomalies = anomaly_data.get('anomalies', [])
            severity = anomaly_data.get('severity', 'unknown')

            logger.warning(f"Anomaly detected - Severity: {severity}, Count: {len(anomalies)}")

            # Send alerts for high-severity anomalies
            if severity == 'high':
                self._send_anomaly_alert(anomalies, event.correlation_id)

            # Store anomaly for analysis
            self._store_anomaly_detection(anomalies, severity)

            return {
                'status': 'anomaly_processed',
                'severity': severity,
                'anomaly_count': len(anomalies)
            }

        except Exception as e:
            logger.error(f"Error handling anomaly detection: {e}")
            raise

    def _handle_campaign_detected(self, event: ThreatIntelEvent) -> Dict[str, Any]:
        """Handle campaign detection events"""
        try:
            campaign_data = event.data
            campaigns = campaign_data.get('campaigns', [])

            logger.warning(f"Threat campaign detected: {len(campaigns)} campaigns identified")

            # Send campaign alerts
            for campaign in campaigns:
                self._send_campaign_alert(campaign, event.correlation_id)

            # Store campaign information
            self._store_campaign_detection(campaigns)

            return {
                'status': 'campaign_processed',
                'campaign_count': len(campaigns)
            }

        except Exception as e:
            logger.error(f"Error handling campaign detection: {e}")
            raise

    def _handle_risk_threshold_exceeded(self, event: ThreatIntelEvent) -> Dict[str, Any]:
        """Handle risk threshold exceeded events"""
        try:
            risk_data = event.data
            risk_score = risk_data.get('risk_score', 0)
            risk_level = risk_data.get('risk_level', 'unknown')
            recommendations = risk_data.get('recommendations', [])

            logger.warning(f"High risk threat detected - Score: {risk_score}, Level: {risk_level}")

            # Send high-risk threat alert
            self._send_high_risk_alert(risk_score, risk_level, recommendations, event.correlation_id)

            # Store high-risk event
            self._store_high_risk_event(risk_score, risk_level, recommendations)

            return {
                'status': 'high_risk_processed',
                'risk_score': risk_score,
                'risk_level': risk_level
            }

        except Exception as e:
            logger.error(f"Error handling high risk event: {e}")
            raise

    def _process_analytics_findings(self, analytics_results: Dict[str, Any], correlation_id: str) -> None:
        """Process analytics findings and emit appropriate events"""
        try:
            event_emitter = EventEmitter()

            # Check for anomalies
            if 'behavioral_analysis' in analytics_results:
                behavioral_results = analytics_results['behavioral_analysis']
                anomalies = behavioral_results.get('anomalies', [])

                high_severity_anomalies = [a for a in anomalies if a.get('severity') == 'high']
                if high_severity_anomalies:
                    anomaly_event = ThreatIntelEvent(
                        event_type=EventType.ANOMALY_DETECTED,
                        source='analytics_engine',
                        event_id=str(uuid.uuid4()),
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        data={
                            'anomalies': high_severity_anomalies,
                            'severity': 'high',
                            'correlation_id': correlation_id
                        },
                        metadata={'detection_type': 'behavioral_analysis'},
                        correlation_id=correlation_id
                    )
                    event_emitter.emit_event(anomaly_event)

            # Check for campaign detection
            if 'correlation_analysis' in analytics_results:
                correlation_results = analytics_results['correlation_analysis']
                campaigns = correlation_results.get('identified_campaigns', [])

                if campaigns:
                    campaign_event = ThreatIntelEvent(
                        event_type=EventType.CAMPAIGN_DETECTED,
                        source='analytics_engine',
                        event_id=str(uuid.uuid4()),
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        data={
                            'campaigns': campaigns,
                            'correlation_id': correlation_id
                        },
                        metadata={'detection_method': 'correlation_analysis'},
                        correlation_id=correlation_id
                    )
                    event_emitter.emit_event(campaign_event)

            # Check for high risk scores
            if 'risk_scoring' in analytics_results:
                risk_results = analytics_results['risk_scoring']
                risk_score = risk_results.get('enhanced_risk_score', 0)

                if risk_score >= 80:  # High risk threshold
                    risk_event = ThreatIntelEvent(
                        event_type=EventType.RISK_THRESHOLD_EXCEEDED,
                        source='analytics_engine',
                        event_id=str(uuid.uuid4()),
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        data={
                            'risk_score': risk_score,
                            'risk_level': risk_results.get('risk_level'),
                            'recommendations': risk_results.get('recommendations', []),
                            'correlation_id': correlation_id
                        },
                        metadata={'threshold': 80},
                        correlation_id=correlation_id
                    )
                    event_emitter.emit_event(risk_event)

        except Exception as e:
            logger.error(f"Error processing analytics findings: {str(e)}")

    def _store_analytics_failure(self, workflow_id: str, error_details: Dict[str, Any]) -> None:
        """Store analytics failure details for monitoring"""
        try:
            cloudwatch.put_metric_data(
                Namespace='ThreatIntel/Analytics',
                MetricData=[
                    {
                        'MetricName': 'AnalyticsFailures',
                        'Value': 1,
                        'Unit': 'Count',
                        'Dimensions': [
                            {
                                'Name': 'WorkflowId',
                                'Value': workflow_id
                            }
                        ]
                    }
                ]
            )
            logger.warning(f"Analytics failure recorded for workflow {workflow_id}: {error_details}")
        except Exception as e:
            logger.error(f"Error storing analytics failure: {str(e)}")

    def _send_anomaly_alert(self, anomalies: List[Dict], correlation_id: str) -> None:
        """Send alert for detected anomalies"""
        try:
            # Implementation would send alerts via SNS, email, etc.
            logger.warning(f"ALERT: High-severity anomalies detected - {len(anomalies)} anomalies (Correlation: {correlation_id})")
        except Exception as e:
            logger.error(f"Error sending anomaly alert: {str(e)}")

    def _send_campaign_alert(self, campaign: Dict, correlation_id: str) -> None:
        """Send alert for detected campaign"""
        try:
            campaign_name = campaign.get('name', 'Unknown')
            threat_count = len(campaign.get('indicators', []))
            logger.warning(f"ALERT: Threat campaign detected - {campaign_name} with {threat_count} indicators (Correlation: {correlation_id})")
        except Exception as e:
            logger.error(f"Error sending campaign alert: {str(e)}")

    def _send_high_risk_alert(self, risk_score: float, risk_level: str, recommendations: List[str], correlation_id: str) -> None:
        """Send alert for high-risk threats"""
        try:
            logger.warning(f"ALERT: High-risk threat detected - Score: {risk_score}, Level: {risk_level} (Correlation: {correlation_id})")
            logger.info(f"Recommendations: {', '.join(recommendations[:3])}")
        except Exception as e:
            logger.error(f"Error sending high-risk alert: {str(e)}")

    def _store_anomaly_detection(self, anomalies: List[Dict], severity: str) -> None:
        """Store anomaly detection for analysis"""
        try:
            cloudwatch.put_metric_data(
                Namespace='ThreatIntel/Analytics',
                MetricData=[
                    {
                        'MetricName': 'AnomaliesDetected',
                        'Value': len(anomalies),
                        'Unit': 'Count',
                        'Dimensions': [
                            {
                                'Name': 'Severity',
                                'Value': severity
                            }
                        ]
                    }
                ]
            )
        except Exception as e:
            logger.error(f"Error storing anomaly detection: {str(e)}")

    def _store_campaign_detection(self, campaigns: List[Dict]) -> None:
        """Store campaign detection for analysis"""
        try:
            cloudwatch.put_metric_data(
                Namespace='ThreatIntel/Analytics',
                MetricData=[
                    {
                        'MetricName': 'CampaignsDetected',
                        'Value': len(campaigns),
                        'Unit': 'Count'
                    }
                ]
            )
        except Exception as e:
            logger.error(f"Error storing campaign detection: {str(e)}")

    def _store_high_risk_event(self, risk_score: float, risk_level: str, recommendations: List[str]) -> None:
        """Store high-risk event for analysis"""
        try:
            cloudwatch.put_metric_data(
                Namespace='ThreatIntel/Analytics',
                MetricData=[
                    {
                        'MetricName': 'HighRiskThreats',
                        'Value': 1,
                        'Unit': 'Count',
                        'Dimensions': [
                            {
                                'Name': 'RiskLevel',
                                'Value': risk_level
                            }
                        ]
                    },
                    {
                        'MetricName': 'RiskScore',
                        'Value': risk_score,
                        'Unit': 'None'
                    }
                ]
            )
        except Exception as e:
            logger.error(f"Error storing high-risk event: {str(e)}")


class ErrorHandler:
    """Comprehensive error handling and retry mechanisms"""

    def handle_event_error(self, event: Dict[str, Any], error_message: str) -> None:
        """Handle event processing errors"""
        try:
            # Log error details
            logger.error(f"Event processing error: {error_message}")

            # Store error for analysis
            self._store_error_details(event, error_message)

            # Attempt recovery if applicable
            if self._is_recoverable_error(error_message):
                self._schedule_retry(event)

        except Exception as e:
            logger.error(f"Error in error handler: {e}")

    def attempt_recovery(self, error_data: Dict[str, Any]) -> Dict[str, str]:
        """Attempt error recovery"""
        error_type = error_data.get('error_type', 'unknown')

        if error_type == 'processing_timeout':
            return self._handle_processing_timeout(error_data)
        elif error_type == 'api_rate_limit':
            return self._handle_rate_limit(error_data)
        elif error_type == 'dependency_failure':
            return self._handle_dependency_failure(error_data)
        else:
            return {'attempted': False, 'status': 'no_recovery_strategy'}

    def _store_error_details(self, event: Dict[str, Any], error_message: str) -> None:
        """Store error details for analysis"""
        # Implementation would store in DynamoDB or CloudWatch Logs
        pass

    def _is_recoverable_error(self, error_message: str) -> bool:
        """Determine if error is recoverable"""
        recoverable_patterns = [
            'timeout', 'rate limit', 'temporary failure', 'connection error'
        ]
        return any(pattern in error_message.lower() for pattern in recoverable_patterns)

    def _schedule_retry(self, event: Dict[str, Any]) -> None:
        """Schedule event retry"""
        # Implementation would use EventBridge with delay
        pass


# Global orchestrator instance
orchestrator = EventOrchestrator()


def lambda_handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    """
    Lambda handler for event orchestration

    Args:
        event: EventBridge event or direct invocation
        context: Lambda runtime context

    Returns:
        Processing result
    """
    try:
        logger.info(f"Event orchestrator triggered: {json.dumps(event, default=str)}")

        # Handle EventBridge events
        if 'source' in event and 'detail' in event:
            result = orchestrator.process_event(event)
        else:
            # Handle direct invocations
            result = orchestrator.process_event({
                'source': 'direct',
                'detail': event
            })

        return {
            'statusCode': 200,
            'body': json.dumps(result, default=str)
        }

    except Exception as e:
        logger.error(f"Event orchestrator failed: {e}", exc_info=True)
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': 'Orchestration failed',
                'message': str(e) if ENVIRONMENT == 'dev' else 'Internal error'
            })
        }