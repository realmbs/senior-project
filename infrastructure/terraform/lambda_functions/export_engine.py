"""
Threat Intelligence Export Engine
Phase 8A Implementation - Multi-Format Export Capabilities

This module provides comprehensive export capabilities for threat intelligence data:
- JSON export with customizable formatting
- CSV export with configurable columns
- STIX 2.1 bundle export for standards compliance
- Bulk export with streaming for large datasets
- Export metadata and provenance tracking
- Compression and optimization for large files
"""

import json
import csv
import io
import gzip
import zipfile
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Union, Iterator
from dataclasses import dataclass
from enum import Enum
import boto3
import logging
import os
import tempfile

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# AWS Service Clients
s3_client = boto3.client('s3')

# Environment Variables
EXPORT_BUCKET = os.environ.get('PROCESSED_DATA_BUCKET', 'default-export-bucket')
MAX_EXPORT_SIZE_MB = int(os.environ.get('MAX_EXPORT_SIZE_MB', '100'))
EXPORT_TTL_HOURS = int(os.environ.get('EXPORT_TTL_HOURS', '24'))


class ExportFormat(Enum):
    """Supported export formats"""
    JSON = "json"
    CSV = "csv"
    STIX = "stix"
    XML = "xml"


class CompressionType(Enum):
    """Supported compression types"""
    NONE = "none"
    GZIP = "gzip"
    ZIP = "zip"


@dataclass
class ExportRequest:
    """Export request configuration"""
    format: ExportFormat
    data: List[Dict[str, Any]]
    filename: Optional[str] = None
    compression: CompressionType = CompressionType.NONE
    include_metadata: bool = True
    include_correlations: bool = True
    include_enrichment: bool = False
    custom_fields: Optional[List[str]] = None
    filter_criteria: Optional[Dict[str, Any]] = None


@dataclass
class ExportMetadata:
    """Export metadata and provenance information"""
    export_id: str
    created_at: str
    format: str
    compression: str
    record_count: int
    file_size_bytes: int
    source_query: Optional[Dict[str, Any]]
    export_criteria: Dict[str, Any]
    stix_version: str = "2.1"


@dataclass
class ExportResult:
    """Export operation result"""
    success: bool
    export_id: str
    download_url: Optional[str]
    metadata: ExportMetadata
    error_message: Optional[str] = None


class ThreatIntelExportEngine:
    """Advanced threat intelligence export engine"""

    def __init__(self):
        self.supported_formats = {
            ExportFormat.JSON: self._export_json,
            ExportFormat.CSV: self._export_csv,
            ExportFormat.STIX: self._export_stix,
            ExportFormat.XML: self._export_xml
        }

    def export_data(self, request: ExportRequest) -> ExportResult:
        """
        Export threat intelligence data in specified format

        Args:
            request: Export request configuration

        Returns:
            ExportResult with download URL and metadata
        """
        try:
            logger.info(f"Starting export: {request.format.value} format, {len(request.data)} records")

            # Generate export ID
            export_id = self._generate_export_id()

            # Apply filters if specified
            filtered_data = self._apply_filters(request.data, request.filter_criteria)

            # Validate data size
            if not self._validate_export_size(filtered_data):
                return ExportResult(
                    success=False,
                    export_id=export_id,
                    download_url=None,
                    metadata=None,
                    error_message=f"Export size exceeds {MAX_EXPORT_SIZE_MB}MB limit"
                )

            # Generate filename if not provided
            if not request.filename:
                request.filename = self._generate_filename(export_id, request.format)

            # Export data using format-specific handler
            export_handler = self.supported_formats.get(request.format)
            if not export_handler:
                raise ValueError(f"Unsupported export format: {request.format}")

            # Create export content
            export_content = export_handler(filtered_data, request)

            # Apply compression if requested
            if request.compression != CompressionType.NONE:
                export_content = self._apply_compression(
                    export_content, request.compression, request.filename)
                request.filename = self._add_compression_extension(
                    request.filename, request.compression)

            # Upload to S3
            s3_key = f"exports/{export_id}/{request.filename}"
            download_url = self._upload_to_s3(export_content, s3_key)

            # Create metadata
            metadata = ExportMetadata(
                export_id=export_id,
                created_at=datetime.now(timezone.utc).isoformat(),
                format=request.format.value,
                compression=request.compression.value,
                record_count=len(filtered_data),
                file_size_bytes=len(export_content),
                source_query=getattr(request, 'source_query', None),
                export_criteria={
                    'include_metadata': request.include_metadata,
                    'include_correlations': request.include_correlations,
                    'include_enrichment': request.include_enrichment,
                    'custom_fields': request.custom_fields,
                    'filter_criteria': request.filter_criteria
                }
            )

            # Store metadata
            self._store_export_metadata(metadata)

            logger.info(f"Export completed: {export_id}, {metadata.file_size_bytes} bytes")

            return ExportResult(
                success=True,
                export_id=export_id,
                download_url=download_url,
                metadata=metadata
            )

        except Exception as e:
            logger.error(f"Export failed: {e}", exc_info=True)
            return ExportResult(
                success=False,
                export_id=export_id if 'export_id' in locals() else 'unknown',
                download_url=None,
                metadata=None,
                error_message=str(e)
            )

    def _export_json(self, data: List[Dict[str, Any]], request: ExportRequest) -> bytes:
        """Export data as JSON format"""
        export_data = {
            'metadata': {
                'export_format': 'json',
                'export_time': datetime.now(timezone.utc).isoformat(),
                'record_count': len(data),
                'stix_version': '2.1'
            } if request.include_metadata else None,
            'indicators': []
        }

        for item in data:
            indicator = self._prepare_indicator_for_export(item, request)
            export_data['indicators'].append(indicator)

        # Remove metadata if not requested
        if not request.include_metadata:
            export_data = export_data['indicators']

        return json.dumps(export_data, indent=2, default=str).encode('utf-8')

    def _export_csv(self, data: List[Dict[str, Any]], request: ExportRequest) -> bytes:
        """Export data as CSV format"""
        if not data:
            return b""

        # Determine CSV columns
        columns = self._determine_csv_columns(data, request.custom_fields)

        # Create CSV content
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=columns, extrasaction='ignore')

        # Write header
        writer.writeheader()

        # Write metadata row if requested
        if request.include_metadata:
            metadata_row = {
                columns[0]: '# Export Metadata',
                columns[1] if len(columns) > 1 else columns[0]: f'Generated: {datetime.now(timezone.utc).isoformat()}',
                columns[2] if len(columns) > 2 else columns[0]: f'Records: {len(data)}'
            }
            writer.writerow(metadata_row)

        # Write data rows
        for item in data:
            row = self._prepare_csv_row(item, columns, request)
            writer.writerow(row)

        return output.getvalue().encode('utf-8')

    def _export_stix(self, data: List[Dict[str, Any]], request: ExportRequest) -> bytes:
        """Export data as STIX 2.1 bundle"""
        bundle = {
            "type": "bundle",
            "id": f"bundle--{self._generate_uuid()}",
            "spec_version": "2.1",
            "objects": []
        }

        # Add metadata object if requested
        if request.include_metadata:
            metadata_object = {
                "type": "note",
                "id": f"note--{self._generate_uuid()}",
                "created": datetime.now(timezone.utc).isoformat(),
                "modified": datetime.now(timezone.utc).isoformat(),
                "content": f"Export bundle containing {len(data)} threat intelligence indicators",
                "object_refs": [],
                "spec_version": "2.1"
            }
            bundle["objects"].append(metadata_object)

        # Add indicators
        for item in data:
            stix_object = self._convert_to_stix_object(item, request)
            if stix_object:
                bundle["objects"].append(stix_object)

        return json.dumps(bundle, indent=2, default=str).encode('utf-8')

    def _export_xml(self, data: List[Dict[str, Any]], request: ExportRequest) -> bytes:
        """Export data as XML format"""
        xml_content = ['<?xml version="1.0" encoding="UTF-8"?>']
        xml_content.append('<threat_intelligence>')

        # Add metadata if requested
        if request.include_metadata:
            xml_content.append('<metadata>')
            xml_content.append(f'  <export_time>{datetime.now(timezone.utc).isoformat()}</export_time>')
            xml_content.append(f'  <record_count>{len(data)}</record_count>')
            xml_content.append(f'  <format>xml</format>')
            xml_content.append('</metadata>')

        # Add indicators
        xml_content.append('<indicators>')
        for item in data:
            xml_content.append('  <indicator>')

            # Add basic fields
            for field, value in item.items():
                if field in ['object_id', 'object_type', 'pattern', 'confidence', 'created_date', 'source_name']:
                    xml_content.append(f'    <{field}>{self._escape_xml(str(value))}</{field}>')

            # Add correlations if requested
            if request.include_correlations and 'correlations' in item:
                xml_content.append('    <correlations>')
                for correlation in item['correlations']:
                    xml_content.append('      <correlation>')
                    for key, value in correlation.items():
                        xml_content.append(f'        <{key}>{self._escape_xml(str(value))}</{key}>')
                    xml_content.append('      </correlation>')
                xml_content.append('    </correlations>')

            xml_content.append('  </indicator>')

        xml_content.append('</indicators>')
        xml_content.append('</threat_intelligence>')

        return '\n'.join(xml_content).encode('utf-8')

    def _prepare_indicator_for_export(self, item: Dict[str, Any], request: ExportRequest) -> Dict[str, Any]:
        """Prepare indicator for JSON export"""
        indicator = item.copy()

        # Remove internal fields
        internal_fields = ['processed_at', 'processor_version', 'relevance_score', 'match_type']
        for field in internal_fields:
            indicator.pop(field, None)

        # Add correlations if requested
        if not request.include_correlations:
            indicator.pop('correlations', None)

        # Add enrichment data if requested
        if not request.include_enrichment:
            indicator.pop('enrichment_data', None)

        # Apply custom field filtering
        if request.custom_fields:
            filtered_indicator = {}
            for field in request.custom_fields:
                if field in indicator:
                    filtered_indicator[field] = indicator[field]
            indicator = filtered_indicator

        return indicator

    def _determine_csv_columns(self, data: List[Dict[str, Any]], custom_fields: Optional[List[str]]) -> List[str]:
        """Determine CSV column headers"""
        if custom_fields:
            return custom_fields

        # Use common fields
        common_fields = [
            'object_id', 'object_type', 'pattern', 'confidence', 'created_date',
            'source_name', 'labels', 'description', 'threat_type'
        ]

        # Add fields that exist in the data
        all_fields = set()
        for item in data:
            all_fields.update(item.keys())

        # Filter to existing common fields and add others
        columns = [field for field in common_fields if field in all_fields]

        # Add any additional fields not in common_fields
        additional_fields = sorted(all_fields - set(common_fields))
        columns.extend(additional_fields)

        return columns

    def _prepare_csv_row(self, item: Dict[str, Any], columns: List[str], request: ExportRequest) -> Dict[str, str]:
        """Prepare a single CSV row"""
        row = {}

        for column in columns:
            value = item.get(column, '')

            # Handle special fields
            if column == 'labels' and isinstance(value, list):
                value = '|'.join(value)
            elif column == 'correlations' and isinstance(value, list):
                if request.include_correlations:
                    value = f"Count: {len(value)}"
                else:
                    value = ''
            elif isinstance(value, (dict, list)):
                value = json.dumps(value)

            row[column] = str(value)

        return row

    def _convert_to_stix_object(self, item: Dict[str, Any], request: ExportRequest) -> Optional[Dict[str, Any]]:
        """Convert indicator to STIX 2.1 object"""
        try:
            stix_object = {
                "type": item.get('object_type', 'indicator'),
                "id": item.get('object_id', f"indicator--{self._generate_uuid()}"),
                "created": item.get('created_date', datetime.now(timezone.utc).isoformat()),
                "modified": item.get('modified_date', item.get('created_date', datetime.now(timezone.utc).isoformat())),
                "pattern": item.get('pattern', ''),
                "labels": item.get('labels', ['malicious-activity']),
                "spec_version": "2.1"
            }

            # Add optional fields
            if 'confidence' in item:
                stix_object['confidence'] = int(item['confidence'])

            if 'description' in item:
                stix_object['description'] = item['description']

            if 'external_references' in item:
                stix_object['external_references'] = item['external_references']

            # Add custom properties for enrichment data
            if request.include_enrichment and 'enrichment_data' in item:
                stix_object['x_enrichment_data'] = item['enrichment_data']

            return stix_object

        except Exception as e:
            logger.warning(f"Failed to convert item to STIX: {e}")
            return None

    def _apply_filters(self, data: List[Dict[str, Any]], filters: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Apply export filters to data"""
        if not filters:
            return data

        filtered_data = []

        for item in data:
            include_item = True

            # Apply confidence filter
            if 'min_confidence' in filters:
                confidence = item.get('confidence', 0)
                if confidence < filters['min_confidence']:
                    include_item = False

            # Apply source filter
            if 'sources' in filters:
                source = item.get('source_name', '')
                if source not in filters['sources']:
                    include_item = False

            # Apply date range filter
            if 'date_range' in filters:
                created_date = item.get('created_date', '')
                if not self._is_in_date_range(created_date, filters['date_range']):
                    include_item = False

            # Apply threat type filter
            if 'threat_types' in filters:
                threat_type = item.get('threat_type', '')
                if threat_type not in filters['threat_types']:
                    include_item = False

            if include_item:
                filtered_data.append(item)

        return filtered_data

    def _is_in_date_range(self, date_str: str, date_range: Dict[str, str]) -> bool:
        """Check if date is within specified range"""
        try:
            item_date = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
            start_date = datetime.fromisoformat(date_range['start'].replace('Z', '+00:00'))
            end_date = datetime.fromisoformat(date_range['end'].replace('Z', '+00:00'))
            return start_date <= item_date <= end_date
        except Exception:
            return True  # Include if date parsing fails

    def _validate_export_size(self, data: List[Dict[str, Any]]) -> bool:
        """Validate that export size is within limits"""
        # Rough size estimation
        estimated_size = len(json.dumps(data, default=str).encode('utf-8'))
        max_size_bytes = MAX_EXPORT_SIZE_MB * 1024 * 1024
        return estimated_size <= max_size_bytes

    def _apply_compression(self, content: bytes, compression: CompressionType, filename: str) -> bytes:
        """Apply compression to export content"""
        if compression == CompressionType.GZIP:
            return gzip.compress(content)
        elif compression == CompressionType.ZIP:
            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                zip_file.writestr(filename, content)
            return zip_buffer.getvalue()
        else:
            return content

    def _add_compression_extension(self, filename: str, compression: CompressionType) -> str:
        """Add compression extension to filename"""
        if compression == CompressionType.GZIP:
            return f"{filename}.gz"
        elif compression == CompressionType.ZIP:
            return f"{filename}.zip"
        else:
            return filename

    def _upload_to_s3(self, content: bytes, s3_key: str) -> str:
        """Upload export content to S3 and return presigned URL"""
        try:
            # Upload file
            s3_client.put_object(
                Bucket=EXPORT_BUCKET,
                Key=s3_key,
                Body=content,
                ContentType=self._get_content_type(s3_key),
                ServerSideEncryption='AES256',
                Metadata={
                    'export-ttl-hours': str(EXPORT_TTL_HOURS),
                    'created-at': datetime.now(timezone.utc).isoformat()
                }
            )

            # Generate presigned URL for download
            download_url = s3_client.generate_presigned_url(
                'get_object',
                Params={'Bucket': EXPORT_BUCKET, 'Key': s3_key},
                ExpiresIn=EXPORT_TTL_HOURS * 3600  # Convert hours to seconds
            )

            return download_url

        except Exception as e:
            logger.error(f"S3 upload failed: {e}")
            raise

    def _store_export_metadata(self, metadata: ExportMetadata) -> None:
        """Store export metadata for tracking"""
        try:
            metadata_key = f"exports/{metadata.export_id}/metadata.json"
            metadata_content = json.dumps({
                'export_id': metadata.export_id,
                'created_at': metadata.created_at,
                'format': metadata.format,
                'compression': metadata.compression,
                'record_count': metadata.record_count,
                'file_size_bytes': metadata.file_size_bytes,
                'source_query': metadata.source_query,
                'export_criteria': metadata.export_criteria,
                'stix_version': metadata.stix_version
            }, default=str)

            s3_client.put_object(
                Bucket=EXPORT_BUCKET,
                Key=metadata_key,
                Body=metadata_content.encode('utf-8'),
                ContentType='application/json',
                ServerSideEncryption='AES256'
            )

        except Exception as e:
            logger.warning(f"Failed to store export metadata: {e}")

    def _generate_export_id(self) -> str:
        """Generate unique export ID"""
        import uuid
        return str(uuid.uuid4())

    def _generate_uuid(self) -> str:
        """Generate UUID for STIX objects"""
        import uuid
        return str(uuid.uuid4())

    def _generate_filename(self, export_id: str, format: ExportFormat) -> str:
        """Generate export filename"""
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
        return f"threat_intel_export_{timestamp}_{export_id[:8]}.{format.value}"

    def _get_content_type(self, filename: str) -> str:
        """Get content type based on file extension"""
        if filename.endswith('.json'):
            return 'application/json'
        elif filename.endswith('.csv'):
            return 'text/csv'
        elif filename.endswith('.xml'):
            return 'application/xml'
        elif filename.endswith('.gz'):
            return 'application/gzip'
        elif filename.endswith('.zip'):
            return 'application/zip'
        else:
            return 'application/octet-stream'

    def _escape_xml(self, text: str) -> str:
        """Escape XML special characters"""
        return (text.replace('&', '&amp;')
                   .replace('<', '&lt;')
                   .replace('>', '&gt;')
                   .replace('"', '&quot;')
                   .replace("'", '&#39;'))


# Global export engine instance
export_engine = ThreatIntelExportEngine()


def lambda_handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    """
    Lambda handler for threat intelligence export

    Args:
        event: API Gateway event with export parameters
        context: Lambda runtime context

    Returns:
        ExportResult with download URL
    """
    try:
        # Parse request
        if 'body' in event:
            body = json.loads(event['body']) if isinstance(event['body'], str) else event['body']
        else:
            body = event

        # Build export request
        export_request = ExportRequest(
            format=ExportFormat(body.get('format', 'json')),
            data=body.get('data', []),
            filename=body.get('filename'),
            compression=CompressionType(body.get('compression', 'none')),
            include_metadata=body.get('include_metadata', True),
            include_correlations=body.get('include_correlations', True),
            include_enrichment=body.get('include_enrichment', False),
            custom_fields=body.get('custom_fields'),
            filter_criteria=body.get('filter_criteria')
        )

        # Execute export
        result = export_engine.export_data(export_request)

        # Build response
        response_data = {
            'success': result.success,
            'export_id': result.export_id,
            'download_url': result.download_url,
            'error_message': result.error_message
        }

        if result.metadata:
            response_data['metadata'] = {
                'export_id': result.metadata.export_id,
                'created_at': result.metadata.created_at,
                'format': result.metadata.format,
                'compression': result.metadata.compression,
                'record_count': result.metadata.record_count,
                'file_size_bytes': result.metadata.file_size_bytes,
                'stix_version': result.metadata.stix_version
            }

        return {
            'statusCode': 200 if result.success else 400,
            'body': json.dumps(response_data, default=str),
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            }
        }

    except Exception as e:
        logger.error(f"Export handler failed: {e}", exc_info=True)
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': 'Export failed',
                'message': str(e) if os.environ.get('ENVIRONMENT') == 'dev' else 'Internal server error'
            }),
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            }
        }