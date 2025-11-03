"""
STIX 2.1 compliance validation tests
Tests compliance with STIX 2.1 specification for threat intelligence data format
"""

import pytest
import json
import time
import os
import re
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
import requests
import jsonschema
from dateutil import parser as date_parser


# Module-level fixtures
@pytest.fixture(scope="module")
def stix_config():
    """STIX compliance test configuration"""
    return {
        'base_url': os.environ.get('API_BASE_URL', 'https://u88kzux168.execute-api.us-east-1.amazonaws.com/dev'),
        'api_key': os.environ.get('TEST_API_KEY'),
        'region': os.environ.get('AWS_REGION', 'us-east-1'),
        'stix_version': '2.1'
    }


@pytest.fixture
def stix_headers(stix_config):
    """Headers for STIX compliance requests"""
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'User-Agent': 'ThreatIntel-STIX-Compliance-Test/1.0'
    }
    if stix_config['api_key']:
        headers['x-api-key'] = stix_config['api_key']
    return headers


class STIXValidator:
    """STIX 2.1 validation utility class"""

    # STIX 2.1 required object properties
    REQUIRED_PROPERTIES = {
        'common': ['type', 'id', 'spec_version', 'created', 'modified'],
        'indicator': ['type', 'id', 'spec_version', 'created', 'modified', 'pattern', 'labels', 'valid_from'],
        'malware': ['type', 'id', 'spec_version', 'created', 'modified', 'name', 'is_family'],
        'attack-pattern': ['type', 'id', 'spec_version', 'created', 'modified', 'name'],
        'campaign': ['type', 'id', 'spec_version', 'created', 'modified', 'name'],
        'course-of-action': ['type', 'id', 'spec_version', 'created', 'modified', 'name'],
        'intrusion-set': ['type', 'id', 'spec_version', 'created', 'modified', 'name'],
        'threat-actor': ['type', 'id', 'spec_version', 'created', 'modified', 'name'],
        'tool': ['type', 'id', 'spec_version', 'created', 'modified', 'name'],
        'vulnerability': ['type', 'id', 'spec_version', 'created', 'modified', 'name'],
        'observed-data': ['type', 'id', 'spec_version', 'created', 'modified', 'first_observed', 'last_observed', 'number_observed', 'objects'],
    }

    # Valid STIX 2.1 object types
    VALID_OBJECT_TYPES = [
        'indicator', 'malware', 'attack-pattern', 'campaign', 'course-of-action',
        'intrusion-set', 'threat-actor', 'tool', 'vulnerability', 'observed-data',
        'bundle', 'relationship', 'sighting', 'marking-definition', 'language-content'
    ]

    # Valid indicator labels
    VALID_INDICATOR_LABELS = [
        'anomalous-activity', 'anonymization', 'benign', 'compromised',
        'malicious-activity', 'attribution'
    ]

    @staticmethod
    def validate_uuid4(uuid_string: str) -> bool:
        """Validate UUID4 format"""
        try:
            uuid_obj = uuid.UUID(uuid_string, version=4)
            return str(uuid_obj) == uuid_string
        except ValueError:
            return False

    @staticmethod
    def validate_stix_id(stix_id: str, object_type: str) -> bool:
        """Validate STIX ID format"""
        # STIX ID format: {object-type}--{UUID4}
        pattern = rf'^{re.escape(object_type)}--[0-9a-f]{{8}}-[0-9a-f]{{4}}-4[0-9a-f]{{3}}-[89ab][0-9a-f]{{3}}-[0-9a-f]{{12}}$'
        return bool(re.match(pattern, stix_id))

    @staticmethod
    def validate_timestamp(timestamp: str) -> bool:
        """Validate ISO 8601 timestamp format"""
        try:
            parsed_time = date_parser.isoparse(timestamp)
            # Should be timezone-aware and in UTC
            return parsed_time.tzinfo is not None
        except (ValueError, TypeError):
            return False

    @staticmethod
    def validate_pattern(pattern: str) -> bool:
        """Basic validation of STIX pattern syntax"""
        # Pattern should be wrapped in square brackets
        if not (pattern.startswith('[') and pattern.endswith(']')):
            return False

        # Should contain a comparison
        comparison_operators = [' = ', ' != ', ' LIKE ', ' MATCHES ', ' IN ', ' SUBSET OF ', ' SUPERSET OF ']
        return any(op in pattern for op in comparison_operators)

    def validate_stix_object(self, stix_obj: Dict[str, Any]) -> List[str]:
        """Validate a single STIX object and return list of errors"""
        errors = []

        # Check object type
        if 'type' not in stix_obj:
            errors.append("Missing required 'type' property")
            return errors  # Can't continue without type

        obj_type = stix_obj['type']

        if obj_type not in self.VALID_OBJECT_TYPES:
            errors.append(f"Invalid object type: {obj_type}")

        # Check required properties
        required_props = self.REQUIRED_PROPERTIES.get(obj_type, self.REQUIRED_PROPERTIES['common'])

        for prop in required_props:
            if prop not in stix_obj:
                errors.append(f"Missing required property: {prop}")

        # Validate spec_version
        if 'spec_version' in stix_obj:
            if stix_obj['spec_version'] != '2.1':
                errors.append(f"Invalid spec_version: {stix_obj['spec_version']} (expected 2.1)")

        # Validate ID format
        if 'id' in stix_obj:
            if not self.validate_stix_id(stix_obj['id'], obj_type):
                errors.append(f"Invalid STIX ID format: {stix_obj['id']}")

        # Validate timestamps
        timestamp_fields = ['created', 'modified', 'valid_from', 'valid_until', 'first_observed', 'last_observed']
        for field in timestamp_fields:
            if field in stix_obj:
                if not self.validate_timestamp(stix_obj[field]):
                    errors.append(f"Invalid timestamp format for {field}: {stix_obj[field]}")

        # Object-specific validations
        if obj_type == 'indicator':
            errors.extend(self._validate_indicator(stix_obj))
        elif obj_type == 'bundle':
            errors.extend(self._validate_bundle(stix_obj))
        elif obj_type == 'relationship':
            errors.extend(self._validate_relationship(stix_obj))

        return errors

    def _validate_indicator(self, indicator: Dict[str, Any]) -> List[str]:
        """Validate STIX indicator specific properties"""
        errors = []

        # Validate pattern
        if 'pattern' in indicator:
            if not self.validate_pattern(indicator['pattern']):
                errors.append(f"Invalid pattern format: {indicator['pattern']}")

        # Validate labels
        if 'labels' in indicator:
            if not isinstance(indicator['labels'], list) or not indicator['labels']:
                errors.append("Labels must be a non-empty list")
            else:
                for label in indicator['labels']:
                    if label not in self.VALID_INDICATOR_LABELS:
                        errors.append(f"Invalid indicator label: {label}")

        # Validate pattern_type if present
        if 'pattern_type' in indicator:
            if indicator['pattern_type'] != 'stix':
                errors.append(f"Unsupported pattern_type: {indicator['pattern_type']}")

        return errors

    def _validate_bundle(self, bundle: Dict[str, Any]) -> List[str]:
        """Validate STIX bundle specific properties"""
        errors = []

        if 'objects' in bundle:
            if not isinstance(bundle['objects'], list):
                errors.append("Bundle objects must be a list")
            else:
                for i, obj in enumerate(bundle['objects']):
                    obj_errors = self.validate_stix_object(obj)
                    for error in obj_errors:
                        errors.append(f"Object {i}: {error}")

        return errors

    def _validate_relationship(self, relationship: Dict[str, Any]) -> List[str]:
        """Validate STIX relationship specific properties"""
        errors = []

        required_rel_props = ['relationship_type', 'source_ref', 'target_ref']
        for prop in required_rel_props:
            if prop not in relationship:
                errors.append(f"Missing required relationship property: {prop}")

        # Validate reference format
        for ref_prop in ['source_ref', 'target_ref']:
            if ref_prop in relationship:
                ref_value = relationship[ref_prop]
                # Should be a valid STIX ID
                if '--' not in ref_value:
                    errors.append(f"Invalid reference format for {ref_prop}: {ref_value}")

        return errors


class TestSTIXBasicCompliance:
    """Test basic STIX 2.1 compliance"""

    def test_search_returns_valid_stix_objects(self, stix_config, stix_headers):
        """Test that search results contain valid STIX objects"""
        url = f"{stix_config['base_url']}/search"
        params = {'q': '*', 'limit': 5, 'format': 'stix'}

        response = requests.get(url, params=params, headers=stix_headers, timeout=30)

        if response.status_code == 200:
            data = response.json()
            validator = STIXValidator()

            if 'results' in data and data['results']:
                for i, result in enumerate(data['results']):
                    if 'stix_data' in result:
                        stix_obj = result['stix_data']

                        # Validate STIX object
                        errors = validator.validate_stix_object(stix_obj)

                        if errors:
                            print(f"STIX validation errors for result {i}:")
                            for error in errors:
                                print(f"  - {error}")
                            assert False, f"STIX validation failed for result {i}: {errors[0]}"

                        print(f"✓ Result {i}: Valid STIX {stix_obj['type']} object")

            else:
                print("No STIX results returned (may be expected)")

        elif response.status_code == 403:
            pytest.skip("API authentication required for STIX compliance test")
        else:
            pytest.fail(f"Search request failed: {response.status_code}")

    def test_stix_object_structure_compliance(self, stix_config, stix_headers):
        """Test STIX object structure compliance"""
        url = f"{stix_config['base_url']}/search"
        params = {'q': 'indicator', 'limit': 1, 'format': 'stix'}

        response = requests.get(url, params=params, headers=stix_headers, timeout=30)

        if response.status_code == 200:
            data = response.json()

            if 'results' in data and data['results']:
                result = data['results'][0]

                if 'stix_data' in result:
                    stix_obj = result['stix_data']

                    # Test basic structure
                    assert isinstance(stix_obj, dict), "STIX object must be a JSON object"

                    # Test required common properties
                    common_props = ['type', 'id', 'spec_version', 'created', 'modified']
                    for prop in common_props:
                        assert prop in stix_obj, f"Missing required property: {prop}"

                    # Test spec_version
                    assert stix_obj['spec_version'] == '2.1', f"Invalid spec_version: {stix_obj['spec_version']}"

                    # Test ID format
                    assert '--' in stix_obj['id'], "STIX ID must contain '--' separator"

                    obj_type, uuid_part = stix_obj['id'].split('--', 1)
                    assert obj_type == stix_obj['type'], "STIX ID type must match object type"

                    print(f"✓ STIX {stix_obj['type']} structure compliant")

        elif response.status_code == 403:
            pytest.skip("API authentication required")

    def test_stix_timestamp_format_compliance(self, stix_config, stix_headers):
        """Test STIX timestamp format compliance"""
        url = f"{stix_config['base_url']}/search"
        params = {'q': '*', 'limit': 3}

        response = requests.get(url, params=params, headers=stix_headers, timeout=30)

        if response.status_code == 200:
            data = response.json()
            validator = STIXValidator()

            if 'results' in data and data['results']:
                for result in data['results']:
                    if 'stix_data' in result:
                        stix_obj = result['stix_data']

                        # Check timestamp fields
                        timestamp_fields = ['created', 'modified', 'valid_from', 'valid_until']

                        for field in timestamp_fields:
                            if field in stix_obj:
                                timestamp = stix_obj[field]

                                # Validate ISO 8601 format
                                assert validator.validate_timestamp(timestamp), \
                                    f"Invalid timestamp format for {field}: {timestamp}"

                                # Should end with 'Z' or have timezone offset
                                assert 'T' in timestamp, f"Timestamp missing 'T' separator: {timestamp}"

                                print(f"✓ Valid timestamp {field}: {timestamp}")

        elif response.status_code == 403:
            pytest.skip("API authentication required")


class TestSTIXIndicatorCompliance:
    """Test STIX indicator specific compliance"""

    def test_indicator_pattern_compliance(self, stix_config, stix_headers):
        """Test STIX indicator pattern compliance"""
        url = f"{stix_config['base_url']}/search"
        params = {'q': '*', 'type': 'indicator', 'limit': 5}

        response = requests.get(url, params=params, headers=stix_headers, timeout=30)

        if response.status_code == 200:
            data = response.json()
            validator = STIXValidator()

            if 'results' in data and data['results']:
                for result in data['results']:
                    if 'stix_data' in result:
                        stix_obj = result['stix_data']

                        if stix_obj.get('type') == 'indicator':
                            # Test pattern presence and format
                            assert 'pattern' in stix_obj, "Indicator missing required 'pattern'"

                            pattern = stix_obj['pattern']
                            assert validator.validate_pattern(pattern), f"Invalid pattern format: {pattern}"

                            # Test pattern syntax
                            assert pattern.startswith('[') and pattern.endswith(']'), \
                                "Pattern must be wrapped in square brackets"

                            print(f"✓ Valid indicator pattern: {pattern}")

        elif response.status_code == 403:
            pytest.skip("API authentication required")

    def test_indicator_labels_compliance(self, stix_config, stix_headers):
        """Test STIX indicator labels compliance"""
        url = f"{stix_config['base_url']}/search"
        params = {'q': '*', 'type': 'indicator', 'limit': 5}

        response = requests.get(url, params=params, headers=stix_headers, timeout=30)

        if response.status_code == 200:
            data = response.json()
            validator = STIXValidator()

            if 'results' in data and data['results']:
                for result in data['results']:
                    if 'stix_data' in result:
                        stix_obj = result['stix_data']

                        if stix_obj.get('type') == 'indicator':
                            # Test labels presence and format
                            assert 'labels' in stix_obj, "Indicator missing required 'labels'"

                            labels = stix_obj['labels']
                            assert isinstance(labels, list), "Labels must be a list"
                            assert len(labels) > 0, "Labels list cannot be empty"

                            # Test label values
                            for label in labels:
                                assert label in validator.VALID_INDICATOR_LABELS, \
                                    f"Invalid indicator label: {label}"

                            print(f"✓ Valid indicator labels: {labels}")

        elif response.status_code == 403:
            pytest.skip("API authentication required")

    def test_indicator_pattern_types(self, stix_config, stix_headers):
        """Test different indicator pattern types"""
        url = f"{stix_config['base_url']}/search"

        # Test different IOC types
        test_queries = [
            ('192.168.1.1', 'IPv4'),
            ('malicious.com', 'domain'),
            ('http://evil.com', 'URL'),
        ]

        for query, expected_type in test_queries:
            params = {'q': query, 'limit': 1}

            response = requests.get(url, params=params, headers=stix_headers, timeout=30)

            if response.status_code == 200:
                data = response.json()

                if 'results' in data and data['results']:
                    result = data['results'][0]

                    if 'stix_data' in result:
                        stix_obj = result['stix_data']

                        if stix_obj.get('type') == 'indicator':
                            pattern = stix_obj['pattern']

                            # Pattern should reference appropriate object type
                            if expected_type == 'IPv4':
                                assert 'ipv4-addr:value' in pattern.lower(), \
                                    f"IPv4 pattern should reference ipv4-addr: {pattern}"
                            elif expected_type == 'domain':
                                assert 'domain-name:value' in pattern.lower(), \
                                    f"Domain pattern should reference domain-name: {pattern}"
                            elif expected_type == 'URL':
                                assert 'url:value' in pattern.lower(), \
                                    f"URL pattern should reference url: {pattern}"

                            print(f"✓ Correct pattern type for {expected_type}: {pattern}")

            elif response.status_code == 403:
                pytest.skip("API authentication required")


class TestSTIXRelationshipCompliance:
    """Test STIX relationship compliance"""

    def test_relationship_structure(self, stix_config, stix_headers):
        """Test STIX relationship object structure"""
        url = f"{stix_config['base_url']}/search"
        params = {'q': '*', 'include_relationships': 'true', 'limit': 5}

        response = requests.get(url, params=params, headers=stix_headers, timeout=30)

        if response.status_code == 200:
            data = response.json()
            validator = STIXValidator()

            relationships_found = False

            if 'results' in data and data['results']:
                for result in data['results']:
                    if 'stix_data' in result:
                        stix_obj = result['stix_data']

                        if stix_obj.get('type') == 'relationship':
                            relationships_found = True

                            # Validate relationship structure
                            errors = validator.validate_stix_object(stix_obj)
                            assert not errors, f"Relationship validation errors: {errors}"

                            # Test relationship-specific properties
                            required_props = ['relationship_type', 'source_ref', 'target_ref']
                            for prop in required_props:
                                assert prop in stix_obj, f"Missing relationship property: {prop}"

                            print(f"✓ Valid relationship: {stix_obj['relationship_type']}")

            if not relationships_found:
                print("No relationships found in results (may be expected)")

        elif response.status_code == 403:
            pytest.skip("API authentication required")


class TestSTIXBundleCompliance:
    """Test STIX bundle compliance"""

    def test_bundle_export_compliance(self, stix_config, stix_headers):
        """Test STIX bundle export compliance"""
        url = f"{stix_config['base_url']}/search"
        params = {'q': '*', 'format': 'bundle', 'limit': 5}

        response = requests.get(url, params=params, headers=stix_headers, timeout=30)

        if response.status_code == 200:
            data = response.json()

            # Check if response is a STIX bundle
            if data.get('type') == 'bundle':
                validator = STIXValidator()

                # Validate bundle structure
                errors = validator.validate_stix_object(data)
                assert not errors, f"Bundle validation errors: {errors}"

                # Test bundle properties
                assert 'id' in data, "Bundle missing ID"
                assert 'spec_version' in data, "Bundle missing spec_version"
                assert 'objects' in data, "Bundle missing objects array"

                assert data['spec_version'] == '2.1', f"Invalid bundle spec_version: {data['spec_version']}"
                assert isinstance(data['objects'], list), "Bundle objects must be a list"

                print(f"✓ Valid STIX bundle with {len(data['objects'])} objects")

                # Validate each object in bundle
                for i, obj in enumerate(data['objects']):
                    obj_errors = validator.validate_stix_object(obj)
                    assert not obj_errors, f"Bundle object {i} validation errors: {obj_errors}"

        elif response.status_code == 403:
            pytest.skip("API authentication required")


class TestSTIXExtensionCompliance:
    """Test STIX extension and custom property compliance"""

    def test_custom_properties_compliance(self, stix_config, stix_headers):
        """Test custom properties follow STIX extension guidelines"""
        url = f"{stix_config['base_url']}/search"
        params = {'q': '*', 'limit': 3}

        response = requests.get(url, params=params, headers=stix_headers, timeout=30)

        if response.status_code == 200:
            data = response.json()

            if 'results' in data and data['results']:
                for result in data['results']:
                    if 'stix_data' in result:
                        stix_obj = result['stix_data']

                        # Check for custom properties (should start with 'x_')
                        custom_props = [prop for prop in stix_obj.keys() if prop.startswith('x_')]

                        for prop in custom_props:
                            # Custom properties should follow naming convention
                            assert re.match(r'^x_[a-z0-9_]+$', prop), \
                                f"Custom property {prop} doesn't follow naming convention"

                            print(f"✓ Valid custom property: {prop}")

        elif response.status_code == 403:
            pytest.skip("API authentication required")

    def test_confidence_scoring_compliance(self, stix_config, stix_headers):
        """Test confidence scoring compliance with STIX guidelines"""
        url = f"{stix_config['base_url']}/search"
        params = {'q': '*', 'limit': 5}

        response = requests.get(url, params=params, headers=stix_headers, timeout=30)

        if response.status_code == 200:
            data = response.json()

            if 'results' in data and data['results']:
                for result in data['results']:
                    if 'stix_data' in result:
                        stix_obj = result['stix_data']

                        if 'confidence' in stix_obj:
                            confidence = stix_obj['confidence']

                            # Confidence should be integer between 0-100
                            assert isinstance(confidence, int), "Confidence must be an integer"
                            assert 0 <= confidence <= 100, f"Confidence must be 0-100: {confidence}"

                            print(f"✓ Valid confidence score: {confidence}")

        elif response.status_code == 403:
            pytest.skip("API authentication required")


if __name__ == "__main__":
    # Run STIX compliance tests
    pytest.main([__file__, "-v", "--tb=short", "-s"])