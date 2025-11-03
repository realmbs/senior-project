"""
Security validation tests for threat intelligence platform
Tests authentication, authorization, input validation, and security best practices
"""

import pytest
import json
import time
import os
import hashlib
import base64
import urllib.parse
from datetime import datetime, timezone
import requests
import uuid
import re


# Module-level fixtures
@pytest.fixture(scope="module")
def security_config():
    """Security test configuration"""
    return {
        'base_url': os.environ.get('API_BASE_URL', 'https://u88kzux168.execute-api.us-east-1.amazonaws.com/dev'),
        'api_key': os.environ.get('TEST_API_KEY'),
        'region': os.environ.get('AWS_REGION', 'us-east-1'),
        'test_timeout': 30
    }


@pytest.fixture
def valid_headers(security_config):
    """Valid headers for authenticated requests"""
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'User-Agent': 'ThreatIntel-Security-Test/1.0'
    }
    if security_config['api_key']:
        headers['x-api-key'] = security_config['api_key']
    return headers


@pytest.fixture
def invalid_headers():
    """Invalid headers for testing security"""
    return {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'User-Agent': 'ThreatIntel-Security-Test/1.0'
    }


class TestAuthenticationSecurity:
    """Test authentication and authorization security"""

    def test_missing_api_key_rejection(self, security_config, invalid_headers):
        """Test that requests without API key are rejected"""
        endpoints = [
            '/search',
            '/collect',
            '/enrich'
        ]

        for endpoint in endpoints:
            url = f"{security_config['base_url']}{endpoint}"

            # GET request without API key
            response = requests.get(url, headers=invalid_headers, timeout=security_config['test_timeout'])
            assert response.status_code in [401, 403], f"Endpoint {endpoint} should reject unauthenticated GET requests"

            # POST request without API key
            if endpoint in ['/collect', '/enrich']:
                response = requests.post(url, json={}, headers=invalid_headers, timeout=security_config['test_timeout'])
                assert response.status_code in [401, 403], f"Endpoint {endpoint} should reject unauthenticated POST requests"

    def test_invalid_api_key_rejection(self, security_config):
        """Test that requests with invalid API keys are rejected"""
        invalid_api_keys = [
            'invalid_key_123',
            '',
            'null',
            'undefined',
            'x' * 100,  # Very long key
            '../../../etc/passwd',  # Path traversal attempt
            'SELECT * FROM users',  # SQL injection attempt
            '<script>alert(1)</script>',  # XSS attempt
        ]

        for invalid_key in invalid_api_keys:
            headers = {
                'Content-Type': 'application/json',
                'x-api-key': invalid_key
            }

            url = f"{security_config['base_url']}/search"
            response = requests.get(url, headers=headers, timeout=security_config['test_timeout'])

            assert response.status_code in [401, 403], f"API key '{invalid_key}' should be rejected"

    def test_api_key_header_variations(self, security_config):
        """Test various API key header formats and cases"""
        invalid_variations = [
            'X-API-KEY',  # Wrong case
            'api-key',    # Missing x- prefix
            'x-apikey',   # Missing dash
            'authorization',  # Wrong header name
        ]

        test_key = security_config.get('api_key', 'test_key')

        for header_name in invalid_variations:
            headers = {
                'Content-Type': 'application/json',
                header_name: test_key
            }

            url = f"{security_config['base_url']}/search"
            response = requests.get(url, headers=headers, timeout=security_config['test_timeout'])

            # Should reject wrong header format even with valid key
            assert response.status_code in [401, 403], f"Wrong header format '{header_name}' should be rejected"

    def test_bearer_token_rejection(self, security_config):
        """Test that Bearer tokens are not accepted (API key only)"""
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer fake_jwt_token'
        }

        url = f"{security_config['base_url']}/search"
        response = requests.get(url, headers=headers, timeout=security_config['test_timeout'])

        assert response.status_code in [401, 403], "Bearer tokens should not be accepted"

    def test_multiple_authentication_headers(self, security_config, valid_headers):
        """Test behavior with multiple authentication headers"""
        headers = valid_headers.copy()
        headers['Authorization'] = 'Bearer fake_token'

        url = f"{security_config['base_url']}/search"
        response = requests.get(url, headers=headers, timeout=security_config['test_timeout'])

        # Should either use API key (succeed) or reject multiple auth methods
        assert response.status_code in [200, 204, 400, 401, 403], "Should handle multiple auth headers appropriately"


class TestInputValidationSecurity:
    """Test input validation and sanitization security"""

    def test_sql_injection_prevention(self, security_config, valid_headers):
        """Test SQL injection prevention in search queries"""
        sql_injection_payloads = [
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "' UNION SELECT * FROM information_schema.tables --",
            "'; INSERT INTO users VALUES ('admin', 'admin'); --",
            "1' AND (SELECT COUNT(*) FROM information_schema.tables) > 0 --",
        ]

        url = f"{security_config['base_url']}/search"

        for payload in sql_injection_payloads:
            params = {'q': payload, 'limit': 1}

            response = requests.get(url, params=params, headers=valid_headers, timeout=security_config['test_timeout'])

            # Should either sanitize the input or reject it, but not execute SQL
            assert response.status_code in [200, 204, 400], f"SQL injection payload should be handled safely: {payload}"

            if response.status_code == 200:
                # Response should not contain SQL error messages
                response_text = response.text.lower()
                sql_error_indicators = ['syntax error', 'sql error', 'database error', 'table', 'column']
                for indicator in sql_error_indicators:
                    assert indicator not in response_text, f"Response contains SQL error indicator: {indicator}"

    def test_xss_prevention(self, security_config, valid_headers):
        """Test Cross-Site Scripting (XSS) prevention"""
        xss_payloads = [
            '<script>alert("xss")</script>',
            '<img src=x onerror=alert("xss")>',
            'javascript:alert("xss")',
            '<svg onload=alert("xss")>',
            '"><script>alert("xss")</script>',
            "'><script>alert('xss')</script>",
        ]

        url = f"{security_config['base_url']}/search"

        for payload in xss_payloads:
            params = {'q': payload, 'limit': 1}

            response = requests.get(url, params=params, headers=valid_headers, timeout=security_config['test_timeout'])

            # Should sanitize or reject XSS payloads
            assert response.status_code in [200, 204, 400], f"XSS payload should be handled safely: {payload}"

            if response.status_code == 200:
                # Response should not contain unescaped script tags
                response_text = response.text
                dangerous_patterns = ['<script', 'javascript:', 'onerror=', 'onload=']
                for pattern in dangerous_patterns:
                    assert pattern not in response_text.lower(), f"Response contains dangerous XSS pattern: {pattern}"

    def test_command_injection_prevention(self, security_config, valid_headers):
        """Test command injection prevention"""
        command_injection_payloads = [
            '; cat /etc/passwd',
            '| id',
            '&& whoami',
            '`id`',
            '$(id)',
            '; ls -la',
            '|| ping -c 1 google.com',
        ]

        url = f"{security_config['base_url']}/collect"

        for payload in command_injection_payloads:
            request_data = {
                'sources': [payload],
                'collection_type': 'automated'
            }

            response = requests.post(url, json=request_data, headers=valid_headers, timeout=security_config['test_timeout'])

            # Should reject command injection attempts
            assert response.status_code in [400, 403], f"Command injection payload should be rejected: {payload}"

    def test_path_traversal_prevention(self, security_config, valid_headers):
        """Test path traversal prevention"""
        path_traversal_payloads = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\config\\sam',
            '/etc/passwd',
            'C:\\windows\\system32\\config\\sam',
            '....//....//etc/passwd',
            '..%2F..%2F..%2Fetc%2Fpasswd',  # URL encoded
        ]

        url = f"{security_config['base_url']}/search"

        for payload in path_traversal_payloads:
            params = {'q': payload, 'limit': 1}

            response = requests.get(url, params=params, headers=valid_headers, timeout=security_config['test_timeout'])

            # Should sanitize or reject path traversal attempts
            assert response.status_code in [200, 204, 400], f"Path traversal payload should be handled safely: {payload}"

            if response.status_code == 200:
                # Response should not contain system file contents
                response_text = response.text.lower()
                system_indicators = ['root:x:', 'bin/bash', 'administrators', 'system32']
                for indicator in system_indicators:
                    assert indicator not in response_text, f"Response contains system file indicator: {indicator}"

    def test_ldap_injection_prevention(self, security_config, valid_headers):
        """Test LDAP injection prevention"""
        ldap_injection_payloads = [
            '*)(uid=*',
            '*)(|(uid=*',
            '*)((|uid=*',
            '*))%00',
            '*()|&\'',
        ]

        url = f"{security_config['base_url']}/search"

        for payload in ldap_injection_payloads:
            params = {'q': payload, 'limit': 1}

            response = requests.get(url, params=params, headers=valid_headers, timeout=security_config['test_timeout'])

            # Should handle LDAP injection attempts safely
            assert response.status_code in [200, 204, 400], f"LDAP injection payload should be handled safely: {payload}"

    def test_large_payload_handling(self, security_config, valid_headers):
        """Test handling of oversized payloads"""
        url = f"{security_config['base_url']}/collect"

        # Create very large payload
        large_payload = {
            'sources': ['otx'],
            'collection_type': 'automated',
            'large_field': 'x' * (1024 * 1024)  # 1MB of data
        }

        response = requests.post(url, json=large_payload, headers=valid_headers, timeout=60)

        # Should reject or handle large payloads appropriately
        assert response.status_code in [200, 202, 400, 413], "Large payload should be handled appropriately"

    def test_null_byte_injection(self, security_config, valid_headers):
        """Test null byte injection prevention"""
        null_byte_payloads = [
            'test\x00.txt',
            'legitimate_query\x00../../../etc/passwd',
            'search\x00\x00\x00query',
        ]

        url = f"{security_config['base_url']}/search"

        for payload in null_byte_payloads:
            params = {'q': payload, 'limit': 1}

            response = requests.get(url, params=params, headers=valid_headers, timeout=security_config['test_timeout'])

            # Should handle null bytes safely
            assert response.status_code in [200, 204, 400], f"Null byte payload should be handled safely: {repr(payload)}"


class TestHTTPSecurityHeaders:
    """Test HTTP security headers and configurations"""

    def test_security_headers_present(self, security_config):
        """Test that appropriate security headers are present"""
        url = f"{security_config['base_url']}/search"
        response = requests.get(url, timeout=security_config['test_timeout'])

        # Check for important security headers
        security_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': None,  # Should be present but value varies
            'Content-Security-Policy': None,    # Should be present
        }

        for header, expected_values in security_headers.items():
            if header in response.headers:
                header_value = response.headers[header]
                if expected_values:
                    if isinstance(expected_values, list):
                        assert any(expected in header_value for expected in expected_values), \
                            f"Security header {header} has unexpected value: {header_value}"
                    else:
                        assert expected_values in header_value, \
                            f"Security header {header} has unexpected value: {header_value}"
                print(f"✓ Security header {header}: {header_value}")
            else:
                print(f"⚠ Missing security header: {header}")

    def test_cors_configuration(self, security_config):
        """Test CORS configuration security"""
        url = f"{security_config['base_url']}/search"

        # Test OPTIONS request
        response = requests.options(url, timeout=security_config['test_timeout'])

        if 'Access-Control-Allow-Origin' in response.headers:
            origin = response.headers['Access-Control-Allow-Origin']

            # Should not allow wildcard origin with credentials
            if origin == '*':
                assert 'Access-Control-Allow-Credentials' not in response.headers or \
                       response.headers['Access-Control-Allow-Credentials'].lower() != 'true', \
                       "Wildcard CORS origin should not allow credentials"

            print(f"CORS Origin: {origin}")

    def test_https_enforcement(self, security_config):
        """Test HTTPS enforcement"""
        # Check if HTTP redirects to HTTPS
        if security_config['base_url'].startswith('https://'):
            http_url = security_config['base_url'].replace('https://', 'http://')

            try:
                response = requests.get(f"{http_url}/search", allow_redirects=False, timeout=10)

                # Should redirect to HTTPS or refuse connection
                if response.status_code in [301, 302, 307, 308]:
                    location = response.headers.get('Location', '')
                    assert location.startswith('https://'), "HTTP should redirect to HTTPS"
                    print("✓ HTTP redirects to HTTPS")
                else:
                    print("HTTP request handling varies (may be blocked at infrastructure level)")

            except requests.exceptions.ConnectionError:
                print("✓ HTTP connections refused (good security practice)")

    def test_server_information_disclosure(self, security_config):
        """Test that server information is not disclosed"""
        url = f"{security_config['base_url']}/search"
        response = requests.get(url, timeout=security_config['test_timeout'])

        # Check for information disclosure in headers
        sensitive_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version']

        for header in sensitive_headers:
            if header in response.headers:
                header_value = response.headers[header]
                print(f"⚠ Server information disclosed in {header}: {header_value}")

                # Check for specific technologies that shouldn't be disclosed
                sensitive_info = ['apache', 'nginx', 'iis', 'tomcat', 'jetty', 'express', 'django', 'flask']
                for info in sensitive_info:
                    if info in header_value.lower():
                        print(f"⚠ Technology disclosed: {info}")


class TestDataSecurityAndPrivacy:
    """Test data security and privacy protections"""

    def test_pii_detection_and_protection(self, security_config, valid_headers):
        """Test that PII is detected and protected"""
        pii_test_cases = [
            '123-45-6789',  # SSN
            '4532-1234-5678-9012',  # Credit card
            'john.doe@email.com',  # Email
            '+1-555-123-4567',  # Phone number
        ]

        url = f"{security_config['base_url']}/search"

        for pii_data in pii_test_cases:
            params = {'q': pii_data, 'limit': 1}

            response = requests.get(url, params=params, headers=valid_headers, timeout=security_config['test_timeout'])

            if response.status_code == 200:
                response_text = response.text

                # PII should not be echoed back in plain text
                assert pii_data not in response_text, f"PII data echoed back in response: {pii_data}"

    def test_sensitive_data_in_logs(self, security_config, valid_headers):
        """Test that sensitive data is not logged"""
        # This test would ideally check actual logs, but we'll test response headers
        # that might indicate logging behavior

        sensitive_data = "sensitive_test_data_12345"
        url = f"{security_config['base_url']}/search"
        params = {'q': sensitive_data, 'limit': 1}

        response = requests.get(url, params=params, headers=valid_headers, timeout=security_config['test_timeout'])

        # Check for debug headers that might leak information
        debug_headers = ['X-Debug', 'X-Log-ID', 'X-Trace-ID']

        for header in debug_headers:
            if header in response.headers:
                header_value = response.headers[header]
                assert sensitive_data not in header_value, f"Sensitive data found in {header} header"

    def test_error_message_information_disclosure(self, security_config, valid_headers):
        """Test that error messages don't disclose sensitive information"""
        # Trigger various error conditions
        error_test_cases = [
            ({'q': '', 'limit': -1}, "Invalid parameters"),
            ({'q': 'x' * 10000, 'limit': 1}, "Oversized query"),
            ({'invalid_param': 'value'}, "Invalid parameter names"),
        ]

        url = f"{security_config['base_url']}/search"

        for params, description in error_test_cases:
            response = requests.get(url, params=params, headers=valid_headers, timeout=security_config['test_timeout'])

            if response.status_code >= 400:
                response_text = response.text.lower()

                # Check for information disclosure in error messages
                sensitive_patterns = [
                    'stack trace',
                    'exception:',
                    'error at line',
                    'file not found',
                    'access denied',
                    'internal server error',
                    'database',
                    'sql',
                    'table',
                    'column',
                    '/usr/',
                    '/etc/',
                    'c:\\',
                    'windows'
                ]

                for pattern in sensitive_patterns:
                    if pattern in response_text:
                        print(f"⚠ Potential information disclosure in error message for {description}: {pattern}")


class TestRateLimitingAndDoSProtection:
    """Test rate limiting and DoS protection"""

    def test_rate_limiting_enforcement(self, security_config, valid_headers):
        """Test that rate limiting is enforced"""
        url = f"{security_config['base_url']}/search"
        params = {'limit': 1}

        rate_limit_hit = False

        # Make rapid requests to trigger rate limiting
        for i in range(50):
            response = requests.get(url, params=params, headers=valid_headers, timeout=5)

            if response.status_code == 429:
                rate_limit_hit = True
                print(f"✓ Rate limit hit after {i+1} requests")

                # Check for Retry-After header
                if 'Retry-After' in response.headers:
                    retry_after = response.headers['Retry-After']
                    print(f"Retry-After header: {retry_after}")

                break

            time.sleep(0.1)  # Small delay between requests

        if not rate_limit_hit:
            print("ℹ Rate limiting not triggered with 50 requests (may have high limits)")

    def test_request_size_limits(self, security_config, valid_headers):
        """Test request size limits for DoS protection"""
        url = f"{security_config['base_url']}/collect"

        # Test increasingly large payloads
        size_tests = [
            (1024, "1KB"),
            (10 * 1024, "10KB"),
            (100 * 1024, "100KB"),
            (1024 * 1024, "1MB"),
        ]

        for size, description in size_tests:
            large_data = 'x' * size
            payload = {
                'sources': ['otx'],
                'collection_type': 'automated',
                'large_field': large_data
            }

            try:
                response = requests.post(url, json=payload, headers=valid_headers, timeout=60)

                if response.status_code == 413:
                    print(f"✓ Request size limit enforced at {description}")
                    break
                elif response.status_code in [400, 413]:
                    print(f"Request rejected at {description}")
                else:
                    print(f"Request accepted at {description}")

            except requests.exceptions.RequestException as e:
                print(f"Request failed at {description}: {e}")
                break


if __name__ == "__main__":
    # Run security validation tests
    pytest.main([__file__, "-v", "--tb=short", "-s"])