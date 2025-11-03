"""
Enhanced mock data and fixtures for external API dependencies
Provides realistic mock responses for OTX, Abuse.ch, Shodan, and other external services
"""

import json
from datetime import datetime, timezone
from typing import Dict, List, Any


class MockOTXResponse:
    """Mock responses for AlienVault OTX API"""

    @staticmethod
    def get_pulses_response(count: int = 5) -> Dict[str, Any]:
        """Generate mock OTX pulses response"""
        pulses = []
        for i in range(count):
            pulse = {
                "id": f"pulse_id_{i}",
                "name": f"Malicious Activity {i}",
                "description": f"Test threat intelligence pulse {i}",
                "author_name": "test_author",
                "created": (datetime.now(timezone.utc)).isoformat(),
                "modified": (datetime.now(timezone.utc)).isoformat(),
                "TLP": "white",
                "tags": ["malware", "test", f"tag_{i}"],
                "indicators": MockOTXResponse.get_indicators(3),
                "pulse_source": "api",
                "targeted_countries": ["US", "EU"]
            }
            pulses.append(pulse)

        return {
            "count": count,
            "next": None,
            "previous": None,
            "results": pulses
        }

    @staticmethod
    def get_indicators(count: int = 3) -> List[Dict[str, Any]]:
        """Generate mock OTX indicators"""
        indicators = []
        indicator_types = ["IPv4", "domain", "hostname", "URL", "FileHash-SHA256"]

        for i in range(count):
            indicator_type = indicator_types[i % len(indicator_types)]

            if indicator_type == "IPv4":
                indicator_value = f"192.168.{i}.{i+1}"
            elif indicator_type == "domain":
                indicator_value = f"malicious{i}.example.com"
            elif indicator_type == "hostname":
                indicator_value = f"host{i}.malicious.com"
            elif indicator_type == "URL":
                indicator_value = f"http://malicious{i}.com/path"
            else:  # FileHash-SHA256
                indicator_value = f"{'a' * 62}{i:02d}"

            indicator = {
                "id": f"indicator_{i}",
                "indicator": indicator_value,
                "type": indicator_type,
                "created": (datetime.now(timezone.utc)).isoformat(),
                "is_active": 1,
                "role": "",
                "title": "",
                "content": "",
                "access_type": "public",
                "access_reason": "",
                "expiration": None
            }
            indicators.append(indicator)

        return indicators

    @staticmethod
    def get_error_response(error_code: int = 400) -> Dict[str, Any]:
        """Generate mock OTX error response"""
        error_messages = {
            400: "Bad Request",
            401: "Unauthorized - Invalid API key",
            403: "Forbidden - Access denied",
            429: "Rate limit exceeded",
            500: "Internal server error"
        }

        return {
            "error": error_messages.get(error_code, "Unknown error"),
            "status_code": error_code
        }


class MockAbuseCHResponse:
    """Mock responses for Abuse.ch URLhaus API"""

    @staticmethod
    def get_urls_recent_response(count: int = 5) -> Dict[str, Any]:
        """Generate mock Abuse.ch recent URLs response"""
        urls = []
        for i in range(count):
            url_data = {
                "id": str(i + 1000),
                "urlhaus_reference": f"https://urlhaus.abuse.ch/url/{i + 1000}/",
                "url": f"http://malicious{i}.example.com/payload.exe",
                "url_status": "online",
                "host": f"malicious{i}.example.com",
                "date_added": (datetime.now(timezone.utc)).strftime("%Y-%m-%d %H:%M:%S UTC"),
                "threat": "malware_download",
                "blacklists": {
                    "surbl": "not listed",
                    "spamhaus_dbl": "not listed"
                },
                "reporter": f"test_reporter_{i}",
                "larted": "true",
                "takedown_time_seconds": None,
                "tags": ["exe", "malware", f"tag_{i}"]
            }
            urls.append(url_data)

        return {
            "query_status": "ok",
            "urls": urls
        }

    @staticmethod
    def get_error_response(error_type: str = "invalid_request") -> Dict[str, Any]:
        """Generate mock Abuse.ch error response"""
        error_responses = {
            "invalid_request": {
                "query_status": "invalid_request",
                "error": "Invalid request parameters"
            },
            "no_results": {
                "query_status": "no_results",
                "urls": []
            },
            "rate_limit": {
                "query_status": "rate_limit_exceeded",
                "error": "Rate limit exceeded"
            }
        }

        return error_responses.get(error_type, {"query_status": "error"})


class MockShodanResponse:
    """Mock responses for Shodan API"""

    @staticmethod
    def get_host_info_response(ip: str = "192.168.1.1") -> Dict[str, Any]:
        """Generate mock Shodan host info response"""
        return {
            "ip": ip,
            "hostnames": [f"host.example.com"],
            "country_code": "US",
            "country_name": "United States",
            "city": "Test City",
            "region_code": "CA",
            "area_code": None,
            "latitude": 37.4419,
            "longitude": -122.1419,
            "postal_code": "94043",
            "dma_code": 807,
            "asn": "AS15169",
            "org": "Google LLC",
            "isp": "Google LLC",
            "last_update": (datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%S.%f"),
            "ports": [22, 80, 443],
            "tags": ["cloud"],
            "vulns": ["CVE-2021-44228"],
            "data": [
                {
                    "port": 80,
                    "banner": "HTTP/1.1 200 OK\\r\\nServer: nginx/1.18.0",
                    "timestamp": (datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%S.%f"),
                    "product": "nginx",
                    "version": "1.18.0",
                    "cpe": ["cpe:/a:nginx:nginx:1.18.0"]
                }
            ]
        }

    @staticmethod
    def get_error_response(error_type: str = "invalid_ip") -> Dict[str, Any]:
        """Generate mock Shodan error response"""
        error_responses = {
            "invalid_ip": {
                "error": "Invalid IP address"
            },
            "no_information": {
                "error": "No information available for this IP address"
            },
            "rate_limit": {
                "error": "Request rate limit reached"
            },
            "unauthorized": {
                "error": "Access denied"
            }
        }

        return error_responses.get(error_type, {"error": "Unknown error"})


class MockDNSResponse:
    """Mock responses for DNS queries"""

    @staticmethod
    def get_dns_resolution_response(domain: str = "example.com") -> Dict[str, Any]:
        """Generate mock DNS resolution response"""
        return {
            "domain": domain,
            "a_records": ["192.0.2.1", "192.0.2.2"],
            "aaaa_records": ["2001:db8::1"],
            "mx_records": [
                {"preference": 10, "exchange": f"mail.{domain}"},
                {"preference": 20, "exchange": f"mail2.{domain}"}
            ],
            "ns_records": [f"ns1.{domain}", f"ns2.{domain}"],
            "txt_records": [
                "v=spf1 include:_spf.google.com ~all",
                "google-site-verification=abc123"
            ],
            "cname_record": None,
            "ttl": 300,
            "timestamp": (datetime.now(timezone.utc)).isoformat()
        }

    @staticmethod
    def get_error_response(error_type: str = "nxdomain") -> Dict[str, Any]:
        """Generate mock DNS error response"""
        error_responses = {
            "nxdomain": {
                "error": "Domain not found",
                "rcode": "NXDOMAIN"
            },
            "timeout": {
                "error": "DNS query timeout",
                "rcode": "TIMEOUT"
            },
            "servfail": {
                "error": "Server failure",
                "rcode": "SERVFAIL"
            }
        }

        return error_responses.get(error_type, {"error": "DNS query failed"})


class MockGeolocationResponse:
    """Mock responses for IP geolocation services"""

    @staticmethod
    def get_geolocation_response(ip: str = "192.0.2.1") -> Dict[str, Any]:
        """Generate mock geolocation response"""
        return {
            "ip": ip,
            "country": "United States",
            "country_code": "US",
            "region": "California",
            "region_code": "CA",
            "city": "Mountain View",
            "zip": "94043",
            "latitude": 37.4056,
            "longitude": -122.0775,
            "timezone": "America/Los_Angeles",
            "isp": "Google LLC",
            "org": "Google LLC",
            "as": "AS15169 Google LLC",
            "as_name": "Google LLC",
            "mobile": False,
            "proxy": False,
            "hosting": True,
            "accuracy_radius": 1000
        }

    @staticmethod
    def get_error_response(error_type: str = "invalid_ip") -> Dict[str, Any]:
        """Generate mock geolocation error response"""
        error_responses = {
            "invalid_ip": {
                "error": "Invalid IP address format"
            },
            "private_ip": {
                "error": "Private IP address - no geolocation data available"
            },
            "no_data": {
                "error": "No geolocation data available for this IP"
            }
        }

        return error_responses.get(error_type, {"error": "Geolocation query failed"})


class MockSTIXResponse:
    """Mock STIX 2.1 formatted responses"""

    @staticmethod
    def get_stix_indicator(indicator_value: str, indicator_type: str) -> Dict[str, Any]:
        """Generate mock STIX 2.1 indicator object"""

        # Map indicator types to STIX patterns
        pattern_mapping = {
            "ipv4": f"[ipv4-addr:value = '{indicator_value}']",
            "domain": f"[domain-name:value = '{indicator_value}']",
            "url": f"[url:value = '{indicator_value}']",
            "file": f"[file:hashes.SHA256 = '{indicator_value}']",
            "email": f"[email-addr:value = '{indicator_value}']"
        }

        pattern = pattern_mapping.get(indicator_type.lower(), f"[{indicator_type}:value = '{indicator_value}']")

        return {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{hash(indicator_value) & 0x7fffffff:08x}-1234-5678-9abc-def012345678",
            "created": (datetime.now(timezone.utc)).isoformat(),
            "modified": (datetime.now(timezone.utc)).isoformat(),
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": (datetime.now(timezone.utc)).isoformat(),
            "labels": ["malicious-activity"],
            "confidence": 85,
            "external_references": [
                {
                    "source_name": "test-source",
                    "url": f"https://test-source.com/indicator/{hash(indicator_value) & 0x7fffffff}",
                    "description": "Test threat intelligence source"
                }
            ],
            "object_marking_refs": ["marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"]
        }

    @staticmethod
    def get_stix_bundle(indicators: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate mock STIX 2.1 bundle containing multiple indicators"""
        return {
            "type": "bundle",
            "id": f"bundle--{hash(str(indicators)) & 0x7fffffff:08x}-1234-5678-9abc-def012345678",
            "spec_version": "2.1",
            "objects": indicators
        }


# Export commonly used mock data instances
MOCK_OTX_PULSES = MockOTXResponse.get_pulses_response(10)
MOCK_ABUSE_CH_URLS = MockAbuseCHResponse.get_urls_recent_response(10)
MOCK_SHODAN_HOST = MockShodanResponse.get_host_info_response("192.168.1.100")
MOCK_DNS_DATA = MockDNSResponse.get_dns_resolution_response("malicious.example.com")
MOCK_GEOLOCATION = MockGeolocationResponse.get_geolocation_response("192.168.1.100")

# Common test indicators
TEST_INDICATORS = {
    "ipv4": ["192.168.1.100", "10.0.0.1", "203.0.113.5"],
    "domain": ["malicious.example.com", "test-threat.com", "evil-domain.net"],
    "url": ["http://malicious.example.com/payload", "https://test-threat.com/download"],
    "hash": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]
}

# Error scenarios for testing
ERROR_SCENARIOS = {
    "network_timeout": {"type": "timeout", "message": "Connection timed out"},
    "rate_limit": {"type": "rate_limit", "message": "Rate limit exceeded"},
    "authentication_failed": {"type": "auth_error", "message": "Invalid API key"},
    "service_unavailable": {"type": "service_error", "message": "Service temporarily unavailable"},
    "malformed_response": {"type": "parse_error", "message": "Invalid response format"}
}