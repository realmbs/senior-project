# Threat Intelligence Platform - Comprehensive Testing Guide

## 📋 Overview

This guide provides comprehensive information about the testing suite for the Threat Intelligence Platform. The testing framework is designed to validate all aspects of the platform including functionality, performance, security, and compliance with STIX 2.1 standards.

## 🏗️ Testing Architecture

### Test Categories

1. **Unit Tests** - Test individual components in isolation with mocked dependencies
2. **Integration Tests** - Test API endpoints and data flow with live infrastructure
3. **End-to-End Tests** - Test complete pipeline from collection to retrieval
4. **Performance Tests** - Validate response times, throughput, and scalability
5. **Security Tests** - Validate authentication, input sanitization, and security headers
6. **Compliance Tests** - Ensure STIX 2.1 format compliance

### Directory Structure

```
tests/
├── unit/                           # Unit tests
│   ├── test_collector.py          # Collector Lambda tests
│   ├── test_processor.py          # Processor Lambda tests
│   ├── test_enrichment.py         # Enrichment Lambda tests
│   ├── test_error_handling.py     # Enhanced error handling tests
│   └── test_enhanced_mocking.py   # Enhanced mocking tests
├── integration/                    # Integration tests
│   ├── test_api_endpoints.py      # Basic API endpoint tests
│   ├── test_enhanced_api_endpoints.py # Enhanced API tests
│   ├── test_end_to_end_data_flow.py   # E2E pipeline tests
│   ├── test_performance.py        # Basic performance tests
│   └── test_enhanced_performance.py   # Comprehensive performance tests
├── security/                      # Security tests
│   └── test_security_validation.py    # Security validation tests
├── compliance/                    # Compliance tests
│   └── test_stix_compliance.py    # STIX 2.1 compliance tests
├── fixtures/                      # Test data and mocks
│   └── enhanced_mock_data.py      # Enhanced mock responses
├── reports/                       # Test execution reports
├── conftest.py                    # Pytest configuration
├── pytest.ini                    # Pytest settings
├── requirements.txt               # Testing dependencies
├── run_tests.py                   # Test execution script
├── test_infrastructure_connectivity.py # Infrastructure validation
├── README.md                      # Basic testing documentation
├── TESTING_GUIDE.md              # This comprehensive guide
└── .env.test                      # Test environment configuration
```

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- AWS CLI configured with appropriate credentials
- API Gateway endpoint deployed and accessible

### Installation

1. **Install Dependencies**
   ```bash
   cd tests
   pip install -r requirements.txt
   ```

2. **Configure Environment**
   ```bash
   export API_BASE_URL="https://your-api-gateway-url/dev"
   export TEST_API_KEY="your-api-key"
   export AWS_REGION="us-east-1"
   ```

3. **Verify Setup**
   ```bash
   python run_tests.py --setup-only
   ```

### Running Tests

#### Using the Test Runner Script

```bash
# Run unit tests only
python run_tests.py unit

# Run integration tests
python run_tests.py integration

# Run performance tests with custom settings
python run_tests.py performance --concurrent-users 5 --duration 60

# Run security tests
python run_tests.py security

# Run STIX compliance tests
python run_tests.py compliance

# Run all tests
python run_tests.py all

# Run tests with coverage
python run_tests.py unit --coverage

# Run specific test pattern
python run_tests.py unit --pattern "test_collector"
```

#### Using Pytest Directly

```bash
# Unit tests
pytest unit/ -v

# Integration tests (requires API credentials)
pytest integration/ -v --tb=short

# Performance tests
CONCURRENT_USERS=3 pytest integration/test_enhanced_performance.py -v

# Security tests
pytest security/ -v

# Compliance tests
pytest compliance/ -v

# Infrastructure connectivity
pytest test_infrastructure_connectivity.py -v
```

## 📊 Test Categories Detail

### Unit Tests

**Purpose**: Test individual Lambda functions and components in isolation

**Location**: `tests/unit/`

**Key Features**:
- Mock AWS services using moto
- Test error handling scenarios
- Validate data processing logic
- Pattern hashing and deduplication
- STIX object creation

**Examples**:
```bash
# Test collector functionality
pytest unit/test_collector.py::TestPatternHashing -v

# Test error handling
pytest unit/test_error_handling.py::TestCollectorErrorHandling -v

# Test enhanced mocking
pytest unit/test_enhanced_mocking.py::TestEnhancedOTXMocking -v
```

### Integration Tests

**Purpose**: Test API endpoints with live infrastructure

**Location**: `tests/integration/`

**Key Features**:
- Real API Gateway testing
- Authentication validation
- Data flow verification
- CORS and security headers
- Rate limiting detection

**Examples**:
```bash
# Basic API endpoint tests
pytest integration/test_api_endpoints.py::TestCollectEndpoint -v

# Enhanced API tests
pytest integration/test_enhanced_api_endpoints.py::TestEnhancedAPIConfiguration -v

# End-to-end data flow
pytest integration/test_end_to_end_data_flow.py::TestCompleteDataPipeline -v
```

### Performance Tests

**Purpose**: Validate system performance and scalability

**Location**: `tests/integration/test_enhanced_performance.py`

**Key Features**:
- Response time measurement
- Concurrent load testing
- Resource utilization monitoring
- Throughput analysis
- Performance grading

**Configuration**:
```bash
# Environment variables for performance tests
export CONCURRENT_USERS=5
export LOAD_TEST_DURATION=60
export MAX_RESPONSE_TIME=10.0
export MIN_SUCCESS_RATE=0.95
```

**Examples**:
```bash
# Baseline performance
pytest integration/test_enhanced_performance.py::TestBaselinePerformance -v

# Scalability tests
pytest integration/test_enhanced_performance.py::TestScalabilityAndLoad -v

# Resource utilization
pytest integration/test_enhanced_performance.py::TestResourceUtilization -v
```

### Security Tests

**Purpose**: Validate security controls and protections

**Location**: `tests/security/test_security_validation.py`

**Key Features**:
- Authentication bypass attempts
- Input validation testing
- SQL injection prevention
- XSS protection validation
- Command injection prevention
- Security header verification

**Examples**:
```bash
# Authentication security
pytest security/test_security_validation.py::TestAuthenticationSecurity -v

# Input validation security
pytest security/test_security_validation.py::TestInputValidationSecurity -v

# HTTP security headers
pytest security/test_security_validation.py::TestHTTPSecurityHeaders -v
```

### Compliance Tests

**Purpose**: Ensure STIX 2.1 format compliance

**Location**: `tests/compliance/test_stix_compliance.py`

**Key Features**:
- STIX object structure validation
- Timestamp format verification
- Pattern syntax validation
- Label compliance checking
- Relationship validation

**Examples**:
```bash
# Basic STIX compliance
pytest compliance/test_stix_compliance.py::TestSTIXBasicCompliance -v

# Indicator compliance
pytest compliance/test_stix_compliance.py::TestSTIXIndicatorCompliance -v

# Bundle compliance
pytest compliance/test_stix_compliance.py::TestSTIXBundleCompliance -v
```

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `API_BASE_URL` | Base URL for API endpoints | - | Yes for integration tests |
| `TEST_API_KEY` | API key for authentication | - | Yes for integration tests |
| `AWS_REGION` | AWS region | us-east-1 | No |
| `CONCURRENT_USERS` | Concurrent users for load tests | 5 | No |
| `LOAD_TEST_DURATION` | Load test duration (seconds) | 60 | No |
| `MAX_RESPONSE_TIME` | Max acceptable response time | 10.0 | No |
| `MIN_SUCCESS_RATE` | Min acceptable success rate | 0.95 | No |

### Pytest Configuration

Key pytest markers:
- `unit` - Unit tests
- `integration` - Integration tests requiring live infrastructure
- `performance` - Performance and load tests
- `security` - Security validation tests
- `compliance` - STIX compliance tests
- `slow` - Tests taking longer than 30 seconds

## 📈 CI/CD Integration

### GitHub Actions Workflow

The platform includes a comprehensive GitHub Actions workflow (`.github/workflows/test-automation.yml`) that:

- Runs different test suites based on trigger (push, PR, schedule)
- Supports manual execution with test level selection
- Generates test reports and artifacts
- Provides PR comments with test results
- Sends notifications for failures

### Workflow Triggers

1. **Push to main/develop**: Runs integration tests
2. **Pull Request**: Runs unit tests with PR comments
3. **Daily Schedule**: Runs full test suite
4. **Manual Dispatch**: Runs selected test level

### Test Execution Matrix

The workflow uses matrix strategies for parallel execution:

```yaml
strategy:
  matrix:
    test-group: [collector, processor, enrichment, error-handling, mocking]
```

## 📊 Test Reports

### Report Generation

Tests generate multiple report formats:

1. **JSON Reports**: Machine-readable test results
2. **HTML Reports**: Human-readable test summaries
3. **Coverage Reports**: Code coverage analysis
4. **Performance Reports**: Performance metrics and analysis

### Report Locations

- `tests/reports/` - JSON test reports
- `tests/htmlcov/` - HTML coverage reports
- `tests/test_summary.html` - Comprehensive test summary

### Accessing Reports

```bash
# Generate all reports
python run_tests.py all

# View HTML coverage report
open tests/htmlcov/index.html

# View test summary
open tests/test_summary.html
```

## 🐛 Troubleshooting

### Common Issues

1. **Import Errors**
   ```bash
   # Missing dependencies
   pip install -r requirements.txt

   # Environment variables not set
   export API_BASE_URL="your-url"
   export TEST_API_KEY="your-key"
   ```

2. **Authentication Failures**
   ```bash
   # Check API key
   curl -H "x-api-key: $TEST_API_KEY" "$API_BASE_URL/search?limit=1"

   # Verify AWS credentials
   aws sts get-caller-identity
   ```

3. **Timeout Issues**
   ```bash
   # Increase timeout for slow tests
   pytest --timeout=600 integration/

   # Run with reduced concurrency
   CONCURRENT_USERS=2 pytest integration/test_enhanced_performance.py
   ```

4. **Infrastructure Issues**
   ```bash
   # Test connectivity
   pytest test_infrastructure_connectivity.py -v

   # Check specific services
   aws dynamodb list-tables
   aws lambda list-functions
   ```

### Debug Mode

```bash
# Run with detailed output
pytest -v -s --tb=long

# Enable request logging
pytest -v -s --log-cli-level=DEBUG

# Run single test with debugging
pytest security/test_security_validation.py::TestAuthenticationSecurity::test_missing_api_key_rejection -v -s
```

## 📋 Best Practices

### Writing Tests

1. **Use descriptive test names**
   ```python
   def test_api_rejects_requests_without_authentication(self):
   ```

2. **Follow AAA pattern** (Arrange, Act, Assert)
   ```python
   def test_indicator_pattern_validation(self):
       # Arrange
       indicator = "192.168.1.1"
       indicator_type = "ipv4"

       # Act
       result = create_pattern_hash(indicator, indicator_type)

       # Assert
       assert len(result) == 64
   ```

3. **Use appropriate markers**
   ```python
   @pytest.mark.integration
   @pytest.mark.slow
   def test_large_dataset_processing(self):
   ```

### Test Maintenance

1. **Keep tests independent** - Each test should be able to run in isolation
2. **Use fixtures for setup** - Centralize common setup code
3. **Mock external dependencies** - Use moto for AWS services
4. **Validate error scenarios** - Test both success and failure paths
5. **Update test data regularly** - Keep mock data realistic and current

### Performance Considerations

1. **Limit concurrent users** in CI/CD environments
2. **Use shorter durations** for development testing
3. **Skip slow tests** during development with `pytest -m "not slow"`
4. **Monitor resource usage** during performance tests

## 🔄 Continuous Improvement

### Metrics to Monitor

1. **Test Coverage**: Aim for >85% code coverage
2. **Test Execution Time**: Monitor and optimize slow tests
3. **Flaky Tests**: Identify and fix unreliable tests
4. **Security Coverage**: Ensure comprehensive security testing

### Adding New Tests

When adding new functionality:

1. **Add unit tests** for new functions/methods
2. **Add integration tests** for new API endpoints
3. **Update performance tests** for new features that affect performance
4. **Add security tests** for new inputs/endpoints
5. **Update compliance tests** for STIX-related changes

## 📞 Support and Contribution

### Getting Help

1. **Check this guide** for common scenarios
2. **Review test output** for specific error messages
3. **Check environment setup** with `python run_tests.py --setup-only`
4. **Run infrastructure tests** to validate connectivity

### Contributing

When contributing new tests:

1. Follow existing patterns and conventions
2. Add appropriate markers and documentation
3. Ensure tests are reliable and repeatable
4. Update this guide for new test categories
5. Test your changes in multiple environments

---

## 🎯 Summary

This comprehensive testing suite provides:

- **6 test categories** covering all aspects of the platform
- **Automated CI/CD integration** with GitHub Actions
- **Flexible execution options** via test runner script
- **Comprehensive reporting** with multiple output formats
- **Security validation** including authentication and input sanitization
- **Performance monitoring** with baseline and load testing
- **STIX 2.1 compliance** validation for industry standards

The testing framework ensures the Threat Intelligence Platform meets high standards for functionality, performance, security, and compliance while providing clear feedback and actionable insights for continuous improvement.