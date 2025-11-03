# Threat Intelligence Platform Testing Suite

Comprehensive testing framework for validating data processing capabilities, API functionality, and system performance.

## 📁 Test Structure

```
tests/
├── unit/                          # Unit tests for Lambda functions
│   ├── test_collector.py         # Collector Lambda tests (OTX/Abuse.ch)
│   ├── test_processor.py         # Processor Lambda tests (STIX validation)
│   └── test_enrichment.py        # Enrichment Lambda tests (Shodan/DNS)
├── integration/                   # Integration and E2E tests
│   ├── test_api_endpoints.py     # API Gateway endpoint tests
│   ├── test_data_flow.py         # End-to-end pipeline tests
│   └── test_performance.py       # Performance and load tests
├── fixtures/                     # Test data and mock responses
│   ├── sample_otx_data.json      # Mock OTX API responses
│   ├── sample_stix_data.json     # STIX 2.1 test data
│   ├── sample_enrichment_data.json # Enrichment mock data
│   └── sample_abuse_ch_data.json # Abuse.ch test data
├── conftest.py                   # Pytest configuration and fixtures
├── requirements.txt              # Testing dependencies
├── pytest.ini                   # Pytest settings
└── README.md                     # This file
```

## 🧪 Test Categories

### Unit Tests
- **Collector Tests**: OTX/Abuse.ch data collection, STIX formatting, deduplication
- **Processor Tests**: STIX validation, confidence scoring, batch processing
- **Enrichment Tests**: Shodan/DNS/geolocation enrichment, caching

### Integration Tests
- **API Endpoints**: POST /collect, POST /enrich, GET /search functionality
- **Data Flow**: Complete pipeline from collection → processing → search
- **Performance**: Load testing, concurrent requests, resource utilization

### Performance Tests
- **Response Times**: API latency under normal and peak load
- **Scalability**: Concurrent user simulation and burst handling
- **Resource Usage**: Lambda memory and execution time monitoring

## 🚀 Quick Start

### 1. Install Dependencies
```bash
cd tests
pip install -r requirements.txt
```

### 2. Configure Environment
```bash
# Required for integration tests
export API_BASE_URL="https://u88kzux168.execute-api.us-east-1.amazonaws.com/dev"
export TEST_API_KEY="your-api-key"
export AWS_REGION="us-east-1"

# Optional performance test settings
export CONCURRENT_USERS="5"
export LOAD_TEST_DURATION="60"
```

### 3. Run Tests

#### Unit Tests Only
```bash
pytest unit/ -v
```

#### Integration Tests
```bash
pytest integration/ -v --integration
```

#### Performance Tests
```bash
pytest integration/test_performance.py -v --performance
```

#### All Tests
```bash
pytest -v --integration --performance
```

#### Coverage Report
```bash
pytest --cov=../infrastructure/terraform/lambda_functions --cov-report=html
```

## 📊 Test Validation Criteria

### Performance Benchmarks
- **API Response Time**: < 3 seconds for search queries
- **Collection Speed**: < 30 seconds for OTX batch (20 indicators)
- **Enrichment Speed**: < 10 seconds for 5 IP lookups
- **Memory Usage**: < 90% of allocated Lambda memory
- **Success Rate**: > 95% under normal load

### Data Quality Standards
- **STIX 2.1 Compliance**: 100% format validation
- **Deduplication Accuracy**: 100% duplicate prevention
- **Data Integrity**: 100% consistency across storage layers
- **Confidence Scoring**: Accurate source-based weighting

### Operational Readiness
- **Scalability**: Handle 10+ concurrent requests
- **Reliability**: < 1% error rate under normal load
- **Error Handling**: Graceful failure recovery
- **Security**: Proper API authentication validation

## 🔧 Test Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `API_BASE_URL` | Base URL for API endpoints | - | ✅ |
| `TEST_API_KEY` | API key for authentication | - | For integration tests |
| `AWS_REGION` | AWS region for resources | us-east-1 | - |
| `CONCURRENT_USERS` | Number of concurrent test users | 5 | - |
| `LOAD_TEST_DURATION` | Load test duration in seconds | 60 | - |
| `MAX_RESPONSE_TIME` | Maximum acceptable response time | 10.0 | - |
| `MIN_SUCCESS_RATE` | Minimum acceptable success rate | 0.95 | - |

### Pytest Markers

| Marker | Description | Usage |
|--------|-------------|-------|
| `unit` | Unit tests for individual components | `pytest -m unit` |
| `integration` | Tests requiring live infrastructure | `pytest -m integration` |
| `performance` | Performance and load tests | `pytest -m performance` |
| `slow` | Tests taking longer than 30 seconds | `pytest -m "not slow"` |
| `external_api` | Tests requiring external API access | `pytest -m external_api` |

## 📋 Test Execution Examples

### Development Testing
```bash
# Quick unit test run during development
pytest unit/test_collector.py::TestPatternHashing -v

# Test specific API endpoint
pytest integration/test_api_endpoints.py::TestSearchEndpoint -v --integration

# Test data flow for specific source
pytest integration/test_data_flow.py::TestOTXCollectionPipeline -v --integration
```

### CI/CD Pipeline Testing
```bash
# Unit tests only (fast feedback)
pytest unit/ --tb=short

# Integration tests with timeout
pytest integration/ --integration --timeout=300

# Performance benchmarking
pytest integration/test_performance.py --performance --load-duration=30
```

### Production Readiness Testing
```bash
# Full test suite with coverage
pytest --integration --performance --cov=../infrastructure/terraform/lambda_functions

# Stress testing
pytest integration/test_performance.py::TestStressConditions --performance

# End-to-end validation
pytest integration/test_data_flow.py --integration -v
```

## 🔍 Debugging Failed Tests

### Common Issues

1. **API Authentication Errors (401/403)**
   ```bash
   # Check API key configuration
   echo $TEST_API_KEY

   # Test API accessibility
   curl -H "x-api-key: $TEST_API_KEY" "$API_BASE_URL/search?limit=1"
   ```

2. **Timeout Errors**
   ```bash
   # Increase timeout for slow tests
   pytest --timeout=600 integration/

   # Run with longer timeouts
   export LOAD_TEST_DURATION="30"
   ```

3. **Mock Data Issues**
   ```bash
   # Validate test fixtures
   python -m json.tool fixtures/sample_otx_data.json

   # Check mock AWS services
   pytest unit/ -v -s
   ```

4. **Performance Test Failures**
   ```bash
   # Run with reduced concurrency
   export CONCURRENT_USERS="2"
   export MAX_RESPONSE_TIME="20.0"

   # Skip slow performance tests
   pytest -m "performance and not slow"
   ```

### Debug Mode
```bash
# Run with detailed output
pytest -v -s --tb=long

# Run single test with debugging
pytest integration/test_api_endpoints.py::TestCollectEndpoint::test_collect_otx_source -v -s

# Enable request logging
export PYTHONPATH="${PYTHONPATH}:."
pytest -v -s --log-cli-level=DEBUG
```

## 📈 Test Reports

### Coverage Report
Generated HTML coverage reports are available at `htmlcov/index.html` after running:
```bash
pytest --cov=../infrastructure/terraform/lambda_functions --cov-report=html
```

### Performance Reports
Performance tests output detailed metrics including:
- Response time percentiles (P95, P99)
- Success rates and error analysis
- Concurrent load handling
- Resource utilization statistics

### Test Results
View detailed test results with:
```bash
pytest --html=report.html --self-contained-html
```

## 🔒 Security Considerations

- API keys are never logged or exposed in test output
- Test data uses only public/example domains and IP addresses
- Mock services prevent actual external API calls during unit tests
- Integration tests use minimal data collection to avoid overwhelming external APIs

## 🤝 Contributing

When adding new tests:
1. Follow existing naming conventions (`test_*.py`)
2. Use appropriate pytest markers
3. Include both positive and negative test cases
4. Add performance validation for new endpoints
5. Update this README with new test categories

## 📞 Support

For test execution issues:
1. Check environment variable configuration
2. Verify API endpoint accessibility
3. Review test logs for specific error messages
4. Ensure AWS credentials are properly configured for integration tests

**Testing Status: COMPREHENSIVE SUITE COMPLETE** - Ready for validation of all threat intelligence platform capabilities.