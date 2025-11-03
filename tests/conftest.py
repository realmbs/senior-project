"""
Test configuration and fixtures for threat intelligence platform testing
"""

import os
import pytest
import boto3
from moto import mock_dynamodb, mock_s3, mock_secretsmanager
import json

# Test configuration
TEST_CONFIG = {
    'API_BASE_URL': 'https://u88kzux168.execute-api.us-east-1.amazonaws.com/dev',
    'AWS_REGION': 'us-east-1',
    'PROJECT_NAME': 'threat-intel-platform',
    'ENVIRONMENT': 'test'
}

@pytest.fixture
def test_config():
    """Test configuration fixture"""
    return TEST_CONFIG

@pytest.fixture
def mock_aws_credentials():
    """Mock AWS credentials for testing"""
    os.environ['AWS_ACCESS_KEY_ID'] = 'testing'
    os.environ['AWS_SECRET_ACCESS_KEY'] = 'testing'
    os.environ['AWS_SECURITY_TOKEN'] = 'testing'
    os.environ['AWS_SESSION_TOKEN'] = 'testing'
    os.environ['AWS_DEFAULT_REGION'] = 'us-east-1'

@pytest.fixture
def mock_dynamodb_setup(mock_aws_credentials):
    """Set up mocked DynamoDB tables"""
    with mock_dynamodb():
        dynamodb = boto3.resource('dynamodb', region_name='us-east-1')

        # Create threat intelligence table
        threat_table = dynamodb.create_table(
            TableName='threat-intel-platform-threat-intelligence-test',
            KeySchema=[
                {'AttributeName': 'object_id', 'KeyType': 'HASH'},
                {'AttributeName': 'object_type', 'KeyType': 'RANGE'}
            ],
            AttributeDefinitions=[
                {'AttributeName': 'object_id', 'AttributeType': 'S'},
                {'AttributeName': 'object_type', 'AttributeType': 'S'},
                {'AttributeName': 'created_date', 'AttributeType': 'S'},
                {'AttributeName': 'source_name', 'AttributeType': 'S'},
                {'AttributeName': 'confidence', 'AttributeType': 'N'},
                {'AttributeName': 'pattern_hash', 'AttributeType': 'S'}
            ],
            GlobalSecondaryIndexes=[
                {
                    'IndexName': 'SourceTimeIndex',
                    'KeySchema': [
                        {'AttributeName': 'source_name', 'KeyType': 'HASH'},
                        {'AttributeName': 'created_date', 'KeyType': 'RANGE'}
                    ],
                    'Projection': {'ProjectionType': 'ALL'},
                    'ProvisionedThroughput': {'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5}
                }
            ],
            BillingMode='PROVISIONED',
            ProvisionedThroughput={'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5}
        )

        # Create deduplication table
        dedup_table = dynamodb.create_table(
            TableName='threat-intel-platform-deduplication-test',
            KeySchema=[{'AttributeName': 'pattern_hash', 'KeyType': 'HASH'}],
            AttributeDefinitions=[{'AttributeName': 'pattern_hash', 'AttributeType': 'S'}],
            BillingMode='PROVISIONED',
            ProvisionedThroughput={'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5}
        )

        # Create enrichment cache table
        enrichment_table = dynamodb.create_table(
            TableName='threat-intel-platform-enrichment-cache-test',
            KeySchema=[{'AttributeName': 'cache_key', 'KeyType': 'HASH'}],
            AttributeDefinitions=[{'AttributeName': 'cache_key', 'AttributeType': 'S'}],
            BillingMode='PROVISIONED',
            ProvisionedThroughput={'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5}
        )

        yield {
            'threat_table': threat_table,
            'dedup_table': dedup_table,
            'enrichment_table': enrichment_table
        }

@pytest.fixture
def mock_s3_setup(mock_aws_credentials):
    """Set up mocked S3 buckets"""
    with mock_s3():
        s3 = boto3.client('s3', region_name='us-east-1')

        # Create test buckets
        buckets = [
            'threat-intel-platform-raw-data-test',
            'threat-intel-platform-processed-data-test',
            'threat-intel-platform-frontend-test'
        ]

        for bucket in buckets:
            s3.create_bucket(Bucket=bucket)

        yield s3

@pytest.fixture
def mock_secrets_manager(mock_aws_credentials):
    """Set up mocked Secrets Manager"""
    with mock_secretsmanager():
        secrets = boto3.client('secretsmanager', region_name='us-east-1')

        # Create API keys secret
        secret_value = {
            'OTX_API_KEY': 'test_otx_key',
            'SHODAN_API_KEY': 'test_shodan_key',
            'ABUSE_CH_API_KEY': 'test_abuse_ch_key'
        }

        secrets.create_secret(
            Name='threat-intel-platform/api-keys/test',
            SecretString=json.dumps(secret_value)
        )

        yield secrets

@pytest.fixture
def sample_lambda_event():
    """Sample Lambda event for testing"""
    return {
        'httpMethod': 'POST',
        'path': '/collect',
        'headers': {
            'Content-Type': 'application/json',
            'x-api-key': 'test-api-key'
        },
        'body': json.dumps({
            'sources': ['otx'],
            'collection_type': 'automated'
        })
    }

@pytest.fixture
def sample_lambda_context():
    """Sample Lambda context for testing"""
    class MockContext:
        def __init__(self):
            self.function_name = 'test-function'
            self.function_version = '$LATEST'
            self.invoked_function_arn = 'arn:aws:lambda:us-east-1:123456789012:function:test-function'
            self.memory_limit_in_mb = 256
            self.remaining_time_in_millis = lambda: 30000
            self.aws_request_id = 'test-request-id'

    return MockContext()