"""
Infrastructure connectivity tests for threat intelligence platform
Validates basic connectivity to deployed AWS services
"""

import pytest
import requests
import os
import boto3
from botocore.exceptions import ClientError


class TestInfrastructureConnectivity:
    """Test connectivity to deployed infrastructure"""

    @pytest.fixture(scope="class")
    def config(self):
        """Test configuration"""
        return {
            'api_base_url': 'https://u88kzux168.execute-api.us-east-1.amazonaws.com/dev',
            'aws_region': 'us-east-1'
        }

    def test_api_gateway_accessibility(self, config):
        """Test that API Gateway is accessible (should return 403 without API key)"""
        url = f"{config['api_base_url']}/search"

        try:
            response = requests.get(url, timeout=10)
            # Expecting 403 Forbidden without API key
            assert response.status_code == 403, f"Expected 403, got {response.status_code}"
            print(f"✅ API Gateway accessible at {config['api_base_url']}")
        except requests.RequestException as e:
            pytest.fail(f"Failed to connect to API Gateway: {e}")

    def test_aws_credentials_configured(self):
        """Test that AWS credentials are properly configured"""
        try:
            # Try to create a boto3 client to test credentials
            sts = boto3.client('sts', region_name='us-east-1')
            identity = sts.get_caller_identity()

            assert 'Account' in identity, "Could not get AWS account information"
            print(f"✅ AWS credentials configured for account: {identity['Account']}")

        except ClientError as e:
            pytest.fail(f"AWS credentials not properly configured: {e}")

    def test_dynamodb_tables_exist(self, config):
        """Test that DynamoDB tables exist and are accessible"""
        dynamodb = boto3.client('dynamodb', region_name=config['aws_region'])

        expected_tables = [
            'threat-intel-platform-threat-intelligence-dev',
            'threat-intel-platform-threat-intel-dedup-dev',
            'threat-intel-platform-osint-enrichment-cache-dev'
        ]

        for table_name in expected_tables:
            try:
                response = dynamodb.describe_table(TableName=table_name)
                table_status = response['Table']['TableStatus']
                assert table_status == 'ACTIVE', f"Table {table_name} is not ACTIVE: {table_status}"
                print(f"✅ DynamoDB table {table_name} is ACTIVE")

            except ClientError as e:
                if e.response['Error']['Code'] == 'ResourceNotFoundException':
                    pytest.fail(f"DynamoDB table {table_name} does not exist")
                else:
                    pytest.fail(f"Error accessing table {table_name}: {e}")

    def test_s3_buckets_exist(self, config):
        """Test that S3 buckets exist and are accessible"""
        s3 = boto3.client('s3', region_name=config['aws_region'])

        # Get list of all buckets
        try:
            response = s3.list_buckets()
            bucket_names = [bucket['Name'] for bucket in response['Buckets']]

            # Check for threat intel platform buckets
            threat_intel_buckets = [
                name for name in bucket_names
                if name.startswith('threat-intel-platform-')
            ]

            assert len(threat_intel_buckets) >= 3, f"Expected at least 3 threat intel buckets, found {len(threat_intel_buckets)}"

            for bucket in threat_intel_buckets:
                print(f"✅ S3 bucket found: {bucket}")

        except ClientError as e:
            pytest.fail(f"Error accessing S3 buckets: {e}")

    def test_secrets_manager_accessible(self, config):
        """Test that Secrets Manager is accessible and contains API keys"""
        secrets = boto3.client('secretsmanager', region_name=config['aws_region'])

        try:
            response = secrets.get_secret_value(
                SecretId='threat-intel-platform/api-keys/dev'
            )

            assert 'SecretString' in response, "Secret does not contain SecretString"

            # Parse the secret to validate structure
            import json
            secret_data = json.loads(response['SecretString'])

            expected_keys = ['OTX_API_KEY', 'SHODAN_API_KEY', 'ABUSE_CH_API_KEY']
            for key in expected_keys:
                assert key in secret_data, f"Missing API key: {key}"
                assert len(secret_data[key]) > 10, f"API key {key} appears too short"

            print("✅ Secrets Manager accessible with all required API keys")

        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                pytest.fail("API keys secret not found in Secrets Manager")
            else:
                pytest.fail(f"Error accessing Secrets Manager: {e}")

    def test_lambda_functions_exist(self, config):
        """Test that Lambda functions exist and are properly configured"""
        lambda_client = boto3.client('lambda', region_name=config['aws_region'])

        expected_functions = [
            'threat-intel-platform-threat-collector-dev',
            'threat-intel-platform-data-processor-dev',
            'threat-intel-platform-osint-enrichment-dev'
        ]

        for function_name in expected_functions:
            try:
                response = lambda_client.get_function(FunctionName=function_name)

                # Check function configuration
                config_data = response['Configuration']
                assert config_data['State'] == 'Active', f"Function {function_name} is not Active"
                assert config_data['Runtime'].startswith('python'), f"Function {function_name} not using Python runtime"

                print(f"✅ Lambda function {function_name} is Active")

            except ClientError as e:
                if e.response['Error']['Code'] == 'ResourceNotFoundException':
                    pytest.fail(f"Lambda function {function_name} does not exist")
                else:
                    pytest.fail(f"Error accessing function {function_name}: {e}")


if __name__ == "__main__":
    # Run connectivity tests
    pytest.main([__file__, "-v"])