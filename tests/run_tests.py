#!/usr/bin/env python3
"""
Test execution script for threat intelligence platform
Provides unified interface for running different types of tests
"""

import os
import sys
import argparse
import subprocess
import json
import time
from datetime import datetime
from pathlib import Path


class TestRunner:
    """Test execution coordinator"""

    def __init__(self):
        self.test_dir = Path(__file__).parent
        self.project_root = self.test_dir.parent
        self.reports_dir = self.test_dir / "reports"
        self.reports_dir.mkdir(exist_ok=True)

    def run_command(self, command, description=""):
        """Run a command and return success status"""
        print(f"\n{'=' * 60}")
        print(f"Running: {description or command}")
        print(f"{'=' * 60}")

        start_time = time.time()
        result = subprocess.run(command, shell=True, cwd=self.test_dir)
        duration = time.time() - start_time

        print(f"\nCompleted in {duration:.2f}s with exit code: {result.returncode}")
        return result.returncode == 0

    def setup_environment(self):
        """Set up test environment"""
        print("Setting up test environment...")

        # Check Python version
        python_version = sys.version_info
        if python_version.major != 3 or python_version.minor < 8:
            print(f"❌ Python 3.8+ required, found {python_version.major}.{python_version.minor}")
            return False

        print(f"✅ Python {python_version.major}.{python_version.minor}.{python_version.micro}")

        # Install/check dependencies
        try:
            import pytest
            import requests
            import boto3
            print("✅ Core dependencies available")
        except ImportError as e:
            print(f"❌ Missing dependency: {e}")
            print("Run: pip install -r requirements.txt")
            return False

        # Check environment variables
        env_vars = {
            'API_BASE_URL': os.environ.get('API_BASE_URL'),
            'AWS_REGION': os.environ.get('AWS_REGION', 'us-east-1'),
            'TEST_API_KEY': os.environ.get('TEST_API_KEY')
        }

        print("\nEnvironment variables:")
        for var, value in env_vars.items():
            if var == 'TEST_API_KEY':
                display_value = '***' if value else 'Not set'
            else:
                display_value = value or 'Not set'
            print(f"  {var}: {display_value}")

        return True

    def run_unit_tests(self, pattern="", verbose=True, coverage=False):
        """Run unit tests"""
        cmd_parts = ["python", "-m", "pytest", "unit/"]

        if pattern:
            cmd_parts.extend(["-k", pattern])

        if verbose:
            cmd_parts.append("-v")

        if coverage:
            cmd_parts.extend([
                "--cov=../infrastructure/terraform/lambda_functions",
                "--cov-report=html",
                "--cov-report=term"
            ])

        cmd_parts.extend([
            "--tb=short",
            "--json-report",
            f"--json-report-file={self.reports_dir}/unit_tests.json"
        ])

        command = " ".join(cmd_parts)
        return self.run_command(command, "Unit tests")

    def run_integration_tests(self, pattern="", timeout=300):
        """Run integration tests"""
        cmd_parts = [
            "python", "-m", "pytest", "integration/",
            "--tb=short",
            f"--timeout={timeout}",
            "--json-report",
            f"--json-report-file={self.reports_dir}/integration_tests.json"
        ]

        if pattern:
            cmd_parts.extend(["-k", pattern])

        command = " ".join(cmd_parts)
        return self.run_command(command, "Integration tests")

    def run_performance_tests(self, concurrent_users=3, duration=30):
        """Run performance tests"""
        env_vars = {
            'CONCURRENT_USERS': str(concurrent_users),
            'LOAD_TEST_DURATION': str(duration),
            'MAX_RESPONSE_TIME': '15.0'
        }

        env_str = " ".join([f"{k}={v}" for k, v in env_vars.items()])

        command = f"{env_str} python -m pytest integration/test_enhanced_performance.py -v --tb=short --json-report --json-report-file={self.reports_dir}/performance_tests.json"

        return self.run_command(command, "Performance tests")

    def run_security_tests(self):
        """Run security tests"""
        command = f"python -m pytest security/ -v --tb=short --json-report --json-report-file={self.reports_dir}/security_tests.json"

        return self.run_command(command, "Security tests")

    def run_compliance_tests(self):
        """Run STIX compliance tests"""
        command = f"python -m pytest compliance/ -v --tb=short --json-report --json-report-file={self.reports_dir}/compliance_tests.json"

        return self.run_command(command, "STIX compliance tests")

    def run_infrastructure_tests(self):
        """Run infrastructure connectivity tests"""
        command = f"python -m pytest test_infrastructure_connectivity.py -v --tb=short --json-report --json-report-file={self.reports_dir}/infrastructure_tests.json"

        return self.run_command(command, "Infrastructure connectivity tests")

    def generate_test_report(self):
        """Generate comprehensive test report"""
        print("\n" + "=" * 60)
        print("GENERATING TEST REPORT")
        print("=" * 60)

        report_files = list(self.reports_dir.glob("*.json"))

        if not report_files:
            print("No test reports found")
            return

        total_tests = 0
        total_passed = 0
        total_failed = 0
        total_skipped = 0
        total_duration = 0

        report_data = {}

        for report_file in report_files:
            try:
                with open(report_file, 'r') as f:
                    data = json.load(f)

                test_type = report_file.stem.replace('_tests', '')
                report_data[test_type] = data

                summary = data.get('summary', {})
                total_tests += summary.get('total', 0)
                total_passed += summary.get('passed', 0)
                total_failed += summary.get('failed', 0)
                total_skipped += summary.get('skipped', 0)
                total_duration += data.get('duration', 0)

            except (json.JSONDecodeError, FileNotFoundError) as e:
                print(f"Error reading {report_file}: {e}")

        # Generate summary
        print(f"\nTEST EXECUTION SUMMARY")
        print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"\nOverall Results:")
        print(f"  Total Tests: {total_tests}")
        print(f"  Passed:      {total_passed} ({total_passed/total_tests*100:.1f}%)" if total_tests > 0 else "  Passed:      0")
        print(f"  Failed:      {total_failed} ({total_failed/total_tests*100:.1f}%)" if total_tests > 0 else "  Failed:      0")
        print(f"  Skipped:     {total_skipped} ({total_skipped/total_tests*100:.1f}%)" if total_tests > 0 else "  Skipped:     0")
        print(f"  Duration:    {total_duration:.2f}s")

        print(f"\nDetailed Results by Test Type:")
        for test_type, data in report_data.items():
            summary = data.get('summary', {})
            duration = data.get('duration', 0)
            print(f"  {test_type.replace('_', ' ').title()}:")
            print(f"    Tests: {summary.get('total', 0)} | "
                  f"Passed: {summary.get('passed', 0)} | "
                  f"Failed: {summary.get('failed', 0)} | "
                  f"Duration: {duration:.2f}s")

        # Generate HTML report
        html_report_path = self.reports_dir / "test_summary.html"
        self.generate_html_report(report_data, html_report_path)
        print(f"\nHTML report generated: {html_report_path}")

        return total_failed == 0

    def generate_html_report(self, report_data, output_path):
        """Generate HTML test report"""
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Threat Intelligence Platform - Test Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #2c3e50; color: white; padding: 20px; text-align: center; }}
        .summary {{ background-color: #ecf0f1; padding: 15px; margin: 20px 0; }}
        .test-section {{ margin: 20px 0; border: 1px solid #bdc3c7; }}
        .test-header {{ background-color: #34495e; color: white; padding: 10px; }}
        .test-content {{ padding: 15px; }}
        .passed {{ color: #27ae60; }}
        .failed {{ color: #e74c3c; }}
        .skipped {{ color: #f39c12; }}
        .metric {{ display: inline-block; margin-right: 20px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Threat Intelligence Platform - Test Report</h1>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>

    <div class="summary">
        <h2>Test Execution Summary</h2>
"""

        total_tests = sum(data.get('summary', {}).get('total', 0) for data in report_data.values())
        total_passed = sum(data.get('summary', {}).get('passed', 0) for data in report_data.values())
        total_failed = sum(data.get('summary', {}).get('failed', 0) for data in report_data.values())
        total_skipped = sum(data.get('summary', {}).get('skipped', 0) for data in report_data.values())
        total_duration = sum(data.get('duration', 0) for data in report_data.values())

        html_content += f"""
        <div class="metric"><strong>Total Tests:</strong> {total_tests}</div>
        <div class="metric passed"><strong>Passed:</strong> {total_passed}</div>
        <div class="metric failed"><strong>Failed:</strong> {total_failed}</div>
        <div class="metric skipped"><strong>Skipped:</strong> {total_skipped}</div>
        <div class="metric"><strong>Duration:</strong> {total_duration:.2f}s</div>
    </div>
"""

        for test_type, data in report_data.items():
            summary = data.get('summary', {})
            html_content += f"""
    <div class="test-section">
        <div class="test-header">
            <h3>{test_type.replace('_', ' ').title()}</h3>
        </div>
        <div class="test-content">
            <div class="metric"><strong>Tests:</strong> {summary.get('total', 0)}</div>
            <div class="metric passed"><strong>Passed:</strong> {summary.get('passed', 0)}</div>
            <div class="metric failed"><strong>Failed:</strong> {summary.get('failed', 0)}</div>
            <div class="metric skipped"><strong>Skipped:</strong> {summary.get('skipped', 0)}</div>
            <div class="metric"><strong>Duration:</strong> {data.get('duration', 0):.2f}s</div>
        </div>
    </div>
"""

        html_content += """
</body>
</html>
"""

        with open(output_path, 'w') as f:
            f.write(html_content)


def main():
    parser = argparse.ArgumentParser(description='Threat Intelligence Platform Test Runner')
    parser.add_argument('test_type', nargs='?', default='unit',
                       choices=['unit', 'integration', 'performance', 'security', 'compliance', 'infrastructure', 'all'],
                       help='Type of tests to run')
    parser.add_argument('--pattern', '-k', help='Test pattern to match')
    parser.add_argument('--coverage', action='store_true', help='Generate coverage report (unit tests only)')
    parser.add_argument('--concurrent-users', type=int, default=3, help='Concurrent users for performance tests')
    parser.add_argument('--duration', type=int, default=30, help='Duration for performance tests')
    parser.add_argument('--no-report', action='store_true', help='Skip generating test report')
    parser.add_argument('--setup-only', action='store_true', help='Only check environment setup')

    args = parser.parse_args()

    runner = TestRunner()

    # Setup environment
    if not runner.setup_environment():
        print("\n❌ Environment setup failed")
        sys.exit(1)

    if args.setup_only:
        print("\n✅ Environment setup successful")
        return

    print(f"\nStarting {args.test_type} tests...")

    success = True

    if args.test_type == 'unit' or args.test_type == 'all':
        success &= runner.run_unit_tests(args.pattern, coverage=args.coverage)

    if args.test_type == 'integration' or args.test_type == 'all':
        success &= runner.run_integration_tests(args.pattern)

    if args.test_type == 'performance' or args.test_type == 'all':
        success &= runner.run_performance_tests(args.concurrent_users, args.duration)

    if args.test_type == 'security' or args.test_type == 'all':
        success &= runner.run_security_tests()

    if args.test_type == 'compliance' or args.test_type == 'all':
        success &= runner.run_compliance_tests()

    if args.test_type == 'infrastructure' or args.test_type == 'all':
        success &= runner.run_infrastructure_tests()

    # Generate report
    if not args.no_report:
        report_success = runner.generate_test_report()
        success &= report_success

    if success:
        print(f"\n✅ {args.test_type.title()} tests completed successfully")
        sys.exit(0)
    else:
        print(f"\n❌ {args.test_type.title()} tests failed")
        sys.exit(1)


if __name__ == "__main__":
    main()