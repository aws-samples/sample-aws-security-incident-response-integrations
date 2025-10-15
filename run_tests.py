import boto3
import sys
import time
import os
from boto3.s3.transfer import TransferConfig
import zipfile

from time import sleep

cfn = boto3.client('cloudformation', region_name='us-east-1')
codebuild = boto3.client('codebuild')
logs = boto3.client('logs')
s3 = boto3.client('s3')
import boto3
import os
import json
from botocore.exceptions import ClientError

def download_build_reports(build_id, output_dir='build_reports'):
    """
    Downloads all report artifacts from a CodeBuild build

    Args:
        build_id (str): The ID of the build
        output_dir (str): Directory to save the reports

    Returns:
        list: List of downloaded report files
    """
    downloaded_files = []

    try:
        # Get build information
        response = codebuild.batch_get_builds(ids=[build_id])

        if not response['builds']:
            print(f"Build {build_id} not found")
            return downloaded_files

        build = response['builds'][0]

        # Get all reports for this build
        reports_arns = build.get('reportArns', [])

        if not reports_arns:
            print("No reports found for this build")
            return downloaded_files

        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)

        # Get detailed information about each report
        report_response = codebuild.batch_get_reports(reportArns=reports_arns)

        for report in report_response.get('reports', []):
            report_type = report.get('type')
            report_group_name = report.get('name')

            # Check if report has export configuration
            export_config = report.get('exportConfig', {})
            if export_config.get('exportConfigType') == 'S3':
                s3_destination = export_config.get('s3Destination', {})
                bucket = s3_destination.get('bucket')
                path = s3_destination.get('path', '').rstrip('/')

                if bucket:
                    try:
                        # Create directory for this report
                        report_dir = os.path.join(output_dir, report_group_name)
                        os.makedirs(report_dir, exist_ok=True)

                        # Download report files
                        if path:
                            # List objects in the S3 path
                            paginator = s3.get_paginator('list_objects_v2')
                            for page in paginator.paginate(Bucket=bucket, Prefix=path):
                                for obj in page.get('Contents', []):
                                    key = obj['Key']
                                    filename = os.path.basename(key)
                                    if filename:  # Skip if key ends with /
                                        local_file = os.path.join(report_dir, filename)
                                        print(f"Downloading {key} to {local_file}")
                                        s3.download_file(bucket, key, local_file)
                                        downloaded_files.append(local_file)

                        # Save report metadata
                        metadata_file = os.path.join(report_dir, 'report_metadata.json')
                        with open(metadata_file, 'w') as f:
                            json.dump({
                                'type': report_type,
                                'name': report_group_name,
                                'status': report.get('status'),
                                'created': str(report.get('created')),
                                'testSummary': report.get('testSummary'),
                                'codeCoverageSummary': report.get('codeCoverageSummary')
                            }, f, indent=2)
                        downloaded_files.append(metadata_file)

                    except ClientError as e:
                        print(f"Error downloading report files: {str(e)}")
                        continue
            else:
                print(f"Report {report_group_name} is not exported to S3")

                # Save report data directly
                report_dir = os.path.join(output_dir, report_group_name)
                os.makedirs(report_dir, exist_ok=True)

                # Save test results if available
                if report.get('testSummary'):
                    test_file = os.path.join(report_dir, 'test_summary.json')
                    with open(test_file, 'w') as f:
                        json.dump(report['testSummary'], f, indent=2)
                    downloaded_files.append(test_file)

                # Save coverage results if available
                if report.get('codeCoverageSummary'):
                    coverage_file = os.path.join(report_dir, 'coverage_summary.json')
                    with open(coverage_file, 'w') as f:
                        json.dump(report['codeCoverageSummary'], f, indent=2)
                    downloaded_files.append(coverage_file)

        return downloaded_files

    except ClientError as e:
        print(f"Error getting build information: {str(e)}")
        return downloaded_files

def print_report_summary(reports_dir='build_reports'):
    """
    Print a summary of downloaded reports

    Args:
        build_id (str): The ID of the build
        reports_dir (str): Directory containing the reports
    """
    try:
        for report_group in os.listdir(reports_dir):
            report_dir = os.path.join(reports_dir, report_group)
            if not os.path.isdir(report_dir):
                continue

            print(f"\nReport Group: {report_group}")

            # Read metadata if available
            metadata_file = os.path.join(report_dir, 'report_metadata.json')
            if os.path.exists(metadata_file):
                with open(metadata_file) as f:
                    metadata = json.load(f)

                print(f"Type: {metadata.get('type')}")
                print(f"Status: {metadata.get('status')}")
                print(f"Created: {metadata.get('created')}")

                # Print test summary if available
                test_summary = metadata.get('testSummary')
                if test_summary:
                    print("\nTest Summary:")
                    print(f"Total Tests: {test_summary.get('total')}")
                    for status, count in test_summary.get('statusCounts', {}).items():
                        print(f"  {status}: {count}")
                    print(f"Duration: {test_summary.get('durationInNanoSeconds', 0) / 1e9:.2f} seconds")

                # Print coverage summary if available
                coverage_summary = metadata.get('codeCoverageSummary')
                if coverage_summary:
                    print("\nCode Coverage Summary:")
                    print(f"Lines covered: {coverage_summary.get('linesCovered', 0)}")
                    print(f"Lines total: {coverage_summary.get('linesTotal', 0)}")
                    covered = coverage_summary.get('linesCovered', 0)
                    total = coverage_summary.get('linesTotal', 0)
                    if total > 0:
                        coverage = (covered / total) * 100
                        print(f"Coverage: {coverage:.2f}%")

            # List downloaded files
            files = [f for f in os.listdir(report_dir) if f != 'report_metadata.json']
            if files:
                print("\nDownloaded Files:")
                for file in files:
                    print(f"- {file}")
    except Exception as e:
        print(f"Error printing report summary: {str(e)}")


def wait_for_build_start(build_id, max_attempts=20, delay=15):
    """
    Wait for a CodeBuild build to start running

    Args:
        build_id (str): The ID of the build to monitor
        max_attempts (int): Maximum number of attempts to check build status
        delay (int): Delay in seconds between status checks

    Returns:
        bool: True if build started successfully, False otherwise
    """

    attempts = 0

    print(f"Waiting for build {build_id} to start...")

    while attempts < max_attempts:
        try:
            response = codebuild.batch_get_builds(ids=[build_id])

            if not response['builds']:
                print(f"Build {build_id} not found")
                return False

            build = response['builds'][0]
            build_status = build.get('buildStatus')
            current_phase = build.get('currentPhase')

            # Check if build has started
            if current_phase == 'BUILD':
                print(f"Build {build_id} has started running")
                return True

            # Check for failed or stopped states
            if build_status in ['FAILED', 'STOPPED', 'TIMED_OUT', 'FAULT']:
                print(f"Build failed to start. Status: {build_status}")
                return False

            # Still in preliminary phases (SUBMITTED, QUEUED, PROVISIONING)
            print(f"Current phase: {current_phase} (Status: {build_status})")

            attempts += 1
            time.sleep(delay)

        except Exception as e:
            print(f"Error checking build status: {str(e)}")
            return False

    print(f"Timed out waiting for build {build_id} to start")
    return False

def is_build_complete(build_id):
    """
    Check if a CodeBuild build is complete

    Args:
        build_id (str): The ID of the build to check

    Returns:
        bool: True if build is complete, False otherwise
    """

    try:
        response = codebuild.batch_get_builds(ids=[build_id])

        if not response['builds']:
            print(f"Build {build_id} not found")
            return False

        build = response['builds'][0]
        build_status = build.get('buildStatus')
        current_phase = build.get('currentPhase')

        # Check if build is complete
        if build_status == 'SUCCEEDED':
            print(f"Build {build_id} completed successfully")
            return True
        elif build_status in ['FAILED', 'STOPPED', 'TIMED_OUT', 'FAULT']:
            print(f"Build {build_id} failed. Status: {build_status}")
            sys.exit(1)
            return True
        else:
            return False

    except Exception as e:
        print(f"Error checking build status: {str(e)}")
        return True

def zip_directory(path='.', output_path='source.zip'):
    """
    Create a zip file of the directory contents

    Args:
        path (str): Path to directory to zip
        output_path (str): Path where to save the zip file
    """
    with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        # Walk through directory
        for root, dirs, files in os.walk(path):
            for file in files:
                # Don't include the output zip file itself or Virtual Environment
                if file == output_path:
                    continue

                file_path = os.path.join(root, file)
                # Calculate path relative to the directory being zipped
                arcname = os.path.relpath(file_path, path)
                print(f"Adding {file_path} to zip")
                zipf.write(file_path, arcname)


def upload_directory_to_s3(bucket_name, prefix=''):
    """
    Zips all files from current directory and uploads to S3 bucket
    using S3 Transfer Manager for better performance

    Args:
        bucket_name (str): Name of the S3 bucket
        prefix (str): Optional prefix (folder path) in the bucket
    """
    # First, create the zip file
    zip_filename = 'source.zip'
    print("Creating zip file...")
    zip_directory('.', zip_filename)

    # Configure transfer settings
    config = TransferConfig(
        multipart_threshold=1024 * 25,  # 25MB
        max_concurrency=10,
        multipart_chunksize=1024 * 25,  # 25MB
        use_threads=True
    )

    s3 = boto3.client('s3')

    # Determine the S3 path
    s3_path = zip_filename
    if prefix:
        s3_path = f"{prefix.rstrip('/')}/{zip_filename}"

    try:
        print(f"Uploading {zip_filename} to {bucket_name}/{s3_path}")
        s3.upload_file(
            zip_filename,
            bucket_name,
            s3_path,
            Config=config,
            Callback=ProgressPercentage(zip_filename)
        )
    except Exception as e:
        print(f"Error uploading {zip_filename}: {str(e)}")
    finally:
        # Clean up the zip file
        try:
            os.remove(zip_filename)
            print(f"Cleaned up {zip_filename}")
        except Exception as e:
            print(f"Error removing zip file: {str(e)}")

class ProgressPercentage:
    def __init__(self, filename):
        self._filename = filename
        self._size = float(os.path.getsize(filename))
        self._seen_so_far = 0
        self._last_percentage = 0

    def __call__(self, bytes_amount):
        self._seen_so_far += bytes_amount
        percentage = (self._seen_so_far / self._size) * 100

        # Only print every 10% to avoid console spam
        if int(percentage) // 10 > self._last_percentage // 10:
            print(f"{self._filename} -> {int(percentage)}%")
            self._last_percentage = percentage

def get_stack_outputs(stack_name):
    """Get CloudFormation stack outputs"""
    try:
        response = cfn.describe_stacks(StackName=stack_name)
        outputs = {}
        for output in response['Stacks'][0]['Outputs']:
            outputs[output['OutputKey']] = output['OutputValue']
        return outputs
    except Exception as e:
        print(f"Error getting stack outputs: {str(e)}")
        sys.exit(1)

def stream_codebuild_logs(build_id):
    """Stream CodeBuild logs and return build status"""

    next_token = None
    response = codebuild.batch_get_builds(ids=[build_id])
    builds = response['builds']
    build = builds[0]
    build_logs = build['logs']
    while True:
        try:
            # Get logs
            if 'groupName' in build_logs and 'streamName' in build_logs:
                log_group = build_logs['groupName']
                log_stream = build_logs['streamName']

                try:
                    if next_token is not None:
                        log_events = logs.get_log_events(
                            logGroupName=log_group,
                            logStreamName=log_stream,
                            nextToken=next_token,
                        )
                    else:
                        log_events = logs.get_log_events(
                            logGroupName=log_group,
                            logStreamName=log_stream,
                            startFromHead=True
                        )
                    next_token = log_events['nextForwardToken']

                    for event in log_events['events']:
                        print(event['message'].strip())

                except Exception as e:
                    print(f"Error getting logs: {str(e)}")
            
            if is_build_complete(build_id):
                break
            else:
                time.sleep(5)
            
        except Exception as e:
            print(f"Error streaming logs: {str(e)}")
            return None

def main():
    if len(sys.argv) != 2:
        print("Usage: python run_test.py <stack-name>")
        sys.exit(1)

    stack_name = sys.argv[1]
    
    # Get stack outputs
    outputs = get_stack_outputs(stack_name)
    project_name = outputs.get('CodeBuildProjectName')
    s3_bucket = outputs.get('BucketName')
    
    if not project_name or not s3_bucket:
        print("Could not find required stack outputs")
        sys.exit(1)
        
    print(f"Found CodeBuild project: {project_name}")
    print(f"Found S3 bucket: {s3_bucket}")

    # Upload to S3
    upload_directory_to_s3(s3_bucket, '')

    # Start build
    try:
        response = codebuild.start_build(projectName=project_name)
        build_id = response['build']['id']
        build_url = f"https://console.aws.amazon.com/codesuite/codebuild/projects/{project_name}/build/{build_id}"
        print(f"\nStarted build: {build_id}")
        print(f"Build URL: {build_url}\n")

        print('Waiting for Build to start')
        wait_for_build_start(build_id)
        print('Build Started')

        # Stream logs
        stream_codebuild_logs(build_id)

        # Download Reports
        download_build_reports(build_id)
        print_report_summary()
            
    except Exception as e:
        print(f"Error starting build: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main()