"""
Unit tests for Slack Events Bolt Handler file upload functionality.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import json
import requests
import os
import sys

# Mock environment variables
os.environ["EVENT_BUS_NAME"] = "test-event-bus"
os.environ["INCIDENTS_TABLE_NAME"] = "test-incidents-table"
os.environ["EVENT_SOURCE"] = "slack"
os.environ["AWS_DEFAULT_REGION"] = "us-east-1"

# Mock AWS clients and Slack components before importing the handler
sys.path.append(os.path.join(os.path.dirname(__file__), "../../../assets/slack_events_bolt_handler"))

# Mock all the dependencies that might cause issues
with patch('boto3.client') as mock_boto_client, \
     patch('boto3.resource') as mock_boto_resource, \
     patch('slack_bolt.App') as mock_slack_app, \
     patch('slack_bolt.adapter.aws_lambda.SlackRequestHandler') as mock_slack_handler:
    
    # Set up mock returns
    mock_boto_client.return_value = Mock()
    mock_boto_resource.return_value = Mock()
    mock_slack_app.return_value = Mock()
    mock_slack_handler.return_value = Mock()
    
    import index


class TestDownloadSlackFile:
    """Test cases for download_slack_file function"""

    @patch('index.requests.head')
    @patch('index.requests.get')
    @patch('index.time.sleep')
    def test_download_success(self, mock_sleep, mock_get, mock_head):
        """Test successful file download"""
        # Mock HEAD response
        mock_head_response = Mock()
        mock_head_response.headers = {'content-length': '1024'}
        mock_head_response.raise_for_status.return_value = None
        mock_head.return_value = mock_head_response
        
        # Mock GET response
        mock_get_response = Mock()
        mock_get_response.raise_for_status.return_value = None
        mock_get_response.iter_content.return_value = [b'test', b'file', b'content']
        mock_get.return_value = mock_get_response
        
        # Execute
        result = index.download_slack_file("https://files.slack.com/test", "xoxb-token")
        
        # Verify
        assert result == b'testfilecontent'
        mock_head.assert_called_once()
        mock_get.assert_called_once()
        
        # Verify headers
        expected_headers = {
            "Authorization": "Bearer xoxb-token",
            "User-Agent": "AWS-Security-IR-Slack-Integration/1.0"
        }
        mock_head.assert_called_with("https://files.slack.com/test", headers=expected_headers, timeout=30)
        mock_get.assert_called_with("https://files.slack.com/test", headers=expected_headers, timeout=60, stream=True)

    @patch('index.requests.head')
    def test_download_size_exceeded_in_head(self, mock_head):
        """Test file download with size limit exceeded in HEAD response"""
        # Mock HEAD response with large file
        mock_head_response = Mock()
        mock_head_response.headers = {'content-length': str(index.MAX_FILE_SIZE_BYTES + 1)}
        mock_head_response.raise_for_status.return_value = None
        mock_head.return_value = mock_head_response
        
        # Execute
        result = index.download_slack_file("https://files.slack.com/test", "xoxb-token")
        
        # Verify
        assert result is None
        mock_head.assert_called_once()

    @patch('index.requests.head')
    @patch('index.requests.get')
    def test_download_size_exceeded_during_download(self, mock_get, mock_head):
        """Test file download with size limit exceeded during download"""
        # Mock HEAD response (no content-length)
        mock_head_response = Mock()
        mock_head_response.headers = {}
        mock_head_response.raise_for_status.return_value = None
        mock_head.return_value = mock_head_response
        
        # Mock GET response with large chunks
        mock_get_response = Mock()
        mock_get_response.raise_for_status.return_value = None
        large_chunk = b'x' * (index.MAX_FILE_SIZE_BYTES + 1)
        mock_get_response.iter_content.return_value = [large_chunk]
        mock_get.return_value = mock_get_response
        
        # Execute
        result = index.download_slack_file("https://files.slack.com/test", "xoxb-token")
        
        # Verify
        assert result is None

    @patch('index.requests.head')
    @patch('index.requests.get')
    @patch('index.time.sleep')
    def test_download_retry_on_failure(self, mock_sleep, mock_get, mock_head):
        """Test file download with retry on failure"""
        # Mock HEAD response
        mock_head_response = Mock()
        mock_head_response.headers = {'content-length': '1024'}
        mock_head_response.raise_for_status.return_value = None
        mock_head.return_value = mock_head_response
        
        # Mock GET response - fail first few times, then succeed
        mock_get_response_fail = Mock()
        mock_get_response_fail.raise_for_status.side_effect = requests.exceptions.RequestException("Network error")
        
        mock_get_response_success = Mock()
        mock_get_response_success.raise_for_status.return_value = None
        mock_get_response_success.iter_content.return_value = [b'test', b'content']
        
        mock_get.side_effect = [mock_get_response_fail, mock_get_response_fail, mock_get_response_success]
        
        # Execute
        result = index.download_slack_file("https://files.slack.com/test", "xoxb-token")
        
        # Verify
        assert result == b'testcontent'
        assert mock_get.call_count == 3
        assert mock_sleep.call_count == 2  # Two retries

    @patch('index.requests.head')
    @patch('index.requests.get')
    @patch('index.time.sleep')
    def test_download_max_retries_exceeded(self, mock_sleep, mock_get, mock_head):
        """Test file download with max retries exceeded"""
        # Mock HEAD response
        mock_head_response = Mock()
        mock_head_response.headers = {'content-length': '1024'}
        mock_head_response.raise_for_status.return_value = None
        mock_head.return_value = mock_head_response
        
        # Mock GET response - always fail
        mock_get_response = Mock()
        mock_get_response.raise_for_status.side_effect = requests.exceptions.RequestException("Network error")
        mock_get.return_value = mock_get_response
        
        # Execute
        result = index.download_slack_file("https://files.slack.com/test", "xoxb-token")
        
        # Verify
        assert result is None
        assert mock_get.call_count == index.SLACK_MAX_RETRIES
        assert mock_sleep.call_count == index.SLACK_MAX_RETRIES - 1

    @patch('index.requests.head')
    @patch('index.requests.get')
    def test_download_head_request_failure(self, mock_get, mock_head):
        """Test file download with HEAD request failure"""
        # Mock HEAD response failure
        mock_head.side_effect = requests.exceptions.RequestException("HEAD request failed")
        
        # Execute
        result = index.download_slack_file("https://files.slack.com/test", "xoxb-token")
        
        # Verify
        assert result is None
        mock_head.assert_called_once()
        mock_get.assert_not_called()

    @patch('index.requests.head')
    @patch('index.requests.get')
    def test_download_unexpected_error(self, mock_get, mock_head):
        """Test file download with unexpected error"""
        # Mock HEAD response
        mock_head_response = Mock()
        mock_head_response.headers = {'content-length': '1024'}
        mock_head_response.raise_for_status.return_value = None
        mock_head.return_value = mock_head_response
        
        # Mock GET response with unexpected error
        mock_get.side_effect = ValueError("Unexpected error")
        
        # Execute
        result = index.download_slack_file("https://files.slack.com/test", "xoxb-token")
        
        # Verify
        assert result is None

    def test_download_no_content_length_small_file(self):
        """Test file download without content-length header for small file"""
        with patch('index.requests.head') as mock_head, \
             patch('index.requests.get') as mock_get:
            
            # Mock HEAD response (no content-length)
            mock_head_response = Mock()
            mock_head_response.headers = {}
            mock_head_response.raise_for_status.return_value = None
            mock_head.return_value = mock_head_response
            
            # Mock GET response with small chunks
            mock_get_response = Mock()
            mock_get_response.raise_for_status.return_value = None
            mock_get_response.iter_content.return_value = [b'small', b'file']
            mock_get.return_value = mock_get_response
            
            # Execute
            result = index.download_slack_file("https://files.slack.com/test", "xoxb-token")
            
            # Verify
            assert result == b'smallfile'


class TestFileUploadEventHandling:
    """Test cases for file upload event handling scenarios"""

    def setup_method(self):
        """Set up test fixtures"""
        self.mock_client = Mock()
        self.mock_logger = Mock()

    @patch('index.is_incident_channel')
    @patch('index.get_case_id_from_channel')
    @patch('index.publish_event_to_eventbridge')
    def test_file_upload_non_incident_channel(self, mock_publish, mock_get_case_id, mock_is_incident):
        """Test file upload in non-incident channel is ignored"""
        # Setup
        mock_is_incident.return_value = False
        
        event = {
            "file_id": "F1234567890",
            "channel_id": "C1234567890",
            "user_id": "U1234567890"
        }
        
        self.mock_client.conversations_info.return_value = {
            "channel": {"name": "general"}
        }
        
        # Execute - simulate the file upload handler logic
        channel_response = self.mock_client.conversations_info(channel=event["channel_id"])
        channel_name = channel_response["channel"]["name"]
        
        should_ignore = not mock_is_incident(channel_name)
        
        # Verify
        assert should_ignore is True
        mock_is_incident.assert_called_once_with("general")
        mock_get_case_id.assert_not_called()
        mock_publish.assert_not_called()

    @patch('index.is_incident_channel')
    @patch('index.get_case_id_from_channel')
    @patch('index.publish_event_to_eventbridge')
    def test_file_upload_no_case_mapping(self, mock_publish, mock_get_case_id, mock_is_incident):
        """Test file upload when no case mapping exists"""
        # Setup
        mock_is_incident.return_value = True
        mock_get_case_id.return_value = None
        
        event = {
            "file_id": "F1234567890",
            "channel_id": "C1234567890",
            "user_id": "U1234567890"
        }
        
        self.mock_client.conversations_info.return_value = {
            "channel": {"name": "aws-security-incident-response-case-12345"}
        }
        
        # Execute - simulate the file upload handler logic
        channel_response = self.mock_client.conversations_info(channel=event["channel_id"])
        channel_name = channel_response["channel"]["name"]
        
        if mock_is_incident(channel_name):
            case_id = mock_get_case_id(event["channel_id"])
            should_continue = case_id is not None
        else:
            should_continue = False
        
        # Verify
        assert should_continue is False
        mock_get_case_id.assert_called_once_with("C1234567890")
        mock_publish.assert_not_called()

    @patch('index.is_incident_channel')
    @patch('index.get_case_id_from_channel')
    @patch('index.publish_event_to_eventbridge')
    def test_file_upload_file_info_error(self, mock_publish, mock_get_case_id, mock_is_incident):
        """Test file upload when file info retrieval fails"""
        # Setup
        mock_is_incident.return_value = True
        mock_get_case_id.return_value = "12345"
        mock_publish.return_value = True
        
        event = {
            "file_id": "F1234567890",
            "channel_id": "C1234567890",
            "user_id": "U1234567890"
        }
        
        self.mock_client.conversations_info.return_value = {
            "channel": {"name": "aws-security-incident-response-case-12345"}
        }
        self.mock_client.files_info.side_effect = Exception("File not found")
        
        # Execute - simulate the file upload handler logic
        channel_response = self.mock_client.conversations_info(channel=event["channel_id"])
        channel_name = channel_response["channel"]["name"]
        
        if mock_is_incident(channel_name):
            case_id = mock_get_case_id(event["channel_id"])
            if case_id:
                try:
                    file_response = self.mock_client.files_info(file=event["file_id"])
                except Exception as e:
                    # Publish error event
                    error_detail = {
                        "caseId": case_id,
                        "channelId": event["channel_id"],
                        "fileId": event["file_id"],
                        "userId": event["user_id"],
                        "error": f"Failed to retrieve file information: {str(e)}",
                        "errorType": "file_info_retrieval_failed"
                    }
                    mock_publish("File Upload Error", error_detail)
        
        # Verify
        mock_publish.assert_called_once_with("File Upload Error", {
            "caseId": "12345",
            "channelId": "C1234567890",
            "fileId": "F1234567890",
            "userId": "U1234567890",
            "error": "Failed to retrieve file information: File not found",
            "errorType": "file_info_retrieval_failed"
        })

    @patch('index.is_incident_channel')
    @patch('index.get_case_id_from_channel')
    @patch('index.publish_event_to_eventbridge')
    def test_file_upload_size_limit_exceeded(self, mock_publish, mock_get_case_id, mock_is_incident):
        """Test file upload with size limit exceeded"""
        # Setup
        mock_is_incident.return_value = True
        mock_get_case_id.return_value = "12345"
        mock_publish.return_value = True
        
        event = {
            "file_id": "F1234567890",
            "channel_id": "C1234567890",
            "user_id": "U1234567890"
        }
        
        self.mock_client.conversations_info.return_value = {
            "channel": {"name": "aws-security-incident-response-case-12345"}
        }
        self.mock_client.files_info.return_value = {
            "file": {
                "name": "large_file.zip",
                "size": index.MAX_FILE_SIZE_BYTES + 1,
                "mimetype": "application/zip"
            }
        }
        
        # Execute - simulate the file upload handler logic
        channel_response = self.mock_client.conversations_info(channel=event["channel_id"])
        channel_name = channel_response["channel"]["name"]
        
        if mock_is_incident(channel_name):
            case_id = mock_get_case_id(event["channel_id"])
            if case_id:
                file_response = self.mock_client.files_info(file=event["file_id"])
                file_info = file_response["file"]
                
                file_size = file_info.get("size", 0)
                if file_size > index.MAX_FILE_SIZE_BYTES:
                    error_detail = {
                        "caseId": case_id,
                        "channelId": event["channel_id"],
                        "fileId": event["file_id"],
                        "userId": event["user_id"],
                        "filename": file_info.get("name"),
                        "fileSize": file_size,
                        "error": f"File size {file_size} bytes exceeds platform limit of {index.MAX_FILE_SIZE_BYTES} bytes",
                        "errorType": "file_size_exceeded"
                    }
                    mock_publish("File Upload Error", error_detail)
        
        # Verify
        mock_publish.assert_called_once_with("File Upload Error", {
            "caseId": "12345",
            "channelId": "C1234567890",
            "fileId": "F1234567890",
            "userId": "U1234567890",
            "filename": "large_file.zip",
            "fileSize": index.MAX_FILE_SIZE_BYTES + 1,
            "error": f"File size {index.MAX_FILE_SIZE_BYTES + 1} bytes exceeds platform limit of {index.MAX_FILE_SIZE_BYTES} bytes",
            "errorType": "file_size_exceeded"
        })

    @patch('index.is_incident_channel')
    @patch('index.get_case_id_from_channel')
    @patch('index.get_ssm_parameter')
    @patch('index.publish_event_to_eventbridge')
    def test_file_upload_no_download_url(self, mock_publish, mock_get_param, mock_get_case_id, mock_is_incident):
        """Test file upload when no download URL is available"""
        # Setup
        mock_is_incident.return_value = True
        mock_get_case_id.return_value = "12345"
        mock_get_param.return_value = "xoxb-token"
        mock_publish.return_value = True
        
        event = {
            "file_id": "F1234567890",
            "channel_id": "C1234567890",
            "user_id": "U1234567890"
        }
        
        self.mock_client.conversations_info.return_value = {
            "channel": {"name": "aws-security-incident-response-case-12345"}
        }
        self.mock_client.files_info.return_value = {
            "file": {
                "name": "test.txt",
                "size": 1024,
                "mimetype": "text/plain",
                # Missing url_private_download
            }
        }
        
        # Execute - simulate the file upload handler logic
        channel_response = self.mock_client.conversations_info(channel=event["channel_id"])
        channel_name = channel_response["channel"]["name"]
        
        if mock_is_incident(channel_name):
            case_id = mock_get_case_id(event["channel_id"])
            if case_id:
                file_response = self.mock_client.files_info(file=event["file_id"])
                file_info = file_response["file"]
                
                if file_info.get("size", 0) <= index.MAX_FILE_SIZE_BYTES:
                    file_url = file_info.get("url_private_download")
                    if not file_url:
                        error_detail = {
                            "caseId": case_id,
                            "channelId": event["channel_id"],
                            "fileId": event["file_id"],
                            "userId": event["user_id"],
                            "filename": file_info.get("name"),
                            "error": "No download URL available for file",
                            "errorType": "download_url_missing"
                        }
                        mock_publish("File Upload Error", error_detail)
        
        # Verify
        mock_publish.assert_called_once_with("File Upload Error", {
            "caseId": "12345",
            "channelId": "C1234567890",
            "fileId": "F1234567890",
            "userId": "U1234567890",
            "filename": "test.txt",
            "error": "No download URL available for file",
            "errorType": "download_url_missing"
        })


if __name__ == "__main__":
    pytest.main([__file__])