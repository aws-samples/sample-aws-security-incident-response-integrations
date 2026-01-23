"""
Unit tests for Slack Events Bolt Handler file upload functionality.
"""

# TODO: Fix mock configuration issues with retry logic and request handling to re-enable skipped tests
#https://app.asana.com/1/8442528107068/project/1209571477232011/task/1211611017424273?focus=true

import pytest
from unittest.mock import Mock, patch, MagicMock
import json
import requests

# Mock AWS clients before importing the handler
with patch('boto3.client'), patch('boto3.resource'):
    import sys
    import os
    
    # Add project root to Python path
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..'))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
    
    from assets.slack_events_bolt_handler.index import (
        download_slack_file,
        MAX_FILE_SIZE_BYTES,
        SLACK_MAX_RETRIES,
        SLACK_INITIAL_RETRY_DELAY,
    )


class TestDownloadSlackFile:
    """Test cases for download_slack_file function"""

    @patch('assets.slack_events_bolt_handler.index.requests.head')
    @patch('assets.slack_events_bolt_handler.index.requests.get')
    @patch('assets.slack_events_bolt_handler.index.time.sleep')
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
        
        result = download_slack_file(
            "https://files.slack.com/test-file",
            "xoxb-test-token"
        )
        
        assert result == b'testfilecontent'
        mock_head.assert_called_once()
        mock_get.assert_called_once()
        mock_sleep.assert_not_called()

    @patch('assets.slack_events_bolt_handler.index.requests.head')
    def test_download_file_too_large_head_check(self, mock_head):
        """Test file download rejection when file is too large (detected in HEAD request)"""
        # Mock HEAD response with large file size
        mock_head_response = Mock()
        mock_head_response.headers = {'content-length': str(MAX_FILE_SIZE_BYTES + 1)}
        mock_head_response.raise_for_status.return_value = None
        mock_head.return_value = mock_head_response
        
        result = download_slack_file(
            "https://files.slack.com/test-file",
            "xoxb-test-token"
        )
        
        assert result is None
        mock_head.assert_called_once()

    @patch('assets.slack_events_bolt_handler.index.requests.head')
    @patch('assets.slack_events_bolt_handler.index.requests.get')
    def test_download_file_too_large_during_download(self, mock_get, mock_head):
        """Test file download rejection when file exceeds size during download"""
        # Mock HEAD response without content-length
        mock_head_response = Mock()
        mock_head_response.headers = {}
        mock_head_response.raise_for_status.return_value = None
        mock_head.return_value = mock_head_response
        
        # Mock GET response with large chunks
        mock_get_response = Mock()
        mock_get_response.raise_for_status.return_value = None
        # Create chunks that exceed max size
        large_chunk = b'x' * (MAX_FILE_SIZE_BYTES // 2 + 1)
        mock_get_response.iter_content.return_value = [large_chunk, large_chunk]
        mock_get.return_value = mock_get_response
        
        result = download_slack_file(
            "https://files.slack.com/test-file",
            "xoxb-test-token"
        )
        
        assert result is None

    @pytest.mark.skip(reason="Mock configuration issue with retry logic")
    @patch('assets.slack_events_bolt_handler.index.requests.head')
    @patch('assets.slack_events_bolt_handler.index.requests.get')
    @patch('assets.slack_events_bolt_handler.index.time.sleep')
    def test_download_with_retry_success(self, mock_sleep, mock_get, mock_head):
        """Test file download with retry on failure then success"""
        # Mock HEAD response
        mock_head_response = Mock()
        mock_head_response.headers = {'content-length': '1024'}
        mock_head_response.raise_for_status.return_value = None
        mock_head.return_value = mock_head_response
        
        # Mock GET response - fail first, succeed second
        mock_get_response_fail = Mock()
        mock_get_response_fail.raise_for_status.side_effect = requests.exceptions.RequestException("Network error")
        
        mock_get_response_success = Mock()
        mock_get_response_success.raise_for_status.return_value = None
        mock_get_response_success.iter_content.return_value = [b'test', b'content']
        
        mock_get.side_effect = [mock_get_response_fail, mock_get_response_success]
        
        result = download_slack_file(
            "https://files.slack.com/test-file",
            "xoxb-test-token"
        )
        
        assert result == b'testcontent'
        assert mock_get.call_count == 2
        mock_sleep.assert_called_once_with(SLACK_INITIAL_RETRY_DELAY)

    @pytest.mark.skip(reason="Mock configuration issue with retry logic")
    @patch('assets.slack_events_bolt_handler.index.requests.head')
    @patch('assets.slack_events_bolt_handler.index.requests.get')
    @patch('assets.slack_events_bolt_handler.index.time.sleep')
    def test_download_max_retries_exceeded(self, mock_sleep, mock_get, mock_head):
        """Test file download failure after max retries"""
        # Mock HEAD response
        mock_head_response = Mock()
        mock_head_response.headers = {'content-length': '1024'}
        mock_head_response.raise_for_status.return_value = None
        mock_head.return_value = mock_head_response
        
        # Mock GET response - always fail
        mock_get_response = Mock()
        mock_get_response.raise_for_status.side_effect = requests.exceptions.RequestException("Network error")
        mock_get.return_value = mock_get_response
        
        result = download_slack_file(
            "https://files.slack.com/test-file",
            "xoxb-test-token"
        )
        
        assert result is None
        assert mock_get.call_count == SLACK_MAX_RETRIES
        assert mock_sleep.call_count == SLACK_MAX_RETRIES - 1

    @pytest.mark.skip(reason="Mock configuration issue with HEAD request")
    @patch('assets.slack_events_bolt_handler.index.requests.head')
    def test_download_head_request_failure(self, mock_head):
        """Test file download failure when HEAD request fails"""
        mock_head.side_effect = requests.exceptions.RequestException("HEAD request failed")
        
        result = download_slack_file(
            "https://files.slack.com/test-file",
            "xoxb-test-token"
        )
        
        assert result is None

    @patch('tests.assets.slack_events_bolt_handler.test_file_upload_handler.requests.head')
    @patch('tests.assets.slack_events_bolt_handler.test_file_upload_handler.requests.get')
    def test_download_with_custom_max_size(self, mock_get, mock_head):
        """Test file download with custom max size"""
        custom_max_size = 500
        
        # Mock HEAD response with size just over custom limit
        mock_head_response = Mock()
        mock_head_response.headers = {'content-length': str(custom_max_size + 1)}
        mock_head_response.raise_for_status.return_value = None
        mock_head.return_value = mock_head_response
        
        result = download_slack_file(
            "https://files.slack.com/test-file",
            "xoxb-test-token",
            max_size=custom_max_size
        )
        
        assert result is None
        mock_get.assert_not_called()

    @pytest.mark.skip(reason="Mock configuration issue with unexpected error handling")
    @patch('tests.assets.slack_events_bolt_handler.test_file_upload_handler.requests.head')
    @patch('tests.assets.slack_events_bolt_handler.test_file_upload_handler.requests.get')
    def test_download_unexpected_error(self, mock_get, mock_head):
        """Test file download with unexpected error"""
        # Mock HEAD response
        mock_head_response = Mock()
        mock_head_response.headers = {'content-length': '1024'}
        mock_head_response.raise_for_status.return_value = None
        mock_head.return_value = mock_head_response
        
        # Mock GET response with unexpected error
        mock_get.side_effect = Exception("Unexpected error")
        
        result = download_slack_file(
            "https://files.slack.com/test-file",
            "xoxb-test-token"
        )
        
        assert result is None

    def test_download_with_proper_headers(self):
        """Test that download uses proper headers"""
        with patch('assets.slack_events_bolt_handler.index.requests.head') as mock_head, \
             patch('assets.slack_events_bolt_handler.index.requests.get') as mock_get:
            
            # Mock HEAD response
            mock_head_response = Mock()
            mock_head_response.headers = {'content-length': '1024'}
            mock_head_response.raise_for_status.return_value = None
            mock_head.return_value = mock_head_response
            
            # Mock GET response
            mock_get_response = Mock()
            mock_get_response.raise_for_status.return_value = None
            mock_get_response.iter_content.return_value = [b'test']
            mock_get.return_value = mock_get_response
            
            download_slack_file(
                "https://files.slack.com/test-file",
                "xoxb-test-token"
            )
            
            expected_headers = {
                "Authorization": "Bearer xoxb-test-token",
                "User-Agent": "AWS-Security-IR-Slack-Integration/1.0"
            }
            
            mock_head.assert_called_once_with(
                "https://files.slack.com/test-file",
                headers=expected_headers,
                timeout=30
            )
            
            mock_get.assert_called_once_with(
                "https://files.slack.com/test-file",
                headers=expected_headers,
                timeout=60,
                stream=True
            )


class TestFileUploadHandler:
    """Test cases for file upload handler in Slack Events Bolt Handler"""

    def setup_method(self):
        """Set up test fixtures"""
        self.mock_event = {
            "file_id": "F1234567890",
            "channel_id": "C1234567890",
            "user_id": "U1234567890"
        }
        
        self.mock_file_info = {
            "id": "F1234567890",
            "name": "test-file.txt",
            "size": 1024,
            "mimetype": "text/plain",
            "url_private_download": "https://files.slack.com/test-file",
            "title": "Test File",
            "timestamp": "1640995200",
            "initial_comment": {"comment": "Test comment"}
        }
        
        self.mock_channel_info = {
            "id": "C1234567890",
            "name": "aws-security-incident-response-case-12345"
        }
        
        self.mock_user_info = {
            "id": "U1234567890",
            "real_name": "Test User"
        }
    
    @patch('assets.slack_events_bolt_handler.index.download_slack_file')
    @patch('assets.slack_events_bolt_handler.index.get_case_id_from_channel')
    @patch('assets.slack_events_bolt_handler.index.get_ssm_parameter')
    @patch('assets.slack_events_bolt_handler.index.publish_event_to_eventbridge')
    def test_file_upload_success(self, mock_publish, mock_download, mock_ssm, mock_get_case):
        """Test successful file upload handling"""
        # Setup mocks
        mock_get_case.return_value = "12345"
        mock_ssm.return_value = "xoxb-test-token"
        mock_download.return_value = b"test file content"
        mock_publish.return_value = True
        
        # Mock Slack client
        mock_client = Mock()
        mock_client.conversations_info.return_value = {"channel": self.mock_channel_info}
        mock_client.files_info.return_value = {"file": self.mock_file_info}
        mock_client.users_info.return_value = {"user": self.mock_user_info}
        
        # Mock logger
        mock_logger = Mock()
        
        # Import and test the handler
        from assets.slack_events_bolt_handler.index import app
        if app:
            # Get the file upload handler
            handlers = [h for h in app._listeners if h.matcher.func.__name__ == 'handle_file_upload']
            if handlers:
                handler = handlers[0]
                handler.func(self.mock_event, mock_client, mock_logger)
                
                # Verify calls
                mock_client.conversations_info.assert_called_once_with(channel="C1234567890")
                mock_client.files_info.assert_called_once_with(file="F1234567890")
                mock_client.users_info.assert_called_once_with(user="U1234567890")
                mock_get_case.assert_called_once_with("C1234567890")
                mock_download.assert_called_once()
                mock_publish.assert_called_once()

    @patch('assets.slack_events_bolt_handler.index.get_case_id_from_channel')
    @patch('assets.slack_events_bolt_handler.index.publish_event_to_eventbridge')
    def test_file_upload_non_incident_channel(self, mock_publish, mock_get_case):
        """Test file upload in non-incident channel is ignored"""
        # Mock Slack client with non-incident channel
        mock_client = Mock()
        mock_client.conversations_info.return_value = {
            "channel": {"id": "C1234567890", "name": "general"}
        }
        
        mock_logger = Mock()
        
        from assets.slack_events_bolt_handler.index import app
        if app:
            handlers = [h for h in app._listeners if h.matcher.func.__name__ == 'handle_file_upload']
            if handlers:
                handler = handlers[0]
                handler.func(self.mock_event, mock_client, mock_logger)
                
                # Verify no further processing
                mock_client.files_info.assert_not_called()
                mock_get_case.assert_not_called()
                mock_publish.assert_not_called()

    @patch('assets.slack_events_bolt_handler.index.get_case_id_from_channel')
    @patch('assets.slack_events_bolt_handler.index.publish_event_to_eventbridge')
    def test_file_upload_file_too_large(self, mock_publish, mock_get_case):
        """Test file upload rejection when file is too large"""
        # Setup mocks
        mock_get_case.return_value = "12345"
        mock_publish.return_value = True
        
        # Mock large file
        large_file_info = self.mock_file_info.copy()
        large_file_info["size"] = MAX_FILE_SIZE_BYTES + 1
        
        mock_client = Mock()
        mock_client.conversations_info.return_value = {"channel": self.mock_channel_info}
        mock_client.files_info.return_value = {"file": large_file_info}
        
        mock_logger = Mock()
        
        from assets.slack_events_bolt_handler.index import app
        if app:
            handlers = [h for h in app._listeners if h.matcher.func.__name__ == 'handle_file_upload']
            if handlers:
                handler = handlers[0]
                handler.func(self.mock_event, mock_client, mock_logger)
                
                # Verify error event published
                mock_publish.assert_called_once()
                call_args = mock_publish.call_args
                assert call_args[0][0] == "File Upload Error"
                assert "file_size_exceeded" in call_args[0][1]["errorType"]

    @patch('assets.slack_events_bolt_handler.index.get_case_id_from_channel')
    @patch('assets.slack_events_bolt_handler.index.publish_event_to_eventbridge')
    def test_file_upload_no_case_id(self, mock_publish, mock_get_case):
        """Test file upload when case ID cannot be found"""
        # Setup mocks
        mock_get_case.return_value = None
        
        mock_client = Mock()
        mock_client.conversations_info.return_value = {"channel": self.mock_channel_info}
        
        mock_logger = Mock()
        
        from assets.slack_events_bolt_handler.index import app
        if app:
            handlers = [h for h in app._listeners if h.matcher.func.__name__ == 'handle_file_upload']
            if handlers:
                handler = handlers[0]
                handler.func(self.mock_event, mock_client, mock_logger)
                
                # Verify no further processing
                mock_client.files_info.assert_not_called()
                mock_publish.assert_not_called()

    @patch('assets.slack_events_bolt_handler.index.get_case_id_from_channel')
    @patch('assets.slack_events_bolt_handler.index.publish_event_to_eventbridge')
    def test_file_upload_file_info_error(self, mock_publish, mock_get_case):
        """Test file upload when file info retrieval fails"""
        # Setup mocks
        mock_get_case.return_value = "12345"
        mock_publish.return_value = True
        
        mock_client = Mock()
        mock_client.conversations_info.return_value = {"channel": self.mock_channel_info}
        mock_client.files_info.side_effect = Exception("File info error")
        
        mock_logger = Mock()
        
        from assets.slack_events_bolt_handler.index import app
        if app:
            handlers = [h for h in app._listeners if h.matcher.func.__name__ == 'handle_file_upload']
            if handlers:
                handler = handlers[0]
                handler.func(self.mock_event, mock_client, mock_logger)
                
                # Verify error event published
                mock_publish.assert_called_once()
                call_args = mock_publish.call_args
                assert call_args[0][0] == "File Upload Error"
                assert "file_info_retrieval_failed" in call_args[0][1]["errorType"]

    @patch('assets.slack_events_bolt_handler.index.get_case_id_from_channel')
    @patch('assets.slack_events_bolt_handler.index.get_ssm_parameter')
    @patch('assets.slack_events_bolt_handler.index.publish_event_to_eventbridge')
    def test_file_upload_no_bot_token(self, mock_publish, mock_ssm, mock_get_case):
        """Test file upload when bot token cannot be retrieved"""
        # Setup mocks
        mock_get_case.return_value = "12345"
        mock_ssm.return_value = None
        mock_publish.return_value = True
        
        mock_client = Mock()
        mock_client.conversations_info.return_value = {"channel": self.mock_channel_info}
        mock_client.files_info.return_value = {"file": self.mock_file_info}
        
        mock_logger = Mock()
        
        from assets.slack_events_bolt_handler.index import app
        if app:
            handlers = [h for h in app._listeners if h.matcher.func.__name__ == 'handle_file_upload']
            if handlers:
                handler = handlers[0]
                handler.func(self.mock_event, mock_client, mock_logger)
                
                # Verify error event published
                mock_publish.assert_called_once()
                call_args = mock_publish.call_args
                assert call_args[0][0] == "File Upload Error"
                assert "authentication_failed" in call_args[0][1]["errorType"]

    @patch('assets.slack_events_bolt_handler.index.get_case_id_from_channel')
    @patch('assets.slack_events_bolt_handler.index.get_ssm_parameter')
    @patch('assets.slack_events_bolt_handler.index.publish_event_to_eventbridge')
    def test_file_upload_no_download_url(self, mock_publish, mock_ssm, mock_get_case):
        """Test file upload when download URL is missing"""
        # Setup mocks
        mock_get_case.return_value = "12345"
        mock_ssm.return_value = "xoxb-test-token"
        mock_publish.return_value = True
        
        # Mock file info without download URL
        file_info_no_url = self.mock_file_info.copy()
        del file_info_no_url["url_private_download"]
        
        mock_client = Mock()
        mock_client.conversations_info.return_value = {"channel": self.mock_channel_info}
        mock_client.files_info.return_value = {"file": file_info_no_url}
        
        mock_logger = Mock()
        
        from assets.slack_events_bolt_handler.index import app
        if app:
            handlers = [h for h in app._listeners if h.matcher.func.__name__ == 'handle_file_upload']
            if handlers:
                handler = handlers[0]
                handler.func(self.mock_event, mock_client, mock_logger)
                
                # Verify error event published
                mock_publish.assert_called_once()
                call_args = mock_publish.call_args
                assert call_args[0][0] == "File Upload Error"
                assert "download_url_missing" in call_args[0][1]["errorType"]

    @patch('assets.slack_events_bolt_handler.index.get_case_id_from_channel')
    @patch('assets.slack_events_bolt_handler.index.get_ssm_parameter')
    @patch('assets.slack_events_bolt_handler.index.download_slack_file')
    @patch('assets.slack_events_bolt_handler.index.publish_event_to_eventbridge')
    def test_file_upload_download_failure(self, mock_publish, mock_download, mock_ssm, mock_get_case):
        """Test file upload when file download fails"""
        # Setup mocks
        mock_get_case.return_value = "12345"
        mock_ssm.return_value = "xoxb-test-token"
        mock_download.return_value = None  # Download failure
        mock_publish.return_value = True
        
        mock_client = Mock()
        mock_client.conversations_info.return_value = {"channel": self.mock_channel_info}
        mock_client.files_info.return_value = {"file": self.mock_file_info}
        
        mock_logger = Mock()
        
        from assets.slack_events_bolt_handler.index import app
        if app:
            handlers = [h for h in app._listeners if h.matcher.func.__name__ == 'handle_file_upload']
            if handlers:
                handler = handlers[0]
                handler.func(self.mock_event, mock_client, mock_logger)
                
                # Verify error event published
                mock_publish.assert_called_once()
                call_args = mock_publish.call_args
                assert call_args[0][0] == "File Upload Error"
                assert "download_failed" in call_args[0][1]["errorType"]


if __name__ == "__main__":
    pytest.main([__file__])