import pytest
from unittest.mock import MagicMock
from datetime import datetime

@pytest.fixture
def mock_clients(mocker):
    # Create mock clients
    mock_security_ir = MagicMock()
    mock_lambda = MagicMock()
    mock_dynamodb = MagicMock()
    mock_events = MagicMock()
    

    # Test case/incident data
    test_incident = {
        'caseId': '1234565789',
        'lastUpdatedDate': datetime(2015, 1, 1),
        'title': 'Example Case',
        'caseArn': 'arn:aws:security-ir:0123456789012:case/1234565789',
        'engagementType': 'Security Incident',
        'caseStatus': 'Submitted',
        'createdDate': datetime(2015, 1, 1),
        'closedDate': datetime(2015, 1, 1),
        'resolverType': 'AWS',
        'pendingAction': 'Customer'
    }
    
    # Configure multiple mock responses for security-ir list_cases
    mock_security_ir.list_cases.side_effect = [
        # First call response with list of cases
        {
            'items': [test_incident],
        },
        # Second call response with an empty list
        {
            'items': []
        }
    ]
    
    # Configure multiple responses for get_case
    mock_security_ir.get_case.return_value = {
            'caseArn': 'arn:aws:security-ir:0123456789012:case/1234565789',
            'title': 'Example Case',
            'caseStatus': 'Submitted'
        }
    
    mock_security_ir.list_comments.return_value = {
        'items': []
    }
    
    # Configure DynamoDB mock responses
    mock_dynamodb.get_item.side_effect = [
        # First call response with Case Id 1234565789
        {
            'Item': {
                'PK': {'S': 'Case#1234565789'},
                'SK': {'S': 'latest'},
                'incidentDetails': {'S': '{}'}
            }
        },
        # Second call with no response
        {'Item': None},  # No existing item
    ]

    # Configure Lambda mock responses
    mock_lambda.get_function_configuration.return_value = {
        'Environment': {
            'Variables': {
                'FAST_POLLING_ENABLED': 'False',
                'PREVIOUS_POLLING_TIME': ''
            }
        }
    }
    
    mock_lambda.update_function_configuration.return_value = {}

    mock_events.put_rule.return_value = {}

    mock_dynamodb.put_item.return_value = {}
    
    # Mock boto3.client
    def mock_client(service_name, **kwargs):
        if service_name == 'security-ir':
            return mock_security_ir
        elif service_name == 'lambda':
            return mock_lambda
        elif service_name == 'dynamodb':
            return mock_dynamodb
        elif service_name == 'events':
            return mock_events
        return MagicMock()
    
    mocker.patch('boto3.client', side_effect=mock_client)
    
    return {
        'security_ir': mock_security_ir,
        'lambda': mock_lambda,
        'dynamodb': mock_dynamodb,
        'events': mock_events,
        'test_incident': test_incident
    }

@pytest.fixture
def lambda_context():
    context = MagicMock()
    context.function_name = "SecurityIncidentResponsePoller"
    return context

def test_get_incidents_from_security_ir(mock_clients):
    # Test different list_cases responses from security_ir
    from assets.security_ir_poller.index import get_incidents_from_security_ir

    # First call to get list of incidents from security_ir
    incidents1 = get_incidents_from_security_ir()
    assert len(incidents1) == 1
    assert incidents1[0]['caseId'] == '1234565789'

    # Second call to get empty list of incidents from security_ir
    incidents2 = get_incidents_from_security_ir()
    assert len(incidents2) == 0

    # Verify all calls were made
    assert mock_clients['security_ir'].list_cases.call_count == 2

def test_store_incidents_in_dynamodb(mock_clients):
    from assets.security_ir_poller.index import store_incidents_in_dynamodb
    
    incidents = [{
        'caseId': '1234565789',
        'lastUpdatedDate': datetime(2015, 1, 1),
        'title': 'Example Case',
        'caseArn': 'arn:aws:security-ir:0123456789012:case/1234565789',
        'engagementType': 'Security Incident',
        'caseStatus': 'Submitted',
        'createdDate': datetime(2015, 1, 1),
        'closedDate': datetime(2015, 1, 1),
        'resolverType': 'AWS',
        'pendingAction': 'Customer'
    }]
    
    result = store_incidents_in_dynamodb(incidents, 'test-table')
    assert result is True

def test_get_number_of_active_incidents():
    """Test counting active incidents"""
    from assets.security_ir_poller.index import get_number_of_active_incidents

    # Test case 1: Active incidents
    incidents = [{
        'caseId': '1234565789',
        'lastUpdatedDate': datetime(2015, 1, 1),
        'title': 'Example Case',
        'caseArn': 'arn:aws:security-ir:0123456789012:case/1234565789',
        'engagementType': 'Security Incident',
        'caseStatus': 'Submitted',
        'createdDate': datetime(2015, 1, 1),
        'closedDate': datetime(2015, 1, 1),
        'resolverType': 'AWS',
        'pendingAction': 'Customer'
    }]
    
    assert get_number_of_active_incidents(incidents) == 1

def test_update_polling_schedule_rate(mock_clients):
    """
    Test updating EventBridge rule schedule rate
    """
    from assets.security_ir_poller.index import update_polling_schedule_rate

    # Test parameters
    rule_name = 'test-rule'
    cron_expression = 'cron(*/1 * * * ? *)'

    # Call function
    response = update_polling_schedule_rate(rule_name, cron_expression)

    assert response == {}