"""Tests for the IR team member merge feature in the Security IR Poller.

Tests cover:
- get_incident_response_team_members(): membership discovery and team extraction
- merge_ir_team_into_watchers(): deduplication and merge logic
- get_incident_details(): integration of team merge into case details
"""

import pytest
from unittest.mock import MagicMock, patch


@pytest.fixture
def mock_clients(mocker):
    """Set up mock AWS clients for testing team member merge functionality."""
    mock_security_ir = MagicMock()
    mock_dynamodb = MagicMock()
    mock_events = MagicMock()
    mock_lambda = MagicMock()

    def mock_client(service_name, **kwargs):
        if service_name == "security-ir":
            return mock_security_ir
        elif service_name == "dynamodb":
            return mock_dynamodb
        elif service_name == "events":
            return mock_events
        elif service_name == "lambda":
            return mock_lambda
        return MagicMock()

    mocker.patch("boto3.client", side_effect=mock_client)

    # Also patch the module-level clients that are already initialized
    mocker.patch("assets.security_ir_poller.index.security_ir_client", mock_security_ir)
    mocker.patch("assets.security_ir_poller.index.dynamodb_client", mock_dynamodb)
    mocker.patch("assets.security_ir_poller.index.events_client", mock_events)
    mocker.patch("assets.security_ir_poller.index.lambda_client", mock_lambda)

    return {
        "security_ir": mock_security_ir,
        "dynamodb": mock_dynamodb,
        "events": mock_events,
        "lambda": mock_lambda,
    }


# ─── Tests for get_incident_response_team_members ────────────────────────────


class TestGetIncidentResponseTeamMembers:
    """Tests for the get_incident_response_team_members function."""

    def test_returns_team_members_from_active_membership(self, mock_clients):
        """Should return team members from the active membership."""
        from assets.security_ir_poller.index import get_incident_response_team_members

        mock_clients["security_ir"].list_memberships.return_value = {
            "items": [
                {"membershipId": "m-active123", "membershipStatus": "Active"},
            ]
        }
        mock_clients["security_ir"].get_membership.return_value = {
            "incidentResponseTeam": [
                {"email": "henry.fonda@email.com", "name": "Henry Fonda", "jobTitle": "Father"},
                {"email": "jane.fonda@email.com", "name": "Jane Fonda", "jobTitle": "Daughter"},
            ]
        }

        result = get_incident_response_team_members()

        assert len(result) == 2
        assert result[0]["email"] == "henry.fonda@email.com"
        assert result[1]["email"] == "jane.fonda@email.com"
        mock_clients["security_ir"].get_membership.assert_called_once_with(
            membershipId="m-active123"
        )

    def test_skips_cancelled_membership(self, mock_clients):
        """Should skip cancelled memberships and use the active one."""
        from assets.security_ir_poller.index import get_incident_response_team_members

        mock_clients["security_ir"].list_memberships.return_value = {
            "items": [
                {"membershipId": "m-cancelled1", "membershipStatus": "Cancelled"},
                {"membershipId": "m-active123", "membershipStatus": "Active"},
                {"membershipId": "m-terminated1", "membershipStatus": "Terminated"},
            ]
        }
        mock_clients["security_ir"].get_membership.return_value = {
            "incidentResponseTeam": [
                {"email": "henry.fonda@email.com", "name": "Henry Fonda", "jobTitle": "Father"},
            ]
        }

        result = get_incident_response_team_members()

        assert len(result) == 1
        mock_clients["security_ir"].get_membership.assert_called_once_with(
            membershipId="m-active123"
        )

    def test_returns_empty_list_when_no_active_membership(self, mock_clients):
        """Should return empty list when no active membership exists."""
        from assets.security_ir_poller.index import get_incident_response_team_members

        mock_clients["security_ir"].list_memberships.return_value = {
            "items": [
                {"membershipId": "m-cancelled1", "membershipStatus": "Cancelled"},
                {"membershipId": "m-terminated1", "membershipStatus": "Terminated"},
            ]
        }

        result = get_incident_response_team_members()

        assert result == []
        mock_clients["security_ir"].get_membership.assert_not_called()

    def test_returns_empty_list_when_no_memberships(self, mock_clients):
        """Should return empty list when no memberships exist at all."""
        from assets.security_ir_poller.index import get_incident_response_team_members

        mock_clients["security_ir"].list_memberships.return_value = {"items": []}

        result = get_incident_response_team_members()

        assert result == []

    def test_returns_empty_list_on_api_error(self, mock_clients):
        """Should return empty list when API call fails (fail-safe)."""
        from assets.security_ir_poller.index import get_incident_response_team_members

        mock_clients["security_ir"].list_memberships.side_effect = Exception(
            "API Error"
        )

        result = get_incident_response_team_members()

        assert result == []

    def test_returns_empty_list_when_membership_has_no_team(self, mock_clients):
        """Should return empty list when membership exists but has no team members."""
        from assets.security_ir_poller.index import get_incident_response_team_members

        mock_clients["security_ir"].list_memberships.return_value = {
            "items": [
                {"membershipId": "m-active123", "membershipStatus": "Active"},
            ]
        }
        mock_clients["security_ir"].get_membership.return_value = {
            "incidentResponseTeam": []
        }

        result = get_incident_response_team_members()

        assert result == []


# ─── Tests for merge_ir_team_into_watchers ───────────────────────────────────


class TestMergeIrTeamIntoWatchers:
    """Tests for the merge_ir_team_into_watchers function."""

    def test_adds_team_members_to_empty_watchers(self, mock_clients):
        """Should add all team members when watchers list is empty."""
        from assets.security_ir_poller.index import merge_ir_team_into_watchers

        watchers = []
        team_members = [
            {"email": "henry.fonda@email.com", "name": "Henry Fonda", "jobTitle": "Father"},
            {"email": "jane.fonda@email.com", "name": "Jane Fonda", "jobTitle": "Daughter"},
        ]

        result = merge_ir_team_into_watchers(watchers, team_members)

        assert len(result) == 2
        assert result[0]["email"] == "henry.fonda@email.com"
        assert result[1]["email"] == "jane.fonda@email.com"

    def test_deduplicates_by_email_case_insensitive(self, mock_clients):
        """Should not add team members already in watchers (case-insensitive email match)."""
        from assets.security_ir_poller.index import merge_ir_team_into_watchers

        watchers = [
            {"email": "Peter.Fonda@email.com", "name": "Peter Fonda", "jobTitle": "Son"},
        ]
        team_members = [
            {"email": "henry.fonda@email.com", "name": "Henry Fonda", "jobTitle": "Father"},
            {"email": "jane.fonda@email.com", "name": "Jane Fonda", "jobTitle": "Daughter"},
            {"email": "peter.fonda@email.com", "name": "Peter Fonda", "jobTitle": "Son"},
        ]

        result = merge_ir_team_into_watchers(watchers, team_members)

        # Peter deduplicated (case-insensitive), so only Henry and Jane added
        assert len(result) == 3
        # Original watcher preserved (with original casing)
        assert result[0]["email"] == "Peter.Fonda@email.com"
        assert result[0]["name"] == "Peter Fonda"
        # Henry and Jane added
        assert result[1]["email"] == "henry.fonda@email.com"
        assert result[2]["email"] == "jane.fonda@email.com"

    def test_returns_original_watchers_when_no_team_members(self, mock_clients):
        """Should return original watchers unchanged when team_members is empty."""
        from assets.security_ir_poller.index import merge_ir_team_into_watchers

        watchers = [
            {"email": "peter.fonda@email.com", "name": "Peter Fonda", "jobTitle": "Son"},
        ]

        result = merge_ir_team_into_watchers(watchers, [])

        assert result == watchers

    def test_returns_original_watchers_when_team_members_none(self, mock_clients):
        """Should return original watchers when team_members is None-ish (empty)."""
        from assets.security_ir_poller.index import merge_ir_team_into_watchers

        watchers = [
            {"email": "peter.fonda@email.com", "name": "Peter Fonda", "jobTitle": "Son"},
        ]

        result = merge_ir_team_into_watchers(watchers, [])

        assert result is watchers  # Same reference, not modified

    def test_skips_team_members_with_empty_email(self, mock_clients):
        """Should skip team members that have no email address."""
        from assets.security_ir_poller.index import merge_ir_team_into_watchers

        watchers = []
        team_members = [
            {"email": "", "name": "No Email", "jobTitle": "Ghost"},
            {"email": "henry.fonda@email.com", "name": "Henry Fonda", "jobTitle": "Father"},
        ]

        result = merge_ir_team_into_watchers(watchers, team_members)

        assert len(result) == 1
        assert result[0]["email"] == "henry.fonda@email.com"

    def test_preserves_all_existing_watchers(self, mock_clients):
        """Should not modify or remove existing watchers."""
        from assets.security_ir_poller.index import merge_ir_team_into_watchers

        watchers = [
            {"email": "peter.fonda@email.com", "name": "Peter Fonda", "jobTitle": "Son"},
            {"email": "bridget.fonda@email.com", "name": "Bridget Fonda", "jobTitle": "GrandDaughter"},
        ]
        team_members = [
            {"email": "henry.fonda@email.com", "name": "Henry Fonda", "jobTitle": "Father"},
        ]

        result = merge_ir_team_into_watchers(watchers, team_members)

        assert len(result) == 3
        assert result[0] == watchers[0]
        assert result[1] == watchers[1]
        assert result[2]["email"] == "henry.fonda@email.com"

    def test_does_not_mutate_original_watchers_list(self, mock_clients):
        """Should not modify the original watchers list."""
        from assets.security_ir_poller.index import merge_ir_team_into_watchers

        watchers = [
            {"email": "peter.fonda@email.com", "name": "Peter Fonda", "jobTitle": "Son"},
        ]
        original_len = len(watchers)
        team_members = [
            {"email": "henry.fonda@email.com", "name": "Henry Fonda", "jobTitle": "Father"},
        ]

        merge_ir_team_into_watchers(watchers, team_members)

        assert len(watchers) == original_len


# ─── Tests for get_incident_details with team merge ──────────────────────────


class TestGetIncidentDetailsWithTeamMerge:
    """Tests for get_incident_details including the team member merge."""

    def test_merges_team_members_into_case_watchers(self, mock_clients):
        """Should merge IR team members into case watchers in the returned details."""
        from assets.security_ir_poller.index import get_incident_details

        mock_clients["security_ir"].get_case.return_value = {
            "caseId": "case-123",
            "title": "Test Case",
            "watchers": [
                {"email": "peter.fonda@email.com", "name": "Peter Fonda", "jobTitle": "Son"},
            ],
        }
        mock_clients["security_ir"].list_comments.return_value = {"items": []}
        mock_clients["security_ir"].list_memberships.return_value = {
            "items": [
                {"membershipId": "m-active123", "membershipStatus": "Active"},
            ]
        }
        mock_clients["security_ir"].get_membership.return_value = {
            "incidentResponseTeam": [
                {"email": "henry.fonda@email.com", "name": "Henry Fonda", "jobTitle": "Father"},
            ]
        }

        result = get_incident_details("case-123")

        assert len(result["watchers"]) == 2
        assert result["watchers"][0]["email"] == "peter.fonda@email.com"
        assert result["watchers"][1]["email"] == "henry.fonda@email.com"
        assert result["caseComments"] == []

    def test_returns_original_watchers_when_no_membership(self, mock_clients):
        """Should return original watchers when membership lookup returns empty."""
        from assets.security_ir_poller.index import get_incident_details

        mock_clients["security_ir"].get_case.return_value = {
            "caseId": "case-123",
            "title": "Test Case",
            "watchers": [
                {"email": "peter.fonda@email.com", "name": "Peter Fonda", "jobTitle": "Son"},
            ],
        }
        mock_clients["security_ir"].list_comments.return_value = {"items": []}
        mock_clients["security_ir"].list_memberships.return_value = {"items": []}

        result = get_incident_details("case-123")

        assert len(result["watchers"]) == 1
        assert result["watchers"][0]["email"] == "peter.fonda@email.com"

    def test_handles_case_with_no_watchers(self, mock_clients):
        """Should add team members even when case has no watchers."""
        from assets.security_ir_poller.index import get_incident_details

        mock_clients["security_ir"].get_case.return_value = {
            "caseId": "case-123",
            "title": "Test Case",
            "watchers": [],
        }
        mock_clients["security_ir"].list_comments.return_value = {"items": []}
        mock_clients["security_ir"].list_memberships.return_value = {
            "items": [
                {"membershipId": "m-active123", "membershipStatus": "Active"},
            ]
        }
        mock_clients["security_ir"].get_membership.return_value = {
            "incidentResponseTeam": [
                {"email": "henry.fonda@email.com", "name": "Henry Fonda", "jobTitle": "Father"},
            ]
        }

        result = get_incident_details("case-123")

        assert len(result["watchers"]) == 1
        assert result["watchers"][0]["email"] == "henry.fonda@email.com"
