"""
Pytest configuration for ServiceNow acceptance tests.
"""

import pytest


def pytest_addoption(parser):
    """Add command line options for ServiceNow credentials."""
    parser.addoption(
        "--service-now-url",
        action="store",
        required=False,
        default=None,
        help="ServiceNow instance URL (e.g., https://dev12345.service-now.com)",
    )
    parser.addoption(
        "--service-now-username",
        action="store",
        required=False,
        default=None,
        help="ServiceNow admin username",
    )
    parser.addoption(
        "--service-now-password",
        action="store",
        required=False,
        default=None,
        help="ServiceNow admin password",
    )
    parser.addoption(
        "--integration-module",
        action="store",
        default="itsm",
        help="ServiceNow integration module: itsm or ir (default: itsm)",
    )
