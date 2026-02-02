"""
Domain models for Service Now
"""

import logging

# Configure logging
logger = logging.getLogger()


# TODO: update the models/fields during the mapping implementation of Security Incident Response to Service Now fields
# TODO: see https://app.asana.com/1/8442528107068/project/1209571477232011/task/1210466353172377?focus=true
class Incident:
    """Domain model for a Service Now incident."""

    def __init__(self, incident_id, title, description, status):
        """Initialize an Incident.

        Args:
            incident_id (str): Incident ID
            title (str): Incident title
            description (str): Incident description
            status (str): Incident status
        """
        self.incident_id = incident_id
        self.title = title
        self.description = description
        self.status = status

    def to_dict(self):
        """Convert the incident to a dictionary.

        Returns:
            dict: Dictionary representation of the incident
        """
        return {
            "incidentId": self.incident_id,
            "title": self.title,
            "description": self.description,
            "status": self.status,
        }
