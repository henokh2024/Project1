from fastapi import APIRouter, Depends, HTTPException, status

from app.auth import get_current_user
from app.models import IncidentCreate, IncidentResponse


router = APIRouter(
    prefix="/incidents",
    tags=["Incidents"],
)


# Temporary in-memory storage for incidents.
#
# The information will disappear whenever the application restarts.
# A real production application would use a database.
incidents_database = []


@router.get(
    "/",
    response_model=list[IncidentResponse],
)
def get_incidents(
    current_user: str = Depends(get_current_user),
):
    """
    Return all incidents.

    A valid JWT token is required because this endpoint
    uses the get_current_user dependency.
    """

    return incidents_database


@router.post(
    "/",
    response_model=IncidentResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_incident(
    incident: IncidentCreate,
    current_user: str = Depends(get_current_user),
):
    """
    Create a new incident.

    A valid JWT token is required.
    """

    # Only allow the supported severity values.
    allowed_severities = {
        "low",
        "medium",
        "high",
        "critical",
    }

    # Convert the submitted severity to lowercase so values
    # such as "HIGH" and "High" are treated as "high".
    normalized_severity = incident.severity.lower()

    if normalized_severity not in allowed_severities:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Severity must be low, medium, high, or critical."
            ),
        )

    # Generate the next incident ID.
    #
    # The first incident receives ID 1, the second receives ID 2,
    # and so on.
    incident_id = len(incidents_database) + 1

    # Build the complete incident record.
    new_incident = {
        "id": incident_id,
        "title": incident.title,
        "description": incident.description,
        "severity": normalized_severity,
        "status": "open",
        "created_by": current_user,
    }

    # Save the incident in temporary memory.
    incidents_database.append(new_incident)

    return new_incident
