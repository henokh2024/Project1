from fastapi import APIRouter, Depends

# Import the authentication dependency responsible for:
# 1. Extracting the JWT from the Authorization header.
# 2. Validating the JWT signature and expiration.
# 3. Returning the authenticated username.
#
# Any route using this dependency automatically becomes protected.
from app.auth import get_current_user


# Create a dedicated router for incident-related endpoints.
#
# prefix="/incidents"
# All routes in this file will begin with:
#   /incidents
#
# tags=["Incidents"]
# Groups these endpoints together in Swagger UI.
router = APIRouter(
    prefix="/incidents",
    tags=["Incidents"],
)


@router.get("/")
def get_incidents(
    current_user: str = Depends(get_current_user)
):
    """
    Retrieve incident information for authenticated users.

    Authentication Flow:
    --------------------
    1. Client sends a JWT in the Authorization header.
    2. FastAPI executes get_current_user().
    3. The JWT is validated.
    4. The username is extracted from the token.
    5. The route executes only if authentication succeeds.

    Current Implementation:
    -----------------------
    This endpoint returns placeholder incident data to demonstrate
    route protection and JWT authentication.

    Future Enhancements:
    --------------------
    - Retrieve incidents from a database.
    - Support incident creation and updates.
    - Add role-based authorization.
    - Integrate incident telemetry into Azure Monitor.
    """

    # current_user contains the username extracted from the JWT.
    #
    # Example:
    # If the JWT was created for user "X",
    # current_user will contain:
    #
    #     "X"
    #
    # This allows future business logic to return
    # user-specific incident data.
    return {
        "message": "Protected incident data retrieved",

        # Useful during development and testing to verify
        # that authentication is functioning correctly.
        "authenticated_user": current_user,

        # Placeholder response.
        #
        # In future phases this will likely be replaced with
        # records from PostgreSQL or another persistent store.
        "incidents": []
    }