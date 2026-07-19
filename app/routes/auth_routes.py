from fastapi import APIRouter, HTTPException, status

# Authentication utility functions used by the API routes.
# These functions handle password security and JWT generation.
from app.auth import (
    create_access_token,
    hash_password,
    verify_password
)

# Pydantic models used to validate incoming requests
# and structure outgoing responses.
from app.models import (
    TokenResponse,
    UserLogin,
    UserRegister
)

# Create a dedicated router for authentication-related endpoints.
#
# prefix="/auth"
# Ensures all routes in this file are grouped under:
#   /auth/register
#   /auth/login
#
# tags=["Authentication"]
# Groups these endpoints together in Swagger UI for easier navigation.
router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)

# Temporary in-memory user store.
#
# This is used only during development and testing to validate
# the authentication workflow without introducing a database.
#
# IMPORTANT:
# - Data is lost whenever the application restarts.
# - This should be replaced with a DAO and persistent database
#   (PostgreSQL, Azure SQL, etc.) in a production environment.
users_database = {}


@router.post(
    "/register",
    status_code=status.HTTP_201_CREATED,
)
def register_user(user: UserRegister):
    """
    Register a new user.

    Workflow:
    1. Validate incoming registration data.
    2. Ensure the username does not already exist.
    3. Hash the user's password before storage.
    4. Store the user record.
    5. Return a success response.

    Security Notes:
    - Passwords are never stored in plain text.
    - Password hashing uses bcrypt via the auth utility layer.
    """

    # Prevent duplicate registrations.
    # Usernames serve as unique identifiers within the temporary
    # in-memory data store.
    if user.username in users_database:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already exists",
        )

    # Convert the plain-text password into a secure bcrypt hash.
    # Storing hashed passwords reduces the impact of data exposure.
    hashed_password = hash_password(user.password)

    # Store the user record.
    #
    # The username is used as the dictionary key to simplify lookups
    # during login authentication.
    users_database[user.username] = {
        "username": user.username,
        "hashed_password": hashed_password,
    }

    # Return a confirmation response.
    #
    # Never return passwords or password hashes to the client.
    return {
        "message": "User registered successfully",
        "username": user.username,
    }


@router.post(
    "/login",
    response_model=TokenResponse,
)
def login_user(user: UserLogin):
    """
    Authenticate a user and issue a JWT.

    Workflow:
    1. Locate the user record.
    2. Verify the provided password.
    3. Generate a JWT access token.
    4. Return the token to the client.

    Security Notes:
    - Invalid usernames and invalid passwords return the same error.
      This prevents attackers from discovering which usernames exist.
    - The JWT is later used to access protected routes.
    """

    # Attempt to locate the user in the temporary user store.
    stored_user = users_database.get(user.username)

    # Return a generic authentication failure if the user
    # does not exist.
    #
    # We intentionally avoid revealing whether the username
    # exists to reduce user-enumeration attacks.
    if stored_user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    # Compare the provided password against the stored bcrypt hash.
    password_is_valid = verify_password(
        user.password,
        stored_user["hashed_password"],
    )

    # Reject the login attempt if password verification fails.
    if not password_is_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    # Generate a signed JWT for the authenticated user.
    #
    # The token contains:
    # - User identity (subject)
    # - Expiration timestamp
    #
    # The token is signed using the application's secret key.
    token = create_access_token(user.username)

    # Return the JWT using the standard Bearer token format.
    #
    # Clients should include this token in the Authorization header:
    #
    # Authorization: Bearer <token>
    #
    # when accessing protected API routes.
    return {
        "access_token": token,
        "token_type": "bearer",
    }