"""
Pydantic Data Models

This module defines the request and response schemas used by the
authentication layer of the application.

FastAPI uses these models to:

- Validate incoming request data
- Reject invalid input automatically
- Generate OpenAPI/Swagger documentation
- Ensure API responses follow a consistent structure

These models represent the contract between API clients and the backend.
"""

from pydantic import BaseModel, Field


class UserRegister(BaseModel):
    """
    Request model for user registration.

    This model defines the data required when a new user creates
    an account.

    Validation Rules:
    - Username must be between 3 and 50 characters.
    - Password must contain at least 8 characters.

    Example Request:
    {
        "username": "henok",
        "password": "password123"
    }
    """

    # Usernames act as unique identifiers in the current
    # authentication implementation.
    #
    # The minimum length helps prevent meaningless usernames,
    # while the maximum length avoids excessively large inputs.
    username: str = Field(
        min_length=3,
        max_length=50
    )

    # Require a minimum password length to encourage stronger
    # credentials and reduce weak-password usage.
    password: str = Field(
        min_length=8
    )


class UserLogin(BaseModel):
    """
    Request model for user authentication.

    This model represents the credentials submitted when a user
    attempts to log in.

    Example Request:
    {
        "username": "henok",
        "password": "password123"
    }
    """

    # Username supplied by the user during login.
    username: str

    # Plain-text password supplied by the user.
    #
    # This password is never stored directly. It is compared
    # against a previously stored bcrypt hash.
    password: str


class TokenResponse(BaseModel):
    """
    Response model returned after successful authentication.

    This ensures all login responses follow the same structure.

    Example Response:
    {
        "access_token": "eyJhbGciOiJIUzI1NiIs...",
        "token_type": "bearer"
    }

    Clients should store the access token and include it in
    subsequent requests using:

        Authorization: Bearer <token>
    """

    # JWT issued after successful login.
    access_token: str

    # Authentication scheme used by the API.
    #
    # The value is expected to be:
    #     "bearer"
    #
    # This helps clients construct the Authorization header
    # correctly for protected routes.
    token_type: str