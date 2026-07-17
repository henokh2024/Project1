"""
Authentication Utilities

This module contains reusable security functions for:

- Loading JWT configuration from environment variables
- Hashing user passwords
- Verifying passwords during login
- Creating short-lived JWT access tokens
- Validating JWTs for protected routes
- Identifying the currently authenticated user

Route files should call these functions instead of implementing
password or token logic directly.
"""

import os
from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext


# Load configuration values from the local .env file.
#
# In Azure, these values can later come from App Service settings
# or Azure Key Vault instead of a local file.
load_dotenv()


# Read JWT configuration from environment variables rather than
# hardcoding secrets in the source code.
#
# JWT_SECRET_KEY:
# Signs tokens and verifies that they were issued by this application.
#
# JWT_ALGORITHM:
# Defines the signing algorithm used to create and validate tokens.
#
# ACCESS_TOKEN_EXPIRE_MINUTES:
# Controls how long an issued access token remains valid.
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(
    os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30")
)


# Stop application startup when the secret key is missing.
#
# Authentication should never operate without a signing key because
# tokens could not be created or validated securely.
if not JWT_SECRET_KEY:
    raise RuntimeError("JWT_SECRET_KEY is not configured")


# Configure bcrypt as the password-hashing algorithm.
#
# Passwords must never be stored in plain text. Bcrypt generates
# salted hashes that can be safely stored and later verified.
password_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
)


# Configure FastAPI to extract Bearer tokens from the
# Authorization header of protected requests.
#
# Example header:
# Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
#
# tokenUrl tells FastAPI and Swagger where users obtain a token.
# It does not perform the login itself.
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/auth/login"
)


def hash_password(password: str) -> str:
    """
    Convert a plain-text password into a secure bcrypt hash.

    This function is called during registration before the password
    is stored. The original password must never be saved.

    Args:
        password: The plain-text password supplied by the user.

    Returns:
        A salted bcrypt password hash.
    """
    return password_context.hash(password)


def verify_password(
    plain_password: str,
    hashed_password: str,
) -> bool:
    """
    Verify a login password against a previously stored hash.

    Passlib applies bcrypt to the entered password using the settings
    embedded in the stored hash. The original password does not need
    to be decrypted or recovered.

    Args:
        plain_password: The password entered during login.
        hashed_password: The bcrypt hash stored during registration.

    Returns:
        True when the password matches; otherwise, False.
    """
    return password_context.verify(
        plain_password,
        hashed_password,
    )


def create_access_token(username: str) -> str:
    """
    Create a signed, short-lived JWT for an authenticated user.

    The token contains two claims:

    - sub: Identifies the authenticated user.
    - exp: Defines when the token expires.

    Sensitive information such as passwords must never be stored
    inside the JWT payload because JWT payloads can be decoded by
    anyone who possesses the token.

    Args:
        username: The identity to store as the token subject.

    Returns:
        A signed JWT string.
    """

    # Use UTC to ensure token expiration behaves consistently
    # regardless of the server's physical location or time zone.
    expiration_time = datetime.now(timezone.utc) + timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    )

    # Build the claims that will be included in the JWT.
    token_payload = {
        "sub": username,
        "exp": expiration_time,
    }

    # Sign the token with the application's secret key.
    #
    # The signature allows the API to detect whether the payload
    # was modified after the token was issued.
    token = jwt.encode(
        token_payload,
        JWT_SECRET_KEY,
        algorithm=JWT_ALGORITHM,
    )

    return token


def verify_access_token(token: str) -> str:
    """
    Validate a JWT and return the authenticated username.

    Validation includes:

    - Checking the token signature
    - Confirming the expected signing algorithm
    - Checking the expiration time
    - Confirming that a subject claim exists

    Args:
        token: The Bearer token extracted from the request.

    Returns:
        The username stored in the token's subject claim.

    Raises:
        HTTPException: When the token is invalid, expired, altered,
        or missing the required subject claim.
    """

    # Define one consistent authentication error response.
    #
    # Returning the same response for all token failures avoids
    # exposing unnecessary security details to the client.
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        # Decode and validate the token.
        #
        # python-jose automatically verifies the signature and
        # expiration claim during this operation.
        payload = jwt.decode(
            token,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
        )

        # Retrieve the authenticated user's identity.
        username = payload.get("sub")

        # Reject tokens that do not identify a user, even when
        # their signature and expiration are otherwise valid.
        if username is None:
            raise credentials_exception

        return username

    except JWTError as error:
        # Convert token-library errors into a standard HTTP 401
        # response that FastAPI can send to the client.
        raise credentials_exception from error


def get_current_user(
    token: str = Depends(oauth2_scheme),
) -> str:
    """
    Extract and validate the JWT for a protected FastAPI route.

    FastAPI first uses oauth2_scheme to read the Bearer token from
    the Authorization header. The token is then validated by
    verify_access_token().

    Routes that include:

        current_user: str = Depends(get_current_user)

    are accessible only when a valid JWT is supplied.

    Args:
        token: The Bearer token automatically extracted by FastAPI.

    Returns:
        The username of the authenticated user.
    """
    return verify_access_token(token)