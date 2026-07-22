import logging
import os
from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext

# Import the function that retrieves secrets from Azure Key Vault.
from app.keyvault import get_secret


# Load local environment variables from the .env file.
# This is mainly useful during local development.
load_dotenv()
logger = logging.getLogger(__name__)

def load_jwt_secret() -> str:
    """
    Load the JWT signing secret.

    First:
        Try to retrieve the secret from Azure Key Vault.

    Fallback:
        If Key Vault is unavailable during local development,
        retrieve JWT_SECRET_KEY from the local environment.

    The application stops if neither source provides a secret.
    """

    try:
        # Retrieve the secret named "jwt-secret-key" from Azure Key Vault.
        jwt_secret = get_secret("jwt-secret-key")
        logger.info(
            "JWT signing secret loaded from Azure key Vault"
        )
        return jwt_secret
    except Exception as key_vault_error:
        logger.warning(
            "Key Vault retrieval failed. Using local fallback. Error: %s",
            key_vault_error,
        )

        # Key Vault may be unavailable locally if Azure authentication
        # or network access is not configured.

        local_secret = os.getenv("JWT_SECRET_KEY")

        # Do not allow the application to start without a secure JWT secret.
        if not local_secret:
            raise RuntimeError(
                "JWT_SECRET_KEY could not be retrieved from Azure Key Vault "
                "and JWT_SECRET_KEY is not configured in the environment."
            ) from key_vault_error
        logger.info(
            "JWT signing secret loaded from environment fallback."
         )

        # Use the local .env secret only as a development fallback.
        return local_secret


# Load the JWT secret when the application starts.
JWT_SECRET_KEY = load_jwt_secret()

# The algorithm used to sign and verify JWT tokens.
JWT_ALGORITHM = os.getenv(
    "JWT_ALGORITHM",
    "HS256",
)

# The number of minutes before an access token expires.
ACCESS_TOKEN_EXPIRE_MINUTES = int(
    os.getenv(
        "ACCESS_TOKEN_EXPIRE_MINUTES",
        "30",
    )
)


# Configure bcrypt for password hashing.
password_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
)


# Extract the Bearer token from the Authorization header.
#
# tokenUrl tells FastAPI Swagger where users should log in
# to obtain an access token.
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/auth/login",
)


def validate_bcrypt_password_length(password: str) -> None:
    """
    Validate that a password does not exceed bcrypt's 72-byte limit.

    We check bytes instead of characters because some Unicode characters
    use more than one byte when encoded with UTF-8.

    Raises:
        ValueError if the password is longer than 72 bytes.
    """

    password_length_in_bytes = len(
        password.encode("utf-8")
    )

    if password_length_in_bytes > 72:
        raise ValueError(
            "Password must not exceed 72 bytes when using bcrypt."
        )


def hash_password(password: str) -> str:
    """
    Convert a plain-text password into a secure bcrypt hash.

    The password length is validated before bcrypt processes it.
    """

    validate_bcrypt_password_length(password)

    return password_context.hash(password)


def verify_password(
    plain_password: str,
    hashed_password: str,
) -> bool:
    """
    Compare a plain-text password with a stored bcrypt hash.

    Returns:
        True when the password matches.
        False when it does not match.

    Raises:
        ValueError if the submitted password exceeds 72 bytes.
    """

    validate_bcrypt_password_length(plain_password)

    return password_context.verify(
        plain_password,
        hashed_password,
    )


def create_access_token(username: str) -> str:
    """
    Create a signed JWT access token for an authenticated user.
    """

    # Calculate when the token should expire.
    expiration_time = datetime.now(timezone.utc) + timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    )

    # Store the username and expiration time inside the token.
    token_payload = {
        "sub": username,
        "exp": expiration_time,
    }

    # Sign the token using the secret retrieved from Key Vault
    # or the local environment fallback.
    token = jwt.encode(
        token_payload,
        JWT_SECRET_KEY,
        algorithm=JWT_ALGORITHM,
    )

    return token


def verify_access_token(token: str) -> str:
    """
    Decode and validate a JWT access token.

    Returns:
        The username stored in the token.

    Raises:
        HTTP 401 if the token is invalid, missing required data,
        incorrectly signed, or expired.
    """

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        # Decode the token using the same secret and algorithm
        # that were used when the token was created.
        payload = jwt.decode(
            token,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
        )

        # The "sub" claim contains the authenticated username.
        username = payload.get("sub")

        # Reject tokens that do not identify a user, even when
        # their signature and expiration are otherwise valid.
        if username is None:
            raise credentials_exception

        return username

    except JWTError as error:
        raise credentials_exception from error


def get_current_user(
    token: str = Depends(oauth2_scheme),
) -> str:
    """
    FastAPI dependency used to protect endpoints.

    It extracts the Bearer token from the request,
    verifies it, and returns the authenticated username.
    """

    return verify_access_token(token)
