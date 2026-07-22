from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm

from app.auth import (
    create_access_token,
    hash_password,
    verify_password,
)

from app.models import (
    TokenResponse,
    UserRegister,
)


router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)


# Temporary in-memory user storage.
#
# Important:
# All registered users disappear when the FastAPI application restarts.
users_database = {}


@router.post(
    "/register",
    status_code=status.HTTP_201_CREATED,
)
def register_user(user: UserRegister):
    """
    Register a new user.

    The endpoint:
    1. Checks whether the username already exists.
    2. Hashes the plain-text password.
    3. Stores the username and hashed password.
    """

    # Prevent two users from registering the same username.
    if user.username in users_database:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already exists",
        )

    # Convert the plain-text password into a secure bcrypt hash.
    hashed_password = hash_password(user.password)

    # Store the username and hashed password.
    #
    # The original plain-text password is never stored.
    users_database[user.username] = {
        "username": user.username,
        "hashed_password": hashed_password,
    }

    return {
        "message": "User registered successfully",
        "username": user.username,
    }


@router.post(
    "/login",
    response_model=TokenResponse,
)
def login_user(
    form_data: OAuth2PasswordRequestForm = Depends(),
):
    """
    Authenticate a user and return a JWT access token.

    OAuth2PasswordRequestForm is used because Swagger's Authorize
    button sends the username and password as form data instead of JSON.
    """

    # Look for the submitted username in the user database.
    stored_user = users_database.get(form_data.username)

    # Do not reveal whether the username or password was incorrect.
    if stored_user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={
                "WWW-Authenticate": "Bearer",
            },
        )

    # Compare the submitted password with the stored bcrypt hash.
    password_is_valid = verify_password(
        form_data.password,
        stored_user["hashed_password"],
    )

    if not password_is_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={
                "WWW-Authenticate": "Bearer",
            },
        )

    # Create a signed JWT containing the authenticated username.
    token = create_access_token(
        form_data.username
    )

    return {
        "access_token": token,
        "token_type": "bearer",
    }
