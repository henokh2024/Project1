from fastapi import APIRouter, HTTPException, status

from app.auth import (
     create_access_token,
     hash_password,
     verify_password

)

from app.models import (
    TokenResponse,
    UserLogin,
    UserRegister

)

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)

users_database = {}

@router.post(
    "/register",
    status_code=status.HTTP_201_CREATED,
)
def register_user(user: UserRegister):
    if user.username in users_database:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already exists",
        )

    hashed_password = hash_password(user.password)

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
def login_user(user: UserLogin):
    stored_user = users_database.get(user.username)

    if stored_user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    password_is_valid = verify_password(
        user.password,
        stored_user["hashed_password"],
    )

    if not password_is_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    token = create_access_token(user.username)

    return {
        "access_token": token,
        "token_type": "bearer",
    }