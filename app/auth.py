import os
from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from app.keyvault import get_secret_from_key_vault

load_dotenv()


def load_jwt_secret() -> str:
    """
    Load the JWT signing secret.

    Azure:
        Retrieve the secret from Azure Key Vault.

    Local fallback:
        Read JWT_SECRET_KEY from the local .env file.
    """

    key_vault_url = os.getenv("KEY_VAULT_URL")

    if key_vault_url:
        return get_secret_from_key_vault("JWT-SECRET-KEY")

    local_secret = os.getenv("JWT_SECRET_KEY")

    if not local_secret:
        raise RuntimeError(
            "JWT secret is unavailable. Configure KEY_VAULT_URL "
            "or JWT_SECRET_KEY."
        )

    return local_secret


JWT_SECRET_KEY = load_jwt_secret()

JWT_ALGORITHM = os.getenv(
    "JWT_ALGORITHM",
    "HS256",
)

ACCESS_TOKEN_EXPIRE_MINUTES = int(
    os.getenv(
        "ACCESS_TOKEN_EXPIRE_MINUTES",
        "30",
    )
)


password_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
)

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/auth/login"
)

def hash_password(password: str) -> str:
    return password_context.hash(password)


def verify_password(
    plain_password: str,
    hashed_password: str,
) -> bool:
    return password_context.verify(
        plain_password,
        hashed_password,
    )





def create_access_token(username: str) -> str:
    expiration_time = datetime.now(timezone.utc) + timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    )

    token_payload = {
        "sub": username,
        "exp": expiration_time,
    }

    token = jwt.encode(
        token_payload,
        JWT_SECRET_KEY,
        algorithm=JWT_ALGORITHM,
    )

    return token


def verify_access_token(token: str) -> str:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(
            token,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
        )

        username = payload.get("sub")

        if username is None:
            raise credentials_exception

        return username

    except JWTError:
        raise credentials_exception
    
def get_current_user(
        token: str = Depends(oauth2_scheme),
) -> str: 
    return verify_access_token(token)