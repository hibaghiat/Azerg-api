import os
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pymongo import MongoClient
from pymongo.collection import Collection

from app.config.db import users_collection
from app.config.schemas import all_users_data, individual_user_data
from app.config.settings import settings
from app.crud.user import (
    get_active_and_verified_user,
    get_current_user,
    get_user_by_email,
    get_user_by_username,
    update_user,
)
from app.models.auth import TokenData
from app.models.user import User, UserBase
from app.utils.redis_utils import check_token_and_get_email

# Get settings from config
SECRET_KEY = settings.SECRET_KEY
ALGORITHM = settings.ALGORITHM
ACCESS_TOKEN_EXPIRE_DAYS = 30

# CryptContext for password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 password bearer for token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/token")


def verify_password(plain_password, password) -> bool:
    """Verify the provided plain password matches the hashed password."""
    return pwd_context.verify(plain_password, password)


def get_password_hash(password) -> str:
    """Hash the provided password."""
    return pwd_context.hash(password)


async def authenticate_user(username: str, password: str) -> User | bool:
    """Authenticate a user with provided username and password."""
    user = await get_user_by_username(username)
    print(user)
    if not user:
        return False
    if not verify_password(password, user.password):
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    """Create an access token with provided data."""
    expire = datetime.now(UTC) + timedelta(days=ACCESS_TOKEN_EXPIRE_DAYS)
    data.update({"exp": expire})
    encoded_jwt: str = jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

    return encoded_jwt


def invalidate_access_token(token: str) -> TokenData:
    """Invalidate the provided access token."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if not username:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token data"
            )
        return TokenData(username=username)
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
        )


async def verify_email_by_token(token: str) -> dict:
    """Verify the email associated with the provided token."""
    email = check_token_and_get_email(token)
    if email:
        user = await get_user_by_email(email)
        user.is_verified = True
        await update_user(user.user_id, user)
        return {"message": "Email has been verified"}
    return None
