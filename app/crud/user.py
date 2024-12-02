import os
import uuid
from datetime import UTC, datetime, timedelta, timezone
from typing import Annotated, List

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pymongo import MongoClient
from pymongo.collection import Collection

from app.config.db import users_collection
from app.config.schemas import all_users_data, individual_user_data
from app.config.settings import settings
from app.crud.utils import generate_uuid
from app.models.auth import TokenData
from app.models.user import User, UserBase, UserInfo, UserRate, UserReq

# Retrieve settings for secret key and algorithm
SECRET_KEY = settings.SECRET_KEY
ALGORITHM = settings.ALGORITHM


async def get_current_user(token: str) -> User:
    """Get the current user based on the provided JWT token."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        # Decode the JWT token and extract username
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception

    # Retrieve user from database
    user = await get_user_by_username(username=token_data.username)
    if user is None:
        raise credentials_exception

    return User(**user.dict())


async def get_active_and_verified_user(
    current_user: User = Depends(get_current_user),
) -> User:
    """Get the current active and verified user."""
    if not current_user.is_verified:
        raise HTTPException(status_code=400, detail="User has not been verified")
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")

    return current_user


async def create_user(user: UserReq) -> dict:
    """Create a new user."""
    try:
        user_dict = {
            "user_id": generate_uuid(),
            **user.dict(),
            "credits": 10,
            "is_active": False,
            "is_verified": False,
            "is_admin": False,
            "date_created": datetime.now(UTC),
            "date_updated": datetime.now(UTC),
        }

        # Insert the user document into the collection
        result = await users_collection.insert_one(user_dict)

        # Check if the insert operation was successful
        if result.inserted_id:
            return {
                "status": "success",
                "message": "User inserted successfully.",
                "user_id": user_dict["user_id"],
            }
        else:
            return {"status": "failure", "message": "User insertion failed."}
    except Exception as e:
        # Handle exceptions and return an error message
        return {"status": "error", "message": "An error occurred while adding user."}


async def get_user_by_username(username: str) -> User:
    """Retrieve a user by username from the database."""
    user_data = await users_collection.find_one({"username": username})
    if user_data:
        return User(**user_data)


async def get_user_by_id(user_id: str) -> User:
    """Retrieve a user by user ID from the database."""
    user_data = await users_collection.find_one({"user_id": user_id})
    if user_data:
        return User(**user_data)


async def get_user_by_email(email: str) -> User:
    """Retrieve a user by user ID from the database."""
    user_data = await users_collection.find_one({"email": email})
    if user_data:
        return User(**user_data)


async def update_user(user_id: str, user: UserBase) -> dict:
    try:
        # Update the user document in the collection
        result = await users_collection.update_one(
            {"user_id": user_id},
            {"$set": user.dict()},
        )

        # Check if the update operation was successful
        if result.modified_count > 0:
            return {
                "status": "success",
                "message": "User updated successfully.",
                "user_id": user_id,
            }
        else:
            return {"status": "failure", "message": "User update failed."}
    except Exception as e:
        # Handle exceptions and return an error message
        return {"status": "error", "message": "An error occurred while updating user"}


async def get_user_limit(user_id: str) -> dict:
    try:
        user_data = await users_collection.find_one(
            {"user_id": user_id}, {"credits": 1}
        )
        if user_data:
            return {
                "status": "success",
                "message": "User rate limit retrieved successfully.",
                "user_id": user_id,
                "credits": user_data["credits"],
            }
        else:
            return {
                "status": "failure",
                "message": "User rate limit retrieval failed.",
                "user_id": user_id,
                "credits": None,
            }
    except Exception as e:
        return {
            "status": "error",
            "message": "An error occurred while fetching user rate limit.",
        }


async def update_user_credits(user_id: str, user_rate: UserRate) -> dict:
    try:
        # Update the user document in the collection
        result = await users_collection.update_one(
            {"user_id": user_id},
            {"$set": {"credits": user_rate.credits}},
        )

        # Check if the update operation was successful
        if result.modified_count > 0:
            return {
                "status": "success",
                "message": "User rate limit updated successfully.",
                "user_id": user_id,
                "rate": user_rate.credits,
            }
        else:
            return {"status": "failure", "message": "User rate limit update failed."}
    except Exception as e:
        return {
            "status": "error",
            "message": "An error occurred while updating user rate limit.",
        }


async def delete_user(user_id: str) -> dict:
    try:
        # Delete the user document from the collection
        result = await users_collection.delete_one({"user_id": user_id})

        # Check if the delete operation was successful
        if result.deleted_count > 0:
            return {
                "status": "success",
                "message": "User deleted successfully.",
                "user_id": user_id,
            }
        else:
            return {"status": "failure", "message": "User deletion failed."}
    except Exception as e:
        # Handle exceptions and return an error message
        return {"status": "error", "message": "An error occurred while deleting user."}


async def get_non_admin_users() -> List[User]:
    """Retrieve all non-admin users."""
    users = await users_collection.find({"is_admin": False}, {"_id": 0}).to_list(
        length=1000
    )
    return [User(**user) for user in users]


def convert_to_user_base(user: User) -> UserBase:
    return UserBase(
        full_name=user.full_name,
        username=user.username,
        email=user.email,
        biography=user.biography,
        avatar=user.avatar,
        date_created=user.date_created,
        date_updated=user.date_updated,
    )


async def is_admin(user_id: str) -> bool:
    user = await get_user_by_id(user_id)
    return user.is_admin


async def get_users_with_pagination(limit: int, page: int):
    skip = (page - 1) * limit
    cursor = users_collection.find({"is_admin": False}).skip(skip).limit(limit)
    users = await cursor.to_list(length=limit)
    return users


async def get_non_admin_users_count():
    return await users_collection.count_documents({"is_admin": False})


async def get_users_by_query(query: str, limit: int, page: int):
    skip = (page - 1) * limit
    query_filter = {
        "$or": [
            {"email": {"$regex": query, "$options": "i"}},
            {"full_name": {"$regex": query, "$options": "i"}},
        ]
    }
    cursor = users_collection.find(query_filter).skip(skip).limit(limit)
    users = await cursor.to_list(length=limit)
    return [User(**user) for user in users]


async def activate_user(user_id: str) -> dict:
    try:
        # Update the user document in the collection
        is_active = await users_collection.find_one(
            {"user_id": user_id}, {"is_active": 1}
        )
        result = await users_collection.update_one(
            {"user_id": user_id},
            {"$set": {"is_active": not is_active["is_active"]}},
        )

        # Check if the update operation was successful
        if result.modified_count > 0:
            return {
                "status": "success",
                "message": "User activated status updated successfully.",
                "user_id": user_id,
            }
        else:
            return {
                "status": "failure",
                "message": "User activated status update failed.",
            }
    except Exception as e:
        return {
            "status": "error",
            "message": "An error occurred while updating the user activated status.",
        }


def convert_to_user(user: User):
    return UserInfo(
        user_id=user.user_id,
        credits=user.credits,
        is_active=user.is_active,
        is_verified=user.is_verified,
        is_admin=user.is_admin,
        date_created=user.date_created,
        date_updated=user.date_updated,
    )
