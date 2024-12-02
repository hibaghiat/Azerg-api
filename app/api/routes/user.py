import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Request, Response, status

from app.crud.auth import get_current_user, get_password_hash
from app.crud.user import (
    convert_to_user,
    convert_to_user_base,
    delete_user,
    get_user_by_id,
    get_user_limit,
    update_user,
    update_user_credits,
)
from app.models.user import (
    CreditReq,
    User,
    UserBase,
    UserInfo,
    UserRate,
    UserReq,
    UserRes,
)

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

router = APIRouter()


## GET /users/{user_id}/user - Retrieve the user with the specified user_id.
@router.get(
    "/{user_id}/user",
    summary="Retrieve the profile information from the access token.",
    response_model=UserInfo,
    status_code=status.HTTP_200_OK,
)
async def get_user_by_access_token(
    user_id: str, request: Request, response: Response
) -> dict:
    access_token = None
    # Extract access token from cookies
    if "access_token" in request.cookies:
        access_token = request.cookies["access_token"]
        verify_user_permission(await get_current_user(access_token), user_id)
    if not access_token:
        logger.error("No access token found")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="No access token found"
        )
    user = await get_user_by_id(user_id)
    if user:
        logger.info(f"User {user_id} retrieved their profile.")
        response = convert_to_user(user)
        return response
    logger.error(f"User {user_id} failed to retrieve user their profile.")
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")


## GET /users/{user_id}/profile - Retrieve the profile information of the authenticated user.
@router.get(
    "/{user_id}/profile",
    summary="Retrieve the profile information of the authenticated user.",
    response_model=UserBase,
    status_code=status.HTTP_200_OK,
)
async def get_user_profile(
    user_id: str, request: Request, response: Response
) -> UserBase:
    """get user profile for an authenticated user."""
    access_token = None
    # Extract access token from cookies
    if "access_token" in request.cookies:
        access_token = request.cookies["access_token"]
        verify_user_permission(await get_current_user(access_token), user_id)
    if not access_token:
        logger.error("No access token found")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="No access token found"
        )
    user = await get_user_by_id(user_id)
    if user:
        response = convert_to_user_base(user)
        logger.info(f"User {user_id} retrieved their profile.")
        return response
    logger.error(f"User {user_id} failed to retrieve user their profile.")
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")


## POST /users/{user_id}/profile - Modify the profile information of the authenticated user.
@router.post(
    "/{user_id}/profile",
    summary="Modify the profile information of the authenticated user.",
    response_model=UserRes,
    status_code=status.HTTP_200_OK,
)
async def update_user_profile(
    request: Request, response: Response, user_id: str, user: UserReq
) -> UserRes:
    access_token = None
    # Extract access token from cookies
    if "access_token" in request.cookies:
        access_token = request.cookies["access_token"]
        verify_user_permission(await get_current_user(access_token), user_id)
    if not access_token:
        logger.error("No access token found")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="No access token found"
        )
    if user.password:
        user.password = get_password_hash(user.password)
    else:
        response = await get_user_by_id(user_id)
        user.password = response.password

    response = await update_user(user_id, user)
    if response:
        logger.info(f"User {user_id} updated user {user_id} profile.")
        return response
    logger.error(f"User {user_id} failed to update user {user_id} profile.")
    raise HTTPException(status_code=405, detail="User not updated.")


## DELETE /users/{user_id} - Delete the user with the specified user_id.
@router.delete(
    "/{user_id}",
    summary="Delete the user with the specified user_id.",
    status_code=status.HTTP_200_OK,
)
async def remove_user(request: Request, response: Response, user_id: str) -> dict:
    access_token = None
    # Extract access token from cookies
    if "access_token" in request.cookies:
        access_token = request.cookies["access_token"]
        verify_user_permission(await get_current_user(access_token), user_id)
    if not access_token:
        logger.error("No access token found")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="No access token found"
        )
    response = await delete_user(user_id)
    if response:
        logger.info(f"User {user_id} deleted.")
        return response
    logger.error(f"Failed to delete user {user_id}.")
    raise HTTPException(status_code=405, detail="User not deleted.")


## GET /users/{user_id}/limits - Retrieve rate limits of the authenticated user.
@router.get(
    "/{user_id}/limits",
    summary="Retrieve rate limits of the authenticated user.",
    response_model=dict,
    status_code=status.HTTP_200_OK,
)
async def retrieve_user_limits(
    request: Request, response: Response, user_id: str
) -> dict:
    access_token = None
    # Extract access token from cookies
    if "access_token" in request.cookies:
        access_token = request.cookies["access_token"]
        verify_user_permission(await get_current_user(access_token), user_id)
    if not access_token:
        logger.error("No access token found")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="No access token found"
        )
    response = await get_user_limit(user_id)
    if response:
        logger.info(f"Retrieved user {user_id} limits.")
        return response
    logger.error(f"failed to retrieve user {user_id} limits.")
    raise HTTPException(status_code=404, detail="User not found.")


def verify_user_permission(auth_user: str, user_id: str) -> bool:
    if auth_user.user_id != user_id:
        logger.error(
            f"User {auth_user.user_id} does not have permission to access user {user_id} profile."
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User does not have permission to access user profile.",
        )
    return True
