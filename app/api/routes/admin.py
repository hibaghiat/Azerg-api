import logging
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status

from app.api.routes.auth import get_current_user
from app.api.routes.user import update_user_credits
from app.crud.error import delete_error, get_error_by_id, get_errors_by_user_id
from app.crud.report import get_all_reports
from app.crud.user import (
    activate_user,
    get_current_user,
    get_user_by_id,
    get_users_by_query,
    get_users_with_pagination,
    is_admin,
)
from app.crud.utils import authenticate_admin
from app.models.error import Error, ErrorReq, ErrorRes
from app.models.report import Report
from app.models.user import CreditReq, User, UserRate

router = APIRouter()

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@router.get(
    "/errors/{error_id}",
    summary="Get an error by error_id.",
    response_model=Error,
    status_code=status.HTTP_200_OK,
)
async def retrieve_errors_by_id(
    error_id: str, request: Request, response: Response
) -> Error:
    """Get an error by error_id."""
    await authenticate_admin(request)
    response = await get_error_by_id(error_id)
    logger.info(f"Error retrieved successfully: {response}")
    return response


@router.get(
    "/errors/user/{user_id}",
    summary="Get errors by user_id.",
    response_model=List[Error],
    status_code=status.HTTP_200_OK,
)
async def retrieve_errors_by_user_id(
    user_id: str, request: Request, response: Response
) -> List[Error]:
    """Get errors by user_id."""
    await authenticate_admin(request)
    response = await get_errors_by_user_id(user_id)
    logger.info(f"Errors retrieved successfully: {response}")
    return response


@router.delete(
    "/errors/{error_id}",
    summary="Delete an error by error_id.",
    status_code=status.HTTP_200_OK,
)
async def remove_error_by_id(error_id: str, request: Request, response: Response):
    """Delete an error by error_id."""
    await authenticate_admin(request)
    response = await delete_error(error_id)
    logger.info(f"Error deleted successfully")
    return response


@router.get(
    "/users/search",
    summary="Search users by email or name with pagination.",
    response_model=List[User],
    status_code=status.HTTP_200_OK,
)
async def search_users(
    request: Request,
    query: Optional[str] = Query(None, description="Search query for email or name"),
    limit: int = Query(10, description="Limit the number of results per page"),
    page: int = Query(1, description="Page number"),
) -> List[User]:
    await authenticate_admin(request)
    try:
        users = await get_users_by_query(query=query, limit=limit, page=page)
        logger.info("Users retrieved successfully")
        return users
    except Exception as e:
        logger.error("An error occurred while searching users")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while searching users.",
        )


@router.get(
    "/reports",
    summary="Get all reports with pagination.",
    response_model=List[Report],
    status_code=status.HTTP_200_OK,
)
async def get_all_reports_route(
    request: Request,
    response: Response,
    skip: int = Query(0, description="Number of reports to skip"),
    limit: int = Query(10, description="Number of reports to retrieve"),
):
    """Get all reports with pagination."""
    # access_token = request.cookies.get("access_token")
    user = await authenticate_admin(request)
    reports = await get_all_reports(skip=skip, limit=limit)
    logger.info(f"Reports retrieved successfully: {reports}")
    return reports


@router.get(
    "/users",
    summary="List all users with pagination.",
    response_model=List[User],
    status_code=status.HTTP_200_OK,
)
async def list_users_with_pagination(
    request: Request,
    response: Response,
    limit: int = Query(10, description="Limit the number of results per page"),
    page: int = Query(1, description="Page number"),
) -> List[User]:
    # Check access token
    await authenticate_admin(request)
    try:
        users = await get_users_with_pagination(limit=limit, page=page)
        logger.info(f"Users retrieved successfully: {users}")
        return users
    except Exception as e:
        logger.error(f"An error occurred while retrieving users: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while retrieving users.",
        )


# Toggle active status of a specific user.
@router.post(
    "/users/{user_id}/activate",
    summary="Toggle active status of a specific user.",
    status_code=status.HTTP_200_OK,
)
async def toggle_active_status(user_id: str, request: Request):
    await authenticate_admin(request)
    try:
        # Check if the user exists
        user = await get_user_by_id(user_id)
        if not user:
            logger.error(f"User not found")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found."
            )
        # Activate the user
        await activate_user(user_id)
        return {"detail": "User activated successfully"}
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"An error occurred while activating user: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while activating user.",
        )


# Update rate limits of the authenticated user.
@router.put(
    "/users/{user_id}/limits",
    summary="Update rate limits of the authenticated user.",
    response_model=UserRate,
    status_code=status.HTTP_200_OK,
)
async def update_user_limits(
    user_id: str, credits: CreditReq, request: Request, response: Response
) -> UserRate:
    await authenticate_admin(request)
    response = await update_user_credits(user_id, credits)
    if response:
        logger.info(f"Updated user {user_id} limits.")
        return response
    logger.error(f"Failed to update user {user_id} limits.")
    raise HTTPException(status_code=405, detail="User limits not updated.")