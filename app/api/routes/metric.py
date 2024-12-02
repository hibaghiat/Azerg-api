import logging

from fastapi import APIRouter, HTTPException, Request, Response, status

from app.crud.error import get_errors_count as retrieve_errors_count
from app.crud.report import get_reports_count as retrieve_reports_count
from app.crud.report import get_status_counts
from app.crud.user import get_current_user
from app.crud.user import get_non_admin_users_count as retrieve_users_count
from app.crud.user import is_admin
from app.crud.utils import authenticate_admin

router = APIRouter()

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@router.get(
    "/users/count",
    summary="Get the total number of users (admin only).",
    response_model=int,
    status_code=status.HTTP_200_OK,
)
async def get_non_admin_users_count(request: Request, response: Response):
    """Get the total number of non-admin users."""

    # Authenticate admin user
    await authenticate_admin(request)
    response = await retrieve_users_count()
    logger.info("Total number of non-admin users retrieved successfully")
    return response


@router.get(
    "/reports/count",
    summary="Get the total number of reports (admin only).",
    response_model=int,
    status_code=status.HTTP_200_OK,
)
async def get_reports_count(request: Request, response: Response):
    """Get the total number of reports."""

    # Authenticate admin user
    await authenticate_admin(request)
    response = await retrieve_reports_count()
    logger.info("Total number of non-admin users retrieved successfully")
    return response


## get the total number of errors
@router.get(
    "/errors/count",
    summary="Get the total number of errors (admin only).",
    response_model=int,
    status_code=status.HTTP_200_OK,
)
async def get_errors_count(request: Request, response: Response):
    """Get the total number of errors."""
    # Authenticate admin user
    await authenticate_admin(request)
    response = await retrieve_errors_count()
    logger.info("Total number of errors retrieved successfully")
    return response


@router.get(
    "/users/search/count",
    summary="Get the total number of searched users (admin only).",
    response_model=int,
    status_code=status.HTTP_200_OK,
)
async def get_query_users_count(request: Request, response: Response, query: str):
    """Get the total number of non-admin users."""
    # Authenticate admin user
    await authenticate_admin(request)
    response = await get_searched_users_count(query)
    logger.info("Total number of searched users retrieved successfully")
    return response


@router.get(
    "/reports/status/count",
    summary="Get the total number for the reports status",
    response_model=dict,
    status_code=status.HTTP_200_OK,
)
async def get_reports_status_counts(response: Response):
    """Get the total number of reports for each status."""
    response = await get_status_counts()
    logger.info("Total number of reports status retrieved successfully")
    return response
