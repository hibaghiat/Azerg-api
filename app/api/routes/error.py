import logging

from fastapi import APIRouter, HTTPException, Request, Response, status

from app.crud.error import add_error
from app.crud.user import get_current_user
from app.models.error import ErrorReq, ErrorRes

router = APIRouter()

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@router.post("/report", summary="Report an error.", status_code=status.HTTP_201_CREATED)
async def report_error(
    error: ErrorReq, request: Request, response: Response
) -> ErrorRes:
    """Report an error."""
    access_token = request.cookies.get("access_token")
    if not access_token:
        logger.error("No access token found")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="User is not logged in"
        )

    user = await get_current_user(access_token)
    error_response = await add_error(error, user.user_id)

    if error_response["status"] == "success":
        logger.info(f"Error reported successfully: {error_response}")
        return error_response

    response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    logger.error(f"Error reporting failed: {error_response}")
    return error_response
