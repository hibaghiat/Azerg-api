import logging
import uuid

from fastapi import Depends, HTTPException, Request, status

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def generate_uuid() -> str:
    """Generate a unique user ID."""
    return str(uuid.uuid4())


async def authenticate_admin(request: Request) -> str:
    from app.crud.user import get_current_user, is_admin

    """Authenticate admin user."""
    access_token = None
    # Extract access token from cookies
    if "access_token" in request.cookies:
        access_token = request.cookies["access_token"]
        user = await get_current_user(access_token)
        if not await is_admin(user.user_id):
            logger.error("Unauthorized access")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized access"
            )
    if not access_token:
        logger.error("No access token found")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="No access token found"
        )
    return access_token
