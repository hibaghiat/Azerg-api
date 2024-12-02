import logging
from datetime import datetime, timedelta
import hashlib

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel

from app.config.schemas import all_users_data, individual_user_data
from app.crud.auth import (
    authenticate_user,
    create_access_token,
    get_password_hash,
    invalidate_access_token,
    verify_email_by_token,
    verify_password
)
from app.crud.user import (
    create_user,
    get_active_and_verified_user,
    get_current_user,
    get_user_by_username,
)
from app.models.auth import Token, TokenData, PasswordValidationRequest
from app.models.user import EmailReq, User, UserBase, UserReq
from app.utils.email_utils import send_password_reset_email, send_verification_email

# OAuth2 scheme for password bearer authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/token")

# Number of days before an access token expires
ACCESS_TOKEN_EXPIRE_DAYS = 30

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize router for authentication routes
router = APIRouter()


# Route for registering a new user
@router.post(
    "/register", summary="Register a new user.", status_code=status.HTTP_201_CREATED
)
async def register_a_new_user(user: UserReq) -> dict:
    # Check if the username is already taken
    existing_user = await get_user_by_username(user.username)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Username is taken"
        )

    # Hash the password
    user.password = get_password_hash(user.password)

    await send_verification_email(user.email)

    # Attempt to create the user
    response = await create_user(user)

    # Check if user creation was successful
    if response["status"] == "success" and response["user_id"]:
        logger.info(f"User created with id: {response['user_id']}")
        return {"message": "User created successfully"}
    else:
        logger.error("Error creating user; database error")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=response
        )


# Route for logging in and obtaining an access token
@router.post(
    "/login",
    summary="Login a user and obtain an access token.",
    status_code=status.HTTP_200_OK,
    response_model=Token,
)
async def login_for_access_token(
    response: Response, form_data: OAuth2PasswordRequestForm = Depends()
) -> dict:
    # Authenticate user
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        logger.error("Error logging in; user does not exist")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check if the user is active
    user = await get_active_and_verified_user(user)

    # Generate access token
    access_token = create_access_token(
        data={"sub": user.username, "user_id": user.user_id}
    )

    # Set access token as a cookie
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=False,
        max_age=ACCESS_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
        secure=False,
        samesite="strict",
    )
    logger.info("User with username: " + user.username + " successfully logged in")
    return {"access_token": access_token, "token_type": "bearer"}


# Route for logging out and invalidating the access token
@router.post(
    "/logout", summary="Logout out the current user.", status_code=status.HTTP_200_OK
)
async def logout(
    request: Request,
    response: Response,
) -> dict:
    access_token = None
    # Extract access token from cookies
    if "access_token" in request.cookies:
        access_token = request.cookies["access_token"]
    if not access_token:
        logger.error("No access token found")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="No access token found"
        )

    # Invalidate access token
    token_data = invalidate_access_token(access_token)

    # Remove access token from cookies
    response.delete_cookie("access_token")
    logger.info("User with id: " + token_data.username + " successfully logged out")
    return {"message": "Logged out successfully"}


@router.get(
    "/verify",
    summary="Verify a token sent through email.",
    status_code=status.HTTP_200_OK,
)
async def verify_token_sent_through_email(request: Request) -> dict:
    token = request.query_params.get("token")
    if not token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Token is required"
        )
    # Verify the token
    response = await verify_email_by_token(token)
    if not response:
        logger.error("Error verifying email")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error verifying email",
        )
    return {"message": "Email verified successfully"}


# Route for sending a verification email to the user
@router.post(
    "/email",
    summary="Send a verification email to the user.",
    status_code=status.HTTP_200_OK,
)
async def send_verification_email_for_user(request: EmailReq) -> dict:
    response = await send_verification_email(request.email)
    if not response:
        logger.error("Error sending verification email")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error sending email",
        )
    return {"message": "Verification email sent successfully"}


@router.post(
    "/validate-password",
    summary="Validate a password against the stored hash for the authenticated user.",
    status_code=status.HTTP_200_OK,
)
async def validate_password(request_data: PasswordValidationRequest, request: Request):
    current_password = request_data.current_password

    try:
        access_token = request.cookies.get("access_token")

        if access_token is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="No access token found"
            )

        user = await get_current_user(access_token)

        if not verify_password(current_password, user.password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Provided password does not match the stored hash"
            )

        logger.info("Provided password matches the stored hash")
        return True

    except HTTPException as http_exception:
        raise http_exception
    except Exception as e:
        logger.error(f"Error validating password: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error validating password",
        )