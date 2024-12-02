from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException, status
from jose import jwt

from app.config.settings import settings
from app.crud.auth import (
    authenticate_user,
    create_access_token,
    invalidate_access_token,
    verify_email_by_token,
)
from app.models.auth import TokenData
from app.models.user import User

# Get settings from config
SECRET_KEY = settings.SECRET_KEY
ALGORITHM = settings.ALGORITHM
ACCESS_TOKEN_EXPIRE_DAYS = 30


@pytest.mark.asyncio
async def test_authenticate_user():
    # Mocking the get_user_by_username function
    with patch("app.crud.auth.get_user_by_username") as mock_get_user:
        # Create a mock user
        mock_user = User(
            user_id="40424098-6655-4e91-b492-5ec01db425f0",
            full_name="John Doe",
            username="johndoe",
            email="johndoe@example.com",
            password="$2b$12$/35bUyHQNOKhnaWsEOhrQ.AC3xHTo/lhIE2r0uMPV/8nl6.YFK0qK",
            is_active=True,
            is_verified=True,
            is_admin=False,
            credits=100,
            biography="Test biography",
            avatar="test_avatar.png",
            date_created=datetime.now(UTC),
            date_updated=datetime.now(UTC),
        )

        # Case: User exists and password matches
        mock_get_user.return_value = mock_user
        authenticated_user = await authenticate_user("johndoe", "password123")
        assert authenticated_user == mock_user

        # Case: User does not exist
        mock_get_user.return_value = None
        authenticated_user = await authenticate_user("nonexistentuser", "password123")
        assert authenticated_user is False

        # Case: Password does not match
        mock_user.password = (
            "$2b$12$cHu65zCdalOOEjkL2WRl6O7ToPkNJcoGSJidUAiA8ue2amudE4fga"
        )
        mock_get_user.return_value = mock_user
        authenticated_user = await authenticate_user("johndoe", "password123")
        assert authenticated_user is False


def test_create_access_token():
    data = {"sub": "testuser"}
    access_token = create_access_token(data)
    assert isinstance(access_token, str)

    # Decode the token to verify its contents
    decoded_token = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
    assert decoded_token["sub"] == "testuser"
    assert "exp" in decoded_token

    # Check if the token expiration is set correctly
    expire = datetime.now(UTC) + timedelta(days=ACCESS_TOKEN_EXPIRE_DAYS)
    assert decoded_token["exp"] == pytest.approx(expire.timestamp(), rel=1e-2)


@pytest.mark.parametrize(
    "username, expected_token_data",
    [("testuser", TokenData(username="testuser")), ("", None)],
)
def test_invalidate_access_token(username, expected_token_data):
    token = create_access_token({"sub": username})
    try:
        token_data = invalidate_access_token(token)
        if expected_token_data:
            assert token_data.username == expected_token_data.username
        else:
            assert token_data == expected_token_data
    except HTTPException as e:
        assert expected_token_data is None
        assert e.status_code == status.HTTP_401_UNAUTHORIZED
        assert e.detail == "Invalid token data"


def test_invalidate_access_token_invalid_token():
    invalid_token = "invalidtoken"
    with pytest.raises(HTTPException) as excinfo:
        invalidate_access_token(invalid_token)
    assert excinfo.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert excinfo.value.detail == "Invalid token"


@pytest.mark.asyncio
async def test_verify_email_by_token():
    # Mocking the check_token_and_get_email function
    with patch("app.crud.auth.check_token_and_get_email") as mock_check_token:
        # Case: Token is valid and email exists
        mock_check_token.return_value = "testuser@example.com"
        mock_get_user_by_email = MagicMock()
        mock_get_user_by_email.user_id = "test_user_id"
        mock_get_user_by_email.is_verified = False
        with patch(
            "app.crud.auth.get_user_by_email", return_value=mock_get_user_by_email
        ):
            with patch("app.crud.auth.update_user") as mock_update_user:
                response = await verify_email_by_token("validtoken")
                assert response == {"message": "Email has been verified"}
                mock_update_user.assert_called_once_with(
                    "test_user_id", mock_get_user_by_email
                )

        # Case: Token is invalid or email does not exist
        mock_check_token.return_value = None
        response = await verify_email_by_token("invalidtoken")
        assert response is None
