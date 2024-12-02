import pdb
from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient

from app.main import app
from app.models.auth import TokenData
from app.models.user import UserBase


@pytest.mark.asyncio
@patch("app.api.routes.auth.get_user_by_username", new_callable=AsyncMock)
@patch("app.api.routes.auth.create_user", new_callable=AsyncMock)
@patch("app.api.routes.auth.send_verification_email", new_callable=AsyncMock)
@patch("app.api.routes.auth.get_password_hash", return_value="hashedpassword")
async def test_register_a_new_user(
    mock_get_password_hash,
    mock_send_verification_email,
    mock_create_user,
    mock_get_user_by_username,
):
    mock_get_user_by_username.return_value = None
    mock_create_user.return_value = {"status": "success", "user_id": "123"}

    user_data = {
        "full_name": "Jane Smith",
        "username": "newuser",
        "email": "newuser@example.com",
        "password": "password123",
        "biography": "Software developer with 10 years of experience.",
        "avatar": "avatar.png",
    }

    async with AsyncClient(app=app, base_url="http://localhost:3000") as client:
        response = await client.post("/api/auth/register", json=user_data)

    assert response.status_code == 201
    assert response.json() == {"message": "User created successfully"}
    mock_send_verification_email.assert_awaited_once_with("newuser@example.com")
    mock_create_user.assert_awaited_once()


@pytest.mark.asyncio
@patch("app.api.routes.auth.get_user_by_username", new_callable=AsyncMock)
async def test_register_a_new_user_username_taken(mock_get_user_by_username):
    mock_get_user_by_username.return_value = {"username": "existinguser"}

    user_data = {
        "full_name": "Jane Smith",
        "username": "existinguser",
        "email": "existinguser@example.com",
        "password": "password123",
        "biography": "Software developer with 10 years of experience.",
        "avatar": "avatar.png",
    }

    async with AsyncClient(app=app, base_url="http://localhost:3000") as client:
        response = await client.post("/api/auth/register", json=user_data)

    assert response.status_code == 400
    assert response.json() == {"detail": "Username is taken"}


@pytest.mark.asyncio
@patch("app.api.routes.auth.authenticate_user", new_callable=AsyncMock)
@patch("app.api.routes.auth.get_active_and_verified_user", new_callable=AsyncMock)
@patch("app.api.routes.auth.create_access_token", return_value="access_token_value")
async def test_login_for_access_token(
    mock_create_access_token, mock_get_active_and_verified_user, mock_authenticate_user
):
    user_data = {
        "full_name": "John Doe",
        "username": "testuser",
        "email": "test@example.com",
        "biography": "Test biography",
        "avatar": "avatar.png",
    }

    mock_authenticate_user.return_value = UserBase(**user_data)
    mock_get_active_and_verified_user.return_value = UserBase(**user_data)

    form_data = {
        "username": "testuser",
        "password": "password123",
    }

    async with AsyncClient(app=app, base_url="http://localhost:3000") as client:
        response = await client.post("/api/auth/login", data=form_data)

    assert response.status_code == 200
    assert response.json() == {
        "access_token": "access_token_value",
        "token_type": "bearer",
    }


@pytest.mark.asyncio
@patch("app.api.routes.auth.authenticate_user", new_callable=AsyncMock)
async def test_login_for_access_token_invalid_credentials(mock_authenticate_user):
    mock_authenticate_user.return_value = None

    form_data = {
        "username": "testuser",
        "password": "wrongpassword",
    }

    async with AsyncClient(app=app, base_url="http://localhost:3000") as client:
        response = await client.post("/api/auth/login", data=form_data)

    assert response.status_code == 401
    assert response.json() == {"detail": "Incorrect username or password"}


@pytest.mark.asyncio
@patch("app.api.routes.auth.invalidate_access_token")
async def test_logout(mock_invalidate_access_token):
    mock_invalidate_access_token.return_value = TokenData(username="testuser")

    async with AsyncClient(app=app, base_url="http://localhost:3000") as client:
        response = await client.post(
            "/api/auth/logout", cookies={"access_token": "valid_token"}
        )

    assert response.status_code == 200
    assert response.json() == {"message": "Logged out successfully"}
    mock_invalidate_access_token.assert_called_once_with("valid_token")


@pytest.mark.asyncio
async def test_logout_no_token():
    async with AsyncClient(app=app, base_url="http://localhost:3000") as client:
        response = await client.post("/api/auth/logout")

    assert response.status_code == 401
    assert response.json() == {"detail": "No access token found"}


@pytest.mark.asyncio
@patch("app.api.routes.auth.verify_email_by_token", new_callable=AsyncMock)
async def test_verify_token_sent_through_email(mock_verify_email_by_token):
    mock_verify_email_by_token.return_value = {"message": "Email verified successfully"}

    async with AsyncClient(app=app, base_url="http://localhost:3000") as client:
        response = await client.get("/api/auth/verify", params={"token": "valid_token"})

    assert response.status_code == 200
    assert response.json() == {"message": "Email verified successfully"}
    mock_verify_email_by_token.assert_awaited_once_with("valid_token")


@pytest.mark.asyncio
@patch("app.api.routes.auth.verify_email_by_token", new_callable=AsyncMock)
async def test_verify_token_sent_through_email_invalid_token(
    mock_verify_email_by_token,
):
    mock_verify_email_by_token.return_value = None

    async with AsyncClient(app=app, base_url="http://localhost:3000") as client:
        response = await client.get(
            "/api/auth/verify", params={"token": "invalid_token"}
        )

    assert response.status_code == 500
    assert response.json() == {"detail": "Error verifying email"}
