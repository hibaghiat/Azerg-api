import asyncio
import datetime
from typing import List

import redis
from fastapi import FastAPI
from fastapi_mail import ConnectionConfig, FastMail, MessageSchema, MessageType
from pydantic import BaseModel, EmailStr

from app.config.settings import settings
from app.utils.redis_utils import generate_unique_token, store_token_in_redis

conf = ConnectionConfig(
    MAIL_USERNAME=settings.MAIL_USERNAME,
    MAIL_PASSWORD=settings.MAIL_PASSWORD,
    MAIL_FROM=settings.MAIL_FROM,
    MAIL_PORT=settings.MAIL_PORT,
    MAIL_SERVER=settings.MAIL_SERVER,
    MAIL_STARTTLS=settings.MAIL_STARTTLS,
    MAIL_SSL_TLS=settings.MAIL_SSL_TLS,
    USE_CREDENTIALS=settings.USE_CREDENTIALS,
    VALIDATE_CERTS=settings.VALIDATE_CERTS,
)

fm = FastMail(conf)


async def send_verification_email(email: str) -> dict:

    random_token = generate_unique_token()
    store_token_in_redis(random_token, email)

    html = await email_html(
        html_path="/app/templates/email-verification-template.html",
        random_token=random_token,
    )

    message = MessageSchema(
        subject="Email Verification",
        recipients=[email],
        body=html,
        subtype=MessageType.html,
    )

    await fm.send_message(message)
    return {"message": "email has been sent"}


async def send_password_reset_email(email: str) -> dict:

    random_token = generate_unique_token()
    store_token_in_redis(random_token)

    html = email_html(
        html_path="/app/templates/password-reset-template.html",
        random_token=random_token,
    )

    message = MessageSchema(
        subject="Password Reset",
        recipients=[email],
        body=html,
        subtype=MessageType.html,
    )

    await fm.send_message(message)
    return {"message": "email has been sent"}


async def email_html(html_path: str, random_token: str):
    with open(html_path, "r") as file:
        html_content = file.read()

    verification_link = f"http://localhost:3000/api/auth/verify?token={random_token}"
    html_content = html_content.replace("{{action_url}}", verification_link)
    return html_content
