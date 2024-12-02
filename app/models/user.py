from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr, Field


class UserRes(BaseModel):
    status: str
    message: str
    user_id: str | None = None

    class Config:
        json_schema_extra = {
            "example": {
                "status": "success",
                "message": "User created successfully",
                "user_id": "60b8f1f7b5f9b3b9d5f9b3b9",
            }
        }


class UserBase(BaseModel):
    full_name: str
    username: str
    email: EmailStr
    biography: str | None = None
    avatar: str | None = None


class UserReq(UserBase):
    password: str | None = None

    class Config:
        json_schema_extra = {
            "example": {
                "full_name": "John Doe",
                "username": "johndoe",
                "email": "johndoe@example.com",
                "password": "johndoe",
                "biography": "Software developer with 10 years of experience.",
                "avatar": "avatar.png",
            }
        }


class User(UserReq):
    user_id: str
    credits: int
    is_active: bool
    is_verified: bool
    is_admin: bool
    date_created: datetime
    date_updated: datetime


class UserRate(BaseModel):
    status: str
    message: str
    user_id: str | None = None
    rate: int | None = None

    class Config:
        json_schema_extra = {
            "example": {"user_id": "60b8f1f7b5f9b3b9d5f9b3b9", "rate": 5}
        }


class CreditReq(BaseModel):
    credits: int | None = None

    class Config:
        json_schema_extra = {"example": {"credits": 5}}


class UserInfo(BaseModel):
    user_id: str
    credits: int
    is_active: bool
    is_verified: bool
    is_admin: bool
    date_created: datetime
    date_updated: datetime

class EmailReq(BaseModel):
    email: EmailStr

    class Config:
        json_schema_extra = {"example": {"email": "johndoe@example.com"}}

