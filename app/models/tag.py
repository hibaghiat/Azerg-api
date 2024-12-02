from typing import List

from pydantic import BaseModel


class TagRes(BaseModel):
    """Response model for tag operations."""

    status: str
    message: str
    tag_id: str | None = None
    user_id: str | None = None

    class Config:
        json_schema_extra = {
            "example": {
                "status": "success",
                "message": "Tag created successfully",
                "tag_id": "2f25ba45-9449-427e-8913-9d0dbe361e7c",
                "user_id": "e3b7c006-6171-42a2-9f03-47630d0cfe63",
            }
        }


class TagReq(BaseModel):
    """Request model for tag operations."""

    tag_name: str
    tag_description: str | None = None

    class Config:
        json_schema_extra = {
            "example": {
                "tag_name": "Python",
                "tag_description": "Python programming language",
            }
        }


class TagItem(BaseModel):
    """Model for a tag item."""

    tag_id: str
    tag_name: str
    tag_description: str | None = None
    user_id: str

    class Config:
        json_schema_extra = {
            "example": {
                "tag_id": "2f25ba45-9449-427e-8913-9d0dbe361e7c",
                "tag_name": "Python",
                "tag_description": "Python programming language",
                "user_id": "e3b7c006-6171-42a2-9f03-47630d0cfe63",
            }
        }
