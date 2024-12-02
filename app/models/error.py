from typing import Optional

from pydantic import BaseModel


class Error(BaseModel):
    error_id: str
    content: str
    user_id: str

    class Config:
        json_schema_extra = {
            "example": {
                "error_id": "aa00da96c64c4d3fce2a5a7050e8fecf",
                "content": "This is a sample error",
                "user_id": "9fb0d015-a211-44ba-a518-d6666392f489",
            }
        }


class ErrorReq(BaseModel):
    content: str

    class Config:
        json_schema_extra = {
            "example": {
                "content": "This is a sample error",
            }
        }


class ErrorRes(BaseModel):
    status: str
    message: str
    error_id: Optional[str] | None = None
    user_id: Optional[str] | None = None

    class Config:
        json_schema_extra = {
            "example": {
                "status": "success",
                "message": "Error reported successfully",
                "error_id": "35c2c4ab-610a-4089-9b49-8a4ff1e05112",
                "user_id": "1acc8c3a-f9db-4729-b723-01cda1c8192b",
            }
        }
