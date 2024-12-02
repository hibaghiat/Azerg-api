from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel


class Relation(BaseModel):
    uuid: str
    relationship_type: str
    source_ref: str
    target_ref: str

    class Config:
        json_schema_extra = {
            "example": {
                "uuid": "e26b24a6-6b26-427d-afb1-ec304f2b5058",
                "relationship_type": "targets",
                "source_ref": "db6f7de6-3bbd-4626-a03f-10f3e10b9930",
                "target_ref": "7b0a3e23-60b4-40e1-9e85-f18898a2f6ba",
            },
        }


class Entity(BaseModel):
    uuid: str
    type: str
    name: str
    pattern: Optional[str] | None = None
    country: Optional[str] | None = None

    class Config:
        json_schema_extra = {
            "example": {
                "uuid": "61866c4a-a186-4413-af39-7567ba7d426d",
                "type": "indicator",
                "name": "fileless.aspx",
                "pattern": "file:name",
                "country": "North Korea",
            }
        }


class ReportParagraph(BaseModel):
    uuid: str
    content: str


class ReportCall(BaseModel):
    uuid: str
    content: str


class ReportLink(BaseModel):
    paragraph: str
    calls: List[str]


class VersionHistory(BaseModel):
    version_id: datetime
    paragraphs: List[ReportParagraph]
    calls: List[ReportCall]
    links: List[ReportLink]


class Report(BaseModel):
    report_id: str
    title: str
    hash: str
    timestamp: datetime
    file_path: str
    user_id: str
    vendor: Optional[str] | None = None
    tags: List[str]
    history: List[VersionHistory]
    status: str


class ReportGraph(BaseModel):
    report_id: str
    title: str
    hash: str
    entities: List[Entity]
    relations: List[Relation]


class ReportRes(BaseModel):
    status: str
    message: str

    class Config:
        json_schema_extra = {
            "example": {
                "status": "success",
                "message": "Report is being processed",
            }
        }


class ContentReq(BaseModel):
    content: str

    class Config:
        json_schema_extra = {"example": {"content": "This is a paragraph."}}


class ReportReq(BaseModel):
    paragraphs: List[ContentReq]
    calls: List[ContentReq]
    links: List[ReportLink]

    class Config:
        json_schema_extra = {
            "example": {
                "paragraphs": [
                    {"content": "First paragraph"},
                    {"content": "Second paragraph"},
                ],
                "calls": [
                    {"content": "First call"},
                    {"content": "Second call"},
                ],
                "links": [
                    {"paragraph": "1", "calls": ["1", "2"]},
                    {"paragraph": "2", "calls": ["1"]},
                ],
            }
        }
