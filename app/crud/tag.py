from typing import List

from app.config.db import tags_collection
from app.crud.report import update_report_tags
from app.crud.utils import generate_uuid
from app.models.tag import TagItem, TagReq, TagRes


async def add_tag(tag: TagReq, report_id: str, user_id: str) -> TagRes:
    try:
        # Check if the tag already exists
        existing_tag = await tags_collection.find_one(
            {"tag_name": tag.tag_name, "user_id": user_id}, {"_id": 0}
        )

        if existing_tag:
            tag_id = existing_tag["tag_id"]
            # Add tag_id to the report's tags array
            await update_report_tags(report_id, tag_id)
            return {
                "status": "success",
                "message": "Tag already exists. Added tag ID to the report.",
                "tag_id": tag_id,
                "user_id": user_id,
            }

        # If tag doesn't exist, create a new tag
        tag_id = generate_uuid()
        tag_dict = {"tag_id": tag_id, **tag.dict(), "user_id": user_id}
        result = await tags_collection.insert_one(tag_dict)
        if result.inserted_id:
            # Add the new tag_id to the report's tags array
            await update_report_tags(report_id, tag_id)
            return {
                "status": "success",
                "message": "Tag inserted and added to the report successfully.",
                "tag_id": tag_id,
                "user_id": user_id,
            }
        else:
            return {"status": "failure", "message": "Tag insertion failed."}
    except Exception as e:
        return {"status": "error", "message": "An error occurred while adding tag."}


async def update_tag(tag_id: str, tag: TagReq, user_id: str) -> TagRes:
    try:
        tag_dict = tag.dict()
        tag_dict["user_id"] = user_id
        result = await tags_collection.update_one(
            {"tag_id": tag_id}, {"$set": tag_dict}
        )
        if result.matched_count > 0:
            if result.modified_count > 0:
                return {
                    "status": "success",
                    "message": "Tag updated successfully.",
                    "tag_id": tag_id,
                    "user_id": user_id,
                }
            else:
                return {"status": "success", "message": "Tag was already up to date."}
        else:
            return {"status": "failure", "message": "Tag not found."}
    except Exception as e:
        return {"status": "error", "message": "An error occurred while updating tag"}


async def delete_tag(tag_id: str) -> TagRes:
    try:
        result = await tags_collection.delete_one({"tag_id": tag_id})
        if result.deleted_count > 0:
            return {
                "status": "success",
                "message": "Tag deleted successfully.",
                "tag_id": tag_id,
            }
        else:
            return {"status": "failure", "message": "Tag deletion failed."}
    except Exception as e:
        return {"status": "error", "message": "An error occurred while deleting tag."}


async def fetch_tag_by_id(tag_id: str) -> TagItem:
    tag_data = await tags_collection.find_one({"tag_id": tag_id}, {"_id": 0})
    if tag_data:
        return TagItem(**tag_data)


async def fetch_all_tags(user_id: str) -> List[TagItem]:
    tag_data = tags_collection.find({"user_id": user_id}, {"_id": 0})
    return [TagItem(**tag) async for tag in tag_data]
