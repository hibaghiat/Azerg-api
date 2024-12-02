import logging
from typing import List

from fastapi import (
    APIRouter,
    Depends,
    Header,
    HTTPException,
    Query,
    Request,
    Response,
    status,
)

from app.crud.report import remove_tag_from_report
from app.crud.tag import (
    add_tag,
    delete_tag,
    fetch_all_tags,
    fetch_tag_by_id,
    update_tag,
)
from app.crud.user import get_current_user
from app.models.tag import TagItem, TagReq, TagRes

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/create", summary="Create a tag.", status_code=status.HTTP_201_CREATED)
async def create_tag(
    tag: TagReq, report_id: str, request: Request, response: Response
) -> dict:
    access_token = request.cookies.get("access_token")
    if not access_token:
        logger.error("No access token found")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="No access token found"
        )
    user = await get_current_user(access_token)
    response = await add_tag(tag, report_id, user.user_id)
    logger.info(f"Tag created or updated successfully: {response}")
    return response


@router.put("/{tag_id}", summary="Update a tag.", status_code=status.HTTP_200_OK)
async def update_tag_by_id(
    tag_id: str, tag: TagReq, request: Request, response: Response
) -> dict:
    access_token = request.cookies.get("access_token")
    if not access_token:
        logger.error("No access token found")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="No access token found"
        )
    user = await get_current_user(access_token)
    response = await update_tag(tag_id, tag, user.user_id)
    if response:
        logger.info(f"Tag {tag_id} updated successfully.")
        return response
    logger.error(f"Tag {tag_id} failed to update.")
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tag not found.")


@router.delete(
    "/{tag_id}",
    summary="Remove a tag from a specific report.",
    status_code=status.HTTP_200_OK,
)
async def remove_tag(
    tag_id: str,
    request: Request,
    response: Response,
    report_id: str = Query(
        ..., description="The ID of the report from which the tag should be removed"
    ),
) -> dict:
    access_token = request.cookies.get("access_token")
    if not access_token:
        logger.error("No access token found")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="No access token found"
        )

    result = await remove_tag_from_report(tag_id, report_id)
    if result:
        logger.info(f"Tag {tag_id} removed from report {report_id} successfully.")
        return result
    logger.error(f"Failed to remove tag {tag_id} from report {report_id}.")
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND, detail="Tag or report not found."
    )


@router.get(
    "/{tag_id}",
    summary="Get a tag.",
    response_model=TagItem,
    status_code=status.HTTP_200_OK,
)
async def get_tag_by_id(tag_id: str, request: Request, response: Response) -> TagItem:
    access_token = request.cookies.get("access_token")
    if not access_token:
        logger.error("No access token found")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="No access token found"
        )
    response = await fetch_tag_by_id(tag_id)
    if response:
        logger.info(f"Tag {tag_id} retrieved successfully.")
        return response
    logger.error(f"Tag {tag_id} failed to retrieve.")
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tag not found.")


@router.get(
    "/",
    summary="Get all tags of the authenticated user.",
    response_model=List[TagItem],
    status_code=status.HTTP_200_OK,
)
async def get_all_tags(request: Request, response: Response) -> List[TagItem]:
    access_token = request.cookies.get("access_token")
    if not access_token:
        logger.error("No access token found")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="No access token found"
        )
    user = await get_current_user(access_token)
    response = await fetch_all_tags(user.user_id)
    if response:
        logger.info("Tags retrieved successfully.")
        return response
    logger.error("Tags failed to retrieve.")
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tags not found.")
