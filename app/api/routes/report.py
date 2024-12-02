import asyncio
import io
import logging
from pathlib import Path
from typing import List, Optional

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    Request,
    Response,
    UploadFile,
    status,
)
from fastapi.responses import FileResponse
from neo4j import AsyncSession

from app.config.db import get_neo4j_session
from app.config.db import neo4j_driver as driver
from app.config.db import reports_collection
from app.crud.report import (
    create_entity_node,
    create_report_relationships,
    create_stix_store,
    extract_text_from_pdf,
    fetch_content_from_url,
    fetch_report_graph,
    get_entities_related,
    get_report,
    get_report_entities,
    get_report_relationships,
    get_reports_for_user,
    search_reports_in_db,
    update_report,
    upload_report,
)
from app.crud.user import get_current_user
from app.models.report import (
    Entity,
    Relation,
    Report,
    ReportGraph,
    ReportReq,
    ReportRes,
)

router = APIRouter()

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@router.get(
    "/",
    summary="List reports for authenticated user.",
    response_model=List[Report],
    status_code=status.HTTP_200_OK,
)
async def get_reports(
    request: Request,
    limit: int = Query(10, description="Limit the number of results per page"),
    page: int = Query(1, description="Page number, starting from 1"),
):
    """Get paginated reports of the authenticated user."""
    access_token = request.cookies.get("access_token")

    if access_token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="No access token found"
        )

    try:
        user = await get_current_user(access_token)
        user_id = user.user_id

        reports = await get_reports_for_user(user_id, page, limit)

        if reports:
            logger.info(f"Reports matching query '{user_id}' retrieved successfully.")
            return reports
        else:
            logger.info(f"No reports found matching query '{user_id}'.")
            return []

    except HTTPException as http_err:
        raise http_err
    except Exception as e:
        logger.error(f"An error occurred while searching for reports: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while searching for reports.",
        )


@router.post(
    "/upload",
    summary="Upload report to the server for processing.",
    status_code=status.HTTP_200_OK,
)
async def upload_report_route(
    request: Request, title: str, file: UploadFile = File(...)
):
    if "access_token" in request.cookies:
        access_token = request.cookies["access_token"]
    if not access_token:
        logger.error("No access token found")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="User is not logged in."
        )
    user = await get_current_user(access_token)
    file_content = await file.read()
    upload_report.apply_async(args=[file_content, title, user.user_id])
    return {"message": "Report is being processed."}


@router.get(
    "/search",
    summary="Search reports by hash, title, vendor, or tag.",
    response_model=List[Report],
    status_code=status.HTTP_200_OK,
)
async def search_reports(
    request: Request,
    query: str = Query(..., description="Search query"),
    limit: int = Query(10, description="Limit the number of results"),
):
    if "access_token" in request.cookies:
        access_token = request.cookies["access_token"]
    if not access_token:
        logger.error("No access token found")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="User is not logged in."
        )
    user = await get_current_user(access_token)
    response = await search_reports_in_db(query, limit, user.user_id)
    logger.info(f"Search response: {response}")
    if response:
        logger.info(f"Search for query '{query}' returned {len(response)} reports.")
        return response
    logger.error(f"No reports found for query '{query}'.")
    return []


@router.get(
    "/{report_id}",
    summary="Get the report.",
    response_model=Report,
    status_code=status.HTTP_200_OK,
)
async def get_report_route(report_id: str):
    response = await get_report(report_id)
    if response:
        logger.info(f"Report {report_id} retrieved successfully.")
        return response
    logger.error(f"Report {report_id} failed to retrieve.")
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND, detail="Report not found."
    )


@router.post(
    "/{report_id}/save",
    summary="Save the modifications made to the report.",
    status_code=status.HTTP_200_OK,
    response_model=ReportRes,
)
async def update_report_with_modifications(
    report_id: str, report: ReportReq, request: Request, response: Response
) -> ReportRes:
    access_token = None
    # Extract access token from cookies
    if "access_token" in request.cookies:
        access_token = request.cookies["access_token"]
    if not access_token:
        logger.error("No access token found")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="No access token found"
        )
    try:
        response = await update_report(report_id, report)
        return response
    except Exception as e:
        logger.error(f"An error occurred while updating the report.")
        raise HTTPException(
            status_code=status.HTTP_405_METHOD_NOT_ALLOWED,
            detail="Failed to update report.",
        )


@router.get(
    "/{report_id}/entities",
    summary="Get entities associated with a report.",
    response_model=List[Entity],
    status_code=status.HTTP_200_OK,
)
async def get_report_entities_route(report_id: str) -> List[Entity]:
    try:
        entities = await get_report_entities(report_id)
        logger.info(
            f"Entities for report {report_id} retrieved successfully: {entities}"
        )
        return entities
    except Exception as e:
        logger.error(f"An error occurred while retrieving entities: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve entities.",
        )


@router.post(
    "/{report_id}/entities",
    summary="Add entities to a report.",
    status_code=status.HTTP_201_CREATED,
)
async def add_entity_node(
    report_id: str,
    entities: List[Entity],
    session: AsyncSession = Depends(get_neo4j_session),
):
    try:
        async with session as neo4j_session:
            await create_entity_node(neo4j_session, report_id, entities)
        return {"message": "Entities added successfully."}
    except Exception as e:
        logger.error(f"An error occurred while creating the entity nodes: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An error occurred while creating the entity nodes",
        )


@router.get(
    "/{report_id}/relations",
    summary="Get the relations of a report.",
    response_model=List[Relation],
    status_code=status.HTTP_200_OK,
)
async def get_report_relations(report_id: str) -> List[Relation]:
    try:
        async with driver.session() as session:
            result = await session.execute_read(get_report_relationships, report_id)
            return result

    except Exception as e:
        logger.error(f"An error occurred while retrieving relations: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve relations.",
        )


@router.post(
    "/{report_id}/relations",
    summary="Add relations to a report.",
    status_code=status.HTTP_201_CREATED,
)
async def add_report_relations(
    report_id: str,
    relations: List[Relation],
    session: AsyncSession = Depends(get_neo4j_session),
):
    try:
        async with session as neo4j_session:
            await create_report_relationships(neo4j_session, report_id, relations)
        return {
            "report_id": report_id,
            "message": "Relationship(s) created successfully.",
        }
    except Exception as e:
        logger.error(f"An error occurred while creating the relationship(s): {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An error occurred while creating the relationship(s).",
        )


## GET /reports/{report_id}/graph/search?entity_id{entity_id}&type={entity_type}&limit={limit} -- Get all related entities to an entity and limit the returned graph nodes
@router.get(
    "/{report_id}/graph/search",
    summary="Get all related entities to an entity and limit the returned graph nodes.",
    response_model=List[Entity],
    status_code=status.HTTP_200_OK,
)
async def get_related_entities(
    report_id: str,
    entity_id: str,
    entity_type: str,
    limit: int = Query(10, description="Limit the number returned graph nodes."),
    session: AsyncSession = Depends(get_neo4j_session),
) -> List[Entity]:
    try:
        async with session as neo4j_session:
            result = await get_entities_related(
                neo4j_session, report_id, entity_id, entity_type, limit
            )
            return result
    except Exception as e:
        logger.error(f"An error occurred while retrieving related entities: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve related entities.",
        )


@router.get(
    "/{report_id}/graph",
    summary="Get the graph of a report.",
    status_code=status.HTTP_200_OK,
    response_model=ReportGraph,
)
async def get_report_graph(
    report_id: str,
    session: AsyncSession = Depends(get_neo4j_session),
) -> ReportGraph:
    try:
        async with session as neo4j_session:
            graph = await fetch_report_graph(neo4j_session, report_id)
            return graph
    except Exception as e:
        logger.error(f"An error occurred while fetching the report graph: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve report graph.",
        )


@router.get("/reports/{report_id}/download")
async def download_report(report_id: str):
    try:
        entities = await get_report_entities(report_id)
        relationships = await get_report_relations(report_id)
        if entities is None or relationships is None:
            raise HTTPException(status_code=500, detail="Data format error")
        stix_store = create_stix_store(entities, relationships)
        file_path = Path(f"{report_id}.json")
        stix_store.save_to_file(file_path)
        return FileResponse(path=file_path, filename=f"{report_id}.json")
    except Exception as e:
        print("Error:", e)
        raise HTTPException(status_code=500, detail=str(e))


@router.post(
    "/create",
    summary="Create a new report by URL or PDF file.",
    status_code=status.HTTP_201_CREATED,
    response_model=ReportRes,
)
async def create_report(
    request: Request,
    title: str = Form(...),
    url: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
):
    if not url and not file:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Either 'url' or 'file' must be provided.",
        )

    access_token = request.cookies.get("access_token")
    if not access_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User is not logged in.",
        )

    user = await get_current_user(access_token)

    try:
        if url:
            try:
                report_content = await fetch_content_from_url(url)
            except RuntimeError as e:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Failed to fetch content from URL: {url}. Error: {str(e)}"
                )

        elif file:
            try:
                file_content = await file.read()
                report_content = extract_text_from_pdf(file_content)
            except Exception as e:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Failed to extract text from PDF file. Error: {str(e)}"
                )

        report_id = await upload_report(report_content, title, user.user_id)

        return {"report_id": report_id, "message": "Report created successfully."}

    except Exception as e:
        logger.error(f"Failed to create report: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create report.",
        )