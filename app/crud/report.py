import aiohttp
import fitz
import json
import logging
import os
import pymupdf as fitz
from datetime import UTC, datetime
from typing import List

from aiohttp.client_exceptions import ClientError
from bson import ObjectId
from fastapi import File, HTTPException, status
from motor.motor_asyncio import AsyncIOMotorCursor
from neo4j import AsyncSession, Transaction
from pymongo import TEXT
from pymongo.collection import Collection
from stix2 import MemoryStore

from app.config.celery import app
from app.config.db import neo4j_driver as driver
from app.config.db import reports_collection, tags_collection
from app.crud.utils import generate_uuid
from app.models.report import (
    Entity,
    Relation,
    Report,
    ReportCall,
    ReportLink,
    ReportParagraph,
    ReportReq,
    ReportRes,
    VersionHistory,
)
from app.utils.stix_conversion import convert_to_stix_objects, get_entity_uuid

UPLOAD_DIR = "/public/files/"

# Setup logging
logging.basicConfig()
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


@app.task
def upload_report(file_content: bytes, title: str, user_id: str) -> dict:

    # Ensure the upload directory exists
    if not os.path.exists(UPLOAD_DIR):
        os.makedirs(UPLOAD_DIR)

    # Save the uploaded file to the file system
    file_path = os.path.join(
        UPLOAD_DIR, datetime.now().strftime("%Y%m%d%H%M%S") + ".json"
    )

    with open(file_path, "wb") as f:
        f.write(file_content)

    # Parse the JSON content
    content_str = file_content.decode("utf-8")
    json_content = json.loads(content_str)

    # Extract the hash from the JSON
    file_hash = json_content["target"]["file"]["sha256"]

    # Create the report document to insert into MongoDB
    report = {
        "report_id": generate_uuid(),
        "title": title,
        "hash": file_hash,
        "timestamp": datetime.now(),
        "user_id": user_id,
        "file_path": file_path,
        "history": [],
        "tags": [],
        "status": "In Analysis",
    }

    logger.info(f"Inserting report into MongoDB: {report}")

    try:
        # Insert the report into MongoDB
        reports_collection.insert_one(report)
        return {"message": "Report uploaded successfully", "file_path": file_path}
    except DuplicateKeyError:
        # Handle the duplicate key error
        logger.error(
            "Duplicate key error: report with same title and user_id already exists."
        )
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"message": "A report with this title already exists"},
        )

    return {"message": "Report could not be uploaded"}


async def get_report(report_id: str):
    try:
        # Retrieve the report document from the collection
        report = await reports_collection.find_one({"report_id": report_id}, {"_id": 0})
        if report:
            return report
        else:
            return None
    except Exception as e:
        # Handle exceptions and return an error message
        return {
            "status": "error",
            "message": f"An error occurred while retrieving the report.",
        }


async def update_report_tags(report_id: str, tag_id: str):
    try:
        result = await reports_collection.update_one(
            {"report_id": report_id}, {"$addToSet": {"tags": tag_id}}
        )
        if result.modified_count > 0:
            return {"status": "success", "message": "Report tags updated successfully."}
        else:
            return {"status": "failure", "message": "Report update failed."}
    except Exception as e:
        return {
            "status": "error",
            "message": "An error occurred while updating report tags.",
        }


async def remove_tag_from_report(tag_id: str, report_id: str) -> dict:
    try:
        # Fetch the report using report_id
        report = await reports_collection.find_one({"report_id": report_id})
        if not report:
            return {"status": "failure", "message": "Report not found."}

        # Check if the tag_id is in the report's tags
        if tag_id not in report.get("tags", []):
            return {"status": "failure", "message": "Tag not found in the report."}

        # Remove the tag_id from the tags list
        updated_tags = [tag for tag in report["tags"] if tag != tag_id]

        # Update the report with the new tags list
        result = await reports_collection.update_one(
            {"report_id": report_id}, {"$set": {"tags": updated_tags}}
        )

        if result.modified_count > 0:
            # Check if the tag_id is still used by any other reports
            remaining_reports = await reports_collection.count_documents(
                {"tags": tag_id}
            )
            if remaining_reports == 0:
                # If the tag is no longer used by any reports, delete it
                tag_deletion_response = await tags_collection.delete_one(
                    {"tag_id": tag_id}
                )
                if tag_deletion_response.deleted_count > 0:
                    return {
                        "status": "success",
                        "message": "Tag removed from report and deleted from the database successfully.",
                        "report_id": report_id,
                        "tag_id": tag_id,
                    }
                else:
                    return {
                        "status": "success",
                        "message": "Tag removed from report, but failed to delete from the database.",
                        "report_id": report_id,
                        "tag_id": tag_id,
                    }
            else:
                return {
                    "status": "success",
                    "message": "Tag removed from report successfully.",
                    "report_id": report_id,
                    "tag_id": tag_id,
                }
        else:
            return {"status": "failure", "message": "Failed to update report."}
    except Exception as e:
        logger.error(f"An error occurred while removing tag from report: {e}")
        return {
            "status": "error",
            "message": "An error occurred while removing tag from report.",
        }


async def update_report(report_id: str, new_report: ReportReq) -> ReportRes:
    """Save the modifications made to the report."""
    try:
        report = await get_report(report_id)
        if not report:
            logger.info("Report not found")
            return ReportRes(
                status="error", message="An error occurred while updating the report"
            )

        logger.info("Report found")

        # Get last version of the report
        last_version = report["history"][-1] if report["history"] else None

        # Create a new version of the report from previous version
        new_version = {
            "version_id": datetime.now(UTC),
            "paragraphs": last_version["paragraphs"] if last_version else [],
            "calls": last_version["calls"] if last_version else [],
            "links": [link.dict() for link in new_report.links],
        }

        old_paragraphs = new_version.get("paragraphs", [])
        old_calls = new_version.get("calls", [])

        # Update the new version with the content from new_report
        new_version["paragraphs"] = [
            ReportParagraph(
                uuid=p.get("uuid") if i < len(old_paragraphs) else generate_uuid(),
                content=new_report.paragraphs[i].content,
            ).dict()
            for i, p in enumerate(
                old_paragraphs
                + [{}]
                * (
                    max(len(new_report.paragraphs), len(old_paragraphs))
                    - len(old_paragraphs)
                )
            )
        ]

        new_version["calls"] = [
            ReportCall(
                uuid=p.get("uuid") if i < len(old_calls) else generate_uuid(),
                content=new_report.calls[i].content,
            ).dict()
            for i, p in enumerate(
                old_calls
                + [{}] * (max(len(new_report.calls), len(old_calls)) - len(old_calls))
            )
        ]

        # Update the report document with the new version
        result = await reports_collection.update_one(
            {"report_id": report_id},
            {"$push": {"history": new_version}},
        )

        # Check if the update operation was successful
        if result.modified_count > 0:
            return ReportRes(status="success", message="Report updated successfully.")
        else:
            return ReportRes(status="failure", message="Failed to update report.")

    except Exception as e:
        # Handle exceptions and return an error message
        logger.error(f"Failed to update report: {e}")
        return ReportRes(
            status="error", message="An error occurred while updating the report"
        )


async def get_reports_count():
    """Get the total number of reports."""
    count = await reports_collection.count_documents({})
    return count


async def get_report_entities(report_id: str) -> List[Entity]:
    session = driver.session()
    entities = []
    try:
        result = session.run(
            "MATCH (report:Report {id: $report_id})-[:OWNS]->(entity) "
            "RETURN entity.uuid AS uuid, labels(entity)[0] AS type, "
            "entity.name AS name, entity.pattern AS pattern, "
            "entity.country AS country",
            report_id=report_id,
        )
        entities = [
            Entity(
                uuid=record["uuid"],
                type=record["type"],
                name=record["name"],
                pattern=record["pattern"],
                country=record["country"],
            )
            for record in result
        ]
        return entities
    finally:
        session.close()


async def add_report_entities(report_id: str, entities: List[Entity]) -> dict:
    """Add entities to a report."""
    try:
        id = ObjectId(report_id)
        entities = await reports_collection.find_one({"_id": id}, {"entities": 1})
        if entities:
            return [Entity(**entity) for entity in entities["entities"]]

    except Exception as e:
        # Handle exceptions and return an error message
        logger.error(f"An error occurred while adding the report entities: {e}")
        return []


async def get_reports_count():
    """Get the total number of reports."""
    count = await reports_collection.count_documents({})
    return count


async def get_all_reports(skip: int = 0, limit: int = 10) -> List[Report]:
    cursor = reports_collection.find().skip(skip).limit(limit)
    reports = []
    async for report in cursor:
        report_obj = Report(
            report_id=report["report_id"],
            hash=report["hash"],
            timestamp=report["timestamp"],
            file_path=report["file_path"],
            user_id=report["user_id"],
            title=report.get("title"),
            vendor=report.get("vendor"),
            tags=report.get("tags", []),
            history=report["history"],
            status=report["status"],
        )
        reports.append(report_obj)
    return reports


async def search_reports_in_db(query: str, limit: int, user_id: str) -> List[Report]:
    tags_cursor = tags_collection.find(
        {"tag_name": {"$regex": f".*{query}.*", "$options": "i"}, "user_id": user_id}
    )
    tags = await tags_cursor.to_list(length=limit)
    logger.info(f"Tags matching query '{query}': {tags}")
    tag_ids = [tag["tag_id"] for tag in tags]
    logger.info(f"Tag IDs matching query '{query}': {tag_ids}")

    search_criteria = {"user_id": user_id}

    if tag_ids:
        search_criteria["$or"] = [
            {"tags": {"$in": tag_ids}},
            {
                "$and": [
                    {"hash": {"$regex": f".*{query}.*", "$options": "i"}},
                    {"title": {"$regex": f".*{query}.*", "$options": "i"}},
                    {"vendor": {"$regex": f".*{query}.*", "$options": "i"}},
                ]
            },
        ]
    else:
        search_criteria["$or"] = [
            {"hash": {"$regex": f".*{query}.*", "$options": "i"}},
            {"title": {"$regex": f".*{query}.*", "$options": "i"}},
            {"vendor": {"$regex": f".*{query}.*", "$options": "i"}},
        ]

    cursor = reports_collection.find(search_criteria).limit(limit)
    reports = await cursor.to_list(length=limit)
    logger.info(f"Reports matching query '{query}': {reports}")

    if reports:
        logger.info(f"Reports matching query '{query}' retrieved successfully.")
        return reports
    else:
        logger.info(
            f"No reports found matching query '{query}' for user_id '{user_id}'."
        )
        return []


async def get_reports_for_user(user_id: str, page: int = 1, limit: int = 10) -> list:
    try:
        search_criteria = {"user_id": user_id}
        skip = (page - 1) * limit
        cursor: AsyncIOMotorCursor = (
            reports_collection.find(search_criteria).skip(skip).limit(limit)
        )
        reports = await cursor.to_list(length=limit)
        return reports
    except Exception as e:
        raise e


async def get_status_counts():
    statuses = ["Completed", "In Analysis", "In Generation", "Failed"]
    status_counts = {}
    try:
        for status in statuses:
            count = await reports_collection.count_documents({"status": status})
            status_counts[status] = count
        return status_counts
    except Exception as e:
        logger.error(f"An error occurred while retrieving the counts: {e}")
        return {status: 0 for status in statuses}


async def get_report_entities(report_id: str) -> List[Entity]:
    async with driver.session() as session:
        result = await session.run(
            "MATCH (report:Report {id: $report_id})-[:OWNS]->(entity) "
            "RETURN entity.uuid AS uuid, labels(entity)[0] AS type, "
            "entity.name AS name, entity.pattern AS pattern, "
            "entity.country AS country",
            report_id=report_id,
        )
        entities = [
            Entity(
                uuid=record["uuid"],
                type=record["type"],
                name=record["name"],
                pattern=record["pattern"],
                country=record["country"],
            )
            async for record in result
        ]
        return entities


async def create_entity_node(session, report_id: str, entities: List[Entity]) -> None:
    entities_dicts = []
    for entity in entities:
        entity_dict = entity.dict()
        entity_dict["type"] = (
            entity_dict["type"][0].upper() + entity_dict["type"][1:].lower()
        )
        entities_dicts.append(entity_dict)

    query = (
        "UNWIND $entities AS entity "
        "MATCH (report:Report {id: $report_id}) "
        "CALL apoc.create.node([entity.type], entity) YIELD node "
        "CREATE (node)-[:BELONGS_TO]->(report), "
        "(report)-[:OWNS]->(node) "
        "SET node.uuid = entity.uuid "
        "RETURN report"
    )

    result = await session.run(query, report_id=report_id, entities=entities_dicts)

    report = await result.single()
    if not report:
        raise ValueError("Report not found.")


async def get_report_relationships(tx: Transaction, report_id: str) -> List[Relation]:
    entities_query = """
    MATCH (report:Report {id: $report_id})-[:OWNS]->(entity)
    RETURN entity.uuid AS entity_uuid
    """

    entities_result = await tx.run(entities_query, report_id=report_id)
    entity_uuids = [record["entity_uuid"] for record in await entities_result.data()]

    if not entity_uuids:
        return []

    relationships_query = """
    UNWIND $entity_uuids AS entity_uuid
    MATCH (node: Entity {uuid: entity_uuid})-[r]->(connected_node)
    WHERE type(r) <> 'OWNS' AND type(r) <> 'BELONGS_TO'
    RETURN node.uuid AS source_ref, r AS relationship, connected_node.uuid AS target_ref
    UNION
    UNWIND $entity_uuids AS entity_uuid
    MATCH (connected_node)-[r]->(node {uuid: entity_uuid})
    WHERE type(r) <> 'OWNS' AND type(r) <> 'BELONGS_TO'
    RETURN connected_node.uuid AS source_ref, r AS relationship, node.uuid AS target_ref
    """

    relationships_result = await tx.run(relationships_query, entity_uuids=entity_uuids)

    relationships = []
    async for record in relationships_result:
        relationship = {
            "uuid": record["relationship"].get("uuid"),
            "relationship_type": record["relationship"].type,
            "source_ref": record["source_ref"],
            "target_ref": record["target_ref"],
        }
        relationships.append(Relation(**relationship))
    return relationships


async def create_report_relationships(
    session: AsyncSession, report_id: str, relationships: List[Relation]
):
    for relationship in relationships:
        query = (
            "MATCH (source {uuid: $source_uuid}), (target {uuid: $target_uuid}) "
            f"CREATE (source)-[:{relationship.relationship_type.upper()}"
            + " {uuid: $relation_uuid}]->(target) "
            "SET source.uuid = $source_uuid, target.uuid = $target_uuid "
            "RETURN source, target"
        )

        result = await session.run(
            query,
            source_uuid=relationship.source_ref,
            target_uuid=relationship.target_ref,
            relation_uuid=relationship.uuid,
        )

        if not await result.single():
            raise ValueError(
                f"Failed to create relationship with UUID {relationship.uuid}."
            )


async def get_entities_related(
    session: AsyncSession, report_id: str, entity_id: str, entity_type: str, limit: int
):
    query = """
    MATCH (r:Report {id: $report_id})-[:OWNS]->(e:Entity {id: $entity_id, type: $entity_type})
    MATCH (e)-[rel]->(related_entity:Entity)
    RETURN related_entity
    LIMIT $limit
    """
    parameters = {
        "report_id": report_id,
        "entity_id": entity_id,
        "entity_type": entity_type,
        "limit": limit,
    }

    async with driver.session() as session:
        result = await session.run(query, parameters)
        related_entities = [
            {
                "uuid": record["related_entity"]["id"],
                "type": record["related_entity"]["type"],
                "name": record["related_entity"]["name"],
                "pattern": record["related_entity"].get("pattern"),
                "country": record["related_entity"].get("country"),
            }
            async for record in result
        ]
        logger.info(f"Related entities: {related_entities}")

        return related_entities


async def fetch_report_graph(session: AsyncSession, report_id: str):
    report = await get_report(report_id)
    if not report:
        return None

    entities = await get_report_entities(report_id)
    report["entities"] = entities
    relations = await get_report_relationships(session, report_id)
    report["relations"] = relations

    return report


def create_stix_store(entities, relationships):
    stix_objects = []
    for entity in entities:
        stix_obj = convert_to_stix_objects(entity)
        if stix_obj:
            stix_objects.append(stix_obj)
    stix_relationships = []
    for relationship in relationships:
        relationship.source_ref = get_entity_uuid(relationship.source_ref, stix_objects)
        relationship.target_ref = get_entity_uuid(relationship.target_ref, stix_objects)
        stix_relationship = convert_to_stix_objects(relationship)
        if stix_relationship:
            stix_relationships.append(stix_relationship)
    stix_data = stix_objects + stix_relationships
    return MemoryStore(stix_data=stix_data)


async def fetch_content_from_url(input_url: str) -> str:
    base_url = "https://r.jina.ai/"
    full_url = base_url + input_url

    api_token = os.getenv("JINA_API_TOKEN")
    if not api_token:
        raise ValueError("API token not found. Please set the JINA_API_TOKEN environment variable.")

    headers = {
        "Authorization": f"Bearer {api_token}",   
        "Accept": "application/json"
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(full_url, headers=headers) as response:
                response.raise_for_status()  # Raise exception for bad status codes

                json_response = await response.json()
                content = json_response.get("content", "")

                # Ensure content is returned as a string
                if isinstance(content, bytes):
                    content = content.decode('utf-8', errors='ignore')

        return content

    except ClientError as e:
        raise RuntimeError(f"Error fetching content from URL: {input_url}. ClientError: {str(e)}") from e

    except Exception as e:
        raise RuntimeError(f"Error fetching content from URL: {input_url}. Error: {str(e)}") from e


def extract_text_from_pdf(file_content: bytes) -> str:
    text = ""
    try:
        pdf_document = fitz.open(stream=file_content, filetype="pdf")
        for page_num in range(len(pdf_document)):
            page = pdf_document.load_page(page_num)
            text += page.get_text()
    except Exception as e:
        logger.error(f"An error occurred while extracting text from PDF: {e}")
        raise RuntimeError(f"Error extracting text from PDF: {str(e)}")
    return text