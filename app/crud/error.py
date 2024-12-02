from app.config.db import errors_collection
from app.crud.utils import generate_uuid
from app.models.error import Error, ErrorReq, ErrorRes


async def add_error(error: ErrorReq, user_id: str) -> ErrorRes:
    """Add an error."""
    try:
        error_id = generate_uuid()
        error_dict = {
            "error_id": error_id,
            "content": error.content,
            "user_id": user_id,
        }

        # Insert the error document into the collection
        result = await errors_collection.insert_one(error_dict)

        # Check if the insert operation was successful
        if result.inserted_id:
            return {
                "status": "success",
                "message": "Error reported successfully.",
                "error_id": error_id,
                "user_id": user_id,
            }
        else:
            return {"status": "failure", "message": "Error reporting failed."}
    except Exception as e:
        return {
            "status": "error",
            "message": f"An error occurred while reporting the error: {str(e)}",
        }


async def get_error_by_id(error_id: str) -> Error:
    """Get an error by error_id."""
    try:
        # Retrieve the error document from the collection
        error = await errors_collection.find_one({"error_id": error_id})
        # Check if the error document was found
        if error:
            return Error(**error)
        else:
            return None
    except Exception as e:
        # Handle exceptions and return an error message
        return {
            "status": "error",
            "message": f"An error occurred while retrieving the error.",
        }


async def get_errors_by_user_id(user_id: str) -> list:
    """Get errors by user_id."""
    try:
        # Retrieve the error documents from the collection
        errors = []
        async for error in errors_collection.find({"user_id": user_id}):
            errors.append(Error(**error))
        return errors
    except Exception as e:
        # Handle exceptions and return an error message
        return {
            "status": "error",
            "message": f"An error occurred while retrieving the errors.",
        }


async def get_errors_count() -> int:
    """Get the total number of errors."""
    count = await errors_collection.count_documents({})
    return count


async def delete_error(error_id: str) -> dict:
    """Delete an error by error_id."""
    try:
        # Delete the error document from the collection
        result = await errors_collection.delete_one({"error_id": error_id})
        # Check if the delete operation was successful
        if result.deleted_count > 0:
            return {"status": "success", "message": "Error deleted successfully."}
        else:
            return {"status": "failure", "message": "Error deletion failed."}
    except Exception as e:
        # Handle exceptions and return an error message
        return {
            "status": "error",
            "message": f"An error occurred while deleting the error.",
        }
