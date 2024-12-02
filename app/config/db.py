from contextlib import asynccontextmanager

from motor import motor_asyncio
from motor.motor_asyncio import AsyncIOMotorClient
from neo4j import AsyncGraphDatabase
from pymongo import ASCENDING, TEXT

from app.config.settings import settings

neo4j_driver = AsyncGraphDatabase.driver(
    settings.NEO4J_URI,
    auth=(settings.NEO4J_USERNAME, settings.NEO4J_PASSWORD),
)


@asynccontextmanager
async def get_neo4j_session():
    async with neo4j_driver.session() as session:
        yield session


class Database:
    # Static variable to store the MongoDB client
    client: AsyncIOMotorClient = None

    @classmethod
    def connect(cls):
        # Establish a connection to the MongoDB database
        cls.client = AsyncIOMotorClient(settings.DATABASE_URL)

    @classmethod
    def get_database(cls):
        # Retrieve the MongoDB database from the client
        return cls.client[settings.DATABASE_NAME]

    @classmethod
    async def close(cls):
        # Close the MongoDB client connection
        cls.client.close()


# Create an instance of the Database class
db = Database()

# Connect to the MongoDB database
db.connect()

# Get the MongoDB database from the client
db = db.get_database()

users_collection = db["users"]
users_collection.create_index("user_id", unique=True)
users_collection.create_index("email", unique=True)

# Access the "tags" collection within the database
tags_collection = db["tags"]
tags_collection.create_index("tag_id", unique=True)

# Access the "reports" collection within the database
reports_collection = db["reports"]
reports_collection.create_index("report_id", unique=True)
reports_collection.create_index("user_id", unique=False)

# Create unique compound index on report_name and user_id
# reports_collection.create_index(
#     [("title", ASCENDING), ("user_id", ASCENDING)],
#     unique=True,
#     name="unique_report_name_user_id",
# )

# Ensure the collection has a text index for the searchable fields
reports_collection.create_index(
    [("title", TEXT), ("vendor", TEXT), ("tags", TEXT)], name="search_index"
)

# Access the "errors" collection within the database
errors_collection = db["errors"]
errors_collection.create_index("error_id", unique=True)
