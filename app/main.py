from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# from app.config.db import initiate_database
import app.config.db as db
from app.api.main import api_router


def get_application():
    app = FastAPI(
        title="AZERG API",
        version="0.1",
        docs_url="/docs",
    )
    app.include_router(api_router, prefix="/api")
    return app


app = get_application()

origins = ["http://localhost:3000", "http://localhost:3001"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)


@app.on_event("startup")
async def on_startup():
    # await initiate_database()
    yield


@app.get("/", tags=["health"])
async def health():
    return dict(
        name="AZERG API",
        version="0.1",
        status="OK",
        message="Visit /docs for more information.",
    )
