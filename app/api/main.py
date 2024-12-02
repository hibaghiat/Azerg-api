from fastapi import APIRouter

from app.api.routes import admin, auth, error, metric, report, tag, user

api_router = APIRouter()
api_router.include_router(user.router, prefix="/users", tags=["users"])
api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(tag.router, prefix="/tags", tags=["tags"])
api_router.include_router(report.router, prefix="/reports", tags=["reports"])
api_router.include_router(error.router, prefix="/errors", tags=["errors"])
api_router.include_router(admin.router, prefix="/admin", tags=["admin"])
api_router.include_router(metric.router, prefix="/metric", tags=["metric"])
