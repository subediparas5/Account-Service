import os
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi

from app.db.models import Users
from app.deps import get_current_user
from app.responses import JsonResponse
from app.routers import auth, client, users


def create_app() -> FastAPI:

    if os.getenv("ENVIRONMENT") == "prd":
        app = FastAPI(title="Accounts API", version="0.1.0", docs_url=None, redoc_url=None, openapi_url=None)
    else:
        app = FastAPI(title="Accounts API", version="0.1.0")

    app.include_router(users.router)
    app.include_router(auth.router)
    app.include_router(client.router)

    # For local development
    origins = [
        "http://localhost:3000",
    ]

    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Generic health route to sanity check the API
    @app.get("/health")
    async def health() -> JsonResponse:
        """
        Health check route
        """
        return JsonResponse(
            content={"message": "Ok"},
            status_code=status.HTTP_200_OK,
        )

    @app.get("/docs", include_in_schema=False)
    async def get_documentation(
        current_user: Annotated[Users, Depends(get_current_user)],
    ):
        """
        Get API documentation
        """
        if not current_user.is_admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this resource"
            )
        return get_swagger_ui_html(openapi_url="/openapi.json", title="Accounts API docs")

    @app.get("/openapi.json", include_in_schema=False)
    async def get_open_api_endpoint(current_user: Annotated[Users, Depends(get_current_user)]):
        if not current_user.is_admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this resource"
            )
        return JsonResponse(get_openapi(title=app.title, version=app.version, routes=app.routes))

    return app
