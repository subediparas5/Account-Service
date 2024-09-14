from fastapi import FastAPI, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.routers import auth, users


def create_app() -> FastAPI:
    app = FastAPI(title="Accounts Service")

    app.include_router(users.router)
    app.include_router(auth.router)

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
    async def health() -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_200_OK, content={"message": "Ok"})

    return app
