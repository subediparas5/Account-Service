from asyncio import current_task
from collections.abc import AsyncGenerator
from os import getenv
from typing import Any

import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_scoped_session,
    async_sessionmaker,
    create_async_engine,
)

from app.app import create_app
from app.db.sessions import Base, async_session_maker

SQLALCHEMY_TEST_DATABASE_URL = getenv("DATABASE_TEST_URL", "mysql+aiomysql://root:root@localhost:3306/app")

async_engine = create_async_engine(SQLALCHEMY_TEST_DATABASE_URL, connect_args={"check_same_thread": False})
async_test_session_local = async_scoped_session(
    async_sessionmaker(autocommit=False, autoflush=False, class_=AsyncSession, bind=async_engine),
    scopefunc=current_task,
)


@pytest_asyncio.fixture
def anyio_backend():
    return "asyncio"


@pytest_asyncio.fixture()
async def async_session() -> AsyncGenerator[AsyncSession, Any]:
    # Create the database
    async with async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    db = async_test_session_local()
    try:
        yield db
    finally:
        await db.close()


@pytest_asyncio.fixture
async def async_client(async_session) -> AsyncGenerator[AsyncClient, Any]:
    # Dependency override
    async def override_get_db():
        try:
            yield async_session
        finally:
            await async_session.close()

    app = create_app()
    app.dependency_overrides[async_session_maker] = override_get_db
    async with AsyncClient(app=app, base_url="http://testserver") as client:
        yield client
