from collections.abc import Sequence
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from sqlalchemy import Delete, delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import sessions
from app.db.models import Users
from app.db.schemas import users as user_schemas
from app.deps import get_current_user
from app.routers.auth import revoke_all_tokens

router = APIRouter(prefix="/users", tags=["users"])

auth_user_dependency = Annotated[Users, Depends(get_current_user)]


@router.get("/get")
async def get_users(
    current_user: auth_user_dependency,
    db: AsyncSession = Depends(sessions.get_async_session),
) -> Sequence[user_schemas.Users]:
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="You are not an admin",
        )

    q = select(Users)
    result = await db.execute(q)
    users = result.scalars().all()

    if not users:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No users found")

    return users


@router.get("/get/{id}")
async def get_user(
    current_user: auth_user_dependency,
    id: int,
    db: AsyncSession = Depends(sessions.get_async_session),
) -> user_schemas.Users:
    q = await db.scalars(select(Users).filter(Users.id == id))
    user = q.first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.id != current_user.id and not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="You are not an admin",
        )
    return user


@router.delete("/delete/{id}")
async def delete_user(
    current_user: auth_user_dependency,
    id: int,
    db: AsyncSession = Depends(sessions.get_async_session),
) -> JSONResponse:
    filter_query = await db.scalars(select(Users).filter(Users.id == id))
    user = filter_query.first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unable to delete yourself",
        )
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="You are not an admin",
        )

    delete_query: Delete = delete(Users).filter(Users.id == id)
    await db.execute(delete_query)
    await db.commit()

    # revoke all user tokens
    await revoke_all_tokens(email=str(user.email))

    return JSONResponse(status_code=status.HTTP_200_OK, content={"message": "Deleted User"})
