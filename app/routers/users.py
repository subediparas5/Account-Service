from collections.abc import Sequence
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from sqlalchemy import Delete, delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import sessions
from app.db.models import Users
from app.db.schemas import users as user_schemas
from app.deps import get_current_user
from app.routers import auth
from app.routers.auth import revoke_user_tokens

router = APIRouter(prefix="/users", tags=["users"])

auth_user_dependency = Annotated[Users, Depends(get_current_user)]


@router.get("/get")
async def get_users(
    current_user: auth_user_dependency,
    db: AsyncSession = Depends(sessions.async_session_maker),
) -> Sequence[user_schemas.Users]:
    """
    Get all users(Only admins can get all users)
    """
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
    db: AsyncSession = Depends(sessions.async_session_maker),
) -> user_schemas.Users:
    """
    Get a user by ID(Admins can get any user, users can only get themselves)
    """
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


@router.put("/update/{id}")
async def update_user(
    current_user: auth_user_dependency,
    id: int,
    user: user_schemas.UsersUpdate,
    db: AsyncSession = Depends(sessions.async_session_maker),
) -> JSONResponse:
    """
    Update a user by ID(Admins can update any user, users can only update themselves)
    """
    filter_query = await db.scalars(select(Users).filter(Users.id == id))
    user_db = filter_query.first()

    if not user_db:
        raise HTTPException(status_code=404, detail="User not found")

    if user_db.id != current_user.id and not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized to update user",
        )

    hashed_password = auth.get_password_hash(user.password)

    update_query = (
        update(Users)
        .where(Users.id == id)
        .values(
            first_name=user.first_name,
            last_name=user.last_name,
            email=user.email,
            is_admin=user.is_admin,
            phone_number=user.phone_number,
            password=hashed_password,
        )
    )
    await db.execute(update_query)
    await db.commit()

    await revoke_user_tokens(user_id=str(user_db.id))

    return JSONResponse(status_code=status.HTTP_200_OK, content={"message": "User updated"})


@router.delete("/delete/{id}")
async def delete_user(
    current_user: auth_user_dependency,
    id: int,
    db: AsyncSession = Depends(sessions.async_session_maker),
) -> JSONResponse:
    """
    Delete a user by ID(Only admins can delete any user but not themselves)
    """
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
    await revoke_user_tokens(user_id=str(user.id))

    return JSONResponse(status_code=status.HTTP_200_OK, content={"message": "Deleted User"})
