from collections.abc import Sequence
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import Delete, delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import sessions
from app.db.models import Users
from app.db.schemas import users as user_schemas
from app.deps import get_current_user
from app.responses import JsonResponse
from app.routers.auth import revoke_user_tokens

router = APIRouter(prefix="/users", tags=["Users"])

auth_user_dependency = Annotated[Users, Depends(get_current_user)]


@router.get("/me", summary="Get current user")
async def get_current_user_route(
    current_user: auth_user_dependency,
) -> JsonResponse:
    """
    Get current user

    Args:
        current_user (Users): Current user object

    Returns:
        JsonResponse: JsonResponse object with current user details
    """
    user_object = {
        "id": current_user.id,
        "first_name": current_user.first_name,
        "last_name": current_user.last_name,
        "email": current_user.email,
        "phone_number": current_user.phone_number,
        "is_admin": current_user.is_admin,
    }
    response_object = {
        "message": "Current user",
        "user": user_object,
    }
    return JsonResponse(status_code=status.HTTP_200_OK, content=response_object)


@router.get("/", summary="Get all users")
async def get_users(
    current_user: auth_user_dependency,
    db: AsyncSession = Depends(sessions.async_session_maker),
    limit: int = Query(default=100, ge=1, le=100, description="Number of records to fetch"),
    offset: int = Query(default=0, ge=0, description="Number of records to skip"),
) -> Sequence[user_schemas.Users]:
    """
    Get all users(Only admins can get all users)

    Args:
        current_user (Users): Current user object
        db (AsyncSession): AsyncSession object
        limit (int): Number of records to fetch (default 100) (min 1, max 100)
        offset (int): Number of records to skip (default 0) (min 0)

    Raises:
        HTTPException: If current user is not an admin

    Returns:
        Sequence[user_schemas.Users]: List of user objects
    """
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="You are not an admin",
        )

    q = select(Users).limit(limit).offset(offset)
    result = await db.execute(q)
    users = result.scalars().all()

    if not users:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No users found")

    return users


@router.get("/{id}", summary="Get user by ID")
async def get_user(
    current_user: auth_user_dependency,
    id: int,
    db: AsyncSession = Depends(sessions.async_session_maker),
) -> user_schemas.Users:
    """
    Get a user by ID(Admins can get any user, users can only get themselves)

    Args:
        current_user (Users): Current user object
        id (int): User ID
        db (AsyncSession): AsyncSession object

    Raises:
        HTTPException: If user not found or unauthorized

    Returns:
        user_schemas.Users: User object
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


@router.put("/{id}", summary="Update user by ID")
async def update_user(
    current_user: auth_user_dependency,
    id: int,
    user: user_schemas.UsersUpdate,
    db: AsyncSession = Depends(sessions.async_session_maker),
) -> JsonResponse:
    """
    Update a user by ID(Admins can update any user, users can only update themselves)

    Args:
        current_user (Users): Current user object
        id (int): User ID
        user (user_schemas.UsersUpdate): User update object
        db (AsyncSession): AsyncSession object

    Raises:
        HTTPException: If user not found or unauthorized

    Returns:
        JsonResponse: JsonResponse object with message
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

    if not current_user.is_admin and user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized to update user to admin",
        )

    values_to_update = {}

    if user.first_name:
        values_to_update["first_name"] = user.first_name
    if user.last_name:
        values_to_update["last_name"] = user.last_name
    if user.email:
        values_to_update["email"] = user.email
    if user.phone_number:
        values_to_update["phone_number"] = user.phone_number

    update_query = update(Users).where(Users.id == id).values(**values_to_update, is_admin=user.is_admin)
    await db.execute(update_query)
    await db.commit()

    return JsonResponse(status_code=status.HTTP_200_OK, content={"message": "User updated"})


@router.delete("/{id}", summary="Delete user by ID")
async def delete_user(
    current_user: auth_user_dependency,
    id: int,
    db: AsyncSession = Depends(sessions.async_session_maker),
) -> JsonResponse:
    """
    Delete a user by ID(Only admins can delete any user but not themselves)

    Args:
        current_user (Users): Current user object
        id (int): User ID
        db (AsyncSession): AsyncSession object

    Raises:
        HTTPException: If user not found or unauthorized
        HTTPException: If user tries to delete themselves

    Returns:
        JsonResponse: JsonResponse object with message
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

    return JsonResponse(status_code=status.HTTP_200_OK, content={"message": "Deleted User"})
