from datetime import datetime, timezone
from typing import Annotated
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from phonenumbers import parse as parse_phone_number
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import sessions
from app.db.models import Users
from app.db.redis import redis_client
from app.db.schemas import users as user_schemas
from app.deps import get_current_user
from app.utils import (
    ALGORITHM,
    JWT_SECRET_KEY,
    create_access_token,
    create_refresh_token,
    get_password_hash,
    verify_password,
)

router = APIRouter(prefix="/auth", tags=["auth"])


# Helper function to generate a unique token identifier
def generate_jti():
    return str(uuid4())


async def store_token_in_redis(
    user_id: str,
    access_jti: str,
    refresh_jti: str,
    access_token: str,
    refresh_token: str,
    access_ttl: int,
    refresh_ttl: int,
):
    # Store access and refresh tokens in Redis as hashes
    await redis_client.hset(
        f"token:{access_jti}",
        mapping={
            "user_id": user_id,
            "jti": access_jti,
            "refresh_jti": refresh_jti,  # Add refresh_jti here
            "type": "access",
            "token": access_token,
        },
    )
    await redis_client.expire(f"token:{access_jti}", access_ttl)

    await redis_client.hset(
        f"token:{refresh_jti}",
        mapping={"user_id": user_id, "jti": refresh_jti, "type": "refresh", "token": refresh_token},
    )
    await redis_client.expire(f"token:{refresh_jti}", refresh_ttl)

    # Index tokens by user_id for quick revocation
    await redis_client.sadd(f"index:user_id:{user_id}", f"token:{access_jti}", f"token:{refresh_jti}")


@router.post("/register", summary="Register a new user")
async def register_user(
    payload: user_schemas.UsersCreate,
    db: AsyncSession = Depends(sessions.get_async_session),
) -> JSONResponse:

    parsed_phone_number = parse_phone_number(payload.phone_number, None)
    phone_number = f"+{parsed_phone_number.country_code}-{parsed_phone_number.national_number}"

    result = await db.execute(
        select(Users).where(or_(Users.email == payload.email, Users.phone_number == phone_number))
    )
    user = result.scalar_one_or_none()

    if user:
        if user.email == payload.email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User with this email already exists",
            )
        if user.phone_number == phone_number:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User with this phone number already exists",
            )

    user = Users(
        first_name=payload.first_name,
        last_name=payload.last_name,
        email=payload.email,
        hashed_password=get_password_hash(payload.password),
        phone_number=phone_number,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    user_object = {
        "id": user.id,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "email": user.email,
    }
    response_object = {
        "message": "User created",
        "user": user_object,
    }
    return JSONResponse(status_code=status.HTTP_201_CREATED, content=response_object)


@router.post("/login", summary="Create access and refresh tokens for user")
async def login(
    payload: user_schemas.UserLogin,
    db: AsyncSession = Depends(sessions.get_async_session),
) -> JSONResponse:

    if not payload.email and not payload.phone_number:
        raise HTTPException(
            status_code=status.HTTP_412_PRECONDITION_FAILED, detail="Email or phone number is required."
        )

    # Authenticate user
    result = await db.execute(
        select(Users).where(or_(Users.email == payload.email, Users.phone_number == payload.phone_number))
    )
    user = result.scalar_one_or_none()

    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect email or password",
        )

    if user:
        user.last_login = datetime.now(timezone.utc)
        await db.flush()
        await db.commit()

    # Generate tokens with unique jti
    access_jti = generate_jti()
    refresh_jti = generate_jti()

    jwt_access_data = {"sub": str(user.id), "jti": access_jti, "type": "access"}
    jwt_refresh_data = {"sub": str(user.id), "jti": refresh_jti, "type": "refresh"}

    access_token = create_access_token(jwt_access_data)
    refresh_token = create_refresh_token(jwt_refresh_data)

    # Decode tokens to get expiration times
    try:
        access_payload = jwt.decode(access_token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
        access_exp = access_payload.get("exp")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid access token")

    try:
        refresh_payload = jwt.decode(refresh_token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
        refresh_exp = refresh_payload.get("exp")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid refresh token")

    if not access_exp or not refresh_exp:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token expiration time")

    access_ttl = int(access_exp - datetime.now(timezone.utc).timestamp())
    refresh_ttl = int(refresh_exp - datetime.now(timezone.utc).timestamp())

    # Store tokens in Redis
    await store_token_in_redis(
        str(user.id), access_jti, refresh_jti, access_token, refresh_token, access_ttl, refresh_ttl
    )

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
        },
    )


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


@router.post("/refresh", summary="Refresh access token")
async def refresh(
    refresh_token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(sessions.get_async_session),
) -> JSONResponse:

    try:
        payload = jwt.decode(refresh_token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        refresh_jti = payload.get("jti")
        token_type = payload.get("type")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    if not user_id or not refresh_jti:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token data")

    if token_type != "refresh":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token type")

    # Check if the refresh token still exists in Redis
    stored_refresh_token = await redis_client.hget(f"token:{refresh_jti}", "token")
    if stored_refresh_token is None or stored_refresh_token != refresh_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired refresh token")

    # Check if the user exists
    result = await db.execute(select(Users).where(Users.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Issue a new access token
    access_jti = generate_jti()
    jwt_access_data = {"sub": user_id, "jti": access_jti, "type": "access"}

    access_token = create_access_token(jwt_access_data)

    try:
        access_payload = jwt.decode(access_token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
        access_exp = access_payload.get("exp")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid access token")

    if not access_exp:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token expiration time")

    access_ttl = int(access_exp - datetime.now(timezone.utc).timestamp())

    # Store the new access token in Redis, linking it to the existing refresh token
    await redis_client.hset(
        f"token:{access_jti}", mapping={"user_id": user_id, "jti": access_jti, "type": "access", "token": access_token}
    )
    await redis_client.expire(f"token:{access_jti}", access_ttl)

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "access_token": access_token,
            "refresh_token": refresh_token,  # The same refresh token is reused
            "token_type": "bearer",
        },
    )


auth_user_dependency = Annotated[Users, Depends(get_current_user)]


@router.post("/logout", summary="Logout user")
async def logout(
    token: str = Depends(oauth2_scheme),
) -> JSONResponse:
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
        access_jti = payload.get("jti")
        token_type = payload.get("type")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    if token_type != "access":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token type for logout")

    # Invalidate access token
    access_token_exists = await redis_client.exists(f"token:{access_jti}")

    if access_token_exists:
        # Retrieve the refresh token jti associated with the access token
        refresh_jti = await redis_client.hget(f"token:{access_jti}", "refresh_jti")

        # Revoke access token
        await redis_client.delete(f"token:{access_jti}")
        await redis_client.srem(f"index:user_id:{access_jti}", f"token:{access_jti}")

        if refresh_jti:
            # Revoke refresh token if it exists
            await redis_client.delete(f"token:{refresh_jti}")
            await redis_client.srem(f"index:user_id:{refresh_jti}", f"token:{refresh_jti}")

    return JSONResponse(status_code=status.HTTP_200_OK, content={"message": "Successfully logged out"})


async def revoke_user_tokens(user_id: str) -> None:
    # Get all token JTIs associated with the user_id
    token_keys = await redis_client.smembers(f"index:user_id:{user_id}")

    # Loop through all the tokens and delete them
    for token_key in token_keys:
        await redis_client.delete(token_key)

    # Finally, remove the user_id index
    await redis_client.delete(f"index:user_id:{user_id}")
