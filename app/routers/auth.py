from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from phonenumbers import parse as parse_phone_number
from pydantic import BaseModel
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import sessions
from app.db.models import Users
from app.db.redis import redis_client
from app.db.schemas import users as user_schemas
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
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this email already exists",
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

    # Use user.id instead of email in the token
    jwt_access_data = {"sub": str(user.id), "jti": access_jti, "type": "access"}
    jwt_refresh_data = {"sub": str(user.id), "jti": refresh_jti, "type": "refresh"}

    access_token = create_access_token(jwt_access_data)
    refresh_token = create_refresh_token(jwt_refresh_data)

    # Decode tokens to get expiration times
    try:
        access_payload = jwt.decode(access_token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
        access_exp = access_payload.get("exp")
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid access token",
        )

    try:
        refresh_payload = jwt.decode(refresh_token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
        refresh_exp = refresh_payload.get("exp")
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid refresh token",
        )

    if not access_exp or not refresh_exp:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid token expiration time",
        )

    access_ttl = int(access_exp - datetime.now(timezone.utc).timestamp())
    refresh_ttl = int(refresh_exp - datetime.now(timezone.utc).timestamp())

    # Store the refresh token's jti in Redis with the current session
    await redis_client.setex(f"refresh_token:{refresh_jti}", refresh_ttl, refresh_token)

    # Store the access token's jti, associated with the refresh jti
    await redis_client.setex(f"access_token:{access_jti}", access_ttl, refresh_jti)

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
        },
    )


class RefreshTokenSchema(BaseModel):
    refresh_token: str


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


@router.post("/refresh", summary="Refresh access token")
async def refresh(
    refresh_token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(sessions.get_async_session),
) -> JSONResponse:

    try:
        payload = jwt.decode(refresh_token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")  # Use id instead of email
        refresh_jti = payload.get("jti")
        token_type = payload.get("type")
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )

    if not user_id or not refresh_jti:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid token data",
        )

    if token_type != "refresh":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid token type",
        )

    # Verify the refresh token's jti
    stored_refresh_token = await redis_client.get(f"refresh_token:{refresh_jti}")
    if stored_refresh_token is None or stored_refresh_token != refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    # Check if the user exists
    result = await db.execute(select(Users).where(Users.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    # Issue new access token
    access_jti = generate_jti()
    jwt_access_data = {"sub": user_id, "jti": access_jti, "type": "access"}

    access_token = create_access_token(jwt_access_data)

    # Decode access token to get expiration time
    try:
        access_payload = jwt.decode(access_token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
        access_exp = access_payload.get("exp")
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid access token",
        )

    if not access_exp:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid token expiration time",
        )

    access_ttl = int(access_exp - datetime.now(timezone.utc).timestamp())

    # Store the new access token's jti, associated with the existing refresh jti
    await redis_client.setex(f"access_token:{access_jti}", access_ttl, refresh_jti)

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "access_token": access_token,
            "refresh_token": refresh_token,  # Reuse the same refresh token
            "token_type": "bearer",
        },
    )


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


@router.post("/logout", summary="Logout user")
async def logout(
    token: str = Depends(oauth2_scheme),
) -> JSONResponse:
    try:
        # Decode the access token to extract the jti and user id (instead of email)
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
        access_jti = payload.get("jti")
        # user_id = payload.get("sub")
        token_type = payload.get("type")
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )

    if token_type != "access":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid token type for logout",
        )

    # Get the refresh_jti associated with the current access token
    refresh_jti = await redis_client.get(f"access_token:{access_jti}")
    if refresh_jti:
        # Revoke the refresh token tied to this session
        await redis_client.delete(f"refresh_token:{refresh_jti}")

    # Revoke the current access token
    await redis_client.delete(f"access_token:{access_jti}")

    return JSONResponse(status_code=status.HTTP_200_OK, content={"message": "Successfully logged out"})


async def revoke_all_tokens(email: str) -> None:
    # Retrieve all the refresh_jtis associated with the user
    pattern = "refresh_token:*"  # We will scan for all refresh tokens
    cursor = 0
    while True:
        cursor, keys = await redis_client.scan(cursor, match=pattern, count=100)
        for key in keys:
            stored_email = await redis_client.get(key)
            if stored_email and stored_email == email:
                refresh_jti = key.split(":")[1]  # Extract refresh_jti
                # Revoke the refresh token
                await redis_client.delete(f"refresh_token:{refresh_jti}")

                # Now revoke all access tokens associated with this refresh_jti
                access_pattern = "access_token:*"
                access_cursor = 0
                while True:
                    access_cursor, access_keys = await redis_client.scan(access_cursor, match=access_pattern, count=100)
                    for access_key in access_keys:
                        linked_refresh_jti = await redis_client.get(access_key)
                        if linked_refresh_jti and linked_refresh_jti == refresh_jti:
                            await redis_client.delete(access_key)
                    if access_cursor == 0:
                        break
        if cursor == 0:
            break
