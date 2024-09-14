from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, status
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
    phone_number = f"{parsed_phone_number.country_code}-{parsed_phone_number.national_number}"

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


@router.post(
    "/login",
    summary="Create access and refresh tokens for user",
    # response_model=auth_schemas.Token,
)
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

    jwt_access_data = {"sub": user.email, "jti": access_jti, "type": "access"}
    jwt_refresh_data = {"sub": user.email, "jti": refresh_jti, "type": "refresh"}

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

    access_ttl = int(access_exp - datetime.now(timezone.utc).timestamp())
    refresh_ttl = int(refresh_exp - datetime.now(timezone.utc).timestamp())

    # Store the access token's jti in Redis
    await redis_client.setex(f"token:{access_jti}", access_ttl, str(user.email))

    # Store the refresh token's jti in Redis
    await redis_client.setex(f"refresh_token:{refresh_jti}", refresh_ttl, str(user.email))

    # Map the user's email to the refresh token's jti
    await redis_client.setex(f"user_refresh_token:{user.email}", refresh_ttl, refresh_jti)

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
        },
    )


@router.post("/refresh", summary="Refresh access token")
async def refresh(
    request: Request,
    db: AsyncSession = Depends(sessions.get_async_session),
) -> JSONResponse:
    form = await request.form()
    refresh_token = form.get("refresh_token")

    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Refresh token is missing",
        )

    try:
        payload = jwt.decode(refresh_token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        refresh_jti = payload.get("jti")
        token_type = payload.get("type")
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )

    if token_type != "refresh":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid token type",
        )

    # Verify the refresh token's jti
    stored_email = await redis_client.get(f"refresh_token:{refresh_jti}")
    if stored_email is None or stored_email.decode("utf-8") != email:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    # Revoke the old refresh token
    await redis_client.delete(f"refresh_token:{refresh_jti}")
    await redis_client.delete(f"user_refresh_token:{email}")

    # Check if user exists
    result = await db.execute(select(Users).where(Users.email == email))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    # Issue new tokens
    access_jti = generate_jti()
    new_refresh_jti = generate_jti()

    jwt_access_data = {"sub": email, "jti": access_jti, "type": "access"}
    jwt_refresh_data = {"sub": email, "jti": new_refresh_jti, "type": "refresh"}

    access_token = create_access_token(jwt_access_data)
    new_refresh_token = create_refresh_token(jwt_refresh_data)

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
        refresh_payload = jwt.decode(new_refresh_token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
        refresh_exp = refresh_payload.get("exp")
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid refresh token",
        )

    access_ttl = int(access_exp - datetime.now(timezone.utc).timestamp())
    refresh_ttl = int(refresh_exp - datetime.now(timezone.utc).timestamp())

    # Store the new access token's jti in Redis
    await redis_client.setex(f"token:{access_jti}", access_ttl, email)

    # Store the new refresh token's jti in Redis
    await redis_client.setex(f"refresh_token:{new_refresh_jti}", refresh_ttl, email)

    # Map the user's email to the new refresh token's jti
    await redis_client.setex(f"user_refresh_token:{email}", refresh_ttl, new_refresh_jti)

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "access_token": access_token,
            "refresh_token": new_refresh_token,
            "token_type": "bearer",
        },
    )


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


@router.post("/logout", summary="Logout user")
async def logout(
    token: str = Depends(oauth2_scheme),
) -> JSONResponse:
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
        access_jti = payload.get("jti")
        email = payload.get("sub")
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

    # Revoke the access token
    await redis_client.delete(f"token:{access_jti}")

    # Retrieve and revoke the refresh token
    refresh_jti = await redis_client.get(f"user_refresh_token:{email}")
    if refresh_jti:
        refresh_jti = refresh_jti.decode("utf-8")
        await redis_client.delete(f"refresh_token:{refresh_jti}")
        await redis_client.delete(f"user_refresh_token:{email}")

    return JSONResponse(status_code=status.HTTP_200_OK, content={"message": "Successfully logged out"})


async def revoke_all_tokens(email: str) -> None:
    # Retrieve and revoke the refresh token
    refresh_jti = await redis_client.get(f"user_refresh_token:{email}")
    if refresh_jti:
        refresh_jti = refresh_jti.decode("utf-8")
        await redis_client.delete(f"refresh_token:{refresh_jti}")
        await redis_client.delete(f"user_refresh_token:{email}")

    # Retrieve and revoke the access token
    access_jti = await redis_client.get(f"token:{email}")
    if access_jti:
        access_jti = access_jti.decode("utf-8")
        await redis_client.delete(f"token:{access_jti}")
