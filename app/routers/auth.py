from datetime import datetime, timedelta, timezone
from typing import Annotated
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from phonenumbers import parse as parse_phone_number
from sqlalchemy import or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import sessions
from app.db.models import Users
from app.db.redis import redis_client
from app.db.schemas import users as user_schemas
from app.deps import get_current_user
from app.utils import (
    ALGORITHM,
    JWT_SECRET_KEY,
    check_client_credentials,
    create_access_token,
    create_refresh_token,
    get_password_hash,
    verify_password,
)

router = APIRouter(prefix="/auth", tags=["auth"])


auth_user_dependency = Annotated[Users, Depends(get_current_user)]


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
    client_id: str,
):
    """
    Store access and refresh tokens in Redis
    """
    await redis_client.hset(
        f"token:{access_jti}",
        mapping={
            "user_id": user_id,
            "jti": access_jti,
            "refresh_jti": refresh_jti,  # Add refresh_jti here
            "type": "access",
            "token": access_token,
            "client_id": client_id,
        },
    )
    await redis_client.expire(f"token:{access_jti}", access_ttl)

    await redis_client.hset(
        f"token:{refresh_jti}",
        mapping={
            "user_id": user_id,
            "jti": refresh_jti,
            "type": "refresh",
            "token": refresh_token,
            "client_id": client_id,
        },
    )
    await redis_client.expire(f"token:{refresh_jti}", refresh_ttl)

    # Index tokens by user_id for quick revocation
    await redis_client.sadd(f"index:user_id:{user_id}", f"token:{access_jti}", f"token:{refresh_jti}")


@router.post("/register", summary="Register a new user")
async def register_user(
    payload: user_schemas.UsersCreate,
    db: AsyncSession = Depends(sessions.async_session_maker),
) -> JSONResponse:
    """
    Register a new user
    """

    # Validate client credentials
    await check_client_credentials(
        client_id=payload.client_id,
        client_secret=payload.client_secret,
        db=db,
    )

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
    db: AsyncSession = Depends(sessions.async_session_maker),
) -> JSONResponse:
    """
    Create access and refresh tokens for user

    Args:
        payload (user_schemas.UserLogin): The login payload containing user credentials.
        db (AsyncSession, optional): The database session. Defaults to Depends(sessions.async_session_maker).

    Raises:
        HTTPException: If client credentials are invalid.
        HTTPException: If neither email nor phone number is provided.
        HTTPException: If user authentication fails.
        HTTPException: If access token is invalid.
        HTTPException: If refresh token is invalid.
        HTTPException: If token expiration time is invalid.

    Returns:
        JSONResponse: A JSON response containing the access and refresh tokens, and token type.
    """

    # Validate client credentials
    await check_client_credentials(
        client_id=payload.client_id,
        client_secret=payload.client_secret,
        db=db,
    )

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

    jwt_access_data = {"sub": str(user.id), "jti": access_jti, "type": "access", "client_id": payload.client_id}
    jwt_refresh_data = {"sub": str(user.id), "jti": refresh_jti, "type": "refresh", "client_id": payload.client_id}

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
        str(user.id), access_jti, refresh_jti, access_token, refresh_token, access_ttl, refresh_ttl, payload.client_id
    )

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
        },
    )


@router.put("/change-password", summary="Change user password")
async def change_password(
    current_user: auth_user_dependency,
    payload: user_schemas.ChangePassword,
    db: AsyncSession = Depends(sessions.async_session_maker),
) -> JSONResponse:
    """
    Change user password, can only change own password

    Args:
        current_user (auth_user_dependency): The currently authenticated user.
        payload (user_schemas.ChangePassword): The payload containing the current, new, and confirmation passwords.
        db (AsyncSession, optional): The database session. Defaults to Depends(sessions.async_session_maker).

    Raises:
        HTTPException: If the new password and confirmation password do not match.
        HTTPException: If the current password is incorrect.
        HTTPException: If the new password is the same as the current password.

    Returns:
        JSONResponse: A JSON response with a status code and message indicating the result of the password change."""

    if payload.new_password != payload.confirm_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Passwords do not match.",
        )

    if not verify_password(payload.current_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password not correct.",
        )

    if verify_password(payload.new_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password cannot be the same as the current password",
        )

    new_hashed_password = get_password_hash(payload.new_password)

    update_query = update(Users).where(Users.id == current_user.id).values(hashed_password=new_hashed_password)
    await db.execute(update_query)
    await db.commit()

    # revoke access tokens
    # await revoke_user_tokens(user_id=str(current_user.id))

    return JSONResponse(status_code=status.HTTP_200_OK, content={"message": "Password updated"})


@router.post("/forgot-password", summary="Forgot password")
async def forgot_password(
    payload: user_schemas.ForgotPassword,
    db: AsyncSession = Depends(sessions.async_session_maker),
) -> JSONResponse:
    """
    Forgot password
    Args:
        payload (user_schemas.ForgotPassword): The payload containing the email address.
        db (AsyncSession, optional): The database session. Defaults to Depends(sessions.async_session_maker).

    Raises:
        HTTPException: If email is not provided.
        HTTPException: If user is not found.

    Returns:
        JSONResponse: A JSON response with a status code and message indicating that
        the reset password token has been sent.
    """

    if not payload.email:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email is required")

    result = await db.execute(select(Users).where(Users.email == payload.email))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    reset_password_token = create_access_token(
        data={"sub": str(user.id), "type": "reset_password"},
        expires_delta=timedelta(hours=1),
    )

    print(reset_password_token)

    return JSONResponse(status_code=status.HTTP_200_OK, content={"message": "Reset password token sent"})


@router.post("/reset-password", summary="Reset password")
async def reset_password(
    payload: user_schemas.ResetPassword,
    db: AsyncSession = Depends(sessions.async_session_maker),
) -> JSONResponse:
    """
    Reset password
    Args:
        payload (user_schemas.ResetPassword): The payload containing the reset password token,
            new password, and confirmation password.
        db (AsyncSession, optional): The database session. Defaults to Depends(sessions.async_session_maker).

    Raises:
        HTTPException: If new password and confirmation password do not match.
        HTTPException: If reset password token is invalid.
        HTTPException: If user is not found.
        HTTPException: If token type is invalid.

    Returns:
        JSONResponse: A JSON response with a status code and message indicating that the password has been reset.
    """

    if payload.new_password != payload.confirm_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Passwords do not match",
        )

    try:
        jwt_payload = jwt.decode(payload.reset_password_token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
        user_id = jwt_payload.get("sub")
        token_type = jwt_payload.get("type")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid reset password token")

    if not user_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token data")

    if token_type != "reset_password":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token type")

    result = await db.execute(select(Users).where(Users.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    new_hashed_password = get_password_hash(payload.new_password)

    update_query = update(Users).where(Users.id == user_id).values(hashed_password=new_hashed_password)
    await db.execute(update_query)
    await db.commit()

    await revoke_user_tokens(user_id=str(user_id))

    return JSONResponse(status_code=status.HTTP_200_OK, content={"message": "Password reset successful"})


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


@router.post("/refresh", summary="Refresh access token")
async def refresh(
    refresh_token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(sessions.async_session_maker),
) -> JSONResponse:
    """
    Refresh access token

    Args:
        refresh_token (str, optional): The refresh token. Defaults to Depends(oauth2_scheme).
        db (AsyncSession, optional): The database session. Defaults to Depends(sessions.async_session_maker).

    Raises:
        HTTPException: If the refresh token is invalid.
        HTTPException: If the token data is invalid.
        HTTPException: If the token type is invalid.
        HTTPException: If the user is not found.
        HTTPException: If the refresh token is invalid or expired.
        HTTPException: If the user is not found.

    Returns:
        JSONResponse: A JSON response with the new access token and refresh token.
    """

    try:
        payload = jwt.decode(refresh_token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        refresh_jti = payload.get("jti")
        token_type = payload.get("type")
        client_id = payload.get("client_id")
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
    jwt_access_data = {"sub": user_id, "jti": access_jti, "type": "access", "client_id": client_id}

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
        f"token:{access_jti}",
        mapping={
            "user_id": user_id,
            "jti": access_jti,
            "type": "access",
            "token": access_token,
            "client_id": client_id,
        },
    )
    await redis_client.expire(f"token:{access_jti}", access_ttl)

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
        },
    )


@router.post("/logout", summary="Logout user")
async def logout(
    token: str = Depends(oauth2_scheme),
) -> JSONResponse:
    """
    Logout user

    Args:
        token (str, optional): The access token. Defaults to Depends(oauth2_scheme).

    Raises:
        HTTPException: If the token is invalid.
        HTTPException: If the token type is invalid for logout.

    Returns:
        JSONResponse: A JSON response with a status code and message indicating that the user has been logged out.
    """
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
    """
    Revoke all tokens associated with a user
    """
    # Get all token JTIs associated with the user_id
    token_keys = await redis_client.smembers(f"index:user_id:{user_id}")

    # Loop through all the tokens and delete them
    for token_key in token_keys:
        await redis_client.delete(token_key)

    # Finally, remove the user_id index
    await redis_client.delete(f"index:user_id:{user_id}")
