# app/middleware.py or wherever your middleware is defined
from datetime import datetime, timezone

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import sessions
from app.db.models import Clients, Users
from app.db.redis import redis_client
from app.db.schemas import auth as auth_schemas
from app.db.schemas import users as user_schemas

from .utils import ALGORITHM, JWT_SECRET_KEY

reuseable_oauth = OAuth2PasswordBearer(tokenUrl="/auth/login", scheme_name="JWT")


async def get_current_user(
    token: str = Depends(reuseable_oauth),
    db: AsyncSession = Depends(sessions.get_async_session),
) -> user_schemas.Users:
    try:
        # Decode the JWT token
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
        token_data = auth_schemas.TokenPayload(**payload)

        # Check token expiration
        if not token_data.exp or datetime.fromtimestamp(token_data.exp, tz=timezone.utc) < datetime.now(timezone.utc):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token expired",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Use jti from the token payload to check Redis
        access_jti = payload.get("jti")
        refresh_jti = await redis_client.get(f"access_token:{access_jti}")

        client_id = payload.get("client_id")
        user_id = token_data.sub

        if not user_id or not client_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Validate client
        result = await db.execute(select(Clients).where(Clients.client_id == client_id))
        client = result.scalar_one_or_none()
        if not client:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid client",
                headers={"WWW-Authenticate": "Bearer"},
            )

        if not refresh_jti:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token",
                headers={"WWW-Authenticate": "Bearer"},
            )

    except (JWTError, ValidationError):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Retrieve user from the database using user id (sub)
    q = await db.scalars(select(Users).filter(Users.id == token_data.sub))
    user = q.first()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Could not find user",
        )

    return user
