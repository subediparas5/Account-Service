from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import sessions
from app.db.models import ClientSecrets, Users
from app.db.schemas.clients import ClientSecretRotate
from app.deps import get_current_user
from app.utils import check_client_credentials, get_password_hash, verify_password

router = APIRouter(prefix="/client", tags=["client"])


@router.post("/rotate-client-secret", summary="Rotate client secret")
async def rotate_client_secret(
    payload: ClientSecretRotate,
    current_user: Users = Depends(get_current_user),
    db: AsyncSession = Depends(sessions.async_session_maker),
):
    """
    Rotate a client secret
    """
    # Validate client credentials
    client = await check_client_credentials(
        client_id=payload.client_id,
        client_secret=payload.current_client_secret,
        db=db,
    )

    # check user is admin
    if not current_user.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")

    new_hashed_client_secret = get_password_hash(payload.new_client_secret)

    # Create a new client secret entry
    now = datetime.now(timezone.utc)
    new_client_secret_entry = ClientSecrets(
        client=client,
        hashed_client_secret=new_hashed_client_secret,
        created_at=now,
        expires_at=None,  # New secret does not expire
    )

    # Set an expiration for the old client secret (e.g., 30 days)
    expiration_period = timedelta(days=30)
    # Find the current secret entry (since we validated it)
    current_secret_entry = None
    for secret in client.secrets:
        if verify_password(payload.current_client_secret, secret.hashed_client_secret):
            current_secret_entry = secret
            break
    if current_secret_entry:
        current_secret_entry.expires_at = now + expiration_period

    db.add(new_client_secret_entry)
    await db.commit()
    await db.refresh(client)

    return {
        "message": "Client secret rotated successfully",
        "old_secret_expires_at": current_secret_entry.expires_at.isoformat() if current_secret_entry else None,
    }
