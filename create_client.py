import asyncio
import os
import uuid
from datetime import datetime, timezone

from app.db.models import Clients, ClientSecrets
from app.db.sessions import get_async_session
from app.utils import get_password_hash


async def create_client():
    client_id = uuid.uuid4().hex

    # Generate a secure random client secret
    client_secret = os.urandom(32)  # Use os.urandom for cryptographic randomness

    print("Client ID:", client_id)
    print("Client Secret:", client_secret.hex())

    hashed_client_secret = get_password_hash(client_secret.hex())

    print("Hashed Client Secret:", hashed_client_secret)

    new_client = Clients(
        client_id=client_id,
    )

    client_secret_entry = ClientSecrets(
        client=new_client,
        hashed_client_secret=hashed_client_secret,
        created_at=datetime.now(timezone.utc),
        expires_at=None,
    )

    async with get_async_session() as db_session:
        db_session.add(new_client)
        db_session.add(client_secret_entry)
        await db_session.commit()
        print("Client created successfully.")


if __name__ == "__main__":
    asyncio.run(create_client())
