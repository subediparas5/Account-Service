import asyncio
from datetime import datetime, timezone

from app.db import sessions
from app.db.models import Clients, ClientSecrets
from app.utils import get_password_hash


async def create_client():
    client_id = input("Enter the client ID: ")
    client_secret = input("Enter the client secret: ")

    hashed_client_secret = get_password_hash(client_secret)

    new_client = Clients(
        client_id=client_id,
    )

    client_secret_entry = ClientSecrets(
        client=new_client,
        hashed_client_secret=hashed_client_secret,
        created_at=datetime.now(timezone.utc),
        expires_at=None,
    )

    async with sessions.get_async_session() as db_session:
        db_session.add(new_client)
        db_session.add(client_secret_entry)
        await db_session.commit()
        print("Client created successfully.")


if __name__ == "__main__":
    asyncio.run(create_client())
