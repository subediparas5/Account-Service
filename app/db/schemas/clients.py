# app/db/schemas/clients.py
from datetime import datetime

from pydantic import BaseModel


class ClientCreate(BaseModel):
    client_id: str
    client_secret: str


class ClientSecret(BaseModel):
    hashed_client_secret: str
    created_at: datetime
    expires_at: datetime | None

    class Config:
        orm_mode = True


class Client(BaseModel):
    client_id: str
    secrets: list[ClientSecret] = []

    class Config:
        orm_mode = True


class ClientSecretRotate(BaseModel):
    client_id: str
    current_client_secret: str
    new_client_secret: str
