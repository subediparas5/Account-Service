from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .sessions import Base


class Users(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    is_admin: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    first_name: Mapped[str] = mapped_column(Text, nullable=False)
    last_name: Mapped[str] = mapped_column(Text, nullable=False)
    email: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    phone_number: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    hashed_password: Mapped[str] = mapped_column(Text, nullable=False)
    last_login: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), nullable=False)


class Clients(Base):
    __tablename__ = "clients"
    id = Column(Integer, primary_key=True, index=True)
    client_id = Column(String, unique=True, index=True, nullable=False)

    client_secrets = relationship("ClientSecrets", back_populates="client", cascade="all, delete-orphan")


class ClientSecrets(Base):
    __tablename__ = "client_secrets"
    id = Column(Integer, primary_key=True, index=True)
    client_id = Column(Integer, ForeignKey("clients.id"), nullable=False)
    hashed_client_secret = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), default=datetime.now(timezone.utc))
    expires_at = Column(DateTime(timezone=True), nullable=True)

    client = relationship("Clients", back_populates="client_secrets")
