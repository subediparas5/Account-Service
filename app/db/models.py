import sqlalchemy as sa

from .sessions import Base


class Users(Base):
    __tablename__ = "users"

    id = sa.Column(sa.Integer, primary_key=True, index=True)
    is_admin = sa.Column(sa.Boolean, nullable=False, default=False)
    first_name = sa.Column(sa.Text, nullable=False)
    last_name = sa.Column(sa.Text, nullable=False)
    email = sa.Column(sa.Text, nullable=False, unique=True)
    phone_number = sa.Column(sa.Text, nullable=False, unique=True)
    hashed_password = sa.Column(sa.Text, nullable=False)
    last_login = sa.Column(sa.DateTime, nullable=True)
    created_at = sa.Column(sa.DateTime, server_default=sa.func.now(), nullable=False)
