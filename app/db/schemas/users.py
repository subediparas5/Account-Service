from datetime import date
from typing import Annotated

from phonenumbers import PhoneNumber
from pydantic import BaseModel, EmailStr, Field


class UsersBase(BaseModel):
    first_name: Annotated[str, Field(to_lower=True)]
    last_name: Annotated[str, Field(to_lower=True)]
    email: EmailStr
    phone_number: PhoneNumber
    is_admin: bool

    class Config:
        from_attributes = True


class UsersCreate(UsersBase):
    password: str = Field(alias="password")


class Users(UsersBase):
    id: int
    creation_date: date
    last_login: date
