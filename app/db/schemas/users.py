from datetime import datetime
from typing import Annotated

from phonenumbers import NumberParseException, PhoneNumber, is_valid_number
from phonenumbers import parse as parse_phone_number
from pydantic import BaseModel, EmailStr, Field, PrivateAttr, field_validator


class UsersBase(BaseModel):
    first_name: Annotated[str, Field(to_lower=True)]
    last_name: Annotated[str, Field(to_lower=True)]
    email: EmailStr
    phone_number: str

    # Private attribute to store the parsed PhoneNumber object
    _parsed_phone_number: PhoneNumber = PrivateAttr()

    @field_validator("phone_number")
    def validate_phone_number(cls, value, values, **kwargs):
        try:
            parsed_number = parse_phone_number(value, None)
            if not is_valid_number(parsed_number):
                raise ValueError("Invalid phone number.")
            # Store the parsed number in the private attribute
            cls._parsed_phone_number = parsed_number
            return value
        except NumberParseException:
            raise ValueError("Invalid phone number.")

    model_config = {"from_attributes": True}


class UsersCreate(UsersBase):
    password: str = Field(alias="password")


class UserLogin(BaseModel):
    email: str | None = None
    phone_number: str | None = None
    password: str


class Users(UsersBase):
    id: int
    is_admin: bool
    created_at: datetime
    last_login: datetime
