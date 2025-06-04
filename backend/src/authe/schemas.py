from ninja import Schema
from typing import Optional
from pydantic import EmailStr


class UserCreate(Schema):
    first_name: str
    last_name: str
    username: str
    email: EmailStr
    password: str


class UserResponse(Schema):
    id: int
    first_name: str
    last_name: str
    username: str
    email: EmailStr
    role: str
    requested_role: Optional[str]
    is_approved: bool
    is_verified: bool


class AdminRequest(Schema):
    requested_role: str


class Login(Schema):
    username: str
    password: str


class UserUpdate(Schema):
    first_name: str = None
    last_name: str = None
    username: str = None
    email: EmailStr = None


class PasswordChange(Schema):
    old_password: str
    new_password: str


class EmailVerificationRequest(Schema):
    email: EmailStr


class EmailVerificationResponse(Schema):
    uid: str
    token: str
