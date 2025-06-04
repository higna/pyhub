import uuid
from pyhub import settings
from ninja import Router
from django.db.models import Q
from ninja.errors import HttpError
from typing import List, Optional
from django.core.mail import send_mail
from django.contrib.auth import authenticate
from django.shortcuts import get_object_or_404
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth import login as log_in, logout as log_out
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode

from .models import *
from .schemas import *

# Initialize Router
router = Router()


# Email verification
def email_verification(user, request):
    token = default_token_generator.make_token(user)
    uid = urlsafe_base64_encode(force_bytes(user.pk))

    verification_url = request.build_absolute_url(
        f"/api/authe/verify-email/{uid}/{token}/"
    )
    subject = "Verify your email address"
    message = f"""
Hi {user.first_name},

Please click the linkbelow to verify your email address:
{verification_url}

if you didn't create an account, please ignore this email.

Best Regards, 
iCatalog
"""
    send_mail(
        subject,
        message,
        settings.DEFAULT_FROM_EMAIL,
        [user.email],
        fail_silently=False,
    )


# Signup route
@router.post("/signup", response=UserResponse, auth=None)
def signup(request, data: UserCreate):
    if Beneficiary.objects.filter(
        Q(username=data.username) | Q(email=data.email)
    ).exists():
        raise HttpError(400, "Username or email already exists")
    user = Beneficiary.objects.create_user(
        first_name=data.first_name,
        last_name=data.last_name,
        username=data.username,
        email=data.email,
        password=data.password,
        role="user",
        is_active=False,
    )
    # Send email verification
    try:
        email_verification(user, request)
        return {
            "id": user.id,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "message": "User created successfully. Please verify your email to activate your account.",
        }
    except Exception as e:
        return {
            "id": user.id,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "message": f"User created successfully, but failed to send verification email: {str(e)}",
        }


# Email verification route
@router.get(
    "/verify-email/{uid}/{token}", response=EmailVerificationResponse, auth=None
)
def verify_email(request, uid: str, token: str):
    try:
        user_id = force_str(urlsafe_base64_decode(uid))
        user = Beneficiary.objects.get(pk=user_id)
    except (TypeError, ValueError, OverflowError, Beneficiary.DoesNotExist):
        raise HttpError(400, "Invalid verification link")

    if default_token_generator.check_token(user, token):
        user.is_active = True
        user.email_verified = True
        user.save()
        return {
            "success": True,
            "message": "Email verified successfully. Proceed to login",
        }
    else:
        raise HttpError(400, "Invalidor expired verification link")


# Resend verification email
@router.post("/resend-verification")
def re_verify(request, data: EmailVerificationRequest):
    try:
        user = Beneficiary.objects.get(email=data.email)
        if user.is_active:
            raise HttpError(400, "Email is already verified")
        email_verification(user, request)
        return {"success": True, "message": "Verification email resent successfully."}
    except Beneficiary.DoesNotExist:
        raise HttpError(404, "User with this email does not exist.")


# Login route
@router.post("/login", response=UserResponse, auth=None)
def login(request, data: Login):
    try:
        user = Beneficiary.objects.get(
            Q(username=data.username) | Q(email=data.username)
        )
    except Beneficiary.DoesNotExist:
        raise HttpError(401, "Invalid username or password")

    # Authenticate user
    if data.username.count("@"):  # Email login
        auth_user = authenticate(
            request, username=user.username, password=data.password
        )
    else:
        auth_user = authenticate(
            request, username=data.username, password=data.password
        )

    if not auth_user:
        raise HttpError(401, "Invalid username or password")

    if not user.is_active:
        raise HttpError(401, "Please verify your email before logging in")

    # Generate JWT tokens
    from ninja_jwt.tokens import RefreshToken

    refresh = RefreshToken.for_user(user)

    return {
        "access_token": str(refresh.access_token),
        "refresh_token": str(refresh),
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "role": user.role,
        },
        "message": f"Successfully logged in as {user.username}",
    }


# Logout route
@router.post("/logout")
def logout(request):
    log_out(request)
    return {"success": True, "message": "Successfully logged out."}


# Update profile route
@router.post("/user/update", response=UserResponse)
def update(request, data: UserUpdate):
    user = request.auth
    if data.first_name is not None:
        user.first_name = data.first_name
    if data.last_name is not None:
        user.last_name = data.last_name
    if data.email is not None:
        if Beneficiary.objects.filter(email=data.email).exclude(id=user.id).exists():
            raise HttpError(400, "Email already taken")
        user.email = data.email
        user.email_verified = False
        email_verification(user, request)
    if not user.email_verified:
        raise HttpError(400, "Please verify your email before updating your profile")
    if data.username is not None:
        if (
            Beneficiary.objects.filter(username=data.username)
            .exclude(id=user.id)
            .exists()
        ):
            raise HttpError(400, "Username already taken")
        user.username = data.username
    user.save()
    return user


# Password change route
@router.post("/user/password-change", response={"message": str})
def password_change(request, data: PasswordChange):
    user = request.auth
    if user is None:
        raise HttpError(401, "User not authenticated")
    if not user.check_password(data.old_password):
        raise HttpError(400, "Old password is incorrect")

    user.set_password(data.new_password)
    user.save()
    return {"message": "Password changed successfully"}
