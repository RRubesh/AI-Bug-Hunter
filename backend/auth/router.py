import re
import secrets
import hashlib
import datetime
from datetime import timedelta
from typing import Dict, List
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from backend.database import get_db, is_mongo_connected, get_mongo_db
from backend.database.mongodb import mongo_manager
from backend.models import User, PasswordResetToken
from backend.schemas import (
    UserCreate, UserResponse, Token, 
    ForgotPasswordRequest, ResetPasswordRequest
)
from backend.auth.jwt import get_password_hash, verify_password, create_access_token, get_current_user
from backend.services.email_service import send_password_reset_email
from backend.config import settings

router = APIRouter(prefix="/auth", tags=["Authentication"])

def utcnow():
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)

# In-memory Rate Limiting Storage (Sliding Window per IP/Endpoint)
_rate_limit_store: Dict[str, List[datetime.datetime]] = {}

def check_rate_limit(key: str, max_requests: int = 10, window_seconds: int = 60):
    now = utcnow()
    cutoff = now - timedelta(seconds=window_seconds)
    timestamps = _rate_limit_store.get(key, [])
    # Filter out timestamps older than the cutoff window
    valid_timestamps = [t for t in timestamps if t > cutoff]
    if len(valid_timestamps) >= max_requests:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests. Please slow down and try again later."
        )
    valid_timestamps.append(now)
    _rate_limit_store[key] = valid_timestamps

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")

def validate_password_strength(password: str):
    if len(password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 8 characters long."
        )
    if not re.search(r"[A-Za-z]", password) or not re.search(r"[0-9!@#$%^&*(),.?\":{}|<>]", password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must contain at least one letter and one number or special symbol."
        )

@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(user_in: UserCreate, request: Request, db: Session = Depends(get_db)):
    ip = request.client.host if request.client else "unknown"
    check_rate_limit(f"register:{ip}", max_requests=10, window_seconds=60)

    clean_username = (user_in.username or "").strip()
    clean_email = (user_in.email or "").strip().lower()

    if not clean_username:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username is required.")
    if len(clean_username) < 3 or len(clean_username) > 50:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username must be between 3 and 50 characters.")

    if not clean_email or not EMAIL_REGEX.match(clean_email):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="A valid email address is required.")

    validate_password_strength(user_in.password)

    # Check if username or email already registered
    existing_user = db.query(User).filter(
        (User.username == clean_username) | (User.email == clean_email)
    ).first()

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email or username is already registered."
        )

    # Public registrations always create standard USER accounts (initial user is admin)
    total_users = db.query(User).count()
    role = "admin" if total_users == 0 else "user"

    hashed_password = get_password_hash(user_in.password)
    now = utcnow()

    new_user = User(
        username=clean_username,
        email=clean_email,
        hashed_password=hashed_password,
        role=role
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # Sync to MongoDB Atlas users collection
    try:
        if is_mongo_connected():
            mongo_db = get_mongo_db()
            if mongo_db is not None:
                mongo_db.users.update_one(
                    {"email": new_user.email},
                    {"$set": {
                        "name": new_user.username,
                        "username": new_user.username,
                        "email": new_user.email,
                        "password_hash": hashed_password,
                        "role": new_user.role,
                        "is_active": True,
                        "created_at": new_user.created_at or now,
                        "updated_at": now,
                        "user_id": new_user.id
                    }},
                    upsert=True
                )
    except Exception:
        pass

    mongo_manager.log_audit_event(
        action="user_registered",
        resource="users",
        resource_id=new_user.id,
        user_id=new_user.id,
        ip_address=ip,
        details={"username": new_user.username, "email": new_user.email, "role": new_user.role}
    )

    return new_user

@router.post("/login", response_model=Token)
def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    ip = request.client.host if request.client else "unknown"
    check_rate_limit(f"login:{ip}", max_requests=15, window_seconds=60)

    identifier = (form_data.username or "").strip()
    identifier_lower = identifier.lower()

    user = None
    try:
        user = db.query(User).filter(
            (User.username == identifier) | (User.email == identifier_lower)
        ).first()
    except Exception as e:
        print(f"[Login Query Exception]: {e}")

    # If database is completely empty, auto-seed the first login attempt as Admin
    if not user:
        try:
            total_users = db.query(User).count()
            if total_users == 0:
                default_user = User(
                    username=identifier,
                    email=f"{identifier_lower}@aibughunter.local" if "@" not in identifier else identifier_lower,
                    hashed_password=get_password_hash(form_data.password),
                    role="admin"
                )
                db.add(default_user)
                db.commit()
                db.refresh(default_user)
                user = default_user
        except Exception as seed_err:
            print(f"[Auto-Seed Admin Notice]: {seed_err}")

    if not user or not verify_password(form_data.password, user.hashed_password):
        try:
            mongo_manager.log_security_event(
                event_type="login_failed",
                description=f"Failed login attempt for identifier: {identifier}",
                ip_address=ip,
                user_agent=request.headers.get("user-agent")
            )
        except Exception:
            pass

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    now = utcnow()
    try:
        if is_mongo_connected():
            mongo_db = get_mongo_db()
            if mongo_db is not None:
                mongo_db.users.update_one(
                    {"username": user.username},
                    {"$set": {"last_login": now, "updated_at": now}},
                    upsert=True
                )
    except Exception:
        pass

    try:
        mongo_manager.log_security_event(
            event_type="login_success",
            description=f"User logged in: {user.username} ({user.email})",
            user_id=user.id,
            ip_address=ip,
            user_agent=request.headers.get("user-agent")
        )
    except Exception:
        pass

    access_token = create_access_token(data={
        "sub": user.username,
        "email": user.email,
        "role": user.role,
        "user_id": user.id
    })

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "role": user.role,
        "username": user.username,
        "email": user.email
    }

@router.post("/logout")
def logout(request: Request, current_user: User = Depends(get_current_user)):
    ip = request.client.host if request.client else "unknown"
    mongo_manager.log_security_event(
        event_type="logout",
        description=f"User logged out: {current_user.username}",
        user_id=current_user.id,
        ip_address=ip,
        user_agent=request.headers.get("user-agent")
    )
    return {"message": "Logged out successfully"}

@router.get("/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_current_user)):
    return current_user

@router.post("/forgot-password")
def forgot_password(req: ForgotPasswordRequest, request: Request, db: Session = Depends(get_db)):
    ip = request.client.host if request.client else "unknown"
    check_rate_limit(f"forgot-password:{ip}", max_requests=6, window_seconds=60)

    clean_email = (req.email or "").strip().lower()
    raw_token = None

    if clean_email and EMAIL_REGEX.match(clean_email):
        user = db.query(User).filter(User.email == clean_email).first()
        if user:
            # Generate cryptographically secure token
            raw_token = secrets.token_urlsafe(32)
            token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
            expires_at = utcnow() + timedelta(minutes=15)

            # Invalidate any prior unused reset tokens for this user
            db.query(PasswordResetToken).filter(
                PasswordResetToken.user_id == user.id,
                PasswordResetToken.used == False
            ).update({"used": True})

            # Save new reset token record
            reset_record = PasswordResetToken(
                user_id=user.id,
                token_hash=token_hash,
                expires_at=expires_at,
                used=False
            )
            db.add(reset_record)
            db.commit()

            # Sync to MongoDB
            try:
                if is_mongo_connected():
                    mongo_db = get_mongo_db()
                    if mongo_db is not None:
                        mongo_db.password_reset_tokens.insert_one({
                            "user_id": user.id,
                            "email": user.email,
                            "token_hash": token_hash,
                            "expires_at": expires_at,
                            "used": False,
                            "created_at": utcnow()
                        })
            except Exception:
                pass

            mongo_manager.log_security_event(
                event_type="password_reset_requested",
                description=f"Password reset token requested for email: {user.email}",
                user_id=user.id,
                ip_address=ip,
                user_agent=request.headers.get("user-agent")
            )
            
            # Dispatch secure reset authorization email
            try:
                send_password_reset_email(
                    to_email=clean_email,
                    username=user.username,
                    raw_token=raw_token,
                    request_host=request.headers.get("host")
                )
            except Exception as email_err:
                print(f"[Email Dispatch Warning]: {email_err}")

    # Always return a uniform generic response to prevent account enumeration
    response_data = {
        "message": "If an account exists for this email, a password reset link has been sent.",
        "status": "success"
    }
    if raw_token and settings.DEBUG:
        response_data["dev_token"] = raw_token

    return response_data

@router.post("/reset-password")
def reset_password(req: ResetPasswordRequest, request: Request, db: Session = Depends(get_db)):
    ip = request.client.host if request.client else "unknown"
    check_rate_limit(f"reset-password:{ip}", max_requests=6, window_seconds=60)

    raw_token = (req.token or "").strip()
    if not raw_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Reset token is required."
        )

    target_password = req.clean_password
    if not target_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password is required."
        )

    validate_password_strength(target_password)

    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    now = utcnow()

    reset_record = db.query(PasswordResetToken).filter(
        PasswordResetToken.token_hash == token_hash,
        PasswordResetToken.used == False
    ).first()

    if not reset_record or reset_record.expires_at < now:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid, expired, or already used password reset token."
        )

    user = db.query(User).filter(User.id == reset_record.user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Associated user account not found."
        )

    # Hash new password and update user
    new_hashed_password = get_password_hash(target_password)
    user.hashed_password = new_hashed_password
    reset_record.used = True
    db.commit()

    # Sync to MongoDB Atlas
    try:
        if is_mongo_connected():
            mongo_db = get_mongo_db()
            if mongo_db is not None:
                mongo_db.users.update_one(
                    {"username": user.username},
                    {"$set": {"password_hash": new_hashed_password, "updated_at": now}}
                )
                mongo_db.password_reset_tokens.update_many(
                    {"user_id": user.id},
                    {"$set": {"used": True}}
                )
    except Exception:
        pass

    mongo_manager.log_security_event(
        event_type="password_reset_completed",
        description=f"Password successfully reset for user: {user.username} ({user.email})",
        user_id=user.id,
        ip_address=ip,
        user_agent=request.headers.get("user-agent")
    )

    return {"message": "Password reset successfully. You can now login with your new credentials."}
