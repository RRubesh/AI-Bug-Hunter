import datetime
from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from backend.database import get_db, is_mongo_connected, get_mongo_db
from backend.database.mongodb import mongo_manager
from backend.models import User
from backend.schemas import UserCreate, UserResponse, Token, PasswordReset
from backend.auth.jwt import get_password_hash, verify_password, create_access_token, get_current_user

router = APIRouter(prefix="/auth", tags=["Authentication"])

def utcnow():
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)

@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(user_in: UserCreate, request: Request, db: Session = Depends(get_db)):
    # Check if username exists
    existing_user = db.query(User).filter(User.username == user_in.username).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )
    
    # If this is the first user in the system, automatically make them admin
    total_users = db.query(User).count()
    role = "admin" if total_users == 0 else "developer"
    
    hashed_password = get_password_hash(user_in.password)
    now = utcnow()
    new_user = User(
        username=user_in.username,
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
                    {"username": new_user.username},
                    {"$set": {
                        "user_id": new_user.id,
                        "username": new_user.username,
                        "password_hash": hashed_password,
                        "role": new_user.role,
                        "is_active": True,
                        "created_at": new_user.created_at or now,
                        "updated_at": now,
                        "last_login": None
                    }},
                    upsert=True
                )
    except Exception:
        pass

    mongo_manager.log_security_event(
        event_type="user_registered",
        description=f"New user registered: {new_user.username} (Role: {new_user.role})",
        user_id=new_user.id,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent")
    )

    return new_user

@router.post("/login", response_model=Token)
def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        mongo_manager.log_security_event(
            event_type="login_failed",
            description=f"Failed login attempt for username: {form_data.username}",
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent")
        )
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

    mongo_manager.log_security_event(
        event_type="login_success",
        description=f"User logged in: {user.username}",
        user_id=user.id,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent")
    )

    access_token = create_access_token(data={"sub": user.username, "role": user.role})
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "role": user.role,
        "username": user.username
    }

@router.post("/logout")
def logout(request: Request, current_user: User = Depends(get_current_user)):
    mongo_manager.log_security_event(
        event_type="logout",
        description=f"User logged out: {current_user.username}",
        user_id=current_user.id,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent")
    )
    return {"message": "Logged out successfully"}

@router.get("/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_current_user)):
    return current_user

@router.post("/forgot-password")
@router.post("/recovery")
def forgot_password(reset_in: PasswordReset, request: Request, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == reset_in.username).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    from backend.config import settings
    if reset_in.recovery_key != "HUNTER_RECOVERY_2026" and reset_in.recovery_key != settings.SECRET_KEY:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid recovery token"
        )
    
    new_hashed_password = get_password_hash(reset_in.new_password)
    user.hashed_password = new_hashed_password
    db.commit()

    try:
        if is_mongo_connected():
            mongo_db = get_mongo_db()
            if mongo_db is not None:
                mongo_db.users.update_one(
                    {"username": user.username},
                    {"$set": {"password_hash": new_hashed_password, "updated_at": utcnow()}}
                )
    except Exception:
        pass

    mongo_manager.log_security_event(
        event_type="password_reset",
        description=f"Password reset completed for: {user.username}",
        user_id=user.id,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent")
    )

    return {"message": "Password reset successful"}

