from datetime import datetime, timedelta, timezone
from typing import Optional
from jose import JWTError, jwt
import bcrypt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from backend.config import settings
from backend.database import get_db
from backend.models import User

# oauth2_scheme setup
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception:
        return False

def get_password_hash(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

def get_current_user(
    request: Request,
    token: Optional[str] = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    token_val = token or request.query_params.get("token")
    if not token_val:
        raise credentials_exception

    try:
        payload = jwt.decode(token_val, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub")
        role: str = payload.get("role", "user")
        email: Optional[str] = payload.get("email")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
        
    try:
        user = db.query(User).filter((User.username == username) | (User.email == username)).first()
    except Exception:
        user = None

    if user is None:
        # Re-create persistent user record in SQLite session for this serverless container
        try:
            user_email = email or f"{username}@aibughunter.local"
            user = User(username=username, email=user_email, hashed_password="", role=role, is_active=True)
            db.add(user)
            db.commit()
            db.refresh(user)
        except Exception:
            user = User(id=1, username=username, email=f"{username}@aibughunter.local", hashed_password="", role=role, is_active=True)
    else:
        if role and role != user.role:
            try:
                user.role = role
                db.commit()
            except Exception:
                pass

    if not getattr(user, "is_active", True):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated."
        )

    return user


def get_current_admin(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator privileges required",
        )
    return current_user

def get_current_developer(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role not in ("developer", "admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Developer or Administrator privileges required",
        )
    return current_user

