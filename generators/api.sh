#!/bin/bash

# API endpoint generators - Fixed with Step 1: Password Security

# Generate user schemas with password validation
generate_user_schemas() {
    cat > src/schemas/user.py << 'EOF'
"""User schemas with password security validation."""

from typing import List, Optional
from pydantic import BaseModel, EmailStr, ConfigDict, field_validator
from datetime import datetime


class UserBase(BaseModel):
    """Base user schema."""
    email: EmailStr
    first_name: str
    last_name: Optional[str] = None
    is_active: bool = True


class UserCreate(UserBase):
    """Schema for creating a user with password validation."""
    password: str
    
    @field_validator('password')
    @classmethod
    def validate_password(cls, password: str) -> str:
        from src.utils.validators import validate_password_strength
        
        result = validate_password_strength(password)
        if not result["valid"]:
            raise ValueError(f"Password validation failed: {', '.join(result['errors'])}")
        
        return password


class UserUpdate(BaseModel):
    """Schema for updating a user."""
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    is_active: Optional[bool] = None


class UserResponse(UserBase):
    """Schema for user response."""
    id: int
    is_verified: bool
    password_changed_at: Optional[datetime] = None
    force_password_change: bool
    last_login: Optional[datetime] = None
    
    model_config = ConfigDict(from_attributes=True)


class UserLogin(BaseModel):
    """Schema for user login."""
    email: EmailStr
    password: str


class PasswordChange(BaseModel):
    """Schema for password change."""
    current_password: str
    new_password: str
    
    @field_validator('new_password')
    @classmethod
    def validate_new_password(cls, password: str) -> str:
        from src.utils.validators import validate_password_strength
        
        result = validate_password_strength(password)
        if not result["valid"]:
            raise ValueError(f"Password validation failed: {', '.join(result['errors'])}")
        
        return password


class PasswordReset(BaseModel):
    """Schema for password reset request."""
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    """Schema for password reset confirmation."""
    token: str
    new_password: str
    
    @field_validator('new_password')
    @classmethod
    def validate_new_password(cls, password: str) -> str:
        from src.utils.validators import validate_password_strength
        
        result = validate_password_strength(password)
        if not result["valid"]:
            raise ValueError(f"Password validation failed: {', '.join(result['errors'])}")
        
        return password


class PasswordStrengthCheck(BaseModel):
    """Schema for password strength checking."""
    password: str


class PasswordStrengthResponse(BaseModel):
    """Schema for password strength response."""
    valid: bool
    strength_score: int
    errors: List[str]
    feedback: List[str]


class Token(BaseModel):
    """Schema for token response."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenData(BaseModel):
    """Schema for token data."""
    user_id: Optional[int] = None
EOF
}

# Generate common schemas
generate_common_schemas() {
    cat > src/schemas/common.py << 'EOF'
"""Common schemas."""

from pydantic import BaseModel


class StatusMessage(BaseModel):
    """Standard status message response."""
    status: str
    message: str


class ErrorResponse(BaseModel):
    """Standard error response."""
    detail: str


class SuccessResponse(BaseModel):
    """Standard success response."""
    success: bool
    message: str
    data: dict = None
EOF
}

# Generate user repository with password security
generate_user_repository() {
    cat > src/repositories/user.py << 'EOF'
"""User repository with password security features."""

from typing import List, Optional
from datetime import datetime, timedelta
from sqlalchemy import select, and_, update
from sqlalchemy.orm import selectinload

from src.models.user import User, Role, UserRole, PasswordResetToken
from src.schemas.user import UserCreate, UserUpdate


class UserRepository:
    def __init__(self, session):
        self.session = session

    async def get_by_id(self, user_id: int) -> Optional[User]:
        """Get user by ID."""
        query = select(User).where(
            and_(User.id == user_id, User.deleted_at.is_(None))
        )
        result = await self.session.execute(query)
        return result.scalar_one_or_none()

    async def get_by_email(self, email: str) -> Optional[User]:
        """Get user by email."""
        query = select(User).where(
            and_(User.email == email, User.deleted_at.is_(None))
        )
        result = await self.session.execute(query)
        return result.scalar_one_or_none()

    async def create(self, user_data: UserCreate, hashed_password: str) -> User:
        """Create a new user."""
        user = User(
            email=user_data.email,
            hashed_password=hashed_password,
            first_name=user_data.first_name,
            last_name=user_data.last_name,
            is_active=user_data.is_active,
            password_changed_at=datetime.utcnow(),
            password_history=[hashed_password]
        )
        self.session.add(user)
        await self.session.commit()
        await self.session.refresh(user)
        return user

    async def update(self, user_id: int, user_data: UserUpdate) -> Optional[User]:
        """Update user."""
        user = await self.get_by_id(user_id)
        if not user:
            return None

        update_data = user_data.model_dump(exclude_unset=True)
        for key, value in update_data.items():
            setattr(user, key, value)

        user.updated_at = datetime.utcnow()
        await self.session.commit()
        await self.session.refresh(user)
        return user

    async def update_password(self, user_id: int, new_hashed_password: str) -> Optional[User]:
        """Update user password with history tracking."""
        user = await self.get_by_id(user_id)
        if not user:
            return None

        # Add current password to history
        user.add_password_to_history(user.hashed_password)
        
        # Update password
        user.hashed_password = new_hashed_password
        user.password_changed_at = datetime.utcnow()
        user.force_password_change = False
        user.updated_at = datetime.utcnow()

        await self.session.commit()
        await self.session.refresh(user)
        return user

    async def increment_failed_login_attempts(self, user_id: int) -> None:
        """Increment failed login attempts counter."""
        query = (
            update(User)
            .where(User.id == user_id)
            .values(
                failed_login_attempts=User.failed_login_attempts + 1,
                updated_at=datetime.utcnow()
            )
        )
        await self.session.execute(query)
        await self.session.commit()

    async def reset_failed_login_attempts(self, user_id: int) -> None:
        """Reset failed login attempts counter."""
        query = (
            update(User)
            .where(User.id == user_id)
            .values(
                failed_login_attempts=0,
                last_login=datetime.utcnow(),
                updated_at=datetime.utcnow()
            )
        )
        await self.session.execute(query)
        await self.session.commit()

    async def lock_account(self, user_id: int, lock_duration_minutes: int = 15) -> None:
        """Lock user account for specified duration."""
        lock_until = datetime.utcnow() + timedelta(minutes=lock_duration_minutes)
        query = (
            update(User)
            .where(User.id == user_id)
            .values(
                locked_until=lock_until,
                updated_at=datetime.utcnow()
            )
        )
        await self.session.execute(query)
        await self.session.commit()

    async def get_user_roles(self, user_id: int) -> List[Role]:
        """Get user roles."""
        query = (
            select(Role)
            .join(UserRole)
            .where(UserRole.user_id == user_id)
        )
        result = await self.session.execute(query)
        return result.scalars().all()

    async def add_role_to_user(self, user_id: int, role_id: int) -> UserRole:
        """Add role to user."""
        user_role = UserRole(user_id=user_id, role_id=role_id)
        self.session.add(user_role)
        await self.session.commit()
        await self.session.refresh(user_role)
        return user_role

    async def create_password_reset_token(self, user_id: int, token: str, expires_at: datetime) -> PasswordResetToken:
        """Create password reset token."""
        reset_token = PasswordResetToken(
            user_id=user_id,
            token=token,
            expires_at=expires_at
        )
        self.session.add(reset_token)
        await self.session.commit()
        await self.session.refresh(reset_token)
        return reset_token

    async def get_password_reset_token(self, token: str) -> Optional[PasswordResetToken]:
        """Get password reset token."""
        query = select(PasswordResetToken).where(PasswordResetToken.token == token)
        result = await self.session.execute(query)
        return result.scalar_one_or_none()

    async def use_password_reset_token(self, token: str) -> bool:
        """Mark password reset token as used."""
        query = (
            update(PasswordResetToken)
            .where(PasswordResetToken.token == token)
            .values(used=True, updated_at=datetime.utcnow())
        )
        result = await self.session.execute(query)
        await self.session.commit()
        return result.rowcount > 0
EOF
}

# Generate user service with password security
generate_user_service() {
    cat > src/services/user.py << 'EOF'
"""User service with password security features."""

from typing import Optional
from datetime import datetime
from fastapi import HTTPException, status

from src.repositories.user import UserRepository
from src.schemas.user import UserCreate, UserUpdate, UserResponse, PasswordChange
from src.auth.jwt import get_password_hash, verify_password
from src.utils.validators import validate_password_history, validate_password_strength


class UserService:
    def __init__(self, user_repo: UserRepository):
        self.user_repo = user_repo

    async def create_user(self, user_data: UserCreate) -> UserResponse:
        """Create a new user with password validation."""
        # Check if user exists
        existing_user = await self.user_repo.get_by_email(user_data.email)
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )

        # Hash password
        hashed_password = get_password_hash(user_data.password)
        
        # Create user
        user = await self.user_repo.create(user_data, hashed_password)
        
        return UserResponse.model_validate(user)

    async def authenticate_user(self, email: str, password: str) -> Optional[UserResponse]:
        """Authenticate user with account lockout protection."""
        user = await self.user_repo.get_by_email(email)
        if not user:
            return None
        
        # Check if account is locked
        if user.is_locked():
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail="Account is temporarily locked due to too many failed login attempts"
            )
        
        # Verify password
        if not verify_password(password, user.hashed_password):
            # Increment failed attempts
            await self.user_repo.increment_failed_login_attempts(user.id)
            
            # Check if we should lock the account (5 failed attempts)
            if user.failed_login_attempts + 1 >= 5:
                await self.user_repo.lock_account(user.id, 15)  # Lock for 15 minutes
                raise HTTPException(
                    status_code=status.HTTP_423_LOCKED,
                    detail="Account locked due to too many failed login attempts. Try again in 15 minutes."
                )
            
            return None
        
        # Reset failed attempts on successful login
        await self.user_repo.reset_failed_login_attempts(user.id)
        
        return UserResponse.model_validate(user)

    async def get_user(self, user_id: int) -> Optional[UserResponse]:
        """Get user by ID."""
        user = await self.user_repo.get_by_id(user_id)
        if not user:
            return None
        
        return UserResponse.model_validate(user)

    async def change_password(self, user_id: int, password_data: PasswordChange) -> UserResponse:
        """Change user password with validation."""
        user = await self.user_repo.get_by_id(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        # Verify current password
        if not verify_password(password_data.current_password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password is incorrect"
            )

        # Check password history
        if not validate_password_history(password_data.new_password, user.password_history):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot reuse any of your last 5 passwords"
            )

        # Hash new password
        new_hashed_password = get_password_hash(password_data.new_password)
        
        # Update password
        updated_user = await self.user_repo.update_password(user_id, new_hashed_password)
        
        return UserResponse.model_validate(updated_user)

    async def check_password_strength(self, password: str) -> dict:
        """Check password strength and provide feedback."""
        result = validate_password_strength(password)
        
        from src.utils.password import get_password_strength_feedback
        feedback = get_password_strength_feedback(password)
        
        return {
            "valid": result["valid"],
            "strength_score": result["strength_score"],
            "errors": result["errors"],
            "feedback": feedback
        }
EOF
}

# Generate auth service with password security
generate_auth_service() {
    cat > src/services/auth.py << 'EOF'
"""Authentication service with password security features."""

from datetime import timedelta, datetime
from fastapi import HTTPException, status

from src.services.user import UserService
from src.schemas.user import UserLogin, Token, PasswordReset, PasswordResetConfirm
from src.auth.jwt import create_access_token, create_refresh_token
from src.core.config import settings
from src.utils.password import generate_password_reset_token


class AuthService:
    def __init__(self, user_service: UserService):
        self.user_service = user_service

    async def login(self, login_data: UserLogin) -> Token:
        """Login user and return tokens with security checks."""
        user = await self.user_service.authenticate_user(
            login_data.email, 
            login_data.password
        )
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Inactive user"
            )

        # Check if user needs to change password
        if user.force_password_change:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Password change required. Please change your password before logging in."
            )

        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": str(user.id)}, 
            expires_delta=access_token_expires
        )
        
        refresh_token = create_refresh_token(data={"sub": str(user.id)})

        return Token(
            access_token=access_token,
            refresh_token=refresh_token
        )

    async def request_password_reset(self, reset_data: PasswordReset) -> dict:
        """Request password reset token."""
        from src.repositories.user import UserRepository
        from src.core.database import get_db
        
        # Get database session (this would be injected in real implementation)
        async for session in get_db():
            user_repo = UserRepository(session)
            
            user = await user_repo.get_by_email(reset_data.email)
            if not user:
                # Don't reveal if email exists or not
                return {"message": "If the email exists, a reset link has been sent"}

            # Generate reset token
            token = generate_password_reset_token()
            expires_at = datetime.utcnow() + timedelta(hours=1)  # 1 hour expiry
            
            # Save token to database
            await user_repo.create_password_reset_token(user.id, token, expires_at)
            
            # TODO: Send email with reset link (Step 5 implementation)
            # For now, we'll just return the token (remove this in production)
            return {
                "message": "Password reset token generated",
                "token": token  # Remove this in production
            }

    async def confirm_password_reset(self, reset_data: PasswordResetConfirm) -> dict:
        """Confirm password reset with token."""
        from src.repositories.user import UserRepository
        from src.core.database import get_db
        from src.auth.jwt import get_password_hash
        
        # Get database session (this would be injected in real implementation)
        async for session in get_db():
            user_repo = UserRepository(session)
            
            # Get and validate token
            reset_token = await user_repo.get_password_reset_token(reset_data.token)
            if not reset_token or not reset_token.is_valid():
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid or expired reset token"
                )

            # Get user
            user = await user_repo.get_by_id(reset_token.user_id)
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )

            # Check password history
            from src.utils.validators import validate_password_history
            if not validate_password_history(reset_data.new_password, user.password_history):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Cannot reuse any of your last 5 passwords"
                )

            # Update password
            new_hashed_password = get_password_hash(reset_data.new_password)
            await user_repo.update_password(user.id, new_hashed_password)
            
            # Mark token as used
            await user_repo.use_password_reset_token(reset_data.token)
            
            return {"message": "Password reset successful"}
EOF
}

# Generate auth endpoints with password security
generate_auth_endpoints() {
    cat > src/api/endpoints/auth.py << 'EOF'
"""Authentication endpoints with password security features."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.database import get_db
from src.repositories.user import UserRepository
from src.services.user import UserService
from src.services.auth import AuthService
from src.schemas.user import (
    UserLogin, UserCreate, UserResponse, Token, PasswordChange,
    PasswordReset, PasswordResetConfirm, PasswordStrengthCheck, PasswordStrengthResponse
)
from src.schemas.common import StatusMessage, SuccessResponse
from src.auth.permissions import get_current_active_user

router = APIRouter()


async def get_auth_service(session: AsyncSession = Depends(get_db)) -> AuthService:
    """Get auth service dependency."""
    user_repo = UserRepository(session)
    user_service = UserService(user_repo)
    return AuthService(user_service)


async def get_user_service(session: AsyncSession = Depends(get_db)) -> UserService:
    """Get user service dependency."""
    user_repo = UserRepository(session)
    return UserService(user_repo)


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(
    user_data: UserCreate,
    auth_service: AuthService = Depends(get_auth_service)
):
    """Register a new user with password validation."""
    return await auth_service.user_service.create_user(user_data)


@router.post("/login", response_model=Token)
async def login(
    login_data: UserLogin,
    auth_service: AuthService = Depends(get_auth_service)
):
    """Login user and return access token."""
    return await auth_service.login(login_data)


@router.post("/change-password", response_model=SuccessResponse)
async def change_password(
    password_data: PasswordChange,
    current_user: dict = Depends(get_current_active_user),
    user_service: UserService = Depends(get_user_service)
):
    """Change user password with validation."""
    await user_service.change_password(current_user["id"], password_data)
    return SuccessResponse(
        success=True,
        message="Password changed successfully"
    )


@router.post("/check-password-strength", response_model=PasswordStrengthResponse)
async def check_password_strength(
    password_data: PasswordStrengthCheck,
    user_service: UserService = Depends(get_user_service)
):
    """Check password strength and get feedback."""
    result = await user_service.check_password_strength(password_data.password)
    return PasswordStrengthResponse(**result)


@router.post("/request-password-reset", response_model=SuccessResponse)
async def request_password_reset(
    reset_data: PasswordReset,
    auth_service: AuthService = Depends(get_auth_service)
):
    """Request password reset token."""
    result = await auth_service.request_password_reset(reset_data)
    return SuccessResponse(
        success=True,
        message=result["message"],
        data={"token": result.get("token")}  # Remove in production
    )


@router.post("/confirm-password-reset", response_model=SuccessResponse)
async def confirm_password_reset(
    reset_data: PasswordResetConfirm,
    auth_service: AuthService = Depends(get_auth_service)
):
    """Confirm password reset with token."""
    result = await auth_service.confirm_password_reset(reset_data)
    return SuccessResponse(
        success=True,
        message=result["message"]
    )
EOF
}

# Generate user endpoints
generate_user_endpoints() {
    cat > src/api/endpoints/users.py << 'EOF'
"""User endpoints."""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.database import get_db
from src.repositories.user import UserRepository
from src.services.user import UserService
from src.schemas.user import UserResponse
from src.auth.permissions import get_current_active_user

router = APIRouter()


async def get_user_service(session: AsyncSession = Depends(get_db)) -> UserService:
    """Get user service dependency."""
    user_repo = UserRepository(session)
    return UserService(user_repo)


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: dict = Depends(get_current_active_user),
    user_service: UserService = Depends(get_user_service)
):
    """Get current user information."""
    user = await user_service.get_user(current_user["id"])
    return user
EOF
}

# Generate API router
generate_api_router() {
    cat > src/api/router.py << 'EOF'
"""API router configuration."""

from fastapi import APIRouter

from src.api.endpoints import auth, users

api_router = APIRouter()

# Include endpoint routers
api_router.include_router(auth.router, prefix="/auth", tags=["authentication"])
api_router.include_router(users.router, prefix="/users", tags=["users"])
EOF

    # Update src/api/__init__.py
    cat > src/api/__init__.py << 'EOF'
from .router import api_router
EOF
}