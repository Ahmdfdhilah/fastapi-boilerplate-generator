#!/bin/bash

# API endpoint generators

# Generate user schemas
generate_user_schemas() {
    cat > src/schemas/user.py << 'EOF'
"""User schemas."""

from typing import List, Optional
from pydantic import BaseModel, EmailStr, ConfigDict


class UserBase(BaseModel):
    """Base user schema."""
    email: EmailStr
    first_name: str
    last_name: Optional[str] = None
    is_active: bool = True


class UserCreate(UserBase):
    """Schema for creating a user."""
    password: str


class UserUpdate(BaseModel):
    """Schema for updating a user."""
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    is_active: Optional[bool] = None


class UserResponse(UserBase):
    """Schema for user response."""
    id: int
    
    model_config = ConfigDict(from_attributes=True)


class UserLogin(BaseModel):
    """Schema for user login."""
    email: EmailStr
    password: str


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
EOF
}

# Generate user repository
generate_user_repository() {
    cat > src/repositories/user.py << 'EOF'
"""User repository."""

from typing import List, Optional
from sqlalchemy import select, and_
from sqlalchemy.orm import selectinload

from src.models.user import User, Role, UserRole
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

        await self.session.commit()
        await self.session.refresh(user)
        return user

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
EOF
}

# Generate user service
generate_user_service() {
    cat > src/services/user.py << 'EOF'
"""User service."""

from typing import Optional
from fastapi import HTTPException, status

from src.repositories.user import UserRepository
from src.schemas.user import UserCreate, UserUpdate, UserResponse
from src.auth.jwt import get_password_hash, verify_password


class UserService:
    def __init__(self, user_repo: UserRepository):
        self.user_repo = user_repo

    async def create_user(self, user_data: UserCreate) -> UserResponse:
        """Create a new user."""
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
        """Authenticate user."""
        user = await self.user_repo.get_by_email(email)
        if not user:
            return None
        
        if not verify_password(password, user.hashed_password):
            return None
        
        return UserResponse.model_validate(user)

    async def get_user(self, user_id: int) -> Optional[UserResponse]:
        """Get user by ID."""
        user = await self.user_repo.get_by_id(user_id)
        if not user:
            return None
        
        return UserResponse.model_validate(user)
EOF
}

# Generate auth service
generate_auth_service() {
    cat > src/services/auth.py << 'EOF'
"""Authentication service."""

from datetime import timedelta
from fastapi import HTTPException, status

from src.services.user import UserService
from src.schemas.user import UserLogin, Token
from src.auth.jwt import create_access_token, create_refresh_token
from src.core.config import settings


class AuthService:
    def __init__(self, user_service: UserService):
        self.user_service = user_service

    async def login(self, login_data: UserLogin) -> Token:
        """Login user and return tokens."""
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
EOF
}

# Generate auth endpoints
generate_auth_endpoints() {
    cat > src/api/endpoints/auth.py << 'EOF'
"""Authentication endpoints."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.database import get_db
from src.repositories.user import UserRepository
from src.services.user import UserService
from src.services.auth import AuthService
from src.schemas.user import UserLogin, UserCreate, UserResponse, Token
from src.schemas.common import StatusMessage

router = APIRouter()


async def get_auth_service(session: AsyncSession = Depends(get_db)) -> AuthService:
    """Get auth service dependency."""
    user_repo = UserRepository(session)
    user_service = UserService(user_repo)
    return AuthService(user_service)


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(
    user_data: UserCreate,
    auth_service: AuthService = Depends(get_auth_service)
):
    """Register a new user."""
    return await auth_service.user_service.create_user(user_data)


@router.post("/login", response_model=Token)
async def login(
    login_data: UserLogin,
    auth_service: AuthService = Depends(get_auth_service)
):
    """Login user and return access token."""
    return await auth_service.login(login_data)
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