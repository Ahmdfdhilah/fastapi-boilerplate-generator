#!/bin/bash

# FastAPI JWT Boilerplate Generator
# Based on company profile service structure with independent JWT auth

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to prompt for input with default value
prompt_with_default() {
    local prompt="$1"
    local default="$2"
    local result
    
    read -p "$prompt [$default]: " result
    echo "${result:-$default}"
}

# Get project details
echo -e "${BLUE}=== FastAPI JWT Boilerplate Generator ===${NC}"
echo ""

PROJECT_NAME=$(prompt_with_default "Enter project name" "my-fastapi-service")
PROJECT_DESCRIPTION=$(prompt_with_default "Enter project description" "FastAPI service with JWT authentication")
AUTHOR_NAME=$(prompt_with_default "Enter author name" "$(git config user.name 2>/dev/null || echo 'Your Name')")
AUTHOR_EMAIL=$(prompt_with_default "Enter author email" "$(git config user.email 2>/dev/null || echo 'your.email@example.com')")

# Ask for deployment preference
echo ""
print_status "Choose deployment method:"
echo "1. Plain uvicorn (no Docker)"
echo "2. Docker with docker-compose"
echo ""
DEPLOYMENT_CHOICE=$(prompt_with_default "Enter your choice (1 or 2)" "1")

case $DEPLOYMENT_CHOICE in
    1)
        USE_DOCKER=false
        print_status "Selected: Plain uvicorn deployment"
        ;;
    2)
        USE_DOCKER=true
        print_status "Selected: Docker deployment with docker-compose"
        ;;
    *)
        USE_DOCKER=false
        print_warning "Invalid choice, defaulting to plain uvicorn"
        ;;
esac

# Sanitize project name for directory
PROJECT_DIR=$(echo "$PROJECT_NAME" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]/-/g' | sed 's/--*/-/g' | sed 's/^-\|-$//g')

print_status "Creating project directory: $PROJECT_DIR"

# Check if directory already exists
if [ -d "$PROJECT_DIR" ]; then
    print_error "Directory $PROJECT_DIR already exists!"
    exit 1
fi

# Create project structure
mkdir -p "$PROJECT_DIR"
cd "$PROJECT_DIR"

print_status "Creating project structure..."

# Create directory structure
# Create base directories
mkdir -p src logs tests docs

# Create sub-directories under src/
mkdir -p src/api/endpoints \
         src/auth \
         src/core \
         src/middleware \
         src/models \
         src/repositories \
         src/schemas \
         src/services \
         src/utils
         
# Create __init__.py files
touch src/__init__.py
touch src/api/__init__.py
touch src/api/endpoints/__init__.py
touch src/auth/__init__.py
touch src/core/__init__.py
touch src/middleware/__init__.py
touch src/models/__init__.py
touch src/repositories/__init__.py
touch src/schemas/__init__.py
touch src/services/__init__.py
touch src/utils/__init__.py
touch tests/__init__.py

print_status "Creating configuration files..."

# Create .env file
cat > .env << EOF
# Application Settings
PROJECT_NAME="$PROJECT_NAME"
VERSION="1.0.0"
DEBUG=true
API_V1_STR="/api/v1"

# CORS Settings
CORS_ORIGINS="http://localhost:3000,http://localhost:8080"
CORS_HEADERS="*"
CORS_METHODS="*"

# Database Settings (PostgreSQL)
POSTGRES_SERVER=localhost
POSTGRES_PORT=5432
POSTGRES_USER=postgres
POSTGRES_PASSWORD=password
POSTGRES_DB=${PROJECT_DIR//-/_}_db

# Database Pool Settings
DB_POOL_SIZE=10
DB_MAX_OVERFLOW=20
SQL_ECHO=false

# JWT Settings
JWT_SECRET_KEY=your-super-secret-jwt-key-change-this-in-production
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7

# Redis Settings (Optional)
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=
REDIS_DB=0
REDIS_TTL=3600

# File Upload Settings
MAX_UPLOAD_SIZE=10485760
MAX_FILENAME_LENGTH=50

# Logging Settings
LOG_DIRECTORY=logs
LOG_MAX_BYTES=10485760
LOG_BACKUP_COUNT=5
SERVICE_NAME="$PROJECT_DIR"
EOF

# Create requirements.txt
cat > requirements.txt << EOF
# FastAPI and dependencies
fastapi==0.104.1
uvicorn[standard]==0.24.0
pydantic==2.5.0
pydantic-settings==2.1.0

# Database
sqlmodel==0.0.14
asyncpg==0.29.0
alembic==1.13.1

# Authentication
python-jose[cryptography]==3.3.0
python-multipart==0.0.6
passlib[bcrypt]==1.7.4

# Redis (optional)
redis==5.0.1

# Utilities
python-slugify==8.0.1
bleach==6.1.0

# Development
pytest==7.4.3
pytest-asyncio==0.21.1
httpx==0.25.2
EOF

# Create .gitignore
cat > .gitignore << EOF
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

# Virtual Environment
venv/
env/
ENV/

# Environment variables
.env
.env.local
.env.production

# IDEs
.vscode/
.idea/
*.swp
*.swo

# Logs
logs/
*.log

# Database
*.db
*.sqlite

# OS
.DS_Store
Thumbs.db

# Uploads
uploads/
static/uploads/
EOF

print_status "Creating core configuration..."

# Create src/core/config.py
cat > src/core/config.py << 'EOF'
"""Application settings and configuration."""

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import PostgresDsn, field_validator
from typing import Any, Dict, Optional, List


class Settings(BaseSettings):
    """Application settings with environment variable loading."""

    # API settings
    PROJECT_NAME: str
    VERSION: str = "1.0.0"
    DEBUG: bool = False
    API_V1_STR: str = "/api/v1"

    # CORS
    CORS_ORIGINS: str = "*"
    CORS_HEADERS: str = "*"
    CORS_METHODS: str = "*"

    # Database
    POSTGRES_SERVER: str
    POSTGRES_USER: str
    POSTGRES_PASSWORD: str
    POSTGRES_DB: str
    POSTGRES_PORT: str = "5432"
    DATABASE_URI: Optional[PostgresDsn] = None
    SQL_ECHO: bool = False

    # Database connection pool settings
    DB_POOL_SIZE: int = 10
    DB_MAX_OVERFLOW: int = 20

    # JWT Settings
    JWT_SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Redis (optional)
    REDIS_HOST: Optional[str] = None
    REDIS_PORT: Optional[int] = None
    REDIS_PASSWORD: Optional[str] = None
    REDIS_DB: int = 0
    REDIS_TTL: int = 3600

    # File handling
    MAX_UPLOAD_SIZE: int = 10 * 1024 * 1024  # 10MB
    MAX_FILENAME_LENGTH: int = 50

    # Logging
    LOG_DIRECTORY: str = "logs"
    LOG_MAX_BYTES: int = 10 * 1024 * 1024  # 10MB
    LOG_BACKUP_COUNT: int = 5
    SERVICE_NAME: str

    @field_validator("DATABASE_URI", mode="before")
    def assemble_db_connection(cls, v: Optional[str], info: Dict[str, Any]) -> Any:
        """Build PostgreSQL connection string from components."""
        if isinstance(v, str):
            return v

        values = info.data
        user = values.get("POSTGRES_USER", "")
        password = values.get("POSTGRES_PASSWORD", "")
        host = values.get("POSTGRES_SERVER", "")
        port = values.get("POSTGRES_PORT", "5432")
        db = values.get("POSTGRES_DB", "")

        auth = f"{user}:{password}" if password else user
        return f"postgresql://{auth}@{host}:{port}/{db}"

    @field_validator("API_V1_STR")
    def ensure_api_prefix_has_slash(cls, v: str) -> str:
        """Ensure API prefix starts with a slash."""
        if not v.startswith("/"):
            return f"/{v}"
        return v

    @property
    def CORS_ORIGINS_LIST(self) -> List[str]:
        """Convert CORS_ORIGINS string to list."""
        if self.CORS_ORIGINS == "*":
            return ["*"]
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",")]

    @property
    def CORS_METHODS_LIST(self) -> List[str]:
        """Convert CORS_METHODS string to list."""
        if self.CORS_METHODS == "*":
            return ["*"]
        return [method.strip() for method in self.CORS_METHODS.split(",")]

    @property
    def CORS_HEADERS_LIST(self) -> List[str]:
        """Convert CORS_HEADERS string to list."""
        if self.CORS_HEADERS == "*":
            return ["*"]
        return [header.strip() for header in self.CORS_HEADERS.split(",")]

    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=True,
    )


# Create global settings instance
settings = Settings()
EOF

print_status "Creating database configuration..."

# Create src/core/database.py
cat > src/core/database.py << 'EOF'
"""Database setup and session management."""

from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlmodel import SQLModel

from src.core.config import settings

# Create async database engine
ASYNC_DATABASE_URI = str(settings.DATABASE_URI).replace("postgresql://", "postgresql+asyncpg://")

engine = create_async_engine(
    ASYNC_DATABASE_URI,
    echo=settings.SQL_ECHO,
    pool_pre_ping=True,
    pool_size=settings.DB_POOL_SIZE,
    max_overflow=settings.DB_MAX_OVERFLOW
)

# Create async session factory
async_session = sessionmaker(
    engine, 
    class_=AsyncSession, 
    expire_on_commit=False
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency for getting an async database session."""
    async with async_session() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def create_db_and_tables() -> None:
    """Create database tables from SQLModel models."""
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)


async def init_db() -> None:
    """Initialize the database with required tables."""
    await create_db_and_tables()
EOF

print_status "Creating authentication system..."

# Create src/auth/jwt.py
cat > src/auth/jwt.py << 'EOF'
"""JWT token handling."""

from datetime import datetime, timedelta
from typing import Dict, Optional, Any
from jose import jwt
from passlib.context import CryptContext

from src.core.config import settings

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Hash a password."""
    return pwd_context.hash(password)


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Create a JWT access token."""
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    
    encoded_jwt = jwt.encode(
        to_encode, 
        settings.JWT_SECRET_KEY, 
        algorithm=settings.ALGORITHM
    )
    
    return encoded_jwt


def create_refresh_token(data: Dict[str, Any]) -> str:
    """Create a JWT refresh token."""
    to_encode = data.copy()
    
    expire = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire})
    
    encoded_jwt = jwt.encode(
        to_encode, 
        settings.JWT_SECRET_KEY, 
        algorithm=settings.ALGORITHM
    )
    
    return encoded_jwt


def verify_token(token: str) -> Dict[str, Any]:
    """Verify and decode a JWT token."""
    payload = jwt.decode(
        token, 
        settings.JWT_SECRET_KEY, 
        algorithms=[settings.ALGORITHM]
    )
    
    return payload
EOF

# Create src/auth/permissions.py
cat > src/auth/permissions.py << 'EOF'
"""Authorization and permission checking."""

from typing import List, Dict, Optional
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError

from src.auth.jwt import verify_token
from src.core.database import get_db
from sqlalchemy.ext.asyncio import AsyncSession
from src.repositories.user import UserRepository


class JWTBearer(HTTPBearer):
    def __init__(self, auto_error: bool = True):
        super(JWTBearer, self).__init__(auto_error=auto_error)

    async def __call__(self, request: Request):
        credentials: HTTPAuthorizationCredentials = await super(
            JWTBearer, self
        ).__call__(request)
        if credentials:
            if not credentials.scheme == "Bearer":
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Invalid authentication scheme.",
                )
            return credentials.credentials
        else:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid authorization code.",
            )


jwt_bearer = JWTBearer()


async def get_current_user(
    token: str = Depends(jwt_bearer), 
    session: AsyncSession = Depends(get_db)
) -> Dict:
    """Get the current authenticated user from the token."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = verify_token(token)
        user_id = payload.get("sub")
        if not user_id:
            raise credentials_exception

        user_repo = UserRepository(session)
        user = await user_repo.get_by_id(int(user_id))

        if not user:
            raise credentials_exception

        # Get user roles
        user_roles = await user_repo.get_user_roles(user.id)
        roles = [role.name for role in user_roles]

        user_data = {
            "id": user.id,
            "email": user.email,
            "name": f"{user.first_name} {user.last_name}".strip(),
            "roles": roles,
            "is_active": user.is_active,
        }

        return user_data

    except JWTError:
        raise credentials_exception


async def get_current_active_user(
    current_user: Dict = Depends(get_current_user),
) -> Dict:
    """Check if the current user is active."""
    if not current_user.get("is_active"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="Inactive user"
        )
    return current_user


def require_roles(required_roles: List[str]):
    """Decorator to require specific roles."""
    async def _check_roles(
        current_user: Dict = Depends(get_current_active_user),
    ) -> Dict:
        user_roles = current_user.get("roles", [])
        
        if not any(role in user_roles for role in required_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Required roles: {', '.join(required_roles)}",
            )
        
        return current_user
    
    return _check_roles


# Common role dependencies
admin_required = require_roles(["admin"])
user_required = require_roles(["user", "admin"])
EOF

print_status "Creating base models..."

# Create src/models/base.py
cat > src/models/base.py << 'EOF'
"""Base model with common fields."""

from datetime import datetime
from typing import Optional
from sqlmodel import Field, SQLModel


class TimestampMixin(SQLModel):
    """Mixin for timestamp fields."""
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: Optional[datetime] = Field(default=None)


class SoftDeleteMixin(SQLModel):
    """Mixin for soft delete functionality."""
    deleted_at: Optional[datetime] = Field(default=None)
    deleted_by: Optional[int] = Field(default=None)


class AuditMixin(SQLModel):
    """Mixin for audit fields."""
    created_by: Optional[int] = Field(default=None)
    updated_by: Optional[int] = Field(default=None)


class BaseModel(TimestampMixin, SoftDeleteMixin, AuditMixin):
    """Base model with all common fields."""
    pass
EOF

# Create src/models/user.py
cat > src/models/user.py << 'EOF'
"""User model."""

from typing import Optional, List
from sqlmodel import Field, SQLModel, Relationship

from .base import BaseModel


class User(BaseModel, SQLModel, table=True):
    """User model."""
    
    __tablename__ = "users"
    
    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(unique=True, index=True)
    hashed_password: str
    first_name: str
    last_name: Optional[str] = None
    is_active: bool = Field(default=True)
    
    # Relationships
    roles: List["UserRole"] = Relationship(back_populates="user")


class Role(BaseModel, SQLModel, table=True):
    """Role model."""
    
    __tablename__ = "roles"
    
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(unique=True, index=True)
    description: Optional[str] = None
    
    # Relationships
    users: List["UserRole"] = Relationship(back_populates="role")


class UserRole(BaseModel, SQLModel, table=True):
    """User-Role association model."""
    
    __tablename__ = "user_roles"
    
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="users.id")
    role_id: int = Field(foreign_key="roles.id")
    
    # Relationships
    user: User = Relationship(back_populates="roles")
    role: Role = Relationship(back_populates="users")
EOF

print_status "Creating schemas..."

# Create src/schemas/user.py
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

# Create src/schemas/common.py
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

print_status "Creating repositories..."

# Create src/repositories/user.py
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

print_status "Creating services..."

# Create src/services/user.py
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

# Create src/services/auth.py
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

print_status "Creating API endpoints..."

# Create src/api/endpoints/auth.py
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

# Create src/api/endpoints/users.py
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

# Create src/api/router.py
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

print_status "Creating middleware..."

# Create src/middleware/error_handler.py
cat > src/middleware/error_handler.py << 'EOF'
"""Global error handling middleware."""

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from sqlalchemy.exc import SQLAlchemyError
from jose import JWTError
import logging
import traceback

logger = logging.getLogger(__name__)


async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle validation errors in request data."""
    details = []
    for error in exc.errors():
        error_location = " -> ".join(str(loc) for loc in error["loc"])
        error_msg = error["msg"]
        details.append(f"{error_location}: {error_msg}")
    
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": details}
    )


async def jwt_exception_handler(request: Request, exc: JWTError):
    """Handle JWT validation errors."""
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={"detail": "Invalid authentication credentials"},
        headers={"WWW-Authenticate": "Bearer"}
    )


async def sqlalchemy_exception_handler(request: Request, exc: SQLAlchemyError):
    """Handle database errors."""
    error_msg = str(exc)
    error_traceback = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    logger.error(f"Database error: {error_msg}\n{error_traceback}")
    
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "A database error occurred. Please try again later."}
    )


async def general_exception_handler(request: Request, exc: Exception):
    """Handle all other exceptions."""
    error_msg = str(exc)
    error_traceback = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    logger.error(f"Unhandled exception: {error_msg}\n{error_traceback}")
    
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An internal server error occurred. Please try again later."}
    )


def setup_exception_handlers(app: FastAPI):
    """Setup exception handlers for the application."""
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(JWTError, jwt_exception_handler)
    app.add_exception_handler(SQLAlchemyError, sqlalchemy_exception_handler)
    app.add_exception_handler(Exception, general_exception_handler)
EOF

# Create src/middleware/logging.py
cat > src/middleware/logging.py << 'EOF'
"""Request logging middleware."""

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
import logging
import time
import uuid

logger = logging.getLogger(__name__)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Generate unique request ID
        request_id = str(uuid.uuid4())
        
        # Log request start
        logger.info(f"Request {request_id} started: {request.method} {request.url.path}")
        
        start_time = time.time()
        
        try:
            response = await call_next(request)
            
            # Log successful response
            process_time = time.time() - start_time
            logger.info(
                f"Request {request_id} completed: {request.method} {request.url.path} "
                f"- Status: {response.status_code} - Duration: {process_time:.4f}s"
            )
            
            # Add request ID to response headers
            response.headers["X-Request-ID"] = request_id
            
            return response
        
        except Exception as e:
            # Log error
            process_time = time.time() - start_time
            logger.error(
                f"Request {request_id} failed: {request.method} {request.url.path} "
                f"- Error: {str(e)} - Duration: {process_time:.4f}s"
            )
            raise


def setup_logging_middleware(app):
    """Setup request logging middleware."""
    app.add_middleware(RequestLoggingMiddleware)
EOF

print_status "Creating utilities..."

# Create src/utils/logging.py
cat > src/utils/logging.py << 'EOF'
"""Logging configuration utilities."""

import logging
import logging.handlers
import json
import os
from datetime import datetime
from src.core.config import settings


class JSONFormatter(logging.Formatter):
    """JSON formatter for structured logging."""
    
    def __init__(self, service_name):
        super().__init__()
        self.service_name = service_name

    def format(self, record):
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "service": self.service_name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        
        if record.exc_info:
            log_entry['exc_info'] = self.formatException(record.exc_info)
        if record.stack_info:
            log_entry['stack_info'] = self.formatStack(record.stack_info)
            
        return json.dumps(log_entry)


def setup_logging():
    """Setup application logging."""
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    formatter = JSONFormatter(settings.SERVICE_NAME)

    # Create logs directory
    try:
        os.makedirs(settings.LOG_DIRECTORY, exist_ok=True)
    except OSError as e:
        print(f"Error creating log directory: {e}")
        # Fallback to console only
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        return

    # File handler with rotation
    log_file_path = os.path.join(settings.LOG_DIRECTORY, f'{settings.SERVICE_NAME}.log')
    
    try:
        file_handler = logging.handlers.RotatingFileHandler(
            log_file_path,
            maxBytes=settings.LOG_MAX_BYTES,
            backupCount=settings.LOG_BACKUP_COUNT
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except Exception as e:
        print(f"Error setting up file handler: {e}")

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
EOF

# Create src/utils/validators.py
cat > src/utils/validators.py << 'EOF'
"""Common validation utilities."""

import re
from typing import List
from fastapi import UploadFile, HTTPException, status


def validate_email(email: str) -> bool:
    """Validate email format."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}
    return bool(re.match(pattern, email))


def validate_password(password: str) -> bool:
    """Validate password strength."""
    # At least 8 characters, 1 uppercase, 1 lowercase, 1 digit
    if len(password) < 8:
        return False
    
    if not re.search(r'[A-Z]', password):
        return False
    
    if not re.search(r'[a-z]', password):
        return False
    
    if not re.search(r'\d', password):
        return False
    
    return True


def validate_upload_file(file: UploadFile, allowed_types: List[str] = None, max_size: int = None) -> None:
    """Validate uploaded file."""
    if max_size is None:
        max_size = 10 * 1024 * 1024  # 10MB default
    
    # Check file size
    if hasattr(file.file, 'seek'):
        file.file.seek(0, 2)  # Seek to end
        file_size = file.file.tell()
        file.file.seek(0)  # Reset position
        
        if file_size > max_size:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"File size exceeds maximum allowed size ({max_size / (1024*1024):.1f}MB)"
            )
    
    # Check file type
    if allowed_types and file.content_type not in allowed_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File type not allowed. Allowed types: {', '.join(allowed_types)}"
        )
EOF

print_status "Creating main application..."

# Create main.py
cat > main.py << 'EOF'
"""Main FastAPI application."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.core.config import settings
from src.core.database import init_db
from src.api import api_router
from src.middleware.error_handler import setup_exception_handlers
from src.middleware.logging import setup_logging_middleware
from src.utils.logging import setup_logging

# Create FastAPI application
app = FastAPI(
    title=settings.PROJECT_NAME,
    description="FastAPI service with JWT authentication",
    version=settings.VERSION,
    debug=settings.DEBUG,
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS_LIST,
    allow_credentials=True,
    allow_methods=settings.CORS_METHODS_LIST,
    allow_headers=settings.CORS_HEADERS_LIST,
)

# Setup middleware
setup_logging_middleware(app)
setup_exception_handlers(app)

# Setup logging
setup_logging()

# Include API router
app.include_router(api_router, prefix=settings.API_V1_STR)


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "message": f"Welcome to {settings.PROJECT_NAME}",
        "version": settings.VERSION,
        "docs": "/docs",
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
    }


@app.on_event("startup")
async def startup_event():
    """Startup event handler."""
    await init_db()
    print(f"🚀 {settings.PROJECT_NAME} started successfully")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app", 
        host="0.0.0.0", 
        port=8000, 
        reload=settings.DEBUG
    )
EOF

print_status "Creating database migration files..."

# Create alembic.ini
cat > alembic.ini << 'EOF'
# A generic, single database configuration.

[alembic]
# path to migration scripts
script_location = alembic

# template used to generate migration file names; The default value is %%(rev)s_%%(slug)s
# Uncomment the line below if you want the files to be prepended with date and time
# file_template = %%(year)d_%%(month).2d_%%(day).2d_%%(hour).2d%%(minute).2d-%%(rev)s_%%(slug)s

# sys.path path, will be prepended to sys.path if present.
# defaults to the current working directory.
prepend_sys_path = .

# timezone to use when rendering the date within the migration file
# as well as the filename.
# If specified, requires the python-dateutil library that can be
# installed by adding `alembic[tz]` to the pip requirements
# string value is passed to dateutil.tz.gettz()
# leave blank for localtime
# timezone =

# max length of characters to apply to the
# "slug" field
# truncate_slug_length = 40

# set to 'true' to run the environment during
# the 'revision' command, regardless of autogenerate
# revision_environment = false

# set to 'true' to allow .pyc and .pyo files without
# a source .py file to be detected as revisions in the
# versions/ directory
# sourceless = false

# version path separator; As mentioned above, this is the character used to split
# version_locations. The default within new alembic.ini files is "os", which uses
# os.pathsep. If this key is omitted entirely, it falls back to the legacy
# behavior of splitting on spaces and/or commas.
# Valid values for version_path_separator are:
#
# version_path_separator = :
# version_path_separator = ;
# version_path_separator = space
version_path_separator = os

# the output encoding used when revision files
# are written from script.py.mako
# output_encoding = utf-8

sqlalchemy.url = driver://user:pass@localhost/dbname


[post_write_hooks]
# post_write_hooks defines scripts or Python functions that are run
# on newly generated revision scripts.  See the documentation for further
# detail and examples

# format using "black" - use the console_scripts runner, against the "black" entrypoint
# hooks = black
# black.type = console_scripts
# black.entrypoint = black
# black.options = -l 79 REVISION_SCRIPT_FILENAME

# Logging configuration
[loggers]
keys = root,sqlalchemy,alembic

[handlers]
keys = console

[formatters]
keys = generic

[logger_root]
level = WARN
handlers = console
qualname =

[logger_sqlalchemy]
level = WARN
handlers =
qualname = sqlalchemy.engine

[logger_alembic]
level = INFO
handlers =
qualname = alembic

[handler_console]
class = StreamHandler
args = (sys.stderr,)
level = NOTSET
formatter = generic

[formatter_generic]
format = %(levelname)-5.5s [%(name)s] %(message)s
datefmt = %H:%M:%S
EOF

# Create alembic directory structure
mkdir -p alembic/versions

# Create alembic/env.py
cat > alembic/env.py << 'EOF'
"""Alembic environment configuration."""

from logging.config import fileConfig
from sqlalchemy import engine_from_config
from sqlalchemy import pool
from alembic import context
import asyncio
from sqlalchemy.ext.asyncio import AsyncEngine

# Import your models here
from src.models.user import User, Role, UserRole
from src.models.base import BaseModel

# this is the Alembic Config object
config = context.config

# Interpret the config file for Python logging.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Import your SQLModel metadata
from sqlmodel import SQLModel
target_metadata = SQLModel.metadata

# Get database URL from settings
from src.core.config import settings
config.set_main_option("sqlalchemy.url", str(settings.DATABASE_URI))


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection):
    context.configure(connection=connection, target_metadata=target_metadata)

    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    connectable = AsyncEngine(
        engine_from_config(
            config.get_section(config.config_ini_section),
            prefix="sqlalchemy.",
            poolclass=pool.NullPool,
        )
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
EOF

# Create alembic/script.py.mako
cat > alembic/script.py.mako << 'EOF'
"""${message}

Revision ID: ${up_revision}
Revises: ${down_revision | comma,n}
Create Date: ${create_date}

"""
from alembic import op
import sqlalchemy as sa
import sqlmodel
${imports if imports else ""}

# revision identifiers, used by Alembic.
revision = ${repr(up_revision)}
down_revision = ${repr(down_revision)}
branch_labels = ${repr(branch_labels)}
depends_on = ${repr(depends_on)}


def upgrade() -> None:
    ${upgrades if upgrades else "pass"}


def downgrade() -> None:
    ${downgrades if downgrades else "pass"}
EOF

print_status "Creating test files..."

# Create tests/conftest.py
cat > tests/conftest.py << 'EOF'
"""Test configuration and fixtures."""

import pytest
import asyncio
from typing import AsyncGenerator
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlmodel import SQLModel

from main import app
from src.core.database import get_db
from src.core.config import settings


# Create test database engine
TEST_DATABASE_URL = str(settings.DATABASE_URI) + "_test"
TEST_ASYNC_DATABASE_URL = TEST_DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://")

test_engine = create_async_engine(
    TEST_ASYNC_DATABASE_URL,
    echo=False,
    pool_pre_ping=True
)

TestingSessionLocal = sessionmaker(
    test_engine, 
    class_=AsyncSession, 
    expire_on_commit=False
)


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
async def setup_database():
    """Setup test database."""
    async with test_engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    yield
    async with test_engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.drop_all)


@pytest.fixture
async def db_session(setup_database) -> AsyncGenerator[AsyncSession, None]:
    """Create a test database session."""
    async with TestingSessionLocal() as session:
        yield session


@pytest.fixture
async def client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    """Create a test client."""
    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac
    
    app.dependency_overrides.clear()
EOF

# Create tests/test_auth.py
cat > tests/test_auth.py << 'EOF'
"""Test authentication endpoints."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_register_user(client: AsyncClient):
    """Test user registration."""
    user_data = {
        "email": "test@example.com",
        "password": "TestPassword123",
        "first_name": "Test",
        "last_name": "User"
    }
    
    response = await client.post("/api/v1/auth/register", json=user_data)
    assert response.status_code == 201
    
    data = response.json()
    assert data["email"] == user_data["email"]
    assert data["first_name"] == user_data["first_name"]


@pytest.mark.asyncio
async def test_login_user(client: AsyncClient):
    """Test user login."""
    # First register a user
    user_data = {
        "email": "login@example.com",
        "password": "TestPassword123",
        "first_name": "Test",
        "last_name": "User"
    }
    
    await client.post("/api/v1/auth/register", json=user_data)
    
    # Then try to login
    login_data = {
        "email": "login@example.com",
        "password": "TestPassword123"
    }
    
    response = await client.post("/api/v1/auth/login", json=login_data)
    assert response.status_code == 200
    
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"


@pytest.mark.asyncio
async def test_login_invalid_credentials(client: AsyncClient):
    """Test login with invalid credentials."""
    login_data = {
        "email": "nonexistent@example.com",
        "password": "WrongPassword123"
    }
    
    response = await client.post("/api/v1/auth/login", json=login_data)
    assert response.status_code == 401
EOF

print_status "Creating documentation..."

# Create README.md
cat > README.md << EOF
# $PROJECT_NAME

$PROJECT_DESCRIPTION

This is a FastAPI boilerplate with JWT authentication, built with modern Python async/await patterns.

## Features

- **FastAPI** - Modern, fast web framework for building APIs
- **JWT Authentication** - Secure token-based authentication
- **SQLModel** - Modern SQL databases with Python types
- **Async/Await** - Full async support with AsyncPG
- **Pydantic V2** - Data validation using Python type annotations
- **Alembic** - Database migrations
- **pytest** - Testing framework with async support
- **CORS** - Cross-Origin Resource Sharing support
- **Structured Logging** - JSON-formatted logs with rotation
- **Docker Ready** - Containerization support

## Project Structure

\`\`\`
$PROJECT_DIR/
├── src/
│   ├── api/
│   │   ├── endpoints/
│   │   │   ├── auth.py          # Authentication endpoints
│   │   │   └── users.py         # User management endpoints
│   │   └── router.py            # API router configuration
│   ├── auth/
│   │   ├── jwt.py               # JWT token handling
│   │   └── permissions.py       # Authorization logic
│   ├── core/
│   │   ├── config.py            # Application configuration
│   │   └── database.py          # Database setup
│   ├── middleware/
│   │   ├── error_handler.py     # Global error handling
│   │   └── logging.py           # Request logging
│   ├── models/
│   │   ├── base.py              # Base model with common fields
│   │   └── user.py              # User models
│   ├── repositories/
│   │   └── user.py              # User data access layer
│   ├── schemas/
│   │   ├── common.py            # Common schemas
│   │   └── user.py              # User schemas
│   ├── services/
│   │   ├── auth.py              # Authentication service
│   │   └── user.py              # User service
│   └── utils/
│       ├── logging.py           # Logging utilities
│       └── validators.py        # Validation utilities
├── tests/
│   ├── conftest.py              # Test configuration
│   └── test_auth.py             # Authentication tests
├── alembic/                     # Database migrations
├── logs/                        # Application logs
├── .env                         # Environment variables
├── main.py                      # Application entry point
└── requirements.txt             # Python dependencies
\`\`\`

## Quick Start

# Update README based on deployment choice
if [ "$USE_DOCKER" = true ]; then
    SETUP_INSTRUCTIONS="### With Docker

\`\`\`bash
cd $PROJECT_DIR
# Edit .env file if needed
docker-compose up --build
\`\`\`

### Alternative: Manual Setup

\`\`\`bash
cd $PROJECT_DIR
python -m venv venv
source venv/bin/activate  # On Windows: venv\\\\Scripts\\\\activate
pip install -r requirements.txt
\`\`\`"

    USAGE_NOTE="## Docker Usage

The project includes Docker configuration for easy setup:

\`\`\`bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down

# Rebuild after changes
docker-compose up --build
\`\`\`

Services included:
- **FastAPI app**: http://localhost:8000
- **PostgreSQL**: localhost:5432
- **Redis**: localhost:6379"

else
    SETUP_INSTRUCTIONS="### Manual Setup

\`\`\`bash
cd $PROJECT_DIR
python -m venv venv
source venv/bin/activate  # On Windows: venv\\\\Scripts\\\\activate
pip install -r requirements.txt
\`\`\`"

    USAGE_NOTE="## Manual Database Setup

You'll need to install and configure:

1. **PostgreSQL Server**
   \`\`\`bash
   # Ubuntu/Debian
   sudo apt install postgresql postgresql-contrib
   
   # macOS
   brew install postgresql
   
   # Windows: Download from postgresql.org
   \`\`\`

2. **Redis Server** (Optional)
   \`\`\`bash
   # Ubuntu/Debian
   sudo apt install redis-server
   
   # macOS
   brew install redis
   
   # Windows: Download from redis.io
   \`\`\`"
fi

# Dan dalam README.md, ganti bagian Quick Start:
## Quick Start

$SETUP_INSTRUCTIONS

### 2. Configure Environment
...

$USAGE_NOTE

## API Endpoints

### Authentication

- \`POST /api/v1/auth/register\` - Register new user
- \`POST /api/v1/auth/login\` - Login user

### Users

- \`GET /api/v1/users/me\` - Get current user info (requires auth)

## Usage Examples

### Register a User

\`\`\`bash
curl -X POST "http://localhost:8000/api/v1/auth/register" \\
  -H "Content-Type: application/json" \\
  -d '{
    "email": "user@example.com",
    "password": "SecurePassword123",
    "first_name": "John",
    "last_name": "Doe"
  }'
\`\`\`

### Login

\`\`\`bash
curl -X POST "http://localhost:8000/api/v1/auth/login" \\
  -H "Content-Type: application/json" \\
  -d '{
    "email": "user@example.com",
    "password": "SecurePassword123"
  }'
\`\`\`

### Access Protected Endpoint

\`\`\`bash
curl -X GET "http://localhost:8000/api/v1/users/me" \\
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
\`\`\`

## Testing

\`\`\`bash
# Install test dependencies
pip install pytest pytest-asyncio httpx

# Run tests
pytest

# Run with coverage
pytest --cov=src tests/
\`\`\`

## Database Migrations

\`\`\`bash
# Create a new migration
alembic revision --autogenerate -m "Description of changes"

# Apply migrations
alembic upgrade head

# Rollback migration
alembic downgrade -1
\`\`\`

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| \`PROJECT_NAME\` | Application name | $PROJECT_NAME |
| \`DEBUG\` | Debug mode | \`false\` |
| \`POSTGRES_SERVER\` | Database host | \`localhost\` |
| \`POSTGRES_PORT\` | Database port | \`5432\` |
| \`POSTGRES_USER\` | Database user | - |
| \`POSTGRES_PASSWORD\` | Database password | - |
| \`POSTGRES_DB\` | Database name | - |
| \`JWT_SECRET_KEY\` | JWT secret key | - |
| \`ACCESS_TOKEN_EXPIRE_MINUTES\` | Token expiry | \`30\` |
| \`CORS_ORIGINS\` | Allowed origins | \`*\` |

## Security Notes

1. **Change JWT Secret**: Always change \`JWT_SECRET_KEY\` in production
2. **CORS Configuration**: Restrict \`CORS_ORIGINS\` to your domains
3. **Password Policy**: Implement strong password requirements
4. **Rate Limiting**: Consider adding rate limiting for production
5. **HTTPS**: Always use HTTPS in production

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

This project is licensed under the MIT License.

## Author

$AUTHOR_NAME <$AUTHOR_EMAIL>
EOF

# Create Docker files if requested
if [ "$USE_DOCKER" = true ]; then
    print_status "Creating Docker configuration files..."
    
    # Create Dockerfile
    cat > Dockerfile << 'EOF'
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create logs directory
RUN mkdir -p logs

# Expose port
EXPOSE 8000

# Run the application
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
EOF

    # Create docker-compose.yml
    cat > docker-compose.yml << 'EOF'
version: '3.8'

services:
  app:
    build: .
    ports:
      - "8000:8000"
    environment:
      - DEBUG=true
      - POSTGRES_SERVER=db
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=password
      - POSTGRES_DB=app_db
      - JWT_SECRET_KEY=your-super-secret-jwt-key-change-this-in-production
    depends_on:
      - db
      - redis
    volumes:
      - ./logs:/app/logs

  db:
    image: postgres:15
    environment:
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=password
      - POSTGRES_DB=app_db
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

volumes:
  postgres_data:
EOF

    # Create .dockerignore
    cat > .dockerignore << 'EOF'
# Python
__pycache__/
*.py[cod]
*$py.class
*.so

# Virtual Environment
venv/
env/
ENV/

# Environment variables
.env.local
.env.production

# IDEs
.vscode/
.idea/
*.swp
*.swo

# Git
.git/
.gitignore

# Logs
logs/
*.log

# Database
*.db
*.sqlite

# OS
.DS_Store
Thumbs.db

# Documentation
README.md
docs/

# Tests
tests/
pytest.ini
.coverage

# Development files
docker-compose.override.yml
EOF

    print_success "Docker configuration files created!"
else
    print_status "Skipping Docker configuration files..."
fi

print_success "FastAPI JWT boilerplate created successfully!"

echo ""
print_status "Next steps:"
echo "1. cd $PROJECT_DIR"

if [ "$USE_DOCKER" = true ]; then
    echo "2. Edit .env file with your database settings (if needed)"
    echo "3. docker-compose up --build"
    echo ""
    print_status "Your FastAPI service will be available at:"
    echo "- API: http://localhost:8000"
    echo "- Docs: http://localhost:8000/docs"
    echo "- ReDoc: http://localhost:8000/redoc"
    echo "- PostgreSQL: localhost:5432"
    echo "- Redis: localhost:6379"
    echo ""
    print_status "Docker services included:"
    echo "- FastAPI application"
    echo "- PostgreSQL database"
    echo "- Redis cache"
else
    echo "2. python -m venv venv"
    echo "3. source venv/bin/activate  # On Windows: venv\\Scripts\\activate"
    echo "4. pip install -r requirements.txt"
    echo "5. Edit .env file with your database settings"
    echo "6. alembic revision --autogenerate -m \"Initial migration\""
    echo "7. alembic upgrade head"
    echo "8. python main.py"
    echo ""
    print_status "Your FastAPI service will be available at:"
    echo "- API: http://localhost:8000"
    echo "- Docs: http://localhost:8000/docs"
    echo "- ReDoc: http://localhost:8000/redoc"
    echo ""
    print_status "Manual setup required:"
    echo "- PostgreSQL database server"
    echo "- Redis server (optional)"
fi

echo ""
print_warning "IMPORTANT: Remember to change JWT_SECRET_KEY in production!"

cd ..

print_success "Project '$PROJECT_NAME' created in directory '$PROJECT_DIR'"