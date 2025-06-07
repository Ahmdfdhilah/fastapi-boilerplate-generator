#!/bin/bash

# Core file generators for FastAPI boilerplate - Fixed with Step 1

# Generate .env file
generate_env_file() {
    local db_name=$(echo "$PROJECT_DIR" | sed 's/-/_/g')_db
    local jwt_secret=$(generate_jwt_secret)
    
    cat > .env << EOF
# Application Settings
PROJECT_NAME="$PROJECT_NAME"
VERSION="1.0.0"
DEBUG=true
API_V1_STR="/api/v1"

# CORS Settings
CORS_ORIGINS="$DEFAULT_CORS_ORIGINS"
CORS_HEADERS="$DEFAULT_CORS_HEADERS"
CORS_METHODS="$DEFAULT_CORS_METHODS"

# Database Settings (PostgreSQL)
POSTGRES_SERVER=$DEFAULT_DB_HOST
POSTGRES_PORT=$DEFAULT_DB_PORT
POSTGRES_USER=postgres
POSTGRES_PASSWORD=password
POSTGRES_DB=$db_name

# Database Pool Settings
DB_POOL_SIZE=10
DB_MAX_OVERFLOW=20
SQL_ECHO=false

# JWT Settings
JWT_SECRET_KEY=$jwt_secret
ALGORITHM=$DEFAULT_JWT_ALGORITHM
ACCESS_TOKEN_EXPIRE_MINUTES=$DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES
REFRESH_TOKEN_EXPIRE_DAYS=$DEFAULT_REFRESH_TOKEN_EXPIRE_DAYS

# Redis Settings (Optional)
REDIS_HOST=$DEFAULT_REDIS_HOST
REDIS_PORT=$DEFAULT_REDIS_PORT
REDIS_PASSWORD=
REDIS_DB=0
REDIS_TTL=3600

# File Upload Settings
MAX_UPLOAD_SIZE=$DEFAULT_MAX_UPLOAD_SIZE
MAX_FILENAME_LENGTH=$DEFAULT_MAX_FILENAME_LENGTH

# Logging Settings
LOG_DIRECTORY=$DEFAULT_LOG_DIRECTORY
LOG_MAX_BYTES=$DEFAULT_LOG_MAX_BYTES
LOG_BACKUP_COUNT=$DEFAULT_LOG_BACKUP_COUNT
SERVICE_NAME="$PROJECT_DIR"

# Password Security Settings (Step 1)
PASSWORD_MIN_LENGTH=12
PASSWORD_MAX_LENGTH=128
PASSWORD_HISTORY_COUNT=5
PASSWORD_MAX_AGE_DAYS=90
ACCOUNT_LOCKOUT_ATTEMPTS=5
ACCOUNT_LOCKOUT_DURATION_MINUTES=15

# Rate Limiting Settings (Step 2)
RATE_LIMIT_CALLS=100
RATE_LIMIT_PERIOD=60
AUTH_RATE_LIMIT_CALLS=5
AUTH_RATE_LIMIT_PERIOD=300
EOF
}

# Generate requirements.txt with Step 1 additions and Redis
generate_requirements() {
    cat > requirements.txt << EOF
# FastAPI and dependencies
fastapi==0.104.1
uvicorn[standard]==0.24.0
starlette==0.27.0

# Database
sqlmodel==0.0.14
sqlalchemy==2.0.41
asyncpg==0.29.0
alembic==1.13.1

# Authentication & Security
python-jose[cryptography]==3.3.0
passlib[bcrypt]==1.7.4
python-multipart==0.0.6

# Data validation
pydantic==2.5.0
pydantic-settings==2.1.0
email-validator==2.2.0

# Environment
python-dotenv==1.1.0

# HTTP client (for testing and OAuth)
httpx==0.25.2

# Redis for caching and sessions
redis[hiredis]==5.0.1

# Development and testing
pytest==7.4.3
pytest-asyncio==0.21.1

# Utilities
python-slugify==8.0.1

# Step 1: Password Security additions
# (Already included in passlib[bcrypt] and python-jose[cryptography])

# Future steps will add:
# pyotp - for TOTP MFA (Step 3)
# qrcode[pil] - for QR code generation (Step 3) 
# slowapi - for rate limiting (Step 2) - Redis-based rate limiting included
# sib-api-v3-sdk - for Brevo email service (Step 5)
EOF

    # Add additional requirements if specified
    if [[ ${#ADDITIONAL_REQUIREMENTS[@]} -gt 0 ]]; then
        echo "" >> requirements.txt
        echo "# Additional requirements" >> requirements.txt
        for req in "${ADDITIONAL_REQUIREMENTS[@]}"; do
            echo "$req" >> requirements.txt
        done
    fi
}

# Generate .gitignore
generate_gitignore() {
    cat > .gitignore << 'EOF'
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

# Testing
.coverage
.pytest_cache/
htmlcov/

# Alembic
alembic/versions/*.py
!alembic/versions/__init__.py

# Security (Step 1 additions)
# Don't commit any security-related files
*.key
*.pem
*.crt
backup_codes.txt
EOF
}

# Generate core config with Step 1 additions
generate_core_config() {
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

    # Password Security Settings (Step 1)
    PASSWORD_MIN_LENGTH: int = 12
    PASSWORD_MAX_LENGTH: int = 128
    PASSWORD_HISTORY_COUNT: int = 5
    PASSWORD_MAX_AGE_DAYS: int = 90
    ACCOUNT_LOCKOUT_ATTEMPTS: int = 5
    ACCOUNT_LOCKOUT_DURATION_MINUTES: int = 15
    
    # Rate Limiting Settings (Step 2)
    RATE_LIMIT_CALLS: int = 100
    RATE_LIMIT_PERIOD: int = 60
    AUTH_RATE_LIMIT_CALLS: int = 5
    AUTH_RATE_LIMIT_PERIOD: int = 300

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
}

# Generate database config
generate_database_config() {
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
}

# Generate main application
generate_main_app() {
    cat > main.py << EOF
"""Main FastAPI application.

Generated by FastAPI Boilerplate Generator
Project: $PROJECT_NAME
Author: $AUTHOR_NAME <$AUTHOR_EMAIL>
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.core.config import settings
from src.core.database import init_db
from src.api import api_router
from src.middleware.error_handler import setup_exception_handlers
from src.middleware.logging import setup_logging_middleware
from src.middleware.rate_limiting import setup_rate_limiting_middleware
from src.utils.logging import setup_logging

# Create FastAPI application
app = FastAPI(
    title=settings.PROJECT_NAME,
    description="$PROJECT_DESCRIPTION",
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

# Setup middleware (Step 2: Rate limiting added)
setup_rate_limiting_middleware(app)
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
}