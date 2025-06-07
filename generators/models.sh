#!/bin/bash

# Model file generators with comprehensive user and auth models

# Generate base models
generate_base_models() {
    cat > src/models/base.py << 'EOF'
"""Base model with common fields."""

from datetime import datetime
from typing import Optional
from sqlmodel import Field, SQLModel
import uuid


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


class UUIDMixin(SQLModel):
    """Mixin for UUID fields."""
    uuid: str = Field(default_factory=lambda: str(uuid.uuid4()), index=True, unique=True)


class BaseModel(TimestampMixin, SoftDeleteMixin, AuditMixin):
    """Base model with all common fields."""
    pass


class BaseModelWithUUID(BaseModel, UUIDMixin):
    """Base model with UUID support."""
    pass
EOF
}

# Generate comprehensive user models
generate_user_models() {
    cat > src/models/user.py << 'EOF'
"""User model with comprehensive authentication features."""

from typing import Optional, List
from datetime import datetime, date
from sqlmodel import Field, SQLModel, Relationship, Index
from enum import Enum

from .base import BaseModel, BaseModelWithUUID


class UserStatus(str, Enum):
    """User account status."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    DELETED = "deleted"


class AuthProvider(str, Enum):
    """Authentication providers."""
    LOCAL = "local"
    GOOGLE = "google"
    FACEBOOK = "facebook"
    GITHUB = "github"
    MICROSOFT = "microsoft"


class User(BaseModelWithUUID, SQLModel, table=True):
    """User model with comprehensive fields."""
    
    __tablename__ = "users"
    __table_args__ = (
        Index("idx_user_email", "email"),
        Index("idx_user_username", "username"),
        Index("idx_user_status", "status"),
    )
    
    id: Optional[int] = Field(default=None, primary_key=True)
    
    # Authentication fields
    email: str = Field(unique=True, index=True)
    username: str = Field(unique=True, index=True)
    hashed_password: Optional[str] = None  # Optional for social auth
    
    # Profile fields
    first_name: str
    last_name: Optional[str] = None
    display_name: Optional[str] = None
    avatar_url: Optional[str] = None
    bio: Optional[str] = None
    date_of_birth: Optional[date] = None
    phone_number: Optional[str] = None
    
    # Status fields
    status: UserStatus = Field(default=UserStatus.ACTIVE)
    is_active: bool = Field(default=True)
    is_verified: bool = Field(default=False)
    is_locked: bool = Field(default=False)
    is_superuser: bool = Field(default=False)
    
    # Security fields
    email_verified_at: Optional[datetime] = None
    phone_verified_at: Optional[datetime] = None
    password_changed_at: Optional[datetime] = None
    last_login_at: Optional[datetime] = None
    last_activity_at: Optional[datetime] = None
    failed_login_attempts: int = Field(default=0)
    locked_until: Optional[datetime] = None
    
    # MFA fields
    mfa_enabled: bool = Field(default=False)
    mfa_secret: Optional[str] = None
    mfa_backup_codes: Optional[str] = None  # JSON array of hashed codes
    
    # Preferences
    language: str = Field(default="en")
    timezone: str = Field(default="UTC")
    notification_preferences: Optional[str] = None  # JSON object
    
    # OAuth fields
    auth_provider: AuthProvider = Field(default=AuthProvider.LOCAL)
    provider_user_id: Optional[str] = None
    
    # Compliance fields
    terms_accepted_at: Optional[datetime] = None
    privacy_accepted_at: Optional[datetime] = None
    marketing_consent: bool = Field(default=False)
    
    # Relationships
    roles: List["UserRole"] = Relationship(back_populates="user")
    sessions: List["UserSession"] = Relationship(back_populates="user")
    api_keys: List["UserAPIKey"] = Relationship(back_populates="user")
    login_history: List["LoginHistory"] = Relationship(back_populates="user")
    
    @property
    def full_name(self) -> str:
        """Get user's full name."""
        return f"{self.first_name} {self.last_name or ''}".strip()


class Role(BaseModel, SQLModel, table=True):
    """Role model."""
    
    __tablename__ = "roles"
    
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(unique=True, index=True)
    display_name: str
    description: Optional[str] = None
    is_system: bool = Field(default=False)  # System roles cannot be deleted
    
    # Relationships
    users: List["UserRole"] = Relationship(back_populates="role")
    permissions: List["RolePermission"] = Relationship(back_populates="role")


class Permission(BaseModel, SQLModel, table=True):
    """Permission model."""
    
    __tablename__ = "permissions"
    
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(unique=True, index=True)  # e.g., "users.create"
    display_name: str
    description: Optional[str] = None
    resource: str  # e.g., "users"
    action: str  # e.g., "create"
    
    # Relationships
    roles: List["RolePermission"] = Relationship(back_populates="permission")


class UserRole(BaseModel, SQLModel, table=True):
    """User-Role association with additional fields."""
    
    __tablename__ = "user_roles"
    __table_args__ = (
        Index("idx_user_role", "user_id", "role_id", unique=True),
    )
    
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="users.id")
    role_id: int = Field(foreign_key="roles.id")
    granted_by: Optional[int] = Field(foreign_key="users.id")
    expires_at: Optional[datetime] = None
    
    # Relationships
    user: User = Relationship(back_populates="roles")
    role: Role = Relationship(back_populates="users")


class RolePermission(BaseModel, SQLModel, table=True):
    """Role-Permission association."""
    
    __tablename__ = "role_permissions"
    __table_args__ = (
        Index("idx_role_permission", "role_id", "permission_id", unique=True),
    )
    
    id: Optional[int] = Field(default=None, primary_key=True)
    role_id: int = Field(foreign_key="roles.id")
    permission_id: int = Field(foreign_key="permissions.id")
    
    # Relationships
    role: Role = Relationship(back_populates="permissions")
    permission: Permission = Relationship(back_populates="roles")


class UserSession(BaseModelWithUUID, SQLModel, table=True):
    """User session tracking."""
    
    __tablename__ = "user_sessions"
    __table_args__ = (
        Index("idx_session_token", "refresh_token_id"),
        Index("idx_session_user", "user_id"),
    )
    
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="users.id")
    
    # Token tracking
    access_token_id: str = Field(index=True)
    refresh_token_id: str = Field(index=True)
    
    # Session info
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    device_type: Optional[str] = None
    device_name: Optional[str] = None
    
    # Timestamps
    expires_at: datetime
    last_activity_at: datetime = Field(default_factory=datetime.utcnow)
    revoked_at: Optional[datetime] = None
    
    # Status
    is_active: bool = Field(default=True)
    revoked_reason: Optional[str] = None
    
    # Relationships
    user: User = Relationship(back_populates="sessions")


class LoginHistory(BaseModel, SQLModel, table=True):
    """Login history for audit trail."""
    
    __tablename__ = "login_history"
    __table_args__ = (
        Index("idx_login_history_user", "user_id"),
        Index("idx_login_history_timestamp", "created_at"),
    )
    
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="users.id")
    
    # Login details
    success: bool
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    location: Optional[str] = None  # Resolved from IP
    
    # Authentication method
    auth_method: str  # password, oauth, api_key, etc.
    auth_provider: Optional[str] = None
    
    # Failure reason
    failure_reason: Optional[str] = None
    
    # Relationships
    user: User = Relationship(back_populates="login_history")


class UserAPIKey(BaseModelWithUUID, SQLModel, table=True):
    """API keys for programmatic access."""
    
    __tablename__ = "user_api_keys"
    __table_args__ = (
        Index("idx_api_key_hash", "key_hash"),
    )
    
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="users.id")
    
    # Key details
    name: str
    key_prefix: str  # First 8 characters for identification
    key_hash: str = Field(unique=True)  # Hashed API key
    
    # Permissions
    scopes: Optional[str] = None  # JSON array of allowed scopes
    
    # Usage tracking
    last_used_at: Optional[datetime] = None
    usage_count: int = Field(default=0)
    
    # Expiration
    expires_at: Optional[datetime] = None
    is_active: bool = Field(default=True)
    
    # Relationships
    user: User = Relationship(back_populates="api_keys")


class PasswordResetToken(BaseModel, SQLModel, table=True):
    """Password reset tokens."""
    
    __tablename__ = "password_reset_tokens"
    __table_args__ = (
        Index("idx_reset_token", "token_hash"),
    )
    
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="users.id")
    token_hash: str = Field(unique=True)
    expires_at: datetime
    used_at: Optional[datetime] = None
    ip_address: Optional[str] = None


class EmailVerificationToken(BaseModel, SQLModel, table=True):
    """Email verification tokens."""
    
    __tablename__ = "email_verification_tokens"
    __table_args__ = (
        Index("idx_verification_token", "token_hash"),
    )
    
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="users.id")
    email: str  # In case user changes email before verifying
    token_hash: str = Field(unique=True)
    expires_at: datetime
    verified_at: Optional[datetime] = None
EOF
}