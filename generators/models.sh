#!/bin/bash

# Model file generators

# Generate base models
generate_base_models() {
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
}

# Generate user models
generate_user_models() {
    cat > src/models/user.py << 'EOF'
"""User model."""

from typing import Optional, List
from sqlmodel import Field, SQLModel, Relationship

from .base import BaseModel


class User(BaseModel, table=True):
    """User model."""
    
    __tablename__ = "users"
    
    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(unique=True, index=True, max_length=255)
    hashed_password: str = Field(max_length=255)
    first_name: str = Field(max_length=100)
    last_name: Optional[str] = Field(default=None, max_length=100)
    is_active: bool = Field(default=True)
    
    # Relationships
    roles: List["UserRole"] = Relationship(back_populates="user")


class Role(BaseModel, table=True):
    """Role model."""
    
    __tablename__ = "roles"
    
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(unique=True, index=True, max_length=50)
    description: Optional[str] = Field(default=None, max_length=255)
    
    # Relationships
    users: List["UserRole"] = Relationship(back_populates="role")


class UserRole(BaseModel, table=True):
    """User-Role association model."""
    
    __tablename__ = "user_roles"
    
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="users.id", index=True)
    role_id: int = Field(foreign_key="roles.id", index=True)
    
    # Relationships
    user: User = Relationship(back_populates="roles")
    role: Role = Relationship(back_populates="users")
    
    class Config:
        # Ensure unique combination of user and role
        table_args = {"extend_existing": True}
EOF

    # Create models __init__.py
    cat > src/models/__init__.py << 'EOF'
"""Models package."""

from .base import BaseModel, TimestampMixin, SoftDeleteMixin, AuditMixin
from .user import User, Role, UserRole

__all__ = [
    "BaseModel",
    "TimestampMixin", 
    "SoftDeleteMixin",
    "AuditMixin",
    "User",
    "Role", 
    "UserRole"
]
EOF
}