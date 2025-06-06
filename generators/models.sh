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
}