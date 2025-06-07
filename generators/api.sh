#!/bin/bash

# API endpoint generators with comprehensive auth features

# Generate enhanced user schemas
generate_user_schemas() {
    cat > src/schemas/user.py << 'EOF'
"""User schemas with comprehensive validation."""

from typing import List, Optional, Dict, Any
from datetime import datetime, date
from pydantic import BaseModel, EmailStr, ConfigDict, field_validator, Field
import re

from src.models.user import UserStatus, AuthProvider


class UserBase(BaseModel):
    """Base user schema."""
    email: EmailStr
    username: str = Field(min_length=3, max_length=50)
    first_name: str = Field(min_length=1, max_length=100)
    last_name: Optional[str] = Field(None, max_length=100)
    display_name: Optional[str] = Field(None, max_length=100)
    bio: Optional[str] = Field(None, max_length=500)
    date_of_birth: Optional[date] = None
    phone_number: Optional[str] = None
    language: str = "en"
    timezone: str = "UTC"
    
    @field_validator('username')
    @classmethod
    def validate_username(cls, v: str) -> str:
        """Validate username format."""
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError('Username can only contain letters, numbers, hyphens and underscores')
        return v.lower()
    
    @field_validator('phone_number')
    @classmethod
    def validate_phone(cls, v: Optional[str]) -> Optional[str]:
        """Validate phone number format."""
        if v:
            # Remove all non-numeric characters
            cleaned = re.sub(r'\D', '', v)
            if len(cleaned) < 10 or len(cleaned) > 15:
                raise ValueError('Invalid phone number')
            return f"+{cleaned}"
        return v


class UserCreate(UserBase):
    """Schema for creating a user."""
    password: str = Field(min_length=8, max_length=128)
    confirm_password: str
    terms_accepted: bool
    privacy_accepted: bool
    marketing_consent: bool = False
    
    @field_validator('confirm_password')
    @classmethod
    def passwords_match(cls, v: str, info) -> str:
        """Validate passwords match."""
        if 'password' in info.data and v != info.data['password']:
            raise ValueError('Passwords do not match')
        return v


class UserUpdate(BaseModel):
    """Schema for updating a user."""
    first_name: Optional[str] = Field(None, min_length=1, max_length=100)
    last_name: Optional[str] = Field(None, max_length=100)
    display_name: Optional[str] = Field(None, max_length=100)
    bio: Optional[str] = Field(None, max_length=500)
    date_of_birth: Optional[date] = None
    phone_number: Optional[str] = None
    language: Optional[str] = None
    timezone: Optional[str] = None
    avatar_url: Optional[str] = None


class UserResponse(UserBase):
    """Schema for user response."""
    id: int
    uuid: str
    status: UserStatus
    is_active: bool
    is_verified: bool
    is_locked: bool
    avatar_url: Optional[str]
    email_verified_at: Optional[datetime]
    phone_verified_at: Optional[datetime]
    last_login_at: Optional[datetime]
    last_activity_at: Optional[datetime]
    created_at: datetime
    mfa_enabled: bool
    auth_provider: AuthProvider
    
    model_config = ConfigDict(from_attributes=True)


class UserDetailResponse(UserResponse):
    """Detailed user response with additional info."""
    roles: List[str] = []
    permissions: List[str] = []
    active_sessions: int = 0
    notification_preferences: Optional[Dict[str, Any]] = None


class UserLogin(BaseModel):
    """Schema for user login."""
    username: str  # Can be email or username
    password: str
    remember_me: bool = False


class UserRegister(UserCreate):
    """Schema for user registration."""
    referral_code: Optional[str] = None
    captcha_token: Optional[str] = None


class PasswordChange(BaseModel):
    """Schema for password change."""
    current_password: str
    new_password: str = Field(min_length=8, max_length=128)
    confirm_password: str
    logout_other_sessions: bool = True
    
    @field_validator('confirm_password')
    @classmethod
    def passwords_match(cls, v: str, info) -> str:
        """Validate passwords match."""
        if 'new_password' in info.data and v != info.data['new_password']:
            raise ValueError('Passwords do not match')
        return v


class PasswordReset(BaseModel):
    """Schema for password reset."""
    token: str
    new_password: str = Field(min_length=8, max_length=128)
    confirm_password: str
    
    @field_validator('confirm_password')
    @classmethod
    def passwords_match(cls, v: str, info) -> str:
        """Validate passwords match."""
        if 'new_password' in info.data and v != info.data['new_password']:
            raise ValueError('Passwords do not match')
        return v


class PasswordResetRequest(BaseModel):
    """Schema for requesting password reset."""
    email: EmailStr


class EmailVerificationRequest(BaseModel):
    """Schema for email verification."""
    token: str


class Token(BaseModel):
    """Schema for token response."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    scope: Optional[str] = None


class TokenRefresh(BaseModel):
    """Schema for token refresh."""
    refresh_token: str


class TokenRevoke(BaseModel):
    """Schema for token revocation."""
    token: str
    token_type: str = "access"  # access or refresh
    revoke_all: bool = False  # Revoke all user tokens


class MFASetup(BaseModel):
    """Schema for MFA setup."""
    password: str  # Require password for security


class MFASetupResponse(BaseModel):
    """Response for MFA setup."""
    secret: str
    qr_code: str
    backup_codes: List[str]


class MFAVerify(BaseModel):
    """Schema for MFA verification."""
    code: str


class MFALogin(UserLogin):
    """Schema for login with MFA."""
    mfa_code: Optional[str] = None


class SessionResponse(BaseModel):
    """Schema for session information."""
    id: int
    uuid: str
    ip_address: Optional[str]
    user_agent: Optional[str]
    device_type: Optional[str]
    device_name: Optional[str]
    last_activity_at: datetime
    created_at: datetime
    is_current: bool = False
    
    model_config = ConfigDict(from_attributes=True)


class APIKeyCreate(BaseModel):
    """Schema for creating API key."""
    name: str = Field(min_length=1, max_length=100)
    scopes: Optional[List[str]] = None
    expires_in_days: Optional[int] = Field(None, ge=1, le=365)


class APIKeyResponse(BaseModel):
    """Schema for API key response."""
    id: int
    name: str
    key_prefix: str
    scopes: Optional[List[str]]
    last_used_at: Optional[datetime]
    expires_at: Optional[datetime]
    created_at: datetime
    
    model_config = ConfigDict(from_attributes=True)


class APIKeyCreateResponse(APIKeyResponse):
    """Response when creating API key (includes full key once)."""
    api_key: str  # Full key, shown only once


class UserPreferences(BaseModel):
    """Schema for user preferences."""
    email_notifications: bool = True
    push_notifications: bool = True
    sms_notifications: bool = False
    marketing_emails: bool = False
    security_alerts: bool = True
    login_alerts: bool = True
    newsletter: bool = False


class UserSecuritySettings(BaseModel):
    """Schema for security settings."""
    mfa_enabled: bool
    active_sessions: int
    api_keys_count: int
    last_password_change: Optional[datetime]
    password_expires_in_days: Optional[int]
    account_recovery_email: Optional[EmailStr]
EOF
}

# Generate auth schemas
generate_auth_schemas() {
    cat > src/schemas/auth.py << 'EOF'
"""Authentication and authorization schemas."""

from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field
from enum import Enum


class LoginResponse(BaseModel):
    """Response after successful login."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: Dict[str, Any]
    requires_mfa: bool = False
    session_id: str


class LogoutResponse(BaseModel):
    """Response after logout."""
    message: str = "Successfully logged out"
    sessions_revoked: int = 1


class MFARequiredResponse(BaseModel):
    """Response when MFA is required."""
    message: str = "MFA verification required"
    session_token: str  # Temporary token for MFA verification
    mfa_methods: List[str] = ["totp"]


class RoleResponse(BaseModel):
    """Schema for role response."""
    id: int
    name: str
    display_name: str
    description: Optional[str]
    permissions: List[str]
    is_system: bool
    
    model_config = ConfigDict(from_attributes=True)


class PermissionResponse(BaseModel):
    """Schema for permission response."""
    id: int
    name: str
    display_name: str
    description: Optional[str]
    resource: str
    action: str
    
    model_config = ConfigDict(from_attributes=True)


class SecurityEventType(str, Enum):
    """Types of security events."""
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILED = "login_failed"
    LOGOUT = "logout"
    PASSWORD_CHANGED = "password_changed"
    PASSWORD_RESET = "password_reset"
    MFA_ENABLED = "mfa_enabled"
    MFA_DISABLED = "mfa_disabled"
    SESSION_REVOKED = "session_revoked"
    ACCOUNT_LOCKED = "account_locked"
    ACCOUNT_UNLOCKED = "account_unlocked"
    API_KEY_CREATED = "api_key_created"
    API_KEY_REVOKED = "api_key_revoked"


class SecurityEvent(BaseModel):
    """Schema for security events."""
    event_type: SecurityEventType
    timestamp: datetime
    ip_address: Optional[str]
    user_agent: Optional[str]
    details: Optional[Dict[str, Any]]
    
    model_config = ConfigDict(from_attributes=True)


class AccountStatus(BaseModel):
    """Schema for account status."""
    is_active: bool
    is_verified: bool
    is_locked: bool
    is_mfa_enabled: bool
    failed_login_attempts: int
    locked_until: Optional[datetime]
    last_login: Optional[datetime]
    password_expires_at: Optional[datetime]
    requires_password_change: bool
EOF
}

# Generate comprehensive auth endpoints
generate_auth_endpoints() {
    cat > src/api/endpoints/auth.py << 'EOF'
"""Authentication endpoints with comprehensive features."""

from fastapi import APIRouter, Depends, HTTPException, status, Request, Response
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional

from src.core.database import get_db
from src.core.cache import get_redis_client
from src.repositories.user import UserRepository
from src.repositories.session import SessionRepository
from src.services.user import UserService
from src.services.auth import AuthService
from src.services.session import SessionService
from src.schemas.user import (
    UserLogin, UserRegister, UserResponse, 
    PasswordResetRequest, PasswordReset,
    EmailVerificationRequest, Token, TokenRefresh, TokenRevoke,
    MFASetup, MFASetupResponse, MFAVerify, MFALogin
)
from src.schemas.auth import (
    LoginResponse, LogoutResponse, MFARequiredResponse,
    AccountStatus
)
from src.schemas.common import StatusMessage
from src.auth.permissions import get_current_user, get_current_active_user
from src.auth.security import LoginAttemptTracker

router = APIRouter()
login_tracker = LoginAttemptTracker()


async def get_services(session: AsyncSession = Depends(get_db)):
    """Get service dependencies."""
    user_repo = UserRepository(session)
    session_repo = SessionRepository(session)
    user_service = UserService(user_repo)
    session_service = SessionService(session_repo, user_repo)
    auth_service = AuthService(user_service, session_service)
    return auth_service, session_service


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(
    user_data: UserRegister,
    request: Request,
    services: tuple = Depends(get_services)
):
    """Register a new user."""
    auth_service, _ = services
    
    # Get client info
    client_ip = request.client.host
    user_agent = request.headers.get("user-agent")
    
    return await auth_service.register(
        user_data,
        client_ip=client_ip,
        user_agent=user_agent
    )


@router.post("/login", response_model=LoginResponse)
async def login(
    login_data: UserLogin,
    request: Request,
    response: Response,
    services: tuple = Depends(get_services),
    redis_client = Depends(get_redis_client)
):
    """Login user and return access token."""
    auth_service, _ = services
    
    # Check login attempts
    identifier = login_data.username.lower()
    if await login_tracker.is_locked(identifier, redis_client):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed attempts. Account temporarily locked."
        )
    
    # Get client info
    client_ip = request.client.host
    user_agent = request.headers.get("user-agent")
    
    try:
        result = await auth_service.login(
            login_data,
            client_ip=client_ip,
            user_agent=user_agent,
            set_cookie=login_data.remember_me
        )
        
        # Clear failed attempts on success
        await login_tracker.clear_attempts(identifier, redis_client)
        
        # Set secure cookie if remember_me
        if login_data.remember_me:
            response.set_cookie(
                key="refresh_token",
                value=result.refresh_token,
                max_age=30 * 24 * 60 * 60,  # 30 days
                httponly=True,
                secure=True,
                samesite="lax"
            )
        
        return result
        
    except HTTPException as e:
        # Record failed attempt
        await login_tracker.record_failed_attempt(identifier, redis_client)
        raise


@router.post("/login/mfa", response_model=LoginResponse)
async def login_with_mfa(
    mfa_data: MFALogin,
    request: Request,
    services: tuple = Depends(get_services)
):
    """Complete login with MFA verification."""
    auth_service, _ = services
    
    client_ip = request.client.host
    user_agent = request.headers.get("user-agent")
    
    return await auth_service.login_with_mfa(
        mfa_data,
        client_ip=client_ip,
        user_agent=user_agent
    )


@router.post("/logout", response_model=LogoutResponse)
async def logout(
    request: Request,
    response: Response,
    current_user: dict = Depends(get_current_user),
    services: tuple = Depends(get_services),
    redis_client = Depends(get_redis_client)
):
    """Logout user and revoke tokens."""
    _, session_service = services
    
    # Revoke current session
    token_id = current_user.get("token_id")
    sessions_revoked = await session_service.revoke_session_by_token(
        token_id,
        user_id=current_user["id"],
        reason="User logout"
    )
    
    # Add token to blacklist
    if redis_client and token_id:
        await redis_client.setex(
            f"blacklist:{token_id}",
            3600,  # 1 hour (should match token expiry)
            "1"
        )
    
    # Clear cookie
    response.delete_cookie("refresh_token")
    
    return LogoutResponse(sessions_revoked=sessions_revoked)


@router.post("/logout/all", response_model=LogoutResponse)
async def logout_all_sessions(
    current_user: dict = Depends(get_current_active_user),
    services: tuple = Depends(get_services),
    redis_client = Depends(get_redis_client)
):
    """Logout from all sessions."""
    _, session_service = services
    
    sessions_revoked = await session_service.revoke_all_user_sessions(
        current_user["id"],
        reason="User logout from all devices"
    )
    
    # Blacklist all user tokens (simplified - in production, track all token IDs)
    if redis_client:
        await redis_client.setex(
            f"blacklist:user:{current_user['id']}",
            3600,
            "1"
        )
    
    return LogoutResponse(
        message="Successfully logged out from all devices",
        sessions_revoked=sessions_revoked
    )


@router.post("/refresh", response_model=Token)
async def refresh_token(
    token_data: TokenRefresh,
    services: tuple = Depends(get_services)
):
    """Refresh access token using refresh token."""
    auth_service, _ = services
    return await auth_service.refresh_token(token_data.refresh_token)


@router.post("/revoke", response_model=StatusMessage)
async def revoke_token(
    revoke_data: TokenRevoke,
    current_user: dict = Depends(get_current_user),
    services: tuple = Depends(get_services),
    redis_client = Depends(get_redis_client)
):
    """Revoke a specific token."""
    auth_service, _ = services
    
    await auth_service.revoke_token(
        revoke_data.token,
        revoke_data.token_type,
        user_id=current_user["id"],
        revoke_all=revoke_data.revoke_all
    )
    
    return StatusMessage(
        status="success",
        message="Token(s) revoked successfully"
    )


@router.post("/password/reset-request", response_model=StatusMessage)
async def request_password_reset(
    reset_request: PasswordResetRequest,
    request: Request,
    services: tuple = Depends(get_services)
):
    """Request password reset email."""
    auth_service, _ = services
    
    client_ip = request.client.host
    await auth_service.request_password_reset(
        reset_request.email,
        client_ip=client_ip
    )
    
    return StatusMessage(
        status="success",
        message="If the email exists, a reset link has been sent"
    )


@router.post("/password/reset", response_model=StatusMessage)
async def reset_password(
    reset_data: PasswordReset,
    request: Request,
    services: tuple = Depends(get_services)
):
    """Reset password using token."""
    auth_service, _ = services
    
    client_ip = request.client.host
    await auth_service.reset_password(
        reset_data.token,
        reset_data.new_password,
        client_ip=client_ip
    )
    
    return StatusMessage(
        status="success",
        message="Password reset successfully"
    )


@router.post("/verify-email", response_model=StatusMessage)
async def verify_email(
    verification: EmailVerificationRequest,
    services: tuple = Depends(get_services)
):
    """Verify email address."""
    auth_service, _ = services
    
    await auth_service.verify_email(verification.token)
    
    return StatusMessage(
        status="success",
        message="Email verified successfully"
    )


@router.post("/resend-verification", response_model=StatusMessage)
async def resend_verification(
    current_user: dict = Depends(get_current_user),
    services: tuple = Depends(get_services)
):
    """Resend email verification."""
    auth_service, _ = services
    
    await auth_service.resend_verification_email(current_user["id"])
    
    return StatusMessage(
        status="success",
        message="Verification email sent"
    )


@router.post("/mfa/setup", response_model=MFASetupResponse)
async def setup_mfa(
    mfa_data: MFASetup,
    current_user: dict = Depends(get_current_active_user),
    services: tuple = Depends(get_services)
):
    """Setup MFA for user account."""
    auth_service, _ = services
    
    return await auth_service.setup_mfa(
        current_user["id"],
        mfa_data.password
    )


@router.post("/mfa/verify", response_model=StatusMessage)
async def verify_mfa_setup(
    verification: MFAVerify,
    current_user: dict = Depends(get_current_active_user),
    services: tuple = Depends(get_services)
):
    """Verify MFA setup."""
    auth_service, _ = services
    
    await auth_service.verify_mfa_setup(
        current_user["id"],
        verification.code
    )
    
    return StatusMessage(
        status="success",
        message="MFA enabled successfully"
    )


@router.post("/mfa/disable", response_model=StatusMessage)
async def disable_mfa(
    mfa_data: MFASetup,  # Require password
    current_user: dict = Depends(get_current_active_user),
    services: tuple = Depends(get_services)
):
    """Disable MFA for user account."""
    auth_service, _ = services
    
    await auth_service.disable_mfa(
        current_user["id"],
        mfa_data.password
    )
    
    return StatusMessage(
        status="success",
        message="MFA disabled successfully"
    )


@router.get("/status", response_model=AccountStatus)
async def get_account_status(
    current_user: dict = Depends(get_current_user),
    services: tuple = Depends(get_services)
):
    """Get current account security status."""
    auth_service, _ = services
    
    return await auth_service.get_account_status(current_user["id"])


# OAuth endpoints
@router.get("/oauth/{provider}")
async def oauth_login(provider: str):
    """Initiate OAuth login."""
    # Implementation depends on OAuth library
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="OAuth not implemented in this boilerplate"
    )


@router.get("/oauth/{provider}/callback")
async def oauth_callback(provider: str, code: str):
    """OAuth callback handler."""
    # Implementation depends on OAuth library
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="OAuth not implemented in this boilerplate"
    )
EOF
}