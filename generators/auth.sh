#!/bin/bash

# Authentication file generators with comprehensive features

# Generate JWT handling with enhanced security
generate_auth_jwt() {
    cat > src/auth/jwt.py << 'EOF'
"""JWT token handling with enhanced security features."""

from datetime import datetime, timedelta
from typing import Dict, Optional, Any, Tuple
from jose import jwt, JWTError
from passlib.context import CryptContext
import secrets

from src.core.config import settings

# Password hashing with stronger configuration
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=12  # OWASP recommended minimum
)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Hash a password using bcrypt."""
    return pwd_context.hash(password)


def generate_token_id() -> str:
    """Generate a unique token ID for tracking."""
    return secrets.token_urlsafe(32)


def create_access_token(
    data: Dict[str, Any], 
    expires_delta: Optional[timedelta] = None,
    token_id: Optional[str] = None
) -> str:
    """Create a JWT access token with unique ID."""
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "jti": token_id or generate_token_id(),  # JWT ID for revocation
        "type": "access"
    })
    
    encoded_jwt = jwt.encode(
        to_encode, 
        settings.JWT_SECRET_KEY, 
        algorithm=settings.ALGORITHM
    )
    
    return encoded_jwt


def create_refresh_token(
    data: Dict[str, Any],
    token_id: Optional[str] = None
) -> str:
    """Create a JWT refresh token with unique ID."""
    to_encode = data.copy()
    
    expire = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "jti": token_id or generate_token_id(),
        "type": "refresh"
    })
    
    encoded_jwt = jwt.encode(
        to_encode, 
        settings.JWT_REFRESH_SECRET_KEY,  # Different secret for refresh tokens
        algorithm=settings.ALGORITHM
    )
    
    return encoded_jwt


def verify_token(token: str, token_type: str = "access") -> Dict[str, Any]:
    """Verify and decode a JWT token."""
    secret_key = settings.JWT_SECRET_KEY if token_type == "access" else settings.JWT_REFRESH_SECRET_KEY
    
    try:
        payload = jwt.decode(
            token, 
            secret_key, 
            algorithms=[settings.ALGORITHM]
        )
        
        # Verify token type
        if payload.get("type") != token_type:
            raise JWTError("Invalid token type")
        
        return payload
    except JWTError:
        raise


def create_token_pair(user_id: int) -> Tuple[str, str, str, str]:
    """Create access and refresh token pair with IDs."""
    access_token_id = generate_token_id()
    refresh_token_id = generate_token_id()
    
    access_token = create_access_token(
        data={"sub": str(user_id)},
        token_id=access_token_id
    )
    
    refresh_token = create_refresh_token(
        data={"sub": str(user_id)},
        token_id=refresh_token_id
    )
    
    return access_token, refresh_token, access_token_id, refresh_token_id


def decode_token_without_verification(token: str) -> Dict[str, Any]:
    """Decode token without verification (for getting JTI during revocation)."""
    return jwt.get_unverified_claims(token)
EOF
}

# Generate enhanced permissions and authorization
generate_auth_permissions() {
    cat > src/auth/permissions.py << 'EOF'
"""Authorization and permission checking with session management."""

from typing import List, Dict, Optional
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError

from src.auth.jwt import verify_token, decode_token_without_verification
from src.core.database import get_db
from sqlalchemy.ext.asyncio import AsyncSession
from src.repositories.user import UserRepository
from src.repositories.session import SessionRepository
from src.core.cache import get_redis_client


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


async def check_token_blacklist(token_id: str, redis_client) -> bool:
    """Check if token is blacklisted in Redis."""
    if redis_client:
        is_blacklisted = await redis_client.get(f"blacklist:{token_id}")
        return bool(is_blacklisted)
    return False


async def get_current_user(
    token: str = Depends(jwt_bearer), 
    session: AsyncSession = Depends(get_db),
    request: Request = None
) -> Dict:
    """Get the current authenticated user from the token."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = verify_token(token, token_type="access")
        user_id = payload.get("sub")
        token_id = payload.get("jti")
        
        if not user_id or not token_id:
            raise credentials_exception

        # Check if token is blacklisted
        redis_client = await get_redis_client()
        if await check_token_blacklist(token_id, redis_client):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has been revoked",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Get user from database
        user_repo = UserRepository(session)
        user = await user_repo.get_by_id(int(user_id))

        if not user:
            raise credentials_exception

        # Check if user account is locked
        if user.is_locked:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account is locked due to security reasons"
            )

        # Update last activity
        await user_repo.update_last_activity(user.id)

        # Get user roles and permissions
        user_roles = await user_repo.get_user_roles(user.id)
        roles = [role.name for role in user_roles]
        
        permissions = set()
        for role in user_roles:
            role_permissions = await user_repo.get_role_permissions(role.id)
            permissions.update([p.name for p in role_permissions])

        # Get client info for session tracking
        client_ip = None
        user_agent = None
        if request:
            client_ip = request.client.host
            user_agent = request.headers.get("user-agent")

        user_data = {
            "id": user.id,
            "email": user.email,
            "username": user.username,
            "name": f"{user.first_name} {user.last_name}".strip(),
            "roles": roles,
            "permissions": list(permissions),
            "is_active": user.is_active,
            "is_verified": user.is_verified,
            "token_id": token_id,
            "client_ip": client_ip,
            "user_agent": user_agent,
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
    if not current_user.get("is_verified"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email not verified"
        )
    return current_user


def require_permissions(required_permissions: List[str]):
    """Decorator to require specific permissions."""
    async def _check_permissions(
        current_user: Dict = Depends(get_current_active_user),
    ) -> Dict:
        user_permissions = set(current_user.get("permissions", []))
        
        if not any(perm in user_permissions for perm in required_permissions):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Required permissions: {', '.join(required_permissions)}",
            )
        
        return current_user
    
    return _check_permissions


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
admin_required = require_roles(["admin", "superadmin"])
user_required = require_roles(["user", "admin", "superadmin"])
superadmin_required = require_roles(["superadmin"])

# Common permission dependencies
can_edit_users = require_permissions(["users.edit"])
can_delete_users = require_permissions(["users.delete"])
can_manage_roles = require_permissions(["roles.manage"])
EOF
}

# Generate security utilities
generate_auth_security() {
    cat > src/auth/security.py << 'EOF'
"""Security utilities for authentication."""

import secrets
import string
from datetime import datetime, timedelta
from typing import Optional
import hashlib
import hmac


def generate_verification_token() -> str:
    """Generate a secure verification token."""
    return secrets.token_urlsafe(32)


def generate_password_reset_token() -> str:
    """Generate a secure password reset token."""
    return secrets.token_urlsafe(32)


def generate_otp(length: int = 6) -> str:
    """Generate a numeric OTP."""
    return ''.join(secrets.choice(string.digits) for _ in range(length))


def generate_api_key() -> str:
    """Generate a secure API key."""
    prefix = "sk_live_" if not settings.DEBUG else "sk_test_"
    key = secrets.token_urlsafe(32)
    return f"{prefix}{key}"


def hash_token(token: str, salt: str) -> str:
    """Hash a token with salt for storage."""
    return hashlib.sha256(f"{token}{salt}".encode()).hexdigest()


def verify_token_hash(token: str, hashed: str, salt: str) -> bool:
    """Verify a token against its hash."""
    return hmac.compare_digest(hash_token(token, salt), hashed)


def is_token_expired(created_at: datetime, expire_minutes: int) -> bool:
    """Check if a token has expired."""
    return datetime.utcnow() > created_at + timedelta(minutes=expire_minutes)


class PasswordValidator:
    """Password strength validator following OWASP guidelines."""
    
    @staticmethod
    def validate(password: str) -> tuple[bool, list[str]]:
        """Validate password strength and return (is_valid, errors)."""
        errors = []
        
        # Length check (minimum 8 characters)
        if len(password) < 8:
            errors.append("Password must be at least 8 characters long")
        
        # Maximum length check
        if len(password) > 128:
            errors.append("Password must not exceed 128 characters")
        
        # Complexity checks
        if not any(c.isupper() for c in password):
            errors.append("Password must contain at least one uppercase letter")
        
        if not any(c.islower() for c in password):
            errors.append("Password must contain at least one lowercase letter")
        
        if not any(c.isdigit() for c in password):
            errors.append("Password must contain at least one digit")
        
        if not any(c in string.punctuation for c in password):
            errors.append("Password must contain at least one special character")
        
        # Common password check (basic)
        common_passwords = [
            "password", "12345678", "qwerty", "abc123", "password123",
            "admin", "letmein", "welcome", "monkey", "dragon"
        ]
        if password.lower() in common_passwords:
            errors.append("Password is too common")
        
        return len(errors) == 0, errors


class LoginAttemptTracker:
    """Track login attempts for brute force protection."""
    
    def __init__(self, max_attempts: int = 5, lockout_duration: int = 30):
        self.max_attempts = max_attempts
        self.lockout_duration = lockout_duration  # minutes
    
    async def is_locked(self, identifier: str, redis_client) -> bool:
        """Check if account is locked due to failed attempts."""
        if not redis_client:
            return False
        
        key = f"login_attempts:{identifier}"
        attempts = await redis_client.get(key)
        
        if attempts and int(attempts) >= self.max_attempts:
            return True
        
        return False
    
    async def record_failed_attempt(self, identifier: str, redis_client):
        """Record a failed login attempt."""
        if not redis_client:
            return
        
        key = f"login_attempts:{identifier}"
        attempts = await redis_client.incr(key)
        
        if attempts == 1:
            # Set expiration on first attempt
            await redis_client.expire(key, self.lockout_duration * 60)
    
    async def clear_attempts(self, identifier: str, redis_client):
        """Clear login attempts after successful login."""
        if not redis_client:
            return
        
        key = f"login_attempts:{identifier}"
        await redis_client.delete(key)
EOF
}

# Generate MFA/2FA support
generate_auth_mfa() {
    cat > src/auth/mfa.py << 'EOF'
"""Multi-factor authentication support."""

import pyotp
import qrcode
import io
import base64
from typing import Optional, Tuple


class MFAService:
    """Service for handling multi-factor authentication."""
    
    @staticmethod
    def generate_secret() -> str:
        """Generate a new TOTP secret."""
        return pyotp.random_base32()
    
    @staticmethod
    def generate_qr_code(email: str, secret: str, issuer: str = None) -> str:
        """Generate QR code for TOTP setup."""
        if not issuer:
            from src.core.config import settings
            issuer = settings.PROJECT_NAME
        
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(
            name=email,
            issuer_name=issuer
        )
        
        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        
        # Convert to base64
        qr_base64 = base64.b64encode(buf.getvalue()).decode()
        return f"data:image/png;base64,{qr_base64}"
    
    @staticmethod
    def verify_totp(secret: str, token: str, window: int = 1) -> bool:
        """Verify a TOTP token."""
        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=window)
    
    @staticmethod
    def generate_backup_codes(count: int = 10) -> list[str]:
        """Generate backup codes for account recovery."""
        import secrets
        codes = []
        for _ in range(count):
            code = f"{secrets.token_hex(4)}-{secrets.token_hex(4)}"
            codes.append(code.upper())
        return codes
EOF
}