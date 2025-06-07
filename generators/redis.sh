#!/bin/bash

# generators/redis.sh - Redis integration generator
# Step 1: Redis Integration for FastAPI Boilerplate

# Generate Redis configuration utilities
generate_redis_config() {
    cat > src/core/redis.py << 'EOF'
"""Redis configuration and connection management."""

import redis.asyncio as redis
from typing import Optional
import logging

from src.core.config import settings

logger = logging.getLogger(__name__)


class RedisManager:
    """Redis connection manager."""
    
    def __init__(self):
        self.redis_client: Optional[redis.Redis] = None
        self._connected = False

    async def connect(self) -> None:
        """Connect to Redis server."""
        if not settings.REDIS_ENABLED:
            logger.info("Redis is disabled, skipping connection")
            return

        try:
            self.redis_client = redis.Redis(
                host=settings.REDIS_HOST,
                port=settings.REDIS_PORT,
                password=settings.REDIS_PASSWORD or None,
                db=settings.REDIS_DB,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5,
                retry_on_timeout=True,
                health_check_interval=30
            )
            
            # Test connection
            await self.redis_client.ping()
            self._connected = True
            logger.info(f"Connected to Redis at {settings.REDIS_HOST}:{settings.REDIS_PORT}")
            
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            self.redis_client = None
            self._connected = False

    async def disconnect(self) -> None:
        """Disconnect from Redis server."""
        if self.redis_client:
            await self.redis_client.close()
            self._connected = False
            logger.info("Disconnected from Redis")

    @property
    def is_connected(self) -> bool:
        """Check if Redis is connected."""
        return self._connected and self.redis_client is not None

    async def get(self, key: str) -> Optional[str]:
        """Get value from Redis."""
        if not self.is_connected:
            return None
        
        try:
            return await self.redis_client.get(key)
        except Exception as e:
            logger.error(f"Redis GET error for key {key}: {e}")
            return None

    async def set(self, key: str, value: str, ttl: Optional[int] = None) -> bool:
        """Set value in Redis with optional TTL."""
        if not self.is_connected:
            return False
        
        try:
            if ttl:
                return await self.redis_client.setex(key, ttl, value)
            else:
                return await self.redis_client.set(key, value)
        except Exception as e:
            logger.error(f"Redis SET error for key {key}: {e}")
            return False

    async def delete(self, key: str) -> bool:
        """Delete key from Redis."""
        if not self.is_connected:
            return False
        
        try:
            result = await self.redis_client.delete(key)
            return result > 0
        except Exception as e:
            logger.error(f"Redis DELETE error for key {key}: {e}")
            return False

    async def exists(self, key: str) -> bool:
        """Check if key exists in Redis."""
        if not self.is_connected:
            return False
        
        try:
            return await self.redis_client.exists(key) > 0
        except Exception as e:
            logger.error(f"Redis EXISTS error for key {key}: {e}")
            return False

    async def expire(self, key: str, ttl: int) -> bool:
        """Set TTL for existing key."""
        if not self.is_connected:
            return False
        
        try:
            return await self.redis_client.expire(key, ttl)
        except Exception as e:
            logger.error(f"Redis EXPIRE error for key {key}: {e}")
            return False


# Global Redis manager instance
redis_manager = RedisManager()


async def get_redis() -> RedisManager:
    """Dependency for getting Redis manager."""
    return redis_manager
EOF
}

# Generate token blacklist service
generate_token_blacklist() {
    cat > src/services/token_blacklist.py << 'EOF'
"""Token blacklist service using Redis."""

import json
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import logging

from src.core.redis import RedisManager, get_redis
from src.core.config import settings

logger = logging.getLogger(__name__)


class TokenBlacklistService:
    """Service for managing token blacklist using Redis."""
    
    def __init__(self, redis_manager: RedisManager):
        self.redis = redis_manager
        self.blacklist_prefix = "blacklist:token:"
        self.refresh_prefix = "refresh:token:"

    async def blacklist_token(self, jti: str, exp: int, token_type: str = "access") -> bool:
        """Add token to blacklist."""
        if not self.redis.is_connected:
            logger.warning("Redis not connected, cannot blacklist token")
            return False

        # Calculate TTL based on token expiration
        current_time = int(datetime.utcnow().timestamp())
        ttl = max(0, exp - current_time)
        
        if ttl <= 0:
            # Token already expired, no need to blacklist
            return True

        key = f"{self.blacklist_prefix}{jti}"
        token_data = {
            "type": token_type,
            "blacklisted_at": current_time,
            "expires_at": exp
        }
        
        return await self.redis.set(key, json.dumps(token_data), ttl)

    async def is_token_blacklisted(self, jti: str) -> bool:
        """Check if token is blacklisted."""
        if not self.redis.is_connected:
            # If Redis is not available, allow token (fail-open)
            # In production, you might want to fail-closed
            return False

        key = f"{self.blacklist_prefix}{jti}"
        return await self.redis.exists(key)

    async def store_refresh_token(self, jti: str, user_id: int, exp: int) -> bool:
        """Store refresh token for rotation."""
        if not self.redis.is_connected:
            return False

        # Calculate TTL
        current_time = int(datetime.utcnow().timestamp())
        ttl = max(0, exp - current_time)
        
        if ttl <= 0:
            return False

        key = f"{self.refresh_prefix}{jti}"
        token_data = {
            "user_id": user_id,
            "issued_at": current_time,
            "expires_at": exp
        }
        
        return await self.redis.set(key, json.dumps(token_data), ttl)

    async def get_refresh_token_data(self, jti: str) -> Optional[Dict[str, Any]]:
        """Get refresh token data."""
        if not self.redis.is_connected:
            return None

        key = f"{self.refresh_prefix}{jti}"
        data = await self.redis.get(key)
        
        if data:
            try:
                return json.loads(data)
            except json.JSONDecodeError:
                logger.error(f"Invalid JSON in refresh token data for JTI: {jti}")
                return None
        
        return None

    async def revoke_refresh_token(self, jti: str) -> bool:
        """Revoke refresh token."""
        if not self.redis.is_connected:
            return False

        key = f"{self.refresh_prefix}{jti}"
        return await self.redis.delete(key)

    async def revoke_all_user_tokens(self, user_id: int) -> int:
        """Revoke all tokens for a user (for logout all devices)."""
        if not self.redis.is_connected:
            return 0

        # This is a simple implementation
        # In production, you might want to maintain a user->tokens mapping
        # for more efficient bulk revocation
        
        # For now, we'll implement this in a future enhancement
        # This method serves as a placeholder for the functionality
        logger.info(f"Bulk token revocation for user {user_id} not yet implemented")
        return 0

    async def cleanup_expired_tokens(self) -> int:
        """Cleanup expired tokens (Redis handles this automatically with TTL)."""
        # Redis automatically removes expired keys
        # This method can be used for additional cleanup logic if needed
        return 0


async def get_token_blacklist_service(
    redis_manager: RedisManager = None
) -> TokenBlacklistService:
    """Dependency for getting token blacklist service."""
    if redis_manager is None:
        redis_manager = await get_redis()
    return TokenBlacklistService(redis_manager)
EOF
}

# Update JWT handling to support JTI and blacklist
generate_enhanced_jwt() {
    cat > src/auth/jwt_enhanced.py << 'EOF'
"""Enhanced JWT token handling with blacklist support."""

import uuid
from datetime import datetime, timedelta
from typing import Dict, Optional, Any, Tuple
from jose import jwt, JWTError

from src.core.config import settings
from src.auth.jwt import verify_password, get_password_hash  # Keep existing functions


def create_access_token(
    data: Dict[str, Any], 
    expires_delta: Optional[timedelta] = None
) -> Tuple[str, str]:
    """Create a JWT access token with JTI (JWT ID)."""
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    # Generate unique JTI (JWT ID) for token identification
    jti = str(uuid.uuid4())
    
    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "type": "access",
        "jti": jti
    })
    
    encoded_jwt = jwt.encode(
        to_encode, 
        settings.JWT_SECRET_KEY, 
        algorithm=settings.ALGORITHM
    )
    
    return encoded_jwt, jti


def create_refresh_token(data: Dict[str, Any]) -> Tuple[str, str]:
    """Create a JWT refresh token with JTI."""
    to_encode = data.copy()
    
    expire = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    jti = str(uuid.uuid4())
    
    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "type": "refresh",
        "jti": jti
    })
    
    encoded_jwt = jwt.encode(
        to_encode, 
        settings.JWT_SECRET_KEY, 
        algorithm=settings.ALGORITHM
    )
    
    return encoded_jwt, jti


def verify_token(token: str) -> Dict[str, Any]:
    """Verify and decode a JWT token."""
    try:
        payload = jwt.decode(
            token, 
            settings.JWT_SECRET_KEY, 
            algorithms=[settings.ALGORITHM]
        )
        return payload
    except JWTError as e:
        raise JWTError(f"Token verification failed: {str(e)}")


def extract_jti_from_token(token: str) -> Optional[str]:
    """Extract JTI from token without full verification (for blacklist check)."""
    try:
        # Decode without verification to get JTI quickly
        payload = jwt.get_unverified_claims(token)
        return payload.get("jti")
    except Exception:
        return None


def get_token_expiry(token: str) -> Optional[int]:
    """Get token expiry timestamp."""
    try:
        payload = jwt.get_unverified_claims(token)
        return payload.get("exp")
    except Exception:
        return None
EOF
}

# Update authentication permissions with blacklist check
generate_enhanced_permissions() {
    cat > src/auth/permissions_enhanced.py << 'EOF'
"""Enhanced authorization with token blacklist checking."""

from typing import List, Dict, Optional
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError

from src.auth.jwt_enhanced import verify_token, extract_jti_from_token
from src.services.token_blacklist import get_token_blacklist_service, TokenBlacklistService
from src.core.database import get_db
from sqlalchemy.ext.asyncio import AsyncSession
from src.repositories.user import UserRepository


class JWTBearerWithBlacklist(HTTPBearer):
    """JWT Bearer with blacklist checking."""
    
    def __init__(self, auto_error: bool = True):
        super(JWTBearerWithBlacklist, self).__init__(auto_error=auto_error)

    async def __call__(self, request: Request):
        credentials: HTTPAuthorizationCredentials = await super(
            JWTBearerWithBlacklist, self
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


jwt_bearer = JWTBearerWithBlacklist()


async def get_current_user(
    token: str = Depends(jwt_bearer), 
    session: AsyncSession = Depends(get_db),
    blacklist_service: TokenBlacklistService = Depends(get_token_blacklist_service)
) -> Dict:
    """Get the current authenticated user with blacklist checking."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        # First, check if token is blacklisted (quick check)
        jti = extract_jti_from_token(token)
        if jti and await blacklist_service.is_token_blacklisted(jti):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has been revoked",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Then verify token
        payload = verify_token(token)
        user_id = payload.get("sub")
        token_type = payload.get("type", "access")
        
        if not user_id or token_type != "access":
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
            "jti": jti  # Include JTI for logout purposes
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
}

# Generate logout endpoint
generate_logout_endpoint() {
    cat > src/api/endpoints/logout.py << 'EOF'
"""Logout endpoint with token revocation."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.database import get_db
from src.auth.permissions_enhanced import get_current_active_user
from src.auth.jwt_enhanced import get_token_expiry
from src.services.token_blacklist import get_token_blacklist_service, TokenBlacklistService
from src.schemas.common import StatusMessage

router = APIRouter()


@router.post("/logout", response_model=StatusMessage)
async def logout(
    current_user: dict = Depends(get_current_active_user),
    blacklist_service: TokenBlacklistService = Depends(get_token_blacklist_service)
):
    """Logout user by blacklisting the current token."""
    try:
        jti = current_user.get("jti")
        if not jti:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid token format"
            )

        # Get token expiry (we need this for TTL calculation)
        # In a real implementation, you might want to pass the original token
        # For now, we'll use a default TTL
        
        # Blacklist the token
        success = await blacklist_service.blacklist_token(
            jti=jti,
            exp=int(settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60),  # Convert to seconds
            token_type="access"
        )
        
        if not success:
            # If Redis is down, we might want to handle this differently
            return StatusMessage(
                status="warning",
                message="Logout completed, but token revocation may not be effective"
            )

        return StatusMessage(
            status="success",
            message="Successfully logged out"
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Logout failed"
        )


@router.post("/logout-all", response_model=StatusMessage)
async def logout_all_devices(
    current_user: dict = Depends(get_current_active_user),
    blacklist_service: TokenBlacklistService = Depends(get_token_blacklist_service)
):
    """Logout user from all devices (placeholder for future implementation)."""
    # This is a placeholder for bulk token revocation
    # Full implementation will come in next steps
    
    user_id = current_user.get("id")
    revoked_count = await blacklist_service.revoke_all_user_tokens(user_id)
    
    return StatusMessage(
        status="success",
        message=f"Logout from all devices initiated (feature coming soon)"
    )
EOF
}

print_step "Step 1: Redis Integration - Generator Created"
print_status "Files that will be generated:"
echo "  - src/core/redis.py (Redis connection manager)"
echo "  - src/services/token_blacklist.py (Token blacklist service)"
echo "  - src/auth/jwt_enhanced.py (Enhanced JWT with JTI)"
echo "  - src/auth/permissions_enhanced.py (Enhanced auth with blacklist)"
echo "  - src/api/endpoints/logout.py (Logout endpoints)"
echo ""
print_status "Configuration updates needed:"
echo "  - Enhanced .env file with Redis options"
echo "  - Updated core/config.py with Redis settings"
echo "  - Updated requirements.txt with Redis dependency"
echo "  - Modified interactive setup for Redis choice"

generate_redis_integration() {
    print_header "Redis Integration - Step 1"
    
    # Source the Redis generator
    source "$SCRIPT_DIR/generators/redis.sh"
    
    print_step "Generating Redis core files..."
    generate_redis_config
    generate_token_blacklist
    
    print_step "Generating enhanced JWT system..."
    generate_enhanced_jwt
    generate_enhanced_permissions
    
    print_step "Generating logout endpoints..."
    generate_logout_endpoint
    
    print_success "Redis integration files generated successfully"
}