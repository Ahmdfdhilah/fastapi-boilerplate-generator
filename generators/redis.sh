#!/bin/bash

# Redis file generators for caching and session management

# Generate Redis connection utilities
generate_redis_connection() {
    cat > src/core/redis.py << 'EOF'
"""Redis connection and utilities."""

import redis.asyncio as redis
from typing import Optional, Any
import json
import logging
from src.core.config import settings

logger = logging.getLogger(__name__)

# Global Redis connection pool
redis_pool: Optional[redis.ConnectionPool] = None
redis_client: Optional[redis.Redis] = None


async def init_redis() -> None:
    """Initialize Redis connection pool."""
    global redis_pool, redis_client
    
    if not settings.REDIS_HOST:
        logger.warning("Redis not configured, skipping Redis initialization")
        return
    
    try:
        redis_pool = redis.ConnectionPool(
            host=settings.REDIS_HOST,
            port=settings.REDIS_PORT or 6379,
            password=settings.REDIS_PASSWORD,
            db=settings.REDIS_DB,
            decode_responses=True,
            max_connections=20
        )
        
        redis_client = redis.Redis(connection_pool=redis_pool)
        
        # Test connection
        await redis_client.ping()
        logger.info("✅ Redis connected successfully")
        
    except Exception as e:
        logger.error(f"❌ Redis connection failed: {e}")
        redis_pool = None
        redis_client = None


async def close_redis() -> None:
    """Close Redis connection."""
    global redis_pool, redis_client
    
    if redis_client:
        await redis_client.close()
    
    if redis_pool:
        await redis_pool.disconnect()
    
    redis_pool = None
    redis_client = None
    logger.info("Redis connection closed")


def get_redis() -> Optional[redis.Redis]:
    """Get Redis client instance."""
    return redis_client


async def redis_set(key: str, value: Any, expire: Optional[int] = None) -> bool:
    """Set a value in Redis with optional expiration."""
    if not redis_client:
        logger.warning("Redis not available")
        return False
    
    try:
        # Serialize value to JSON if it's not a string
        if not isinstance(value, str):
            value = json.dumps(value)
        
        expire_time = expire or settings.REDIS_TTL
        await redis_client.setex(key, expire_time, value)
        return True
        
    except Exception as e:
        logger.error(f"Redis SET error for key {key}: {e}")
        return False


async def redis_get(key: str) -> Optional[Any]:
    """Get a value from Redis."""
    if not redis_client:
        logger.warning("Redis not available")
        return None
    
    try:
        value = await redis_client.get(key)
        if value is None:
            return None
        
        # Try to deserialize JSON, fallback to string
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
            
    except Exception as e:
        logger.error(f"Redis GET error for key {key}: {e}")
        return None


async def redis_delete(key: str) -> bool:
    """Delete a key from Redis."""
    if not redis_client:
        logger.warning("Redis not available")
        return False
    
    try:
        result = await redis_client.delete(key)
        return result > 0
        
    except Exception as e:
        logger.error(f"Redis DELETE error for key {key}: {e}")
        return False


async def redis_exists(key: str) -> bool:
    """Check if a key exists in Redis."""
    if not redis_client:
        return False
    
    try:
        result = await redis_client.exists(key)
        return result > 0
        
    except Exception as e:
        logger.error(f"Redis EXISTS error for key {key}: {e}")
        return False


async def redis_increment(key: str, amount: int = 1, expire: Optional[int] = None) -> Optional[int]:
    """Increment a counter in Redis."""
    if not redis_client:
        logger.warning("Redis not available")
        return None
    
    try:
        # Use pipeline for atomic operation
        async with redis_client.pipeline() as pipe:
            await pipe.incrby(key, amount)
            if expire:
                await pipe.expire(key, expire)
            results = await pipe.execute()
            return results[0]
            
    except Exception as e:
        logger.error(f"Redis INCREMENT error for key {key}: {e}")
        return None


async def redis_get_pattern(pattern: str) -> list:
    """Get all keys matching a pattern."""
    if not redis_client:
        return []
    
    try:
        keys = await redis_client.keys(pattern)
        return keys
        
    except Exception as e:
        logger.error(f"Redis KEYS error for pattern {pattern}: {e}")
        return []


async def redis_flush_pattern(pattern: str) -> int:
    """Delete all keys matching a pattern."""
    if not redis_client:
        return 0
    
    try:
        keys = await redis_get_pattern(pattern)
        if not keys:
            return 0
        
        result = await redis_client.delete(*keys)
        return result
        
    except Exception as e:
        logger.error(f"Redis FLUSH error for pattern {pattern}: {e}")
        return 0
EOF
}

# Generate Redis cache utilities
generate_redis_cache() {
    cat > src/utils/cache.py << 'EOF'
"""Cache utilities using Redis."""

import functools
import hashlib
import json
from typing import Any, Callable, Optional
import logging
from src.core.redis import redis_get, redis_set, redis_delete, redis_exists

logger = logging.getLogger(__name__)


def cache_key(*args, **kwargs) -> str:
    """Generate a cache key from function arguments."""
    # Create a string representation of all arguments
    key_data = {
        'args': args,
        'kwargs': sorted(kwargs.items())
    }
    key_string = json.dumps(key_data, sort_keys=True, default=str)
    
    # Create a hash of the key for consistent length
    return hashlib.md5(key_string.encode()).hexdigest()


def redis_cache(expire: int = 3600, key_prefix: str = "cache"):
    """
    Decorator to cache function results in Redis.
    
    Args:
        expire: Cache expiration time in seconds
        key_prefix: Prefix for cache keys
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            # Generate cache key
            func_name = f"{func.__module__}.{func.__name__}"
            key_suffix = cache_key(*args, **kwargs)
            cache_key_name = f"{key_prefix}:{func_name}:{key_suffix}"
            
            # Try to get from cache first
            cached_result = await redis_get(cache_key_name)
            if cached_result is not None:
                logger.debug(f"Cache HIT for {func_name}")
                return cached_result
            
            # Call the function and cache result
            logger.debug(f"Cache MISS for {func_name}")
            result = await func(*args, **kwargs)
            
            # Cache the result
            await redis_set(cache_key_name, result, expire)
            
            return result
        
        # Add cache management methods
        wrapper.cache_clear = lambda *args, **kwargs: redis_delete(
            f"{key_prefix}:{func.__module__}.{func.__name__}:{cache_key(*args, **kwargs)}"
        )
        wrapper.cache_exists = lambda *args, **kwargs: redis_exists(
            f"{key_prefix}:{func.__module__}.{func.__name__}:{cache_key(*args, **kwargs)}"
        )
        
        return wrapper
    return decorator


class CacheManager:
    """Centralized cache management."""
    
    def __init__(self, prefix: str = "app"):
        self.prefix = prefix
    
    async def get(self, key: str) -> Optional[Any]:
        """Get value from cache."""
        full_key = f"{self.prefix}:{key}"
        return await redis_get(full_key)
    
    async def set(self, key: str, value: Any, expire: Optional[int] = None) -> bool:
        """Set value in cache."""
        full_key = f"{self.prefix}:{key}"
        return await redis_set(full_key, value, expire)
    
    async def delete(self, key: str) -> bool:
        """Delete key from cache."""
        full_key = f"{self.prefix}:{key}"
        return await redis_delete(full_key)
    
    async def exists(self, key: str) -> bool:
        """Check if key exists in cache."""
        full_key = f"{self.prefix}:{key}"
        return await redis_exists(full_key)
    
    async def clear_pattern(self, pattern: str) -> int:
        """Clear all keys matching pattern."""
        from src.core.redis import redis_flush_pattern
        full_pattern = f"{self.prefix}:{pattern}"
        return await redis_flush_pattern(full_pattern)


# Global cache manager instance
cache = CacheManager()
EOF
}

# Generate Redis session management
generate_redis_sessions() {
    cat > src/utils/sessions.py << 'EOF'
"""Session management using Redis."""

import json
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
import logging
from src.core.redis import redis_set, redis_get, redis_delete, redis_exists
from src.core.config import settings

logger = logging.getLogger(__name__)


class SessionManager:
    """Manage user sessions in Redis."""
    
    def __init__(self, prefix: str = "session"):
        self.prefix = prefix
        self.default_expire = 3600 * 24  # 24 hours
    
    def _session_key(self, session_id: str) -> str:
        """Generate session key."""
        return f"{self.prefix}:{session_id}"
    
    def _user_sessions_key(self, user_id: int) -> str:
        """Generate user sessions key."""
        return f"{self.prefix}:user:{user_id}"
    
    async def create_session(self, user_id: int, data: Dict[str, Any], expire: Optional[int] = None) -> str:
        """Create a new session."""
        session_id = str(uuid.uuid4())
        expire_time = expire or self.default_expire
        
        session_data = {
            "user_id": user_id,
            "created_at": datetime.utcnow().isoformat(),
            "last_activity": datetime.utcnow().isoformat(),
            "data": data
        }
        
        session_key = self._session_key(session_id)
        success = await redis_set(session_key, session_data, expire_time)
        
        if success:
            # Track session for user
            await self._add_user_session(user_id, session_id)
            logger.info(f"Created session {session_id} for user {user_id}")
            return session_id
        
        raise Exception("Failed to create session")
    
    async def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session data."""
        session_key = self._session_key(session_id)
        session_data = await redis_get(session_key)
        
        if session_data:
            # Update last activity
            session_data["last_activity"] = datetime.utcnow().isoformat()
            await redis_set(session_key, session_data, self.default_expire)
        
        return session_data
    
    async def update_session(self, session_id: str, data: Dict[str, Any]) -> bool:
        """Update session data."""
        session_data = await self.get_session(session_id)
        if not session_data:
            return False
        
        session_data["data"].update(data)
        session_data["last_activity"] = datetime.utcnow().isoformat()
        
        session_key = self._session_key(session_id)
        return await redis_set(session_key, session_data, self.default_expire)
    
    async def delete_session(self, session_id: str) -> bool:
        """Delete a session."""
        session_data = await self.get_session(session_id)
        if session_data:
            user_id = session_data["user_id"]
            await self._remove_user_session(user_id, session_id)
        
        session_key = self._session_key(session_id)
        result = await redis_delete(session_key)
        
        if result:
            logger.info(f"Deleted session {session_id}")
        
        return result
    
    async def delete_user_sessions(self, user_id: int) -> int:
        """Delete all sessions for a user."""
        sessions = await self.get_user_sessions(user_id)
        deleted_count = 0
        
        for session_id in sessions:
            if await self.delete_session(session_id):
                deleted_count += 1
        
        # Clear user sessions tracking
        user_sessions_key = self._user_sessions_key(user_id)
        await redis_delete(user_sessions_key)
        
        logger.info(f"Deleted {deleted_count} sessions for user {user_id}")
        return deleted_count
    
    async def get_user_sessions(self, user_id: int) -> list:
        """Get all session IDs for a user."""
        user_sessions_key = self._user_sessions_key(user_id)
        sessions = await redis_get(user_sessions_key)
        return sessions or []
    
    async def _add_user_session(self, user_id: int, session_id: str) -> None:
        """Add session to user's session list."""
        sessions = await self.get_user_sessions(user_id)
        if session_id not in sessions:
            sessions.append(session_id)
            user_sessions_key = self._user_sessions_key(user_id)
            await redis_set(user_sessions_key, sessions, self.default_expire * 2)
    
    async def _remove_user_session(self, user_id: int, session_id: str) -> None:
        """Remove session from user's session list."""
        sessions = await self.get_user_sessions(user_id)
        if session_id in sessions:
            sessions.remove(session_id)
            user_sessions_key = self._user_sessions_key(user_id)
            if sessions:
                await redis_set(user_sessions_key, sessions, self.default_expire * 2)
            else:
                await redis_delete(user_sessions_key)
    
    async def cleanup_expired_sessions(self) -> int:
        """Clean up expired sessions (run periodically)."""
        from src.core.redis import redis_get_pattern
        
        pattern = f"{self.prefix}:*"
        session_keys = await redis_get_pattern(pattern)
        
        cleaned_count = 0
        for key in session_keys:
            # Skip user session tracking keys
            if ":user:" in key:
                continue
            
            session_data = await redis_get(key)
            if not session_data:
                cleaned_count += 1
                continue
            
            # Check if session is too old (more than 7 days of inactivity)
            try:
                last_activity = datetime.fromisoformat(session_data["last_activity"])
                if datetime.utcnow() - last_activity > timedelta(days=7):
                    session_id = key.split(":")[-1]
                    await self.delete_session(session_id)
                    cleaned_count += 1
            except (KeyError, ValueError):
                # Invalid session data, delete it
                await redis_delete(key)
                cleaned_count += 1
        
        if cleaned_count > 0:
            logger.info(f"Cleaned up {cleaned_count} expired sessions")
        
        return cleaned_count


# Global session manager instance
session_manager = SessionManager()
EOF
}

# Generate Redis rate limiting utilities
generate_redis_rate_limiting() {
    cat > src/utils/rate_limiting.py << 'EOF'
"""Rate limiting utilities using Redis."""

import time
from typing import Optional, Tuple
from src.core.redis import redis_get, redis_set, redis_increment
import logging

logger = logging.getLogger(__name__)


class RateLimiter:
    """Redis-based rate limiter."""
    
    def __init__(self, prefix: str = "rate_limit"):
        self.prefix = prefix
    
    def _get_key(self, identifier: str, window: str) -> str:
        """Generate rate limit key."""
        return f"{self.prefix}:{identifier}:{window}"
    
    async def is_allowed(
        self, 
        identifier: str, 
        limit: int, 
        window_seconds: int,
        identifier_type: str = "ip"
    ) -> Tuple[bool, int, int]:
        """
        Check if request is allowed based on rate limit.
        
        Returns:
            Tuple of (is_allowed, current_count, remaining)
        """
        current_window = int(time.time()) // window_seconds
        key = self._get_key(f"{identifier_type}:{identifier}", str(current_window))
        
        # Get current count
        current_count = await redis_increment(key, 1, window_seconds)
        
        if current_count is None:
            # Redis not available, allow request
            logger.warning("Redis not available for rate limiting, allowing request")
            return True, 0, limit
        
        is_allowed = current_count <= limit
        remaining = max(0, limit - current_count)
        
        if not is_allowed:
            logger.warning(f"Rate limit exceeded for {identifier_type}:{identifier}")
        
        return is_allowed, current_count, remaining
    
    async def reset_limit(self, identifier: str, identifier_type: str = "ip") -> bool:
        """Reset rate limit for an identifier."""
        from src.core.redis import redis_flush_pattern
        
        pattern = f"{self.prefix}:{identifier_type}:{identifier}:*"
        deleted_count = await redis_flush_pattern(pattern)
        
        if deleted_count > 0:
            logger.info(f"Reset rate limit for {identifier_type}:{identifier}")
        
        return deleted_count > 0


class FailedAttemptTracker:
    """Track failed login attempts with Redis."""
    
    def __init__(self, prefix: str = "failed_attempts"):
        self.prefix = prefix
    
    def _get_key(self, identifier: str) -> str:
        """Generate failed attempts key."""
        return f"{self.prefix}:{identifier}"
    
    async def record_failure(self, identifier: str, window_seconds: int = 3600) -> int:
        """Record a failed attempt."""
        key = self._get_key(identifier)
        count = await redis_increment(key, 1, window_seconds)
        
        if count:
            logger.warning(f"Failed attempt recorded for {identifier}, count: {count}")
        
        return count or 1
    
    async def get_failure_count(self, identifier: str) -> int:
        """Get current failure count."""
        key = self._get_key(identifier)
        count = await redis_get(key)
        return int(count) if count else 0
    
    async def reset_failures(self, identifier: str) -> bool:
        """Reset failure count."""
        from src.core.redis import redis_delete
        
        key = self._get_key(identifier)
        result = await redis_delete(key)
        
        if result:
            logger.info(f"Reset failure count for {identifier}")
        
        return result
    
    async def is_blocked(self, identifier: str, max_attempts: int = 5) -> bool:
        """Check if identifier is blocked due to too many failures."""
        count = await self.get_failure_count(identifier)
        return count >= max_attempts


# Global instances
rate_limiter = RateLimiter()
failed_attempts = FailedAttemptTracker()
EOF
}

# Generate Redis middleware for rate limiting
generate_redis_middleware() {
    cat > src/middleware/rate_limit.py << 'EOF'
"""Rate limiting middleware using Redis."""

import time
from fastapi import Request, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from src.utils.rate_limiting import rate_limiter
from src.core.config import settings
import logging

logger = logging.getLogger(__name__)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limiting middleware."""
    
    def __init__(self, app, calls_per_minute: int = 60, calls_per_hour: int = 1000):
        super().__init__(app)
        self.calls_per_minute = calls_per_minute
        self.calls_per_hour = calls_per_hour
    
    def get_client_ip(self, request: Request) -> str:
        """Get client IP address."""
        # Check for forwarded headers
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
        
        # Fallback to direct client IP
        return request.client.host if request.client else "unknown"
    
    async def dispatch(self, request: Request, call_next):
        """Apply rate limiting."""
        client_ip = self.get_client_ip(request)
        
        # Skip rate limiting for health checks
        if request.url.path in ["/health", "/", "/docs", "/redoc", "/openapi.json"]:
            return await call_next(request)
        
        # Check minute-based rate limit
        minute_allowed, minute_count, minute_remaining = await rate_limiter.is_allowed(
            client_ip, self.calls_per_minute, 60, "ip"
        )
        
        # Check hour-based rate limit
        hour_allowed, hour_count, hour_remaining = await rate_limiter.is_allowed(
            client_ip, self.calls_per_hour, 3600, "ip"
        )
        
        if not minute_allowed or not hour_allowed:
            # Rate limit exceeded
            retry_after = 60 if not minute_allowed else 3600
            
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "detail": "Rate limit exceeded",
                    "retry_after": retry_after,
                    "minute_limit": self.calls_per_minute,
                    "hour_limit": self.calls_per_hour
                },
                headers={
                    "Retry-After": str(retry_after),
                    "X-RateLimit-Limit-Minute": str(self.calls_per_minute),
                    "X-RateLimit-Remaining-Minute": str(minute_remaining),
                    "X-RateLimit-Limit-Hour": str(self.calls_per_hour),
                    "X-RateLimit-Remaining-Hour": str(hour_remaining),
                }
            )
        
        # Process request
        response = await call_next(request)
        
        # Add rate limit headers to response
        response.headers["X-RateLimit-Limit-Minute"] = str(self.calls_per_minute)
        response.headers["X-RateLimit-Remaining-Minute"] = str(minute_remaining)
        response.headers["X-RateLimit-Limit-Hour"] = str(self.calls_per_hour)
        response.headers["X-RateLimit-Remaining-Hour"] = str(hour_remaining)
        
        return response


def setup_rate_limiting_middleware(app, calls_per_minute: int = 60, calls_per_hour: int = 1000):
    """Setup rate limiting middleware."""
    app.add_middleware(RateLimitMiddleware, calls_per_minute=calls_per_minute, calls_per_hour=calls_per_hour)
EOF
}