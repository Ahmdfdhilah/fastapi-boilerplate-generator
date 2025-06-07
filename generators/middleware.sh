#!/bin/bash

# Middleware file generators

# Generate error handler middleware
generate_error_handler() {
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
}

# Generate logging middleware
generate_logging_middleware() {
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

    # Create middleware __init__.py
    cat > src/middleware/__init__.py << 'EOF'
"""Middleware package."""

from .error_handler import setup_exception_handlers
from .logging import setup_logging_middleware
from .rate_limiting import setup_rate_limiting_middleware

__all__ = ["setup_exception_handlers", "setup_logging_middleware", "setup_rate_limiting_middleware"]
EOF
}

# Generate rate limiting middleware (Step 2)
generate_rate_limiting_middleware() {
    cat > src/middleware/rate_limiting.py << 'EOF'
"""Rate limiting middleware with Redis support."""

from fastapi import Request, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
import time
import logging
from typing import Dict, Tuple
import asyncio

logger = logging.getLogger(__name__)


class RateLimitingMiddleware(BaseHTTPMiddleware):
    """Rate limiting middleware with IP-based tracking."""
    
    def __init__(self, app, calls: int = 100, period: int = 60):
        """Initialize rate limiting middleware.
        
        Args:
            app: FastAPI application
            calls: Number of calls allowed per period
            period: Time period in seconds
        """
        super().__init__(app)
        self.calls = calls
        self.period = period
        self.storage: Dict[str, Dict] = {}  # In-memory storage (use Redis in production)
    
    async def dispatch(self, request: Request, call_next):
        client_ip = self._get_client_ip(request)
        
        # Check if request should be rate limited
        if await self._is_rate_limited(request, client_ip):
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "detail": "Rate limit exceeded. Too many requests.",
                    "retry_after": self.period
                },
                headers={"Retry-After": str(self.period)}
            )
        
        # Update request count
        await self._update_request_count(client_ip)
        
        response = await call_next(request)
        return response
    
    def _get_client_ip(self, request: Request) -> str:
        """Get client IP address from request."""
        # Check for forwarded headers first
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
        
        # Fallback to direct client IP
        return request.client.host if request.client else "unknown"
    
    async def _is_rate_limited(self, request: Request, client_ip: str) -> bool:
        """Check if the client IP is rate limited."""
        current_time = time.time()
        
        # Get or create client data
        if client_ip not in self.storage:
            self.storage[client_ip] = {
                "requests": [],
                "blocked_until": 0
            }
        
        client_data = self.storage[client_ip]
        
        # Check if client is currently blocked
        if current_time < client_data["blocked_until"]:
            return True
        
        # Clean old requests (outside the time window)
        client_data["requests"] = [
            req_time for req_time in client_data["requests"]
            if current_time - req_time < self.period
        ]
        
        # Check if limit exceeded
        if len(client_data["requests"]) >= self.calls:
            # Block for the remaining time window
            oldest_request = min(client_data["requests"])
            client_data["blocked_until"] = oldest_request + self.period
            
            logger.warning(f"Rate limit exceeded for IP {client_ip}. Blocked until {client_data['blocked_until']}")
            return True
        
        return False
    
    async def _update_request_count(self, client_ip: str) -> None:
        """Update request count for the client IP."""
        current_time = time.time()
        
        if client_ip in self.storage:
            self.storage[client_ip]["requests"].append(current_time)


class AuthRateLimitingMiddleware(BaseHTTPMiddleware):
    """Specialized rate limiting for authentication endpoints."""
    
    def __init__(self, app, calls: int = 5, period: int = 300):  # 5 attempts per 5 minutes
        super().__init__(app)
        self.calls = calls
        self.period = period
        self.storage: Dict[str, Dict] = {}
    
    async def dispatch(self, request: Request, call_next):
        # Only apply to auth endpoints
        if not self._is_auth_endpoint(request):
            return await call_next(request)
        
        client_ip = self._get_client_ip(request)
        
        # Check rate limit for auth endpoints
        if await self._is_auth_rate_limited(client_ip):
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "detail": "Too many authentication attempts. Please try again later.",
                    "retry_after": self.period
                },
                headers={"Retry-After": str(self.period)}
            )
        
        response = await call_next(request)
        
        # If auth attempt failed, increment counter
        if self._is_failed_auth(response):
            await self._update_auth_attempt_count(client_ip)
        elif self._is_successful_auth(response):
            # Reset counter on successful auth
            await self._reset_auth_attempts(client_ip)
        
        return response
    
    def _is_auth_endpoint(self, request: Request) -> bool:
        """Check if request is to an authentication endpoint."""
        auth_paths = ["/api/v1/auth/login", "/api/v1/auth/register"]
        return request.url.path in auth_paths and request.method == "POST"
    
    def _get_client_ip(self, request: Request) -> str:
        """Get client IP address from request."""
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
        
        return request.client.host if request.client else "unknown"
    
    async def _is_auth_rate_limited(self, client_ip: str) -> bool:
        """Check if auth attempts are rate limited."""
        current_time = time.time()
        
        if client_ip not in self.storage:
            self.storage[client_ip] = {
                "attempts": [],
                "blocked_until": 0
            }
        
        client_data = self.storage[client_ip]
        
        # Check if blocked
        if current_time < client_data["blocked_until"]:
            return True
        
        # Clean old attempts
        client_data["attempts"] = [
            attempt_time for attempt_time in client_data["attempts"]
            if current_time - attempt_time < self.period
        ]
        
        return len(client_data["attempts"]) >= self.calls
    
    async def _update_auth_attempt_count(self, client_ip: str) -> None:
        """Update failed auth attempt count."""
        current_time = time.time()
        
        if client_ip not in self.storage:
            self.storage[client_ip] = {"attempts": [], "blocked_until": 0}
        
        self.storage[client_ip]["attempts"].append(current_time)
        
        # If limit reached, block for the period
        if len(self.storage[client_ip]["attempts"]) >= self.calls:
            self.storage[client_ip]["blocked_until"] = current_time + self.period
            logger.warning(f"Auth rate limit exceeded for IP {client_ip}")
    
    async def _reset_auth_attempts(self, client_ip: str) -> None:
        """Reset auth attempts on successful login."""
        if client_ip in self.storage:
            self.storage[client_ip]["attempts"] = []
            self.storage[client_ip]["blocked_until"] = 0
    
    def _is_failed_auth(self, response) -> bool:
        """Check if response indicates failed authentication."""
        return response.status_code in [401, 403, 423]  # Unauthorized, Forbidden, Locked
    
    def _is_successful_auth(self, response) -> bool:
        """Check if response indicates successful authentication."""
        return response.status_code == 200


def setup_rate_limiting_middleware(app):
    """Setup rate limiting middleware."""
    # General rate limiting
    app.add_middleware(RateLimitingMiddleware, calls=100, period=60)  # 100 requests per minute
    
    # Auth-specific rate limiting
    app.add_middleware(AuthRateLimitingMiddleware, calls=5, period=300)  # 5 auth attempts per 5 minutes
EOF
}