#!/bin/bash

# Multi-Factor Authentication (MFA) file generators

# Generate MFA configuration
generate_mfa_config() {
    cat > src/auth/mfa.py << 'EOF'
"""Multi-Factor Authentication (MFA) implementation with TOTP."""

import secrets
import time
import hmac
import hashlib
import base64
import struct
from typing import Optional, Tuple, Dict, Any
from datetime import datetime, timedelta
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config import settings
from src.repositories.user_mfa import UserMFARepository
from src.auth.jwt import create_access_token

# TOTP Configuration
TOTP_INTERVAL = 30  # 30 seconds
TOTP_DIGITS = 6  # 6-digit codes
TOTP_WINDOW = 2  # Allow codes from 2 intervals before/after


class TOTPManager:
    """Time-based One-Time Password (TOTP) manager."""
    
    @staticmethod
    def generate_secret() -> str:
        """Generate a new TOTP secret key."""
        secret = secrets.token_bytes(32)
        return base64.b32encode(secret).decode('utf-8')
    
    @staticmethod
    def generate_qr_code_url(secret: str, email: str, issuer: str = None) -> str:
        """Generate QR code URL for TOTP setup."""
        if issuer is None:
            issuer = settings.PROJECT_NAME
        
        # Format: otpauth://totp/ISSUER:EMAIL?secret=SECRET&issuer=ISSUER
        return (f"otpauth://totp/{issuer}:{email}?"
                f"secret={secret}&issuer={issuer}&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_INTERVAL}")
    
    @staticmethod
    def _get_counter(timestamp: Optional[int] = None) -> int:
        """Get TOTP counter for given timestamp."""
        if timestamp is None:
            timestamp = int(time.time())
        return timestamp // TOTP_INTERVAL
    
    @staticmethod
    def _generate_hotp(secret: str, counter: int) -> str:
        """Generate HOTP code for given counter."""
        # Decode base32 secret
        secret_bytes = base64.b32decode(secret.upper())
        
        # Convert counter to bytes
        counter_bytes = struct.pack('>Q', counter)
        
        # Generate HMAC-SHA1
        hmac_digest = hmac.new(secret_bytes, counter_bytes, hashlib.sha1).digest()
        
        # Dynamic truncation
        offset = hmac_digest[-1] & 0x0f
        truncated = struct.unpack('>I', hmac_digest[offset:offset + 4])[0]
        truncated &= 0x7fffffff
        
        # Generate OTP
        otp = truncated % (10 ** TOTP_DIGITS)
        return str(otp).zfill(TOTP_DIGITS)
    
    @classmethod
    def generate_totp(cls, secret: str, timestamp: Optional[int] = None) -> str:
        """Generate TOTP code for given timestamp."""
        counter = cls._get_counter(timestamp)
        return cls._generate_hotp(secret, counter)
    
    @classmethod
    def verify_totp(cls, secret: str, code: str, timestamp: Optional[int] = None) -> bool:
        """Verify TOTP code with time window tolerance."""
        if timestamp is None:
            timestamp = int(time.time())
        
        current_counter = cls._get_counter(timestamp)
        
        # Check current and nearby time windows
        for i in range(-TOTP_WINDOW, TOTP_WINDOW + 1):
            counter = current_counter + i
            expected_code = cls._generate_hotp(secret, counter)
            if secrets.compare_digest(code, expected_code):
                return True
        
        return False


class MFAService:
    """Multi-Factor Authentication service."""
    
    def __init__(self, session: AsyncSession):
        self.session = session
        self.user_repo = UserMFARepository(session)
    
    async def enable_mfa(self, user_id: int) -> Dict[str, Any]:
        """Enable MFA for a user and return setup information."""
        user = await self.user_repo.get_by_id(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        if user.mfa_enabled:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="MFA is already enabled"
            )
        
        # Generate new secret
        mfa_secret = TOTPManager.generate_secret()
        
        # Save secret (temporarily until verified)
        await self.user_repo.update_mfa_secret(user_id, mfa_secret, enabled=False)
        
        # Generate QR code URL
        qr_code_url = TOTPManager.generate_qr_code_url(mfa_secret, user.email)
        
        return {
            "secret": mfa_secret,
            "qr_code_url": qr_code_url,
            "backup_codes": await self._generate_backup_codes(user_id)
        }
    
    async def verify_and_enable_mfa(self, user_id: int, totp_code: str) -> bool:
        """Verify TOTP code and enable MFA."""
        user = await self.user_repo.get_by_id(user_id)
        if not user or not user.mfa_secret:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="MFA setup not initiated"
            )
        
        if user.mfa_enabled:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="MFA is already enabled"
            )
        
        # Verify TOTP code
        if not TOTPManager.verify_totp(user.mfa_secret, totp_code):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid verification code"
            )
        
        # Enable MFA
        await self.user_repo.update_mfa_secret(user_id, user.mfa_secret, enabled=True)
        return True
    
    async def disable_mfa(self, user_id: int, totp_code: str) -> bool:
        """Disable MFA for a user."""
        user = await self.user_repo.get_by_id(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        if not user.mfa_enabled:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="MFA is not enabled"
            )
        
        # Verify TOTP code
        if not TOTPManager.verify_totp(user.mfa_secret, totp_code):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid verification code"
            )
        
        # Disable MFA
        await self.user_repo.update_mfa_secret(user_id, None, enabled=False)
        await self.user_repo.clear_backup_codes(user_id)
        return True
    
    async def verify_mfa_code(self, user_id: int, code: str) -> bool:
        """Verify MFA code (TOTP or backup code)."""
        user = await self.user_repo.get_by_id(user_id)
        if not user or not user.mfa_enabled:
            return False
        
        # First try TOTP
        if TOTPManager.verify_totp(user.mfa_secret, code):
            return True
        
        # Then try backup codes
        backup_codes = await self.user_repo.get_backup_codes(user_id)
        for backup_code in backup_codes:
            if not backup_code.used and secrets.compare_digest(backup_code.code, code):
                # Mark backup code as used
                await self.user_repo.use_backup_code(backup_code.id)
                return True
        
        return False
    
    async def _generate_backup_codes(self, user_id: int, count: int = 10) -> list[str]:
        """Generate backup codes for MFA recovery."""
        codes = []
        for _ in range(count):
            code = secrets.token_hex(4).upper()  # 8 character hex codes
            codes.append(code)
        
        # Save to database
        await self.user_repo.save_backup_codes(user_id, codes)
        return codes
    
    async def regenerate_backup_codes(self, user_id: int) -> list[str]:
        """Regenerate backup codes for a user."""
        user = await self.user_repo.get_by_id(user_id)
        if not user or not user.mfa_enabled:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="MFA is not enabled"
            )
        
        # Clear existing backup codes
        await self.user_repo.clear_backup_codes(user_id)
        
        # Generate new ones
        return await self._generate_backup_codes(user_id)
    
    async def get_mfa_status(self, user_id: int) -> Dict[str, Any]:
        """Get MFA status for a user."""
        user = await self.user_repo.get_by_id(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        backup_codes_count = 0
        if user.mfa_enabled:
            backup_codes = await self.user_repo.get_backup_codes(user_id)
            backup_codes_count = len([code for code in backup_codes if not code.used])
        
        return {
            "mfa_enabled": user.mfa_enabled,
            "backup_codes_remaining": backup_codes_count
        }


class MFAMiddleware:
    """Middleware for enforcing MFA when required."""
    
    @staticmethod
    def require_mfa_verification(user_data: Dict[str, Any]) -> bool:
        """Check if user needs MFA verification."""
        # Check if user has MFA enabled
        if not user_data.get("mfa_enabled", False):
            return False
        
        # Check if current session has MFA verified
        return not user_data.get("mfa_verified", False)
    
    @staticmethod
    def create_mfa_verified_token(user_data: Dict[str, Any]) -> str:
        """Create a new JWT token with MFA verification flag."""
        token_data = {
            "sub": str(user_data["id"]),
            "email": user_data["email"],
            "mfa_verified": True
        }
        return create_access_token(token_data)


# Admin functions for MFA management
class MFAAdminService:
    """Admin functions for MFA management."""
    
    def __init__(self, session: AsyncSession):
        self.session = session
        self.user_repo = UserRepository(session)
    
    async def force_disable_mfa(self, user_id: int) -> bool:
        """Force disable MFA for a user (admin only)."""
        user = await self.user_repo.get_by_id(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        if not user.mfa_enabled:
            return False
        
        # Disable MFA without requiring verification
        await self.user_repo.update_mfa_secret(user_id, None, enabled=False)
        await self.user_repo.clear_backup_codes(user_id)
        return True
    
    async def get_mfa_stats(self) -> Dict[str, int]:
        """Get MFA usage statistics."""
        stats = await self.user_repo.get_mfa_stats()
        return {
            "total_users": stats.get("total_users", 0),
            "mfa_enabled_users": stats.get("mfa_enabled_users", 0),
            "mfa_adoption_rate": round(
                (stats.get("mfa_enabled_users", 0) / max(stats.get("total_users", 1), 1)) * 100, 2
            )
        }
EOF
}

# Generate MFA schemas
generate_mfa_schemas() {
    cat > src/schemas/mfa.py << 'EOF'
"""MFA-related Pydantic schemas."""

from pydantic import BaseModel, Field
from typing import List, Optional


class MFAEnableRequest(BaseModel):
    """Request to enable MFA."""
    pass


class MFAEnableResponse(BaseModel):
    """Response when enabling MFA."""
    secret: str = Field(..., description="TOTP secret key")
    qr_code_url: str = Field(..., description="QR code URL for authenticator apps")
    backup_codes: List[str] = Field(..., description="Backup recovery codes")


class MFAVerifyRequest(BaseModel):
    """Request to verify MFA setup."""
    code: str = Field(..., min_length=6, max_length=6, description="6-digit verification code")


class MFAVerifyResponse(BaseModel):
    """Response after MFA verification."""
    success: bool = Field(..., description="Whether verification was successful")
    message: str = Field(..., description="Success or error message")


class MFADisableRequest(BaseModel):
    """Request to disable MFA."""
    code: str = Field(..., min_length=6, max_length=8, description="TOTP code or backup code")


class MFACodeRequest(BaseModel):
    """Request with MFA code for login."""
    code: str = Field(..., min_length=6, max_length=8, description="TOTP code or backup code")


class MFAStatusResponse(BaseModel):
    """MFA status response."""
    mfa_enabled: bool = Field(..., description="Whether MFA is enabled")
    backup_codes_remaining: int = Field(..., description="Number of unused backup codes")


class MFAStatsResponse(BaseModel):
    """MFA statistics response (admin only)."""
    total_users: int = Field(..., description="Total number of users")
    mfa_enabled_users: int = Field(..., description="Number of users with MFA enabled")
    mfa_adoption_rate: float = Field(..., description="MFA adoption rate percentage")


class BackupCodesResponse(BaseModel):
    """Backup codes response."""
    backup_codes: List[str] = Field(..., description="New backup recovery codes")


# Login with MFA
class LoginMFARequest(BaseModel):
    """Login request when MFA is required."""
    email: str = Field(..., description="User email")
    password: str = Field(..., description="User password")
    mfa_code: Optional[str] = Field(None, min_length=6, max_length=8, description="MFA code if required")


class LoginMFAResponse(BaseModel):
    """Login response when MFA is involved."""
    requires_mfa: bool = Field(..., description="Whether MFA verification is required")
    mfa_verified: bool = Field(default=False, description="Whether MFA was verified")
    access_token: Optional[str] = Field(None, description="JWT access token (only if fully authenticated)")
    refresh_token: Optional[str] = Field(None, description="JWT refresh token (only if fully authenticated)")
    token_type: str = Field(default="bearer", description="Token type")
    message: str = Field(..., description="Status message")
EOF
}

# Generate MFA endpoints
generate_mfa_endpoints() {
    cat > src/api/endpoints/mfa.py << 'EOF'
"""MFA endpoints."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.database import get_db
from src.auth.permissions import get_current_active_user, admin_required
from src.auth.mfa import MFAService, MFAAdminService
from src.schemas.mfa import (
    MFAEnableRequest, MFAEnableResponse, MFAVerifyRequest, MFAVerifyResponse,
    MFADisableRequest, MFAStatusResponse, MFAStatsResponse, BackupCodesResponse
)

router = APIRouter()


@router.post("/enable", response_model=MFAEnableResponse)
async def enable_mfa(
    request: MFAEnableRequest,
    current_user: dict = Depends(get_current_active_user),
    session: AsyncSession = Depends(get_db)
):
    """
    Enable MFA for the current user.
    
    Returns TOTP secret, QR code URL, and backup codes.
    User must verify with TOTP code to complete setup.
    """
    mfa_service = MFAService(session)
    result = await mfa_service.enable_mfa(current_user["id"])
    
    return MFAEnableResponse(
        secret=result["secret"],
        qr_code_url=result["qr_code_url"],
        backup_codes=result["backup_codes"]
    )


@router.post("/verify", response_model=MFAVerifyResponse)
async def verify_mfa_setup(
    request: MFAVerifyRequest,
    current_user: dict = Depends(get_current_active_user),
    session: AsyncSession = Depends(get_db)
):
    """
    Verify MFA setup with TOTP code and complete MFA enabling.
    """
    mfa_service = MFAService(session)
    
    try:
        success = await mfa_service.verify_and_enable_mfa(current_user["id"], request.code)
        
        if success:
            return MFAVerifyResponse(
                success=True,
                message="MFA has been successfully enabled"
            )
        else:
            return MFAVerifyResponse(
                success=False,
                message="Invalid verification code"
            )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to verify MFA setup"
        )


@router.post("/disable", response_model=MFAVerifyResponse)
async def disable_mfa(
    request: MFADisableRequest,
    current_user: dict = Depends(get_current_active_user),
    session: AsyncSession = Depends(get_db)
):
    """
    Disable MFA for the current user.
    Requires TOTP code verification.
    """
    mfa_service = MFAService(session)
    
    try:
        success = await mfa_service.disable_mfa(current_user["id"], request.code)
        
        if success:
            return MFAVerifyResponse(
                success=True,
                message="MFA has been successfully disabled"
            )
        else:
            return MFAVerifyResponse(
                success=False,
                message="Invalid verification code"
            )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to disable MFA"
        )


@router.get("/status", response_model=MFAStatusResponse)
async def get_mfa_status(
    current_user: dict = Depends(get_current_active_user),
    session: AsyncSession = Depends(get_db)
):
    """Get MFA status for the current user."""
    mfa_service = MFAService(session)
    status_data = await mfa_service.get_mfa_status(current_user["id"])
    
    return MFAStatusResponse(
        mfa_enabled=status_data["mfa_enabled"],
        backup_codes_remaining=status_data["backup_codes_remaining"]
    )


@router.post("/backup-codes/regenerate", response_model=BackupCodesResponse)
async def regenerate_backup_codes(
    current_user: dict = Depends(get_current_active_user),
    session: AsyncSession = Depends(get_db)
):
    """Regenerate backup codes for the current user."""
    mfa_service = MFAService(session)
    new_codes = await mfa_service.regenerate_backup_codes(current_user["id"])
    
    return BackupCodesResponse(backup_codes=new_codes)


# Admin endpoints
@router.post("/admin/disable/{user_id}", response_model=MFAVerifyResponse)
async def admin_disable_mfa(
    user_id: int,
    current_user: dict = Depends(admin_required),
    session: AsyncSession = Depends(get_db)
):
    """
    Force disable MFA for a user (admin only).
    Does not require MFA code verification.
    """
    admin_service = MFAAdminService(session)
    
    try:
        success = await admin_service.force_disable_mfa(user_id)
        
        if success:
            return MFAVerifyResponse(
                success=True,
                message=f"MFA has been disabled for user {user_id}"
            )
        else:
            return MFAVerifyResponse(
                success=False,
                message=f"User {user_id} does not have MFA enabled"
            )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to disable MFA for user"
        )


@router.get("/admin/stats", response_model=MFAStatsResponse)
async def get_mfa_stats(
    current_user: dict = Depends(admin_required),
    session: AsyncSession = Depends(get_db)
):
    """Get MFA usage statistics (admin only)."""
    admin_service = MFAAdminService(session)
    stats = await admin_service.get_mfa_stats()
    
    return MFAStatsResponse(
        total_users=stats["total_users"],
        mfa_enabled_users=stats["mfa_enabled_users"],
        mfa_adoption_rate=stats["mfa_adoption_rate"]
    )
EOF
}

# Generate UserRepository MFA methods
generate_user_repository_mfa() {
    cat > src/repositories/user_mfa.py << 'EOF'
"""User repository MFA methods."""

from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_
from datetime import datetime

from src.models.user import User, MFABackupCode


class UserMFARepository:
    """User repository with MFA-specific methods."""
    
    def __init__(self, session: AsyncSession):
        self.session = session
    
    async def get_by_id(self, user_id: int) -> Optional[User]:
        """Get user by ID."""
        result = await self.session.execute(
            select(User).where(User.id == user_id)
        )
        return result.scalar_one_or_none()
    
    async def update_mfa_secret(self, user_id: int, secret: Optional[str], enabled: bool = False) -> bool:
        """Update user MFA secret and enabled status."""
        result = await self.session.execute(
            select(User).where(User.id == user_id)
        )
        user = result.scalar_one_or_none()
        
        if not user:
            return False
        
        user.mfa_secret = secret
        user.mfa_enabled = enabled
        
        await self.session.commit()
        return True
    
    async def get_backup_codes(self, user_id: int) -> List[MFABackupCode]:
        """Get all backup codes for a user."""
        result = await self.session.execute(
            select(MFABackupCode).where(
                and_(
                    MFABackupCode.user_id == user_id,
                    MFABackupCode.deleted_at.is_(None)
                )
            )
        )
        return result.scalars().all()
    
    async def save_backup_codes(self, user_id: int, codes: List[str]) -> bool:
        """Save backup codes for a user."""
        backup_codes = []
        for code in codes:
            backup_code = MFABackupCode(
                user_id=user_id,
                code=code,
                used=False
            )
            backup_codes.append(backup_code)
        
        self.session.add_all(backup_codes)
        await self.session.commit()
        return True
    
    async def clear_backup_codes(self, user_id: int) -> bool:
        """Soft delete all backup codes for a user."""
        result = await self.session.execute(
            select(MFABackupCode).where(
                and_(
                    MFABackupCode.user_id == user_id,
                    MFABackupCode.deleted_at.is_(None)
                )
            )
        )
        backup_codes = result.scalars().all()
        
        for backup_code in backup_codes:
            backup_code.deleted_at = datetime.utcnow()
        
        await self.session.commit()
        return True
    
    async def use_backup_code(self, backup_code_id: int) -> bool:
        """Mark a backup code as used."""
        result = await self.session.execute(
            select(MFABackupCode).where(MFABackupCode.id == backup_code_id)
        )
        backup_code = result.scalar_one_or_none()
        
        if not backup_code:
            return False
        
        backup_code.used = True
        backup_code.used_at = datetime.utcnow()
        
        await self.session.commit()
        return True
    
    async def get_mfa_stats(self) -> dict:
        """Get MFA usage statistics."""
        # Total users
        total_users_result = await self.session.execute(
            select(func.count(User.id)).where(
                and_(
                    User.deleted_at.is_(None),
                    User.is_active == True
                )
            )
        )
        total_users = total_users_result.scalar() or 0
        
        # MFA enabled users
        mfa_enabled_result = await self.session.execute(
            select(func.count(User.id)).where(
                and_(
                    User.deleted_at.is_(None),
                    User.is_active == True,
                    User.mfa_enabled == True
                )
            )
        )
        mfa_enabled_users = mfa_enabled_result.scalar() or 0
        
        return {
            "total_users": total_users,
            "mfa_enabled_users": mfa_enabled_users
        }
EOF
}