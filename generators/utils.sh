#!/bin/bash

# Utility file generators - Step 1: Password Security Standards

# Generate logging utilities
generate_logging_utils() {
    cat > src/utils/logging.py << 'EOF'
"""Logging configuration utilities."""

import logging
import logging.handlers
import json
import os
from datetime import datetime

from src.core.config import settings


class JSONFormatter(logging.Formatter):
    """JSON formatter for structured logging."""
    
    def __init__(self, service_name):
        super().__init__()
        self.service_name = service_name

    def format(self, record):
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "service": self.service_name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        
        if record.exc_info:
            log_entry['exc_info'] = self.formatException(record.exc_info)
        if record.stack_info:
            log_entry['stack_info'] = self.formatStack(record.stack_info)
            
        return json.dumps(log_entry)


def setup_logging():
    """Setup application logging."""
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    formatter = JSONFormatter(settings.SERVICE_NAME)

    # Create logs directory
    try:
        os.makedirs(settings.LOG_DIRECTORY, exist_ok=True)
    except OSError as e:
        print(f"Error creating log directory: {e}")
        # Fallback to console only
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        return

    # File handler with rotation
    log_file_path = os.path.join(settings.LOG_DIRECTORY, f'{settings.SERVICE_NAME}.log')
    
    try:
        file_handler = logging.handlers.RotatingFileHandler(
            log_file_path,
            maxBytes=settings.LOG_MAX_BYTES,
            backupCount=settings.LOG_BACKUP_COUNT
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except Exception as e:
        print(f"Error setting up file handler: {e}")

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
EOF
}

# Generate validators with STEP 1: Password Security Standards
generate_validators() {
    cat > src/utils/validators.py << 'EOF'
"""Common validation utilities with password security standards."""

import re
from typing import List, Dict, Any
from fastapi import UploadFile, HTTPException, status


# Common weak passwords to blacklist (OWASP recommendations)
COMMON_PASSWORDS = {
    "password", "123456", "123456789", "12345678", "12345", "1234567", "1234567890",
    "qwerty", "abc123", "111111", "123123", "admin", "letmein", "welcome", "monkey",
    "login", "admin123", "qwerty123", "password123", "123abc", "master", "hello",
    "welcome123", "administrator", "root", "toor", "pass", "test", "guest", "info",
    "user", "default", "changeme", "password1", "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "superman", "batman", "dragon", "ninja", "mustang", "access", "shadow", "football",
    "baseball", "basketball", "jordan", "harley", "ranger", "buster", "soccer", "hockey"
}


def validate_email(email: str) -> bool:
    """Validate email format."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def validate_password_strength(password: str) -> Dict[str, Any]:
    """
    Validate password strength according to OWASP standards.
    
    Requirements:
    - Minimum 12 characters
    - At least one lowercase letter
    - At least one uppercase letter  
    - At least one digit
    - At least one special character
    - Not in common password blacklist
    - No sequential characters
    - No repeated characters
    
    Returns:
        Dict with 'valid' (bool) and 'errors' (list) keys
    """
    errors = []
    
    # Basic length checks
    if len(password) < 12:
        errors.append("Password must be at least 12 characters long")
    
    if len(password) > 128:
        errors.append("Password must not exceed 128 characters")
    
    # Character variety requirements
    if not re.search(r'[a-z]', password):
        errors.append("Password must contain at least one lowercase letter")
    
    if not re.search(r'[A-Z]', password):
        errors.append("Password must contain at least one uppercase letter")
    
    if not re.search(r'\d', password):
        errors.append("Password must contain at least one digit")
    
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>?/~`]', password):
        errors.append("Password must contain at least one special character")
    
    # Check against common password blacklist
    if password.lower() in COMMON_PASSWORDS:
        errors.append("Password is too common and easily guessable")
    
    # Check for sequential characters (123, abc, qwe, etc.)
    if _has_sequential_chars(password.lower()):
        errors.append("Password cannot contain sequential characters (like 123, abc)")
    
    # Check for repeated characters (aaa, 111, etc.)
    if _has_repeated_chars(password):
        errors.append("Password cannot contain more than 2 consecutive identical characters")
    
    # Check for common substitution patterns (@ for a, 3 for e, etc.)
    if _has_common_substitutions(password.lower()):
        errors.append("Password uses common character substitutions that are easily guessable")
    
    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "strength_score": _calculate_strength_score(password)
    }


def _has_sequential_chars(password: str) -> bool:
    """Check for sequential characters in password."""
    sequences = [
        "abcdefghijklmnopqrstuvwxyz",
        "qwertyuiopasdfghjklzxcvbnm",  # QWERTY keyboard layout
        "0123456789"
    ]
    
    for sequence in sequences:
        for i in range(len(sequence) - 2):
            if sequence[i:i+3] in password:
                return True
    
    return False


def _has_repeated_chars(password: str) -> bool:
    """Check for more than 2 consecutive repeated characters."""
    for i in range(len(password) - 2):
        if password[i] == password[i+1] == password[i+2]:
            return True
    return False


def _has_common_substitutions(password: str) -> bool:
    """Check for common character substitutions."""
    substitutions = {
        '@': 'a', '3': 'e', '1': 'i', '0': 'o', '5': 's', 
        '7': 't', '4': 'a', '8': 'b', '6': 'g', '2': 'z'
    }
    
    # Convert substitutions back to check if it becomes a common password
    normalized = password
    for sub, char in substitutions.items():
        normalized = normalized.replace(sub, char)
    
    if normalized in COMMON_PASSWORDS:
        return True
    
    return False


def _calculate_strength_score(password: str) -> int:
    """Calculate password strength score (0-100)."""
    score = 0
    
    # Length scoring
    if len(password) >= 12:
        score += 25
    elif len(password) >= 8:
        score += 10
    
    # Character variety scoring
    if re.search(r'[a-z]', password):
        score += 15
    if re.search(r'[A-Z]', password):
        score += 15
    if re.search(r'\d', password):
        score += 15
    if re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>?/~`]', password):
        score += 20
    
    # Bonus for longer passwords
    if len(password) >= 16:
        score += 10
    
    return min(score, 100)


def validate_password_history(new_password: str, password_history: List[str]) -> bool:
    """
    Check if new password is different from recent passwords.
    OWASP recommends not reusing last 5 passwords.
    """
    from src.auth.jwt import verify_password
    
    for old_password_hash in password_history[-5:]:  # Check last 5 passwords
        if verify_password(new_password, old_password_hash):
            return False
    
    return True


def validate_upload_file(file: UploadFile, allowed_types: List[str] = None, max_size: int = None) -> None:
    """Validate uploaded file."""
    if max_size is None:
        max_size = 10 * 1024 * 1024  # 10MB default
    
    # Check file size
    if hasattr(file.file, 'seek'):
        file.file.seek(0, 2)  # Seek to end
        file_size = file.file.tell()
        file.file.seek(0)  # Reset position
        
        if file_size > max_size:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"File size exceeds maximum allowed size ({max_size / (1024*1024):.1f}MB)"
            )
    
    # Check file type
    if allowed_types and file.content_type not in allowed_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File type not allowed. Allowed types: {', '.join(allowed_types)}"
        )


def sanitize_filename(filename: str, max_length: int = 50) -> str:
    """Sanitize filename for safe storage."""
    # Remove or replace dangerous characters
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    
    # Limit length
    if len(filename) > max_length:
        name, ext = filename.rsplit('.', 1) if '.' in filename else (filename, '')
        max_name_length = max_length - len(ext) - 1 if ext else max_length
        filename = name[:max_name_length] + ('.' + ext if ext else '')
    
    return filename
EOF
}

# Generate password utilities
generate_password_utils() {
    cat > src/utils/password.py << 'EOF'
"""Password security utilities for STEP 1 implementation."""

import secrets
import string
from typing import List
from datetime import datetime, timedelta


def generate_secure_password(length: int = 16) -> str:
    """Generate a cryptographically secure random password."""
    if length < 12:
        length = 12
    
    # Ensure we have at least one character from each required category
    lowercase = secrets.choice(string.ascii_lowercase)
    uppercase = secrets.choice(string.ascii_uppercase)
    digit = secrets.choice(string.digits)
    special = secrets.choice("!@#$%^&*()_+-=[]{}|;:,.<>?")
    
    # Generate remaining characters
    remaining_length = length - 4
    all_chars = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"
    remaining = ''.join(secrets.choice(all_chars) for _ in range(remaining_length))
    
    # Combine and shuffle
    password_list = list(lowercase + uppercase + digit + special + remaining)
    secrets.SystemRandom().shuffle(password_list)
    
    return ''.join(password_list)


def generate_password_reset_token() -> str:
    """Generate secure token for password reset."""
    return secrets.token_urlsafe(32)


def is_password_expired(last_changed: datetime, max_age_days: int = 90) -> bool:
    """Check if password has expired based on age policy."""
    if not last_changed:
        return True
    
    expiry_date = last_changed + timedelta(days=max_age_days)
    return datetime.utcnow() > expiry_date


def get_password_strength_feedback(password: str) -> List[str]:
    """Get user-friendly feedback for password improvement."""
    from src.utils.validators import validate_password_strength
    
    result = validate_password_strength(password)
    feedback = []
    
    if not result["valid"]:
        feedback.extend(result["errors"])
    
    # Add positive feedback based on strength score
    score = result["strength_score"]
    if score >= 80:
        feedback.append("Excellent password strength!")
    elif score >= 60:
        feedback.append("Good password strength.")
    elif score >= 40:
        feedback.append("Fair password strength. Consider making it stronger.")
    else:
        feedback.append("Weak password. Please choose a stronger password.")
    
    return feedback
EOF
}