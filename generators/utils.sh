#!/bin/bash

# Utility file generators

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

# Generate validators
generate_validators() {
    cat > src/utils/validators.py << 'EOF'
"""Common validation utilities."""

import re
from typing import List
from fastapi import UploadFile, HTTPException, status


def validate_email(email: str) -> bool:
    """Validate email format."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def validate_password(password: str) -> bool:
    """Validate password strength."""
    # At least 8 characters, 1 uppercase, 1 lowercase, 1 digit
    if len(password) < 8:
        return False
    
    if not re.search(r'[A-Z]', password):
        return False
    
    if not re.search(r'[a-z]', password):
        return False
    
    if not re.search(r'\d', password):
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
    # Remove unsafe characters
    filename = re.sub(r'[^\w\-_\.]', '_', filename)
    
    # Limit length
    if len(filename) > max_length:
        name, ext = filename.rsplit('.', 1) if '.' in filename else (filename, '')
        max_name_length = max_length - len(ext) - 1 if ext else max_length
        filename = f"{name[:max_name_length]}.{ext}" if ext else name[:max_length]
    
    return filename
EOF

    # Create utils __init__.py
    cat > src/utils/__init__.py << 'EOF'
"""Utils package."""

from .logging import setup_logging
from .validators import validate_email, validate_password, validate_upload_file, sanitize_filename

__all__ = [
    "setup_logging",
    "validate_email",
    "validate_password",
    "validate_upload_file",
    "sanitize_filename"
]
EOF
}