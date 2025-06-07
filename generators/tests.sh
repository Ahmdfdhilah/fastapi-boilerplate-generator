#!/bin/bash

# Test file generators - Fixed with Step 1: Password Security

# Generate test configuration
generate_test_config() {
    cat > tests/conftest.py << 'EOF'
"""Test configuration and fixtures."""

import pytest
import asyncio
from typing import AsyncGenerator
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlmodel import SQLModel

from main import app
from src.core.database import get_db
from src.core.config import settings


# Create test database engine
TEST_DATABASE_URL = str(settings.DATABASE_URI) + "_test"
TEST_ASYNC_DATABASE_URL = TEST_DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://")

test_engine = create_async_engine(
    TEST_ASYNC_DATABASE_URL,
    echo=False,
    pool_pre_ping=True
)

TestingSessionLocal = sessionmaker(
    test_engine, 
    class_=AsyncSession, 
    expire_on_commit=False
)


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
async def setup_database():
    """Setup test database."""
    async with test_engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    yield
    async with test_engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.drop_all)


@pytest.fixture
async def db_session(setup_database) -> AsyncGenerator[AsyncSession, None]:
    """Create a test database session."""
    async with TestingSessionLocal() as session:
        yield session


@pytest.fixture
async def client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    """Create a test client."""
    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac
    
    app.dependency_overrides.clear()
EOF
}

# Generate auth tests with Step 1: Password Security
generate_auth_tests() {
    cat > tests/test_auth.py << 'EOF'
"""Test authentication endpoints with password security."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_register_user_valid_password(client: AsyncClient):
    """Test user registration with valid strong password."""
    user_data = {
        "email": "test@example.com",
        "password": "StrongPass123!@#",
        "first_name": "Test",
        "last_name": "User"
    }
    
    response = await client.post("/api/v1/auth/register", json=user_data)
    assert response.status_code == 201
    
    data = response.json()
    assert data["email"] == user_data["email"]
    assert data["first_name"] == user_data["first_name"]
    assert "password_changed_at" in data
    assert data["force_password_change"] == False


@pytest.mark.asyncio
async def test_register_user_weak_password(client: AsyncClient):
    """Test user registration with weak password fails."""
    user_data = {
        "email": "weak@example.com",
        "password": "123456",  # Weak password
        "first_name": "Test",
        "last_name": "User"
    }
    
    response = await client.post("/api/v1/auth/register", json=user_data)
    assert response.status_code == 422
    
    data = response.json()
    assert "Password validation failed" in str(data["detail"])


@pytest.mark.asyncio
async def test_register_user_common_password(client: AsyncClient):
    """Test user registration with common password fails."""
    user_data = {
        "email": "common@example.com",
        "password": "password123",  # Common password with complexity
        "first_name": "Test",
        "last_name": "User"
    }
    
    response = await client.post("/api/v1/auth/register", json=user_data)
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_login_user_success(client: AsyncClient):
    """Test successful user login."""
    # First register a user
    user_data = {
        "email": "login@example.com",
        "password": "SecurePassword123!",
        "first_name": "Test",
        "last_name": "User"
    }
    
    await client.post("/api/v1/auth/register", json=user_data)
    
    # Then try to login
    login_data = {
        "email": "login@example.com",
        "password": "SecurePassword123!"
    }
    
    response = await client.post("/api/v1/auth/login", json=login_data)
    assert response.status_code == 200
    
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"


@pytest.mark.asyncio
async def test_login_invalid_credentials(client: AsyncClient):
    """Test login with invalid credentials."""
    login_data = {
        "email": "nonexistent@example.com",
        "password": "WrongPassword123!"
    }
    
    response = await client.post("/api/v1/auth/login", json=login_data)
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_login_account_lockout(client: AsyncClient):
    """Test account lockout after multiple failed attempts."""
    # First register a user
    user_data = {
        "email": "lockout@example.com",
        "password": "SecurePassword123!",
        "first_name": "Test",
        "last_name": "User"
    }
    
    await client.post("/api/v1/auth/register", json=user_data)
    
    # Attempt login with wrong password 5 times
    login_data = {
        "email": "lockout@example.com",
        "password": "WrongPassword123!"
    }
    
    for i in range(5):
        response = await client.post("/api/v1/auth/login", json=login_data)
        if i < 4:
            assert response.status_code == 401
        else:
            assert response.status_code == 423  # Account locked


@pytest.mark.asyncio
async def test_password_strength_check(client: AsyncClient):
    """Test password strength checking endpoint."""
    # Test weak password
    weak_password = {"password": "123456"}
    response = await client.post("/api/v1/auth/check-password-strength", json=weak_password)
    assert response.status_code == 200
    
    data = response.json()
    assert data["valid"] == False
    assert data["strength_score"] < 50
    assert len(data["errors"]) > 0
    
    # Test strong password
    strong_password = {"password": "VeryStrongPassword123!@#"}
    response = await client.post("/api/v1/auth/check-password-strength", json=strong_password)
    assert response.status_code == 200
    
    data = response.json()
    assert data["valid"] == True
    assert data["strength_score"] >= 80


@pytest.mark.asyncio
async def test_change_password_success(client: AsyncClient):
    """Test successful password change."""
    # Register and login user
    user_data = {
        "email": "changepass@example.com",
        "password": "OldPassword123!",
        "first_name": "Test",
        "last_name": "User"
    }
    
    await client.post("/api/v1/auth/register", json=user_data)
    
    login_response = await client.post("/api/v1/auth/login", json={
        "email": "changepass@example.com",
        "password": "OldPassword123!"
    })
    
    token = login_response.json()["access_token"]
    
    # Change password
    password_change_data = {
        "current_password": "OldPassword123!",
        "new_password": "NewSecurePassword456#"
    }
    
    response = await client.post(
        "/api/v1/auth/change-password",
        json=password_change_data,
        headers={"Authorization": f"Bearer {token}"}
    )
    
    assert response.status_code == 200
    data = response.json()
    assert data["success"] == True


@pytest.mark.asyncio
async def test_change_password_wrong_current(client: AsyncClient):
    """Test password change with wrong current password."""
    # Register and login user
    user_data = {
        "email": "wrongcurrent@example.com",
        "password": "CurrentPassword123!",
        "first_name": "Test",
        "last_name": "User"
    }
    
    await client.post("/api/v1/auth/register", json=user_data)
    
    login_response = await client.post("/api/v1/auth/login", json={
        "email": "wrongcurrent@example.com",
        "password": "CurrentPassword123!"
    })
    
    token = login_response.json()["access_token"]
    
    # Try to change password with wrong current password
    password_change_data = {
        "current_password": "WrongCurrentPassword123!",
        "new_password": "NewSecurePassword456#"
    }
    
    response = await client.post(
        "/api/v1/auth/change-password",
        json=password_change_data,
        headers={"Authorization": f"Bearer {token}"}
    )
    
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_change_password_reuse_prevention(client: AsyncClient):
    """Test prevention of password reuse."""
    # Register and login user
    user_data = {
        "email": "noreuse@example.com",
        "password": "OriginalPassword123!",
        "first_name": "Test",
        "last_name": "User"
    }
    
    await client.post("/api/v1/auth/register", json=user_data)
    
    login_response = await client.post("/api/v1/auth/login", json={
        "email": "noreuse@example.com",
        "password": "OriginalPassword123!"
    })
    
    token = login_response.json()["access_token"]
    
    # Try to change password to the same password
    password_change_data = {
        "current_password": "OriginalPassword123!",
        "new_password": "OriginalPassword123!"
    }
    
    response = await client.post(
        "/api/v1/auth/change-password",
        json=password_change_data,
        headers={"Authorization": f"Bearer {token}"}
    )
    
    assert response.status_code == 400
    data = response.json()
    assert "Cannot reuse" in data["detail"]


@pytest.mark.asyncio
async def test_password_reset_request(client: AsyncClient):
    """Test password reset request."""
    # Register user first
    user_data = {
        "email": "reset@example.com",
        "password": "OriginalPassword123!",
        "first_name": "Test",
        "last_name": "User"
    }
    
    await client.post("/api/v1/auth/register", json=user_data)
    
    # Request password reset
    reset_data = {"email": "reset@example.com"}
    response = await client.post("/api/v1/auth/request-password-reset", json=reset_data)
    
    assert response.status_code == 200
    data = response.json()
    assert data["success"] == True
    assert "token" in data["data"]  # This should be removed in production


@pytest.mark.asyncio
async def test_password_reset_confirm(client: AsyncClient):
    """Test password reset confirmation."""
    # Register user first
    user_data = {
        "email": "resetconfirm@example.com",
        "password": "OriginalPassword123!",
        "first_name": "Test",
        "last_name": "User"
    }
    
    await client.post("/api/v1/auth/register", json=user_data)
    
    # Request password reset
    reset_data = {"email": "resetconfirm@example.com"}
    response = await client.post("/api/v1/auth/request-password-reset", json=reset_data)
    
    token = response.json()["data"]["token"]
    
    # Confirm password reset
    confirm_data = {
        "token": token,
        "new_password": "NewResetPassword456#"
    }
    
    response = await client.post("/api/v1/auth/confirm-password-reset", json=confirm_data)
    
    assert response.status_code == 200
    data = response.json()
    assert data["success"] == True


@pytest.mark.asyncio
async def test_get_current_user(client: AsyncClient):
    """Test getting current user info."""
    # Register and login user
    user_data = {
        "email": "current@example.com",
        "password": "CurrentUserPassword123!",
        "first_name": "Current",
        "last_name": "User"
    }
    
    await client.post("/api/v1/auth/register", json=user_data)
    
    login_response = await client.post("/api/v1/auth/login", json={
        "email": "current@example.com",
        "password": "CurrentUserPassword123!"
    })
    
    token = login_response.json()["access_token"]
    
    # Get current user info
    response = await client.get(
        "/api/v1/users/me",
        headers={"Authorization": f"Bearer {token}"}
    )
    
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == "current@example.com"
    assert data["first_name"] == "Current"


@pytest.mark.asyncio
async def test_unauthorized_access(client: AsyncClient):
    """Test accessing protected endpoint without token."""
    response = await client.get("/api/v1/users/me")
    assert response.status_code == 403
EOF
}

# Generate password validation tests
generate_password_tests() {
    cat > tests/test_password_validation.py << 'EOF'
"""Test password validation functionality."""

import pytest
from src.utils.validators import validate_password_strength, validate_password_history
from src.utils.password import generate_secure_password, get_password_strength_feedback


def test_password_strength_validation():
    """Test password strength validation function."""
    # Test weak passwords
    weak_passwords = [
        "123456",
        "password",
        "abc123",
        "short",
        "ALLUPPERCASE123!",
        "alllowercase123!",
        "NoNumbers!@#",
        "NoSpecialChars123"
    ]
    
    for password in weak_passwords:
        result = validate_password_strength(password)
        assert result["valid"] == False
        assert len(result["errors"]) > 0
    
    # Test strong passwords
    strong_passwords = [
        "VeryStrongPassword123!@#",
        "ComplexP@ssw0rd2024",
        "Secure#Passw0rd$2024",
        "MyStr0ng!P@ssword"
    ]
    
    for password in strong_passwords:
        result = validate_password_strength(password)
        assert result["valid"] == True
        assert len(result["errors"]) == 0
        assert result["strength_score"] >= 80


def test_common_password_detection():
    """Test detection of common passwords."""
    common_passwords = [
        "password",
        "123456",
        "admin",
        "qwerty",
        "welcome"
    ]
    
    for password in common_passwords:
        result = validate_password_strength(password)
        assert result["valid"] == False
        assert any("common" in error.lower() for error in result["errors"])


def test_sequential_character_detection():
    """Test detection of sequential characters."""
    sequential_passwords = [
        "MyPassword123abc",  # Contains 'abc'
        "Pass123word",       # Contains '123'
        "Secure@qwerty",     # Contains 'qwe'
    ]
    
    for password in sequential_passwords:
        result = validate_password_strength(password)
        assert result["valid"] == False
        assert any("sequential" in error.lower() for error in result["errors"])


def test_repeated_character_detection():
    """Test detection of repeated characters."""
    repeated_passwords = [
        "Passwordaaa123!",   # Contains 'aaa'
        "Pass111word@",      # Contains '111'
        "SecurePassword@@@", # Contains '@@@'
    ]
    
    for password in repeated_passwords:
        result = validate_password_strength(password)
        assert result["valid"] == False
        assert any("consecutive" in error.lower() for error in result["errors"])


def test_password_history_validation():
    """Test password history validation."""
    # Simulate password history (hashed passwords)
    from src.auth.jwt import get_password_hash
    
    old_passwords = [
        "OldPassword1!",
        "OldPassword2!",
        "OldPassword3!",
        "OldPassword4!",
        "OldPassword5!"
    ]
    
    password_history = [get_password_hash(pwd) for pwd in old_passwords]
    
    # Test reusing old password (should fail)
    assert validate_password_history("OldPassword1!", password_history) == False
    assert validate_password_history("OldPassword3!", password_history) == False
    
    # Test new password (should pass)
    assert validate_password_history("NewPassword6!", password_history) == True


def test_generate_secure_password():
    """Test secure password generation."""
    password = generate_secure_password()
    
    # Test generated password meets requirements
    result = validate_password_strength(password)
    assert result["valid"] == True
    assert result["strength_score"] >= 80
    
    # Test custom length
    long_password = generate_secure_password(20)
    assert len(long_password) == 20
    
    # Test minimum length enforcement
    short_password = generate_secure_password(8)
    assert len(short_password) == 12  # Should be enforced to minimum


def test_password_strength_feedback():
    """Test password strength feedback generation."""
    weak_password = "123456"
    feedback = get_password_strength_feedback(weak_password)
    
    assert len(feedback) > 0
    assert any("weak" in fb.lower() for fb in feedback)
    
    strong_password = "VeryStrongPassword123!@#"
    feedback = get_password_strength_feedback(strong_password)
    
    assert any("excellent" in fb.lower() or "good" in fb.lower() for fb in feedback)


def test_password_length_limits():
    """Test password length validation."""
    # Too short
    short_result = validate_password_strength("Short1!")
    assert short_result["valid"] == False
    assert any("12 characters" in error for error in short_result["errors"])
    
    # Too long
    long_password = "A" * 130 + "1!"
    long_result = validate_password_strength(long_password)
    assert long_result["valid"] == False
    assert any("128 characters" in error for error in long_result["errors"])
    
    # Just right
    good_password = "GoodPassword123!"
    good_result = validate_password_strength(good_password)
    assert good_result["valid"] == True
EOF
}