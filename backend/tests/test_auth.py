# backend/tests/test_auth.py
"""
Unit and integration tests for Authentication API endpoints.
"""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_health_check(client: AsyncClient) -> None:
    """Test health check endpoint."""
    response = await client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "app_name" in data


@pytest.mark.asyncio
async def test_register_user_success(client: AsyncClient) -> None:
    """Test successful user registration."""
    payload = {
        "email": "testuser@example.com",
        "password": "SecurePassword123!",
        "full_name": "Test User",
    }
    response = await client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["email"] == "testuser@example.com"
    assert data["full_name"] == "Test User"
    assert data["is_active"] is True
    assert "id" in data
    assert "password" not in data
    assert "hashed_password" not in data


@pytest.mark.asyncio
async def test_register_duplicate_email(client: AsyncClient) -> None:
    """Test registering with an existing email returns 400 error."""
    payload = {
        "email": "duplicate@example.com",
        "password": "SecurePassword123!",
        "full_name": "Original User",
    }
    res1 = await client.post("/api/v1/auth/register", json=payload)
    assert res1.status_code == 201

    res2 = await client.post("/api/v1/auth/register", json=payload)
    assert res2.status_code == 400
    assert "already exists" in res2.json()["detail"]


@pytest.mark.asyncio
async def test_register_short_password(client: AsyncClient) -> None:
    """Test registering with a short password fails validation."""
    payload = {
        "email": "shortpw@example.com",
        "password": "short",
        "full_name": "Short Password User",
    }
    response = await client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_login_success(client: AsyncClient) -> None:
    """Test login with valid credentials returns access token."""
    reg_payload = {
        "email": "loginuser@example.com",
        "password": "SecurePassword123!",
        "full_name": "Login User",
    }
    await client.post("/api/v1/auth/register", json=reg_payload)

    login_payload = {
        "email": "loginuser@example.com",
        "password": "SecurePassword123!",
    }
    response = await client.post("/api/v1/auth/login", json=login_payload)
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"


@pytest.mark.asyncio
async def test_login_invalid_password(client: AsyncClient) -> None:
    """Test login with invalid password returns 401 error."""
    reg_payload = {
        "email": "wrongpw@example.com",
        "password": "SecurePassword123!",
    }
    await client.post("/api/v1/auth/register", json=reg_payload)

    login_payload = {
        "email": "wrongpw@example.com",
        "password": "WrongPassword123!",
    }
    response = await client.post("/api/v1/auth/login", json=login_payload)
    assert response.status_code == 401
    assert response.json()["detail"] == "Incorrect email or password"


@pytest.mark.asyncio
async def test_get_me_success(client: AsyncClient) -> None:
    """Test fetching profile for authenticated user."""
    reg_payload = {
        "email": "meuser@example.com",
        "password": "SecurePassword123!",
        "full_name": "Me User",
    }
    await client.post("/api/v1/auth/register", json=reg_payload)

    login_res = await client.post(
        "/api/v1/auth/login",
        json={"email": "meuser@example.com", "password": "SecurePassword123!"},
    )
    token = login_res.json()["access_token"]

    headers = {"Authorization": f"Bearer {token}"}
    response = await client.get("/api/v1/auth/me", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == "meuser@example.com"
    assert data["full_name"] == "Me User"


@pytest.mark.asyncio
async def test_get_me_invalid_token(client: AsyncClient) -> None:
    """Test fetching profile with invalid token returns 401."""
    headers = {"Authorization": "Bearer invalid.jwt.token"}
    response = await client.get("/api/v1/auth/me", headers=headers)
    assert response.status_code == 401
