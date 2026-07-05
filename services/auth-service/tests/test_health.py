import pytest


@pytest.mark.asyncio
async def test_health(client):
    response = await client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "VulnShield Auth Service"


@pytest.mark.asyncio
async def test_openapi(client):
    response = await client.get("/openapi.json")
    assert response.status_code == 200
    assert "VulnShield Auth Service" in response.json()["info"]["title"]
