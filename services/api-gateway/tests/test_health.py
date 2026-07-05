import pytest
import httpx


@pytest.mark.asyncio
async def test_health():
    """Gateway health is served by nginx; skip if not running."""
    try:
        async with httpx.AsyncClient(base_url="http://localhost:8080", timeout=2.0) as c:
            r = await c.get("/health")
            if r.status_code == 200:
                assert r.json()["status"] == "healthy"
    except httpx.ConnectError:
        pytest.skip("api-gateway not running")
