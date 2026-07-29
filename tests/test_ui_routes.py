import pytest
from fastapi.testclient import TestClient
from netgrade.main import app

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "netgrade"}


def test_homepage_rendering():
    response = client.get("/")
    assert response.status_code == 200
    assert "Instant, Plain-Language Security Posture Audits" in response.text
    assert "Scan Domain" in response.text


def test_compare_page_rendering():
    response = client.get("/compare")
    assert response.status_code == 200
    assert "Side-by-Side Posture Comparison" in response.text
