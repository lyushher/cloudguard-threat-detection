from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_health_check():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_analyze_endpoint():
    event = {
        "service": "auth-service",
        "event_type": "brute_force_attempt",
        "ip": "10.0.0.15",
        "status_code": 401,
        "timestamp": "2026-05-28T12:30:00Z"
    }

    response = client.post("/analyze", json=event)
    data = response.json()

    assert response.status_code == 200
    assert data["incident"] is True
    assert data["severity"] == "high"
    assert data["priority"] == "P1"