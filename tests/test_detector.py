from app.detector import analyze_event


def test_brute_force_event():
    event = {
        "service": "auth-service",
        "event_type": "brute_force_attempt",
        "ip": "10.0.0.15",
        "status_code": 401,
        "timestamp": "2026-05-28T12:30:00Z"
    }

    result = analyze_event(event)

    assert result["incident"] is True
    assert result["severity"] == "high"
    assert result["priority"] == "P1"
    assert result["risk_score"] == 110





def test_normal_event():
    event = {
        "service": "web-service",
        "event_type": "normal_request",
        "ip": "192.168.1.20",
        "status_code": 200,
        "timestamp": "2026-05-28T12:30:00Z"
    }

    result = analyze_event(event)

    assert result["incident"] is False
    assert result["severity"] == "low"
    assert result["priority"] == "P3"
    assert result["risk_score"] == 0