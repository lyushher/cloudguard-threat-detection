from uuid import uuid4
from datetime import datetime, timezone


def calculate_severity(risk_score):
    if risk_score >= 80:
        return "high"
    if risk_score >= 40:
        return "medium"
    return "low"

def calculate_priority(severity):
    if severity == "high":
        return "P1"
    if severity == "medium":
        return "P2"
    return "P3"

def get_recommended_action(severity):
    if severity == "high":
        return "Immediately investigate the source IP and temporarily block suspicious traffic."
    if severity == "medium":
        return "Review recent authentication attempts and monitor the source IP."
    return "No immediate action required. Continue monitoring."


def analyze_event(event):
    risk_score = 0
    reasons = []

    event_type = event.get("event_type")
    status_code = event.get("status_code")
    ip = event.get("ip")

    if event_type == "login_failed":
        risk_score += 40
        reasons.append("Failed authentication attempt detected")

    if event_type == "brute_force_attempt":
        risk_score += 80
        reasons.append("Possible brute force attack detected")

    if event_type == "suspicious_ip":
        risk_score += 50
        reasons.append("Suspicious IP activity detected")

    if event_type == "repeated_requests":
        risk_score += 30
        reasons.append("Repeated request pattern detected")

    if status_code == 401:
        risk_score += 20
        reasons.append("Unauthorized status code detected")

    if status_code >= 500:
        risk_score += 20
        reasons.append("Server error detected")

    if ip and ip.startswith("10."):
        risk_score += 10
        reasons.append("Internal network IP detected")

    severity = calculate_severity(risk_score)
    incident = risk_score >= 40
    priority = calculate_priority(severity)

    return {
        "incident_id": str(uuid4()) if incident else None,
        "incident": incident,
        "service": event.get("service"),
        "source_ip": ip,
        "severity": severity,
        "priority": priority,
        "risk_score": risk_score,
        "timestamp": event.get("timestamp"),
        "status": "OPEN",
        "reasons": reasons if reasons else ["No suspicious activity detected"],
        "recommended_action": get_recommended_action(severity),
        "history": [
            {
            "action": "CREATED",
            "timestamp": datetime.now(timezone.utc).isoformat()
            }
        ]
    }