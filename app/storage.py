from datetime import datetime, timezone


incidents = []


def save_incident(incident):
    incidents.append(incident)
    return incident


def get_all_incidents():
    return incidents


def get_incident_by_id(incident_id):
    for incident in incidents:
        if incident["incident_id"] == incident_id:
            return incident

    return None


def filter_incidents(severity=None, service=None, priority=None, ip=None):
    filtered = incidents

    if severity:
        filtered = [
            incident for incident in filtered
            if incident["severity"] == severity
        ]

    if service:
        filtered = [
            incident for incident in filtered
            if incident["service"] == service
        ]

    if priority:
        filtered = [
            incident for incident in filtered
            if incident["priority"] == priority
        ]

    if ip:
        filtered = [
            incident for incident in filtered
            if incident["source_ip"] == ip
        ]

    return filtered


def get_incident_stats():
    total = len(incidents)

    severity_counts = {
        "high": 0,
        "medium": 0,
        "low": 0
    }

    service_counts = {}
    total_risk_score = 0

    for incident in incidents:
        severity = incident["severity"]
        service = incident["service"]
        risk_score = incident["risk_score"]

        severity_counts[severity] += 1
        service_counts[service] = service_counts.get(service, 0) + 1
        total_risk_score += risk_score

    average_risk_score = total_risk_score / total if total > 0 else 0
    most_affected_service = max(service_counts, key=service_counts.get) if service_counts else None

    return {
        "total_incidents": total,
        "severity_counts": severity_counts,
        "average_risk_score": average_risk_score,
        "most_affected_service": most_affected_service
    }


def is_valid_status_transition(current_status, new_status):
    allowed_transitions = {
        "OPEN": ["ACKNOWLEDGED", "RESOLVED"],
        "ACKNOWLEDGED": ["RESOLVED"],
        "RESOLVED": []
    }

    return new_status in allowed_transitions.get(current_status, [])


def update_incident_status(incident_id, new_status):
    for incident in incidents:
        if incident["incident_id"] == incident_id:
            current_status = incident["status"]

            if not is_valid_status_transition(current_status, new_status):
                return {
                    "error": "Invalid status transition",
                    "current_status": current_status,
                    "requested_status": new_status
                }

            incident["status"] = new_status

            incident["history"].append(
                {
                    "action": new_status,
                    "timestamp": datetime.now(
                        timezone.utc
                    ).isoformat()
                }
            )

            return incident

    return None


def get_incidents_by_status(status):
    return [
        incident
        for incident in incidents
        if incident["status"] == status
    ]
