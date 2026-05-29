from datetime import datetime, timezone

import boto3
from app.config import AWS_REGION, DYNAMODB_TABLE_NAME


dynamodb = boto3.resource(
    "dynamodb",
    region_name=AWS_REGION
)

table = dynamodb.Table(DYNAMODB_TABLE_NAME)


def save_incident(incident):
    table.put_item(Item=incident)
    return incident


def get_all_incidents():
    response = table.scan()
    return response.get("Items", [])


def get_incident_by_id(incident_id):
    response = table.get_item(
        Key={
            "incident_id": incident_id
        }
    )

    return response.get("Item")


def filter_incidents(severity=None, service=None, priority=None, ip=None):
    incidents = get_all_incidents()

    if severity:
        incidents = [
            incident for incident in incidents
            if incident["severity"] == severity
        ]

    if service:
        incidents = [
            incident for incident in incidents
            if incident["service"] == service
        ]

    if priority:
        incidents = [
            incident for incident in incidents
            if incident["priority"] == priority
        ]

    if ip:
        incidents = [
            incident for incident in incidents
            if incident["source_ip"] == ip
        ]

    return incidents


def get_incident_stats():
    incidents = get_all_incidents()
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
        risk_score = int(incident["risk_score"])

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
    incident = get_incident_by_id(incident_id)

    if incident is None:
        return None

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
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    )

    table.put_item(Item=incident)

    return incident


def get_incidents_by_status(status):
    incidents = get_all_incidents()

    return [
        incident
        for incident in incidents
        if incident["status"] == status
    ]