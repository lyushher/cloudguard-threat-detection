from enum import Enum
from pydantic import BaseModel, Field
from typing import Optional


class EventType(str, Enum):
    LOGIN_FAILED = "login_failed"
    BRUTE_FORCE_ATTEMPT = "brute_force_attempt"
    SUSPICIOUS_IP = "suspicious_ip"
    REPEATED_REQUESTS = "repeated_requests"


class LogEvent(BaseModel):
    service: str
    event_type: EventType
    ip: str
    status_code: int = Field(..., ge=100, le=599)
    timestamp: str


class IncidentStatus(str, Enum):
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"


class HistoryItem(BaseModel):
    action: str
    timestamp: str


class IncidentResponse(BaseModel):
    incident_id: Optional[str]
    incident: bool
    status: str
    service: str
    source_ip: str
    severity: str
    priority: str
    risk_score: int
    timestamp: str
    reasons: list[str]
    recommended_action: str
    history: list[HistoryItem]