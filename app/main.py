import logging
from app.config import API_KEY
from fastapi import FastAPI, HTTPException, Header
from app.detector import analyze_event
from app.models import LogEvent, IncidentStatus, IncidentResponse
from app.storage import (save_incident, get_incident_by_id, filter_incidents, get_incident_stats, update_incident_status, get_incidents_by_status)


logger = logging.getLogger("cloudguard-lite")
logging.basicConfig(level=logging.INFO)


def verify_api_key(x_api_key: str):
    if x_api_key != API_KEY:
        raise HTTPException(
            status_code=401,
            detail="Invalid API Key"
        )


app = FastAPI(
    title="CloudGuard Lite",
    description="Cloud-Native Threat Detection & Incident Management API",
    version="1.0.0"
)


@app.get("/")
def root():
    return {
        "message": "CloudGuard Lite API is running"
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "cloudguard-lite",
        "version": "1.0.0"
    }


@app.post("/analyze", response_model=IncidentResponse)
def analyze(event: LogEvent, x_api_key: str = Header(...)):
    verify_api_key(x_api_key)
    result = analyze_event(event.model_dump())

    if result["incident"]:
        save_incident(result)

        logger.info(
            "Incident created | id=%s service=%s severity=%s priority=%s",
            result["incident_id"],
            result["service"],
            result["severity"],
            result["priority"]
        )

        if result["severity"] == "high":
            logger.warning(
                "High severity incident detected | id=%s source_ip=%s",
                result["incident_id"],
                result["source_ip"]
            )

    return result


@app.get("/incidents")
def list_incidents(
    severity: str | None = None,
    service: str | None = None,
    priority: str | None = None,
    ip: str | None = None
):
    filtered_incidents = filter_incidents(
        severity=severity,
        service=service,
        priority=priority,
        ip=ip
    )

    return {"count": len(filtered_incidents),  "incidents": filtered_incidents}


@app.get("/incidents/{incident_id}")
def get_incident(incident_id: str):
    incident = get_incident_by_id(incident_id)

    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    return incident


@app.get("/stats")
def get_stats():
    return get_incident_stats()


@app.patch("/incidents/{incident_id}/status")
def change_incident_status(
    incident_id: str,
    status: IncidentStatus
):
    updated_incident = update_incident_status(
        incident_id,
        status.value
    )

    if updated_incident is None:
        raise HTTPException(
            status_code=404,
            detail="Incident not found"
        )

    if "error" in updated_incident:
        raise HTTPException(
            status_code=400,
            detail=updated_incident
        )

    return updated_incident


@app.patch("/incidents/{incident_id}/acknowledge")
def acknowledge_incident(incident_id: str):
    updated_incident = update_incident_status(
        incident_id,
        IncidentStatus.ACKNOWLEDGED.value
    )

    if updated_incident is None:
        raise HTTPException(
            status_code=404,
            detail="Incident not found"
        )
    
    if "error" in updated_incident:
        raise HTTPException(
            status_code=400,
            detail=updated_incident
        )

    return updated_incident


@app.patch("/incidents/{incident_id}/resolve")
def resolve_incident(incident_id: str):
    updated_incident = update_incident_status(
        incident_id,
        IncidentStatus.RESOLVED.value
    )

    if updated_incident is None:
        raise HTTPException(
            status_code=404,
            detail="Incident not found"
        )
    

    if "error" in updated_incident:
        raise HTTPException(
            status_code=400,
            detail=updated_incident
        )

    return updated_incident


@app.get("/incidents/open")
def get_open_incidents():
    open_incidents = get_incidents_by_status("OPEN")

    return {
        "count": len(open_incidents),
        "incidents": open_incidents
    }


@app.get("/incidents/resolved")
def get_resolved_incidents():
    resolved_incidents = get_incidents_by_status("RESOLVED")

    return {
        "count": len(resolved_incidents),
        "incidents": resolved_incidents
    }
