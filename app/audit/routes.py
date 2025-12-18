"""
Audit Dashboard API for Real-time ZTA Event Monitoring
"""

from flask import Blueprint, jsonify, render_template
from app.logs.zta_event_logger import zta_logger

audit_bp = Blueprint("audit", __name__, url_prefix="/api/audit")


@audit_bp.route("/dashboard")
def audit_dashboard():
    """Serve the audit dashboard HTML"""
    return render_template("audit.html")


@audit_bp.route("/events/recent")
def get_recent_events():
    """Get recent ZTA events for real-time display"""
    events = zta_logger.get_recent_events(limit=100)
    return jsonify({"events": events})


@audit_bp.route("/events/request/<request_id>")
def get_request_events(request_id):
    """Get all events for a specific request ID"""
    events = zta_logger.get_events_by_request(request_id)

    # Reconstruct ZTA flow
    zta_flow = {
        "request_id": request_id,
        "steps": [],
        "authentication": None,
        "opa_check": None,
        "final_decision": None,
    }

    for event in events:
        if "JWT" in event["event_type"] or "MTLS" in event["event_type"]:
            zta_flow["authentication"] = event
        elif "OPA" in event["event_type"]:
            zta_flow["opa_check"] = event
        elif "ACCESS_" in event["event_type"]:
            zta_flow["final_decision"] = event

        zta_flow["steps"].append(
            {
                "type": event["event_type"],
                "timestamp": event["timestamp"],
                "details": event["details"],
            }
        )

    return jsonify({"events": events, "zta_flow": zta_flow})


@audit_bp.route("/statistics")
def get_statistics():
    """Get ZTA statistics for dashboard"""
    events = zta_logger.get_recent_events(limit=1000)

    stats = {
        "total_events": len(events),
        "by_type": {},
        "by_outcome": {"granted": 0, "denied": 0},
        "by_auth_method": {"jwt": 0, "mtls": 0, "hybrid": 0},
        "opa_decisions": {"allowed": 0, "denied": 0},
    }

    for event in events:
        # Count by event type
        stats["by_type"][event["event_type"]] = (
            stats["by_type"].get(event["event_type"], 0) + 1
        )

        # Count access decisions
        if "ACCESS_GRANTED" in event["event_type"]:
            stats["by_outcome"]["granted"] += 1
        elif "ACCESS_DENIED" in event["event_type"]:
            stats["by_outcome"]["denied"] += 1

        # Count auth methods
        auth_method = event.get("details", {}).get("auth_method")
        if auth_method:
            stats["by_auth_method"][auth_method] = (
                stats["by_auth_method"].get(auth_method, 0) + 1
            )

        # Count OPA decisions
        if "OPA_RESPONSE" in event["event_type"]:
            decision = event.get("details", {}).get("decision")
            if decision:
                stats["opa_decisions"]["allowed" if decision else "denied"] += 1

    return jsonify(stats)
