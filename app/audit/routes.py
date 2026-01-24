"""
Enhanced Audit Dashboard with Real-Time Event Streaming
"""

from flask import Blueprint, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import json
from datetime import datetime, timedelta
import threading
import time

from app.logs.zta_event_logger import event_logger, ZTAEvent, Severity
from app.logs.request_tracker import request_tracker

# Create blueprint
audit_bp = Blueprint("audit", __name__, url_prefix="/audit")

# SocketIO instance (will be set from main app)
socketio = None


def init_socketio(sio):
    """Initialize SocketIO for real-time updates"""
    global socketio
    socketio = sio
    event_logger.set_socketio(sio)


@audit_bp.route("/dashboard")
def dashboard():
    """Main audit dashboard"""
    return render_template("audit_dashboard.html")


@audit_bp.route("/events")
def get_events():
    """Get recent events with filters"""
    limit = request.args.get("limit", 100, type=int)
    event_type = request.args.get("type")
    user_id = request.args.get("user_id")
    component = request.args.get("component")

    events = event_logger.get_recent_events(limit)

    # Apply filters
    filtered_events = []
    for event in events:
        if event_type and event.event_type != event_type:
            continue
        if user_id and event.user_id != user_id:
            continue
        if component and event.source_component != component:
            continue

        filtered_events.append(event.to_dict())

    return jsonify({"events": filtered_events, "total": len(filtered_events)})


@audit_bp.route("/statistics")
def get_statistics():
    """Get event statistics"""
    stats = event_logger.get_statistics()

    # Add active requests
    stats["active_requests"] = len(request_tracker.active_requests)

    # Add server status
    stats["server_status"] = {
        "gateway": "running",
        "opa_agent": "running",
        "opa_server": "running",
        "api_server": "running",
    }

    return jsonify(stats)


@audit_bp.route("/trace/<trace_id>")
def get_trace(trace_id):
    """Get all events for a specific trace"""
    events = event_logger.get_events_by_trace(trace_id)

    # Reconstruct flow
    flow = []
    for event in events:
        flow.append(
            {
                "timestamp": event.timestamp,
                "component": event.source_component,
                "action": event.action,
                "status": event.status,
                "details": event.details,
            }
        )

    return jsonify(
        {"trace_id": trace_id, "events": [e.to_dict() for e in events], "flow": flow}
    )


@audit_bp.route("/users/activity")
def get_user_activity():
    """Get user activity overview"""
    limit = request.args.get("limit", 50, type=int)

    # Get recent events with user info
    events = event_logger.get_recent_events(limit)

    # Group by user
    user_activity = {}
    for event in events:
        if event.user_id:
            if event.user_id not in user_activity:
                user_activity[event.user_id] = {
                    "user_id": event.user_id,
                    "username": event.username or "Unknown",
                    "events": [],
                    "last_activity": event.timestamp,
                    "event_count": 0,
                    "failed_attempts": 0,
                }

            user_activity[event.user_id]["events"].append(
                {
                    "timestamp": event.timestamp,
                    "type": event.event_type,
                    "action": event.action,
                    "status": event.status,
                }
            )
            user_activity[event.user_id]["event_count"] += 1

            if event.status == "failure":
                user_activity[event.user_id]["failed_attempts"] += 1

            # Update last activity
            if event.timestamp > user_activity[event.user_id]["last_activity"]:
                user_activity[event.user_id]["last_activity"] = event.timestamp

    # Convert to list and sort by last activity
    activity_list = list(user_activity.values())
    activity_list.sort(key=lambda x: x["last_activity"], reverse=True)

    return jsonify(
        {
            "users": activity_list[:20],  # Top 20 active users
            "total_users": len(activity_list),
        }
    )


@audit_bp.route("/alerts")
def get_alerts():
    """Get security alerts"""
    events = event_logger.get_recent_events(200)

    alerts = []
    for event in events:
        if event.severity in [Severity.HIGH.value, Severity.CRITICAL.value]:
            alerts.append(event.to_dict())

    return jsonify({"alerts": alerts, "total_alerts": len(alerts)})


# SocketIO event handlers
def init_socketio_handlers(sio):
    """Initialize SocketIO event handlers"""

    @sio.on("connect")
    def handle_connect():
        """Handle client connection"""
        print(f"Client connected: {request.sid}")
        emit("connected", {"message": "Connected to ZTA Audit Dashboard"})

    @sio.on("subscribe_events")
    def handle_subscribe(data):
        """Subscribe to real-time events"""
        event_type = data.get("event_type")
        user_id = data.get("user_id")

        # Store subscription
        # In production, use Redis for pub/sub

        emit(
            "subscribed",
            {
                "message": f"Subscribed to events",
                "event_type": event_type,
                "user_id": user_id,
            },
        )

    @sio.on("request_trace")
    def handle_request_trace(data):
        """Request specific trace details"""
        trace_id = data.get("trace_id")
        events = event_logger.get_events_by_trace(trace_id)

        emit(
            "trace_details",
            {"trace_id": trace_id, "events": [e.to_dict() for e in events]},
        )

    @sio.on("disconnect")
    def handle_disconnect():
        """Handle client disconnect"""
        print(f"Client disconnected: {request.sid}")


# Background thread for periodic updates
def start_background_updates(sio):
    """Start background thread for periodic dashboard updates"""

    def send_periodic_updates():
        while True:
            try:
                # Send statistics every 5 seconds
                stats = event_logger.get_statistics()
                sio.emit("statistics_update", stats)

                # Send active requests count
                active_count = len(request_tracker.active_requests)
                sio.emit(
                    "active_requests_update",
                    {
                        "count": active_count,
                        "requests": list(request_tracker.active_requests.keys())[:10],
                    },
                )

            except Exception as e:
                print(f"Error in background updates: {e}")

            time.sleep(5)

    thread = threading.Thread(target=send_periodic_updates, daemon=True)
    thread.start()
