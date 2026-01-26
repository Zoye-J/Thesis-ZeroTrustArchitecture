from flask import Blueprint, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import json
from datetime import datetime, timedelta
import threading
import time
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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


def get_redis_status():
    """Check Redis connection status"""
    try:
        from app.logs.zta_event_logger import event_logger

        if event_logger.redis_client:
            event_logger.redis_client.ping()
            return "connected"
        return "not_configured"
    except Exception as e:
        return f"error: {str(e)}"


@audit_bp.route("/dashboard")
def dashboard():
    """Main audit dashboard"""
    return render_template("audit_dashboard.html")


@audit_bp.route("/events")
def get_events():
    """Get recent events WITH FILTERING"""
    try:
        limit = request.args.get("limit", 50, type=int)
        event_type = request.args.get("type")
        component = request.args.get("component")

        all_events = []

        # Get events from Redis
        if event_logger.redis_client:
            from datetime import datetime

            redis_key = f"zta_events:{datetime.utcnow().strftime('%Y%m%d')}"
            events_json = event_logger.redis_client.lrange(
                redis_key, 0, limit * 2
            )  # Get extra for filtering

            for event_json in events_json:
                try:
                    event = json.loads(event_json)

                    # Apply filters
                    if event_type and event.get("event_type") != event_type:
                        continue
                    if component and event.get("source_component") != component:
                        continue

                    all_events.append(event)

                    # Stop when we have enough filtered events
                    if len(all_events) >= limit:
                        break

                except:
                    continue

        return jsonify(
            {
                "success": True,
                "events": all_events[:limit],  # Return only up to limit
                "total": len(all_events),
            }
        )

    except Exception as e:
        print(f"Events error: {e}")
        return jsonify({"success": False, "events": [], "total": 0})


@audit_bp.route("/statistics")
def get_statistics():
    """Get SIMPLE event statistics"""
    try:
        # Get server status (this works)
        server_status = check_real_server_status()

        # SIMPLE: Just count Redis events
        total_events = 0
        active_users_count = 0

        if event_logger.redis_client:
            try:
                from datetime import datetime

                redis_key = f"zta_events:{datetime.utcnow().strftime('%Y%m%d')}"
                events_json = event_logger.redis_client.lrange(redis_key, 0, -1)
                total_events = len(events_json)

                # Count unique users (SIMPLE - just count any user_id)
                user_ids = set()
                for event_json in events_json[:100]:  # Check first 100 events only
                    try:
                        event = json.loads(event_json)
                        user_id = event.get("user_id")
                        if user_id:
                            user_ids.add(str(user_id))
                    except:
                        continue

                active_users_count = len(user_ids)

            except Exception as e:
                print(f"Simple Redis count error: {e}")
                total_events = 0
                active_users_count = 0

        # Return SIMPLE stats
        return jsonify(
            {
                "success": True,
                "total_events": total_events,
                "active_users": active_users_count,
                "active_requests": 0,  # We'll skip this for now
                "security_alerts": 0,  # We'll skip this for now
                "server_status": server_status,
            }
        )

    except Exception as e:
        print(f"Simple statistics error: {e}")
        return jsonify(
            {
                "success": False,
                "total_events": 0,
                "active_users": 0,
                "active_requests": 0,
                "security_alerts": 0,
                "server_status": check_real_server_status(),
            }
        )


def check_real_server_status():
    """Simple port checking instead of HTTP requests"""
    import socket

    servers = {
        "gateway": ("localhost", 5000),
        "api_server": ("localhost", 5001),
        "opa_agent": ("localhost", 8282),
        "opa_server": ("localhost", 8181),
    }

    status = {}

    for server_name, (host, port) in servers.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((host, port))
            sock.close()

            if result == 0:
                status[server_name] = "running"
            else:
                status[server_name] = "down"
        except:
            status[server_name] = "error"

    return status


# ========== TRACE ENDPOINTS ==========

@audit_bp.route("/trace/<trace_id>")
def get_trace_api(trace_id):
    """API endpoint to get trace details (for manual testing)"""
    try:
        events = []

        # Search in Redis
        if event_logger.redis_client:
            from datetime import datetime

            redis_key = f"zta_events:{datetime.utcnow().strftime('%Y%m%d')}"
            all_events_json = event_logger.redis_client.lrange(redis_key, 0, -1)

            for event_json in all_events_json:
                try:
                    event = json.loads(event_json)
                    if event.get("trace_id") == trace_id:
                        events.append(event)
                except:
                    continue

        if not events:
            return jsonify(
                {
                    "trace_id": trace_id,
                    "events": [],
                    "message": "No events found",
                    "count": 0,
                }
            )

        # Sort by timestamp
        events.sort(key=lambda x: x.get("timestamp", ""))

        # Create flow visualization
        flow = []
        for event in events:
            flow.append(
                {
                    "timestamp": event.get("timestamp"),
                    "component": event.get("source_component"),
                    "event_type": event.get("event_type"),
                    "action": event.get("action"),
                    "status": event.get("status"),
                }
            )

        return jsonify(
            {
                "trace_id": trace_id,
                "events": events,
                "flow": flow,
                "count": len(events),
                "components": list(
                    set([e.get("source_component") for e in events])
                ),
            }
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ========== OTHER ENDPOINTS ==========

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


# ========== SOCKETIO HANDLERS ==========

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
        """Request specific trace details - FIXED VERSION"""
        trace_id = data.get("trace_id")

        if not trace_id:
            emit("trace_details", {"error": "No trace_id provided"})
            return

        print(f"Looking for trace: {trace_id}")

        try:
            events = []

            # Search in Redis first
            if event_logger.redis_client:
                from datetime import datetime

                # Check today's events
                redis_key = f"zta_events:{datetime.utcnow().strftime('%Y%m%d')}"
                all_events_json = event_logger.redis_client.lrange(redis_key, 0, -1)

                for event_json in all_events_json:
                    try:
                        event = json.loads(event_json)
                        if event.get("trace_id") == trace_id:
                            events.append(event)
                    except:
                        continue

            # If not found in Redis, check memory buffer
            if not events:
                memory_events = event_logger.get_events_by_trace(trace_id)
                events = [e.to_dict() for e in memory_events]

            if not events:
                emit(
                    "trace_details",
                    {
                        "trace_id": trace_id,
                        "events": [],
                        "message": "No events found for this trace ID",
                        "found": False,
                    },
                )
                return

            # Sort events by timestamp
            events.sort(key=lambda x: x.get("timestamp", ""))

            emit(
                "trace_details",
                {
                    "trace_id": trace_id,
                    "events": events,
                    "found": True,
                    "count": len(events),
                },
            )

        except Exception as e:
            print(f"Error finding trace: {e}")
            emit("trace_details", {"error": str(e), "trace_id": trace_id})

    @sio.on("disconnect")
    def handle_disconnect():
        """Handle client disconnect"""
        print(f"Client disconnected: {request.sid}")


# ========== BACKGROUND UPDATES ==========

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


# ========== UTILITY ENDPOINTS ==========

def get_redis_status():
    """Check Redis connection status"""
    try:
        from app.logs.zta_event_logger import event_logger

        if event_logger.redis_client:
            event_logger.redis_client.ping()
            return "connected"
    except:
        pass
    return "disconnected"


@audit_bp.route("/health")
def dashboard_health():
    """Dashboard health endpoint"""
    return jsonify(
        {
            "status": "healthy",
            "redis": get_redis_status(),
            "event_count": len(event_logger.events_buffer),
            "timestamp": datetime.utcnow().isoformat(),
        }
    )


@audit_bp.route("/events/recent")
def get_recent_events_api():
    """API endpoint for recent events (for dashboard AJAX calls) - FIXED"""
    try:
        limit = request.args.get("limit", 50, type=int)

        events = []
        # Try Redis first
        if event_logger.redis_client:
            from datetime import datetime

            redis_key = f"zta_events:{datetime.utcnow().strftime('%Y%m%d')}"
            events_json = event_logger.redis_client.lrange(redis_key, 0, limit - 1)

            for event_json in events_json:
                try:
                    event_dict = json.loads(event_json)
                    events.append(event_dict)
                except:
                    continue
        else:
            # Fallback to memory
            events_data = event_logger.get_recent_events(limit)
            events = [event.to_dict() for event in events_data]

        return jsonify(
            {
                "success": True,
                "events": events,
                "total": len(events),
                "timestamp": datetime.utcnow().isoformat(),
            }
        )

    except Exception as e:
        return (
            jsonify({"success": False, "error": str(e), "events": [], "total": 0}),
            500,
        )


@audit_bp.route("/api/audit/events/recent")
def api_audit_events_recent():
    """Legacy endpoint for compatibility"""
    return get_recent_events_api()


@audit_bp.route("/debug/redis-events")
def debug_redis_events():
    """Debug endpoint to see Redis events"""
    try:
        if not event_logger.redis_client:
            return jsonify({"error": "Redis not connected"}), 500

        # Get today's key
        from datetime import datetime

        redis_key = f"zta_events:{datetime.utcnow().strftime('%Y%m%d')}"

        # Get all events
        events = event_logger.redis_client.lrange(redis_key, 0, -1)

        parsed_events = []
        for event_json in events:
            try:
                parsed_events.append(json.loads(event_json))
            except:
                parsed_events.append({"raw": event_json[:100]})

        return jsonify(
            {
                "redis_connected": True,
                "redis_key": redis_key,
                "event_count": len(events),
                "events": parsed_events[:10],  # First 10
            }
        )

    except Exception as e:
        return jsonify({"redis_connected": False, "error": str(e)}), 500