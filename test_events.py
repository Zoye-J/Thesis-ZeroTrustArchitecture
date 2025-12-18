# Create test_events.py
import sys

sys.path.insert(0, ".")

from app import create_app
from app.logs.zta_event_logger import zta_logger, EVENT_TYPES

app = create_app()
with app.app_context():
    # Check if all event types are defined
    print("Available Event Types:")
    for key, desc in EVENT_TYPES.items():
        print(f"  {key}: {desc}")

    # Add a test event
    test_event = zta_logger.log_event("TEST", {"message": "Testing ZTA logger"})
    print(f"\nTest event created with ID: {test_event['id']}")

    # Get recent events
    events = zta_logger.get_recent_events(5)
    print(f"\nRecent events in memory: {len(events)}")
