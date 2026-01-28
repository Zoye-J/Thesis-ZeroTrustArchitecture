"""
Risk Scoring Engine for ZTA
Calculates risk score based on context
"""

from datetime import datetime


class RiskScorer:
    def __init__(self):
        self.weights = {
            "time_factor": 0.2,
            "location_factor": 0.3,
            "device_factor": 0.2,
            "behavior_factor": 0.3,
        }

    def calculate_risk(self, context, resource_sensitivity):
        """
        Calculate risk score (0-100)
        Higher score = higher risk
        """
        score = 0

        # 1. Time factor (off-hours = higher risk)
        hour = datetime.now().hour
        if hour < 8 or hour >= 18:  # Outside 8AM-6PM
            score += 20

        # 2. Location factor (unusual IP = higher risk)
        # In production, check against known IP ranges
        ip = context.get("network", {}).get("ip_address", "")
        if ip.startswith("192.168.") or ip.startswith("10."):
            score += 0  # Internal network
        else:
            score += 15  # External network

        # 3. Device factor (check user agent)
        user_agent = context.get("network", {}).get("user_agent", "")
        if "mobile" in user_agent.lower():
            score += 10
        if "postman" in user_agent.lower():
            score += 20  # API testing tools are suspicious

        # 4. Behavior factor (first access, multiple requests)
        # This would track user behavior over time
        # For now, simple implementation
        if context.get("is_first_access", False):
            score += 10

        # 5. Authentication strength factor
        auth_strength = context.get("authentication", {}).get("strength", 0)
        if auth_strength == 0:
            score += 30
        elif auth_strength == 1:
            score += 10

        # 6. Resource sensitivity factor
        sensitivity_map = {"PUBLIC": 0, "DEPARTMENT": 10, "TOP_SECRET": 30}
        score += sensitivity_map.get(resource_sensitivity, 0)

        # Cap at 100
        return min(score, 100)

    def get_risk_level(self, score):
        """Convert score to risk level"""
        if score <= 20:
            return "LOW"
        elif score <= 50:
            return "MEDIUM"
        elif score <= 80:
            return "HIGH"
        else:
            return "CRITICAL"
