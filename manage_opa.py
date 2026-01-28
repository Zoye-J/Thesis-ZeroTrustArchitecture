#!/usr/bin/env python3
"""
OPA Management Script for ZTA Thesis
"""
import requests
import json
import sys


class OPAManager:
    def __init__(self, base_url="https://localhost:8181"):
        self.base_url = base_url

    def health(self):
        """Check OPA health"""
        try:
            response = requests.get(f"{self.base_url}/health")
            return response.json()
        except Exception as e:
            return {"error": str(e)}

    def list_policies(self):
        """List all policies"""
        try:
            response = requests.get(f"{self.base_url}/v1/policies")
            return response.json()
        except Exception as e:
            return {"error": str(e)}

    def get_policy(self, policy_id):
        """Get specific policy"""
        try:
            response = requests.get(f"{self.base_url}/v1/policies/{policy_id}")
            return response.json()
        except Exception as e:
            return {"error": str(e)}

    def update_policy(self, policy_id, policy_rego):
        """Update or create policy"""
        try:
            response = requests.put(
                f"{self.base_url}/v1/policies/{policy_id}",
                headers={"Content-Type": "text/plain"},
                data=policy_rego,
            )
            return response.json()
        except Exception as e:
            return {"error": str(e)}

    def test_policy(self, input_data, policy_path="zta/allow"):
        """Test policy evaluation"""
        try:
            response = requests.post(
                f"{self.base_url}/v1/data/{policy_path}", json={"input": input_data}
            )
            return response.json()
        except Exception as e:
            return {"error": str(e)}

    def upload_data(self, data_path, data):
        """Upload data to OPA"""
        try:
            response = requests.put(f"{self.base_url}/v1/data/{data_path}", json=data)
            return response.json()
        except Exception as e:
            return {"error": str(e)}

    def get_decision_logs(self):
        """Get decision logs"""
        try:
            response = requests.get(f"{self.base_url}/v1/logs")
            return response.json()
        except Exception as e:
            return {"error": str(e)}


def main():
    manager = OPAManager()

    if len(sys.argv) < 2:
        print("Usage: python manage_opa.py [command]")
        print("Commands: health, policies, test, upload, logs")
        return

    command = sys.argv[1]

    if command == "health":
        result = manager.health()
        print(json.dumps(result, indent=2))

    elif command == "policies":
        result = manager.list_policies()
        print(json.dumps(result, indent=2))

    elif command == "test":
        # Test with sample data
        test_data = {
            "user": {
                "id": 1,
                "role": "admin",
                "department": "Finance",
                "facility": "Ministry of Finance",
                "clearance": "SECRET",
            },
            "resource": {
                "type": "document",
                "id": 1,
                "classification": "CONFIDENTIAL",
                "department": "Finance",
                "facility": "Ministry of Finance",
                "owner": 1,
            },
            "action": "read",
        }
        result = manager.test_policy(test_data)
        print(json.dumps(result, indent=2))

    elif command == "upload":
        # Upload test data
        test_data = {
            "users": [
                {"id": 1, "name": "admin", "role": "superadmin"},
                {"id": 2, "name": "finance_user", "role": "user"},
            ],
            "documents": [
                {"id": 1, "classification": "SECRET", "department": "Finance"}
            ],
        }
        result = manager.upload_data("zta/data", test_data)
        print(json.dumps(result, indent=2))

    elif command == "logs":
        result = manager.get_decision_logs()
        print(json.dumps(result, indent=2))

    else:
        print(f"Unknown command: {command}")


if __name__ == "__main__":
    main()
