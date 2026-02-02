#!/usr/bin/env python3
"""
Test script to verify URL verification challenge handling
"""

import json

# Simulate the Lambda handler for URL verification
def test_challenge_handler():
    # Simulate API Gateway event with Slack challenge
    test_event = {
        "body": json.dumps({
            "type": "url_verification",
            "challenge": "test_challenge_value_12345"
        }),
        "headers": {
            "Content-Type": "application/json"
        }
    }
    
    # Simulate the challenge handling logic
    body_str = test_event.get("body", "")
    if body_str:
        try:
            body = json.loads(body_str)
            if body.get("type") == "url_verification" and "challenge" in body:
                challenge = body["challenge"]
                print(f"Challenge found: {challenge}")
                response = {
                    "statusCode": 200,
                    "headers": {"Content-Type": "text/plain"},
                    "body": challenge
                }
                print(f"Response: {response}")
                return response
        except json.JSONDecodeError as e:
            print(f"JSON decode error: {e}")
    
    print("No challenge found")
    return None

if __name__ == "__main__":
    test_challenge_handler()