#!/usr/bin/env python3
"""
Debug admin functionality and user registration
"""

import requests
import json

BASE_URL = "https://hack-monitor.preview.emergentagent.com/api"

def test_admin_logic():
    print("🔍 Testing Admin Logic")
    
    # First, let's check how many users exist
    print("\n1. Checking existing users by trying to register a new admin...")
    
    admin_data = {
        "email": "debug_admin@wolfcyber.com",
        "password": "DebugAdminPassword123456",  # Exactly 24 characters
        "pin": "99999"
    }
    
    response = requests.post(f"{BASE_URL}/auth/register", json=admin_data)
    print(f"Registration response: {response.status_code}")
    print(f"Response data: {response.json()}")
    
    if response.status_code == 200:
        data = response.json()
        admin_token = data["access_token"]
        print(f"Is admin: {data['is_admin']}")
        
        # Test admin functionality
        print("\n2. Testing admin functionality...")
        threat_data = {
            "title": "Admin Test Threat",
            "description": "Testing admin access",
            "threat_type": "malware",
            "level": "alto",
            "country": "Test Country",
            "country_code": "TC"
        }
        
        headers = {"Authorization": f"Bearer {admin_token}"}
        threat_response = requests.post(f"{BASE_URL}/threats", json=threat_data, headers=headers)
        print(f"Threat creation response: {threat_response.status_code}")
        print(f"Threat response: {threat_response.json()}")
    
    # Test with a regular user
    print("\n3. Testing regular user...")
    user_data = {
        "email": "debug_user@wolfcyber.com",
        "password": "DebugUserPassword1234567",  # Exactly 24 characters
        "pin": "11111"
    }
    
    user_response = requests.post(f"{BASE_URL}/auth/register", json=user_data)
    print(f"User registration response: {user_response.status_code}")
    if user_response.status_code == 200:
        user_data_resp = user_response.json()
        user_token = user_data_resp["access_token"]
        print(f"User is admin: {user_data_resp['is_admin']}")
        
        # Test user trying to create threat
        headers = {"Authorization": f"Bearer {user_token}"}
        threat_response = requests.post(f"{BASE_URL}/threats", json=threat_data, headers=headers)
        print(f"User threat creation response: {threat_response.status_code}")
        print(f"User threat response: {threat_response.json()}")
    else:
        print(f"User registration failed: {user_response.json()}")

if __name__ == "__main__":
    test_admin_logic()