#!/usr/bin/env python3
"""
Check if the first registered user is admin
"""

import requests

BASE_URL = "https://hack-monitor.preview.emergentagent.com/api"

def check_first_user():
    # Try to login with the first user
    login_data = {
        "email": "testuser@wolfcyber.com",
        "password": "TestPassword123456789012"  # Exactly 24 characters
    }
    
    response = requests.post(f"{BASE_URL}/auth/login", json=login_data)
    print(f"Login response: {response.status_code}")
    
    if response.status_code == 200:
        data = response.json()
        print(f"User data: {data}")
        print(f"Is admin: {data['is_admin']}")
        
        # Test admin functionality
        if data['is_admin']:
            print("\n✅ First user is admin! Testing admin functionality...")
            admin_token = data["access_token"]
            
            threat_data = {
                "title": "First User Admin Test",
                "description": "Testing first user admin access",
                "threat_type": "malware",
                "level": "alto",
                "country": "Test Country",
                "country_code": "TC"
            }
            
            headers = {"Authorization": f"Bearer {admin_token}"}
            threat_response = requests.post(f"{BASE_URL}/threats", json=threat_data, headers=headers)
            print(f"Threat creation response: {threat_response.status_code}")
            print(f"Threat response: {threat_response.json()}")
        else:
            print("❌ First user is not admin")
    else:
        print(f"Login failed: {response.json()}")

if __name__ == "__main__":
    check_first_user()