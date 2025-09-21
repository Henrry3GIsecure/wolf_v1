#!/usr/bin/env python3
"""
Additional edge case tests for WOLF API
"""

import requests
import json

BASE_URL = "https://hack-monitor.preview.emergentagent.com/api"

def test_edge_cases():
    print("🔍 Running Edge Case Tests")
    
    # Test 1: Invalid email format
    print("\n1. Testing invalid email format...")
    invalid_email_data = {
        "email": "invalid-email",
        "password": "TestPassword123456789012",
        "pin": "12345"
    }
    response = requests.post(f"{BASE_URL}/auth/register", json=invalid_email_data)
    print(f"Invalid email response: {response.status_code}")
    if response.status_code == 422:
        print("✅ Email validation working correctly")
    else:
        print(f"❌ Expected 422, got {response.status_code}: {response.json()}")
    
    # Test 2: PIN with non-digits
    print("\n2. Testing PIN with non-digits...")
    invalid_pin_data = {
        "email": "test@example.com",
        "password": "TestPassword123456789012",
        "pin": "1234a"
    }
    response = requests.post(f"{BASE_URL}/auth/register", json=invalid_pin_data)
    print(f"Invalid PIN response: {response.status_code}")
    if response.status_code == 422:
        print("✅ PIN validation working correctly")
    else:
        print(f"❌ Expected 422, got {response.status_code}: {response.json()}")
    
    # Test 3: Password reset with wrong PIN
    print("\n3. Testing password reset with wrong PIN...")
    wrong_pin_data = {
        "email": "regularuser@wolfcyber.com",
        "pin": "99999",  # Wrong PIN
        "new_password": "NewPassword1234567890123"
    }
    response = requests.post(f"{BASE_URL}/auth/reset-password", json=wrong_pin_data)
    print(f"Wrong PIN response: {response.status_code}")
    if response.status_code == 401:
        print("✅ PIN verification working correctly")
    else:
        print(f"❌ Expected 401, got {response.status_code}: {response.json()}")
    
    # Test 4: Password reset for non-existent user
    print("\n4. Testing password reset for non-existent user...")
    nonexistent_user_data = {
        "email": "nonexistent@example.com",
        "pin": "12345",
        "new_password": "NewPassword1234567890123"
    }
    response = requests.post(f"{BASE_URL}/auth/reset-password", json=nonexistent_user_data)
    print(f"Non-existent user response: {response.status_code}")
    if response.status_code == 404:
        print("✅ User existence check working correctly")
    else:
        print(f"❌ Expected 404, got {response.status_code}: {response.json()}")
    
    # Test 5: Invalid JSON upload
    print("\n5. Testing invalid JSON upload...")
    # First get admin token
    admin_login = {
        "email": "testuser@wolfcyber.com",
        "password": "TestPassword123456789012"
    }
    admin_response = requests.post(f"{BASE_URL}/auth/login", json=admin_login)
    if admin_response.status_code == 200:
        admin_token = admin_response.json()["access_token"]
        
        # Upload invalid JSON
        invalid_json = "invalid json content"
        files = {'file': ('invalid.json', invalid_json, 'application/json')}
        headers = {"Authorization": f"Bearer {admin_token}"}
        
        upload_response = requests.post(f"{BASE_URL}/threats/upload-json", 
                                      files=files, headers=headers)
        print(f"Invalid JSON upload response: {upload_response.status_code}")
        if upload_response.status_code == 400:
            print("✅ JSON validation working correctly")
        else:
            print(f"❌ Expected 400, got {upload_response.status_code}: {upload_response.json()}")
    
    # Test 6: Unauthorized access to protected endpoints
    print("\n6. Testing unauthorized access...")
    response = requests.get(f"{BASE_URL}/threats")
    print(f"Unauthorized threats access: {response.status_code}")
    if response.status_code == 200:
        print("✅ Public threat access working correctly")
    else:
        print(f"❌ Unexpected response: {response.status_code}")
    
    # Test 7: Invalid threat level filtering
    print("\n7. Testing invalid threat level filtering...")
    response = requests.get(f"{BASE_URL}/threats?level=invalid_level")
    print(f"Invalid level filter response: {response.status_code}")
    if response.status_code == 200:
        threats = response.json()
        print(f"✅ Invalid level filter handled gracefully, returned {len(threats)} threats")
    else:
        print(f"❌ Unexpected response: {response.status_code}")
    
    print("\n🏁 Edge case tests completed!")

if __name__ == "__main__":
    test_edge_cases()