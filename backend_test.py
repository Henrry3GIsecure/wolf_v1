#!/usr/bin/env python3
"""
WOLF Cybersecurity Threat Intelligence Backend API Tests
Tests all backend functionalities including authentication, threat management, and admin functions.
"""

import requests
import json
import uuid
import time
from datetime import datetime
from typing import Dict, Any, Optional

# Configuration
BASE_URL = "https://hack-monitor.preview.emergentagent.com/api"
TEST_ADMIN_EMAIL = "testuser@wolfcyber.com"  # First user is admin
TEST_ADMIN_PASSWORD = "TestPassword123456789012"  # Exactly 24 characters
TEST_ADMIN_PIN = "12345"  # Exactly 5 digits
TEST_USER_EMAIL = "regularuser@wolfcyber.com"
TEST_USER_PASSWORD = "UserPassword123456789012"  # Exactly 24 characters
TEST_USER_PIN = "54321"  # Exactly 5 digits

class WOLFAPITester:
    def __init__(self):
        self.base_url = BASE_URL
        self.user_token = None
        self.admin_token = None
        self.user_id = None
        self.admin_id = None
        self.test_threat_id = None
        self.results = []
        
    def log_result(self, test_name: str, success: bool, message: str, details: Any = None):
        """Log test result"""
        result = {
            "test": test_name,
            "success": success,
            "message": message,
            "timestamp": datetime.now().isoformat(),
            "details": details
        }
        self.results.append(result)
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} {test_name}: {message}")
        if details and not success:
            print(f"   Details: {details}")
    
    def make_request(self, method: str, endpoint: str, data: Dict = None, 
                    files: Dict = None, headers: Dict = None, token: str = None) -> requests.Response:
        """Make HTTP request with proper headers"""
        url = f"{self.base_url}{endpoint}"
        
        request_headers = {"Content-Type": "application/json"}
        if headers:
            request_headers.update(headers)
        
        if token:
            request_headers["Authorization"] = f"Bearer {token}"
        
        try:
            if method.upper() == "GET":
                response = requests.get(url, headers=request_headers, timeout=30)
            elif method.upper() == "POST":
                if files:
                    # Remove Content-Type for file uploads
                    request_headers.pop("Content-Type", None)
                    response = requests.post(url, files=files, data=data, headers=request_headers, timeout=30)
                else:
                    response = requests.post(url, json=data, headers=request_headers, timeout=30)
            elif method.upper() == "PUT":
                response = requests.put(url, json=data, headers=request_headers, timeout=30)
            elif method.upper() == "DELETE":
                response = requests.delete(url, headers=request_headers, timeout=30)
            else:
                raise ValueError(f"Unsupported method: {method}")
            
            return response
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
            raise
    
    def test_language_detection(self):
        """Test IP-based language detection"""
        try:
            response = self.make_request("GET", "/detect-language")
            
            if response.status_code == 200:
                data = response.json()
                required_fields = ["ip", "language", "detected_at"]
                
                if all(field in data for field in required_fields):
                    # Check if language is one of supported languages
                    supported_languages = ["es", "en", "pt", "fr", "de", "it", "ru", "zh", "ja"]
                    if data["language"] in supported_languages:
                        self.log_result("Language Detection", True, 
                                      f"Language detected: {data['language']} for IP: {data['ip']}", data)
                    else:
                        self.log_result("Language Detection", False, 
                                      f"Unsupported language detected: {data['language']}", data)
                else:
                    self.log_result("Language Detection", False, 
                                  f"Missing required fields in response", data)
            else:
                self.log_result("Language Detection", False, 
                              f"HTTP {response.status_code}: {response.text}")
        except Exception as e:
            self.log_result("Language Detection", False, f"Exception: {str(e)}")
    
    def test_user_registration(self):
        """Test user registration with validation"""
        # Test regular user registration
        try:
            user_data = {
                "email": TEST_USER_EMAIL,
                "password": TEST_USER_PASSWORD,
                "pin": TEST_USER_PIN,
                "phone": "+1234567890"
            }
            
            response = self.make_request("POST", "/auth/register", user_data)
            
            if response.status_code == 200:
                data = response.json()
                required_fields = ["access_token", "token_type", "user_id", "is_admin"]
                
                if all(field in data for field in required_fields):
                    self.user_token = data["access_token"]
                    self.user_id = data["user_id"]
                    self.log_result("User Registration", True, 
                                  f"User registered successfully. Admin: {data['is_admin']}", data)
                else:
                    self.log_result("User Registration", False, 
                                  "Missing required fields in registration response", data)
            else:
                # If user already exists, try to login instead
                if response.status_code == 400 and "already registered" in response.text:
                    self.test_user_login()
                else:
                    self.log_result("User Registration", False, 
                                  f"HTTP {response.status_code}: {response.text}")
        except Exception as e:
            self.log_result("User Registration", False, f"Exception: {str(e)}")
        
        # Get admin token by logging in with first user (who should be admin)
        self.test_admin_login()
    
    def test_admin_login(self):
        """Test admin login"""
        try:
            login_data = {
                "email": TEST_ADMIN_EMAIL,
                "password": TEST_ADMIN_PASSWORD
            }
            
            response = self.make_request("POST", "/auth/login", login_data)
            
            if response.status_code == 200:
                data = response.json()
                self.admin_token = data["access_token"]
                self.admin_id = data["user_id"]
                self.log_result("Admin Login", True, 
                              f"Admin logged in successfully. Admin: {data['is_admin']}", data)
            else:
                self.log_result("Admin Login", False, 
                              f"HTTP {response.status_code}: {response.text}")
        except Exception as e:
            self.log_result("Admin Login", False, f"Exception: {str(e)}")
    
    def test_user_login(self):
        """Test regular user login"""
        try:
            login_data = {
                "email": TEST_USER_EMAIL,
                "password": TEST_USER_PASSWORD
            }
            
            response = self.make_request("POST", "/auth/login", login_data)
            
            if response.status_code == 200:
                data = response.json()
                required_fields = ["access_token", "token_type", "user_id", "is_admin"]
                
                if all(field in data for field in required_fields):
                    self.user_token = data["access_token"]
                    self.user_id = data["user_id"]
                    self.log_result("User Login", True, 
                                  f"User logged in successfully. Admin: {data['is_admin']}", data)
                else:
                    self.log_result("User Login", False, 
                                  "Missing required fields in login response", data)
            else:
                self.log_result("User Login", False, 
                              f"HTTP {response.status_code}: {response.text}")
        except Exception as e:
            self.log_result("User Login", False, f"Exception: {str(e)}")
    
    def test_password_reset(self):
        """Test password reset with PIN"""
        try:
            new_password = "NewPassword1234567890123"  # Exactly 24 characters
            reset_data = {
                "email": TEST_USER_EMAIL,
                "pin": TEST_USER_PIN,
                "new_password": new_password
            }
            
            response = self.make_request("POST", "/auth/reset-password", reset_data)
            
            if response.status_code == 200:
                data = response.json()
                if "message" in data and "successfully" in data["message"].lower():
                    # Test login with new password
                    login_data = {
                        "email": TEST_USER_EMAIL,
                        "password": new_password
                    }
                    login_response = self.make_request("POST", "/auth/login", login_data)
                    
                    if login_response.status_code == 200:
                        self.user_token = login_response.json()["access_token"]
                        self.log_result("Password Reset", True, 
                                      "Password reset and login with new password successful", data)
                    else:
                        self.log_result("Password Reset", False, 
                                      "Password reset succeeded but login with new password failed")
                else:
                    self.log_result("Password Reset", False, 
                                  "Unexpected response format", data)
            else:
                self.log_result("Password Reset", False, 
                              f"HTTP {response.status_code}: {response.text}")
        except Exception as e:
            self.log_result("Password Reset", False, f"Exception: {str(e)}")
    
    def test_qr_code_generation(self):
        """Test QR code generation"""
        try:
            response = self.make_request("GET", "/qr-code")
            
            if response.status_code == 200:
                data = response.json()
                required_fields = ["qr_code", "url", "generated_at"]
                
                if all(field in data for field in required_fields):
                    # Check if QR code is base64 encoded
                    if data["qr_code"].startswith("data:image/png;base64,"):
                        self.log_result("QR Code Generation", True, 
                                      f"QR code generated for URL: {data['url']}", 
                                      {"url": data["url"], "generated_at": data["generated_at"]})
                    else:
                        self.log_result("QR Code Generation", False, 
                                      "QR code is not in expected base64 format", data)
                else:
                    self.log_result("QR Code Generation", False, 
                                  "Missing required fields in QR code response", data)
            else:
                self.log_result("QR Code Generation", False, 
                              f"HTTP {response.status_code}: {response.text}")
        except Exception as e:
            self.log_result("QR Code Generation", False, f"Exception: {str(e)}")
    
    def test_threat_creation(self):
        """Test threat creation (admin only)"""
        if not self.admin_token:
            self.log_result("Threat Creation", False, "No admin token available")
            return
        
        try:
            threat_data = {
                "title": "Test Cybersecurity Threat",
                "description": "This is a test threat for API validation",
                "threat_type": "malware",
                "level": "alto",
                "country": "United States",
                "country_code": "US",
                "url": "https://example.com/threat-details",
                "image_url": "https://example.com/threat-image.jpg",
                "social_reference": "@cybersec_alert"
            }
            
            response = self.make_request("POST", "/threats", threat_data, token=self.admin_token)
            
            if response.status_code == 200:
                data = response.json()
                if "id" in data:
                    self.test_threat_id = data["id"]
                    self.log_result("Threat Creation", True, 
                                  f"Threat created successfully with ID: {data['id']}", data)
                else:
                    self.log_result("Threat Creation", False, 
                                  "Threat created but no ID returned", data)
            else:
                self.log_result("Threat Creation", False, 
                              f"HTTP {response.status_code}: {response.text}")
        except Exception as e:
            self.log_result("Threat Creation", False, f"Exception: {str(e)}")
    
    def test_threat_retrieval(self):
        """Test threat retrieval with filtering"""
        try:
            # Test basic threat retrieval
            response = self.make_request("GET", "/threats")
            
            if response.status_code == 200:
                threats = response.json()
                if isinstance(threats, list):
                    self.log_result("Threat Retrieval", True, 
                                  f"Retrieved {len(threats)} threats", {"count": len(threats)})
                    
                    # Test filtering by level
                    filter_response = self.make_request("GET", "/threats?level=alto")
                    if filter_response.status_code == 200:
                        filtered_threats = filter_response.json()
                        self.log_result("Threat Filtering by Level", True, 
                                      f"Retrieved {len(filtered_threats)} high-level threats", 
                                      {"count": len(filtered_threats)})
                    else:
                        self.log_result("Threat Filtering by Level", False, 
                                      f"HTTP {filter_response.status_code}: {filter_response.text}")
                    
                    # Test filtering by country
                    country_response = self.make_request("GET", "/threats?country=US")
                    if country_response.status_code == 200:
                        country_threats = country_response.json()
                        self.log_result("Threat Filtering by Country", True, 
                                      f"Retrieved {len(country_threats)} US threats", 
                                      {"count": len(country_threats)})
                    else:
                        self.log_result("Threat Filtering by Country", False, 
                                      f"HTTP {country_response.status_code}: {country_response.text}")
                else:
                    self.log_result("Threat Retrieval", False, 
                                  "Response is not a list", threats)
            else:
                self.log_result("Threat Retrieval", False, 
                              f"HTTP {response.status_code}: {response.text}")
        except Exception as e:
            self.log_result("Threat Retrieval", False, f"Exception: {str(e)}")
    
    def test_threat_update(self):
        """Test threat update (admin only)"""
        if not self.admin_token or not self.test_threat_id:
            self.log_result("Threat Update", False, "No admin token or threat ID available")
            return
        
        try:
            update_data = {
                "title": "Updated Test Cybersecurity Threat",
                "description": "This threat has been updated via API",
                "threat_type": "vulnerability",
                "level": "medio",
                "country": "Canada",
                "country_code": "CA",
                "url": "https://example.com/updated-threat",
                "image_url": "https://example.com/updated-image.jpg",
                "social_reference": "@updated_alert"
            }
            
            response = self.make_request("PUT", f"/threats/{self.test_threat_id}", 
                                       update_data, token=self.admin_token)
            
            if response.status_code == 200:
                data = response.json()
                if "message" in data and "successfully" in data["message"].lower():
                    self.log_result("Threat Update", True, 
                                  f"Threat updated successfully", data)
                else:
                    self.log_result("Threat Update", False, 
                                  "Unexpected response format", data)
            else:
                self.log_result("Threat Update", False, 
                              f"HTTP {response.status_code}: {response.text}")
        except Exception as e:
            self.log_result("Threat Update", False, f"Exception: {str(e)}")
    
    def test_threat_deletion(self):
        """Test threat deletion (admin only)"""
        if not self.admin_token or not self.test_threat_id:
            self.log_result("Threat Deletion", False, "No admin token or threat ID available")
            return
        
        try:
            response = self.make_request("DELETE", f"/threats/{self.test_threat_id}", 
                                       token=self.admin_token)
            
            if response.status_code == 200:
                data = response.json()
                if "message" in data and "successfully" in data["message"].lower():
                    self.log_result("Threat Deletion", True, 
                                  f"Threat deleted successfully", data)
                else:
                    self.log_result("Threat Deletion", False, 
                                  "Unexpected response format", data)
            else:
                self.log_result("Threat Deletion", False, 
                              f"HTTP {response.status_code}: {response.text}")
        except Exception as e:
            self.log_result("Threat Deletion", False, f"Exception: {str(e)}")
    
    def test_json_upload(self):
        """Test bulk threat upload via JSON file"""
        if not self.admin_token:
            self.log_result("JSON Upload", False, "No admin token available")
            return
        
        try:
            # Create test JSON data
            test_threats = [
                {
                    "title": "Bulk Upload Threat 1",
                    "description": "First threat from bulk upload",
                    "threat_type": "leak",
                    "level": "alto",
                    "country": "Spain",
                    "country_code": "ES"
                },
                {
                    "title": "Bulk Upload Threat 2",
                    "description": "Second threat from bulk upload",
                    "threat_type": "hack",
                    "level": "medio",
                    "country": "Mexico",
                    "country_code": "MX"
                }
            ]
            
            # Create temporary JSON file content
            json_content = json.dumps(test_threats)
            
            # Prepare file upload
            files = {
                'file': ('threats.json', json_content, 'application/json')
            }
            
            response = self.make_request("POST", "/threats/upload-json", 
                                       files=files, token=self.admin_token)
            
            if response.status_code == 200:
                data = response.json()
                if "message" in data and "total_processed" in data:
                    self.log_result("JSON Upload", True, 
                                  f"Bulk upload successful: {data['message']}", data)
                else:
                    self.log_result("JSON Upload", False, 
                                  "Unexpected response format", data)
            else:
                self.log_result("JSON Upload", False, 
                              f"HTTP {response.status_code}: {response.text}")
        except Exception as e:
            self.log_result("JSON Upload", False, f"Exception: {str(e)}")
    
    def test_statistics(self):
        """Test threat statistics endpoint"""
        try:
            response = self.make_request("GET", "/stats")
            
            if response.status_code == 200:
                data = response.json()
                required_fields = ["total_threats", "by_level", "by_type", "by_country"]
                
                if all(field in data for field in required_fields):
                    self.log_result("Statistics", True, 
                                  f"Statistics retrieved: {data['total_threats']} total threats", data)
                else:
                    self.log_result("Statistics", False, 
                                  "Missing required fields in statistics response", data)
            else:
                self.log_result("Statistics", False, 
                              f"HTTP {response.status_code}: {response.text}")
        except Exception as e:
            self.log_result("Statistics", False, f"Exception: {str(e)}")
    
    def test_admin_access_control(self):
        """Test admin-only endpoint access control"""
        if not self.user_token:
            self.log_result("Admin Access Control", False, "No user token available")
            return
        
        try:
            # Try to create threat with regular user token (should fail)
            threat_data = {
                "title": "Unauthorized Threat",
                "description": "This should fail",
                "threat_type": "malware",
                "level": "alto",
                "country": "Test",
                "country_code": "TS"
            }
            
            response = self.make_request("POST", "/threats", threat_data, token=self.user_token)
            
            if response.status_code == 403:
                self.log_result("Admin Access Control", True, 
                              "Regular user correctly denied admin access")
            elif response.status_code == 401:
                self.log_result("Admin Access Control", True, 
                              "Regular user correctly denied admin access (401)")
            else:
                self.log_result("Admin Access Control", False, 
                              f"Expected 403/401 but got {response.status_code}: {response.text}")
        except Exception as e:
            self.log_result("Admin Access Control", False, f"Exception: {str(e)}")
    
    def test_password_validation(self):
        """Test password length validation"""
        try:
            # Test with invalid password length
            invalid_user_data = {
                "email": "invalid@test.com",
                "password": "short",  # Less than 24 characters
                "pin": TEST_USER_PIN
            }
            
            response = self.make_request("POST", "/auth/register", invalid_user_data)
            
            if response.status_code == 422:  # Validation error
                self.log_result("Password Validation", True, 
                              "Password length validation working correctly")
            else:
                self.log_result("Password Validation", False, 
                              f"Expected 422 validation error but got {response.status_code}: {response.text}")
        except Exception as e:
            self.log_result("Password Validation", False, f"Exception: {str(e)}")
    
    def test_pin_validation(self):
        """Test PIN validation"""
        try:
            # Test with invalid PIN
            invalid_user_data = {
                "email": "invalidpin@test.com",
                "password": TEST_USER_PASSWORD,
                "pin": "123"  # Less than 5 digits
            }
            
            response = self.make_request("POST", "/auth/register", invalid_user_data)
            
            if response.status_code == 422:  # Validation error
                self.log_result("PIN Validation", True, 
                              "PIN length validation working correctly")
            else:
                self.log_result("PIN Validation", False, 
                              f"Expected 422 validation error but got {response.status_code}: {response.text}")
        except Exception as e:
            self.log_result("PIN Validation", False, f"Exception: {str(e)}")
    
    def run_all_tests(self):
        """Run all tests in sequence"""
        print(f"\n🚀 Starting WOLF Cybersecurity API Tests")
        print(f"📍 Base URL: {self.base_url}")
        print(f"⏰ Started at: {datetime.now().isoformat()}")
        print("=" * 80)
        
        # Test sequence
        test_methods = [
            self.test_language_detection,
            self.test_user_registration,
            self.test_user_login,
            self.test_password_reset,
            self.test_password_validation,
            self.test_pin_validation,
            self.test_qr_code_generation,
            self.test_threat_creation,
            self.test_threat_retrieval,
            self.test_threat_update,
            self.test_threat_deletion,
            self.test_json_upload,
            self.test_statistics,
            self.test_admin_access_control
        ]
        
        for test_method in test_methods:
            try:
                test_method()
                time.sleep(0.5)  # Small delay between tests
            except Exception as e:
                print(f"❌ CRITICAL ERROR in {test_method.__name__}: {str(e)}")
        
        # Summary
        print("\n" + "=" * 80)
        print("📊 TEST SUMMARY")
        print("=" * 80)
        
        passed = sum(1 for r in self.results if r["success"])
        failed = len(self.results) - passed
        
        print(f"✅ Passed: {passed}")
        print(f"❌ Failed: {failed}")
        print(f"📈 Success Rate: {(passed/len(self.results)*100):.1f}%")
        
        if failed > 0:
            print(f"\n🔍 FAILED TESTS:")
            for result in self.results:
                if not result["success"]:
                    print(f"   ❌ {result['test']}: {result['message']}")
        
        print(f"\n⏰ Completed at: {datetime.now().isoformat()}")
        return self.results

if __name__ == "__main__":
    tester = WOLFAPITester()
    results = tester.run_all_tests()
    
    # Save results to file
    with open("/app/test_results.json", "w") as f:
        json.dump(results, f, indent=2, default=str)
    
    print(f"\n💾 Detailed results saved to: /app/test_results.json")