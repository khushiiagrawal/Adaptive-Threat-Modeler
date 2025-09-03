#!/usr/bin/env python3
"""
Test script for the MCP Code Analysis API
"""

import requests
import json
import time

# API endpoint
API_URL = "http://localhost:8000/analyze-file"

def test_api_with_vulnerable_code():
    """Test the API with the vulnerable code from vuln_sample.py"""
    
    # Read the vulnerable code
    with open("vuln_sample.py", "r") as f:
        vulnerable_code = f.read()
    
    # Prepare the request
    payload = {
        "code": vulnerable_code,
        "language": "python"
    }
    
    print("🧪 Testing API with vulnerable code...")
    print(f"📡 Sending request to: {API_URL}")
    print(f"📄 Code length: {len(vulnerable_code)} characters")
    
    try:
        # Send the request
        response = requests.post(
            API_URL,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=60  # 60 second timeout for analysis
        )
        
        if response.status_code == 200:
            result = response.json()
            print("✅ API request successful!")
            print("\n" + "="*80)
            print("🔒 SECURITY ANALYSIS REPORT")
            print("="*80)
            print(result["report"])
            print("="*80)
            return True
        else:
            print(f"❌ API request failed with status: {response.status_code}")
            print(f"Response: {response.text}")
            return False
            
    except requests.exceptions.ConnectionError:
        print("❌ Connection failed. Is the API server running on localhost:8000?")
        print("💡 Try running: python api.py")
        return False
    except requests.exceptions.Timeout:
        print("❌ Request timed out. The analysis took too long.")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False

def test_api_with_simple_code():
    """Test the API with a simple, safe code snippet"""
    
    simple_code = '''
def hello_world():
    """A simple, safe function"""
    return "Hello, World!"

def add_numbers(a, b):
    """Add two numbers safely"""
    return a + b

if __name__ == "__main__":
    print(hello_world())
    print(add_numbers(5, 3))
'''
    
    payload = {
        "code": simple_code,
        "language": "python"
    }
    
    print("\n🧪 Testing API with simple, safe code...")
    
    try:
        response = requests.post(
            API_URL,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            print("✅ Simple code test successful!")
            print("\n" + "="*50)
            print("📊 ANALYSIS RESULT")
            print("="*50)
            print(result["report"])
            print("="*50)
            return True
        else:
            print(f"❌ Simple code test failed: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Simple code test error: {e}")
        return False

def main():
    """Run all tests"""
    print("🚀 Starting API Tests for Threat Detection System")
    print("="*60)
    
    # Wait a moment for server to be ready
    print("⏳ Waiting 2 seconds for server to be ready...")
    time.sleep(2)
    
    # Test 1: Simple code
    success1 = test_api_with_simple_code()
    
    # Test 2: Vulnerable code
    success2 = test_api_with_vulnerable_code()
    
    # Summary
    print("\n" + "="*60)
    print("📋 TEST SUMMARY")
    print("="*60)
    print(f"Simple Code Test: {'✅ PASSED' if success1 else '❌ FAILED'}")
    print(f"Vulnerable Code Test: {'✅ PASSED' if success2 else '❌ FAILED'}")
    
    if success1 and success2:
        print("\n🎉 All tests passed! Your threat detection API is working correctly.")
    else:
        print("\n⚠️ Some tests failed. Check the error messages above.")
    
    return success1 and success2

if __name__ == "__main__":
    main()
