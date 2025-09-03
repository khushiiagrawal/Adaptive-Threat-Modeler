#!/usr/bin/env python3
"""
Debug script for Slack integration issues
"""

import os
import json
import requests
from dotenv import load_dotenv

load_dotenv()

def test_slack_webhook():
    """Test basic Slack webhook functionality"""
    print("🔍 Debugging Slack Integration")
    print("=" * 50)
    
    # Get webhook URL
    webhook_url = os.getenv("SLACK_WEBHOOK_URL")
    if not webhook_url:
        print("❌ SLACK_WEBHOOK_URL not found in environment variables")
        return False
    
    print(f"📋 Webhook URL: {webhook_url[:50]}...")
    
    # Test 1: Simple message
    print("\n1. Testing simple message...")
    simple_payload = {
        "text": "🧪 Test message from Adaptive Threat Modeler"
    }
    
    try:
        response = requests.post(webhook_url, json=simple_payload, timeout=10)
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            print("   ✅ Simple message sent successfully")
        else:
            print(f"   ❌ Failed: {response.text}")
            return False
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")
        return False
    
    # Test 2: Basic blocks
    print("\n2. Testing basic blocks...")
    basic_blocks_payload = {
        "text": "Security Analysis Report",
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "Security Analysis Report"
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "This is a test security report."
                }
            }
        ]
    }
    
    try:
        response = requests.post(webhook_url, json=basic_blocks_payload, timeout=10)
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            print("   ✅ Basic blocks sent successfully")
        else:
            print(f"   ❌ Failed: {response.text}")
            return False
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")
        return False
    
    # Test 3: Full enhanced message (without GitHub issue)
    print("\n3. Testing full enhanced message...")
    enhanced_payload = {
        "text": "Security Analysis Report",
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "🔒 Security Analysis Report"
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": "*Timestamp:* 2024-01-15 14:30:25"
                    },
                    {
                        "type": "mrkdwn",
                        "text": "*Analysis Type:* Automated Security Scan"
                    }
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "```\nTest security findings...\n```"
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*Severity Summary:* 🔴 Critical: 1 | 🟠 High: 2"
                }
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": "🔒 *Adaptive Threat Modeler* - Automated Security Analysis"
                    }
                ]
            }
        ]
    }
    
    try:
        response = requests.post(webhook_url, json=enhanced_payload, timeout=10)
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            print("   ✅ Enhanced message sent successfully")
        else:
            print(f"   ❌ Failed: {response.text}")
            print(f"   Payload: {json.dumps(enhanced_payload, indent=2)}")
            return False
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")
        return False
    
    # Test 4: Message with actions (buttons)
    print("\n4. Testing message with action buttons...")
    actions_payload = {
        "text": "Security Analysis Report",
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "Test security report with action buttons."
                }
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "View GitHub Issue"
                        },
                        "url": "https://github.com/test/repo/issues/1"
                    },
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "View Full Report"
                        },
                        "url": "https://example.com/report"
                    }
                ]
            }
        ]
    }
    
    try:
        response = requests.post(webhook_url, json=actions_payload, timeout=10)
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            print("   ✅ Action buttons sent successfully")
        else:
            print(f"   ❌ Failed: {response.text}")
            print(f"   Payload: {json.dumps(actions_payload, indent=2)}")
            return False
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")
        return False
    
    print("\n🎉 All Slack tests passed!")
    return True

def check_webhook_url():
    """Check if the webhook URL is valid"""
    print("\n🔍 Checking webhook URL format...")
    
    webhook_url = os.getenv("SLACK_WEBHOOK_URL")
    if not webhook_url:
        print("❌ No webhook URL found")
        return False
    
    # Check URL format
    if not webhook_url.startswith("https://hooks.slack.com/services/"):
        print("❌ Invalid webhook URL format")
        print("   Expected: https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX")
        return False
    
    # Check URL length
    if len(webhook_url) < 60:
        print("❌ Webhook URL seems too short")
        return False
    
    print("✅ Webhook URL format looks correct")
    return True

def main():
    """Main debug function"""
    print("🔧 Slack Integration Debug Tool")
    print("=" * 50)
    
    # Check webhook URL format
    if not check_webhook_url():
        return 1
    
    # Test webhook functionality
    if not test_slack_webhook():
        print("\n❌ Slack integration has issues")
        print("\nTroubleshooting tips:")
        print("1. Check your webhook URL is correct")
        print("2. Ensure the Slack app has proper permissions")
        print("3. Verify the webhook is enabled in your Slack app")
        print("4. Check if there are any rate limits")
        return 1
    
    print("\n✅ All tests passed! Slack integration is working correctly.")
    return 0

if __name__ == "__main__":
    exit(main())
