#!/usr/bin/env python3
"""
Test script for GitHub integration functionality
"""

import os
import asyncio
from dotenv import load_dotenv
from api import GitHubIssueCreator, send_to_slack_with_github_issue

load_dotenv()

async def test_github_integration():
    """Test the GitHub issue creation functionality"""
    
    print("🧪 Testing GitHub Integration")
    print("=" * 50)
    
    # Test 1: Check environment variables
    print("\n1. Checking environment variables...")
    github_token = os.getenv("GITHUB_TOKEN")
    github_owner = os.getenv("GITHUB_OWNER")
    github_repo = os.getenv("GITHUB_REPO")
    
    if not github_token:
        print("❌ GITHUB_TOKEN not found in environment variables")
        return False
    if not github_owner:
        print("❌ GITHUB_OWNER not found in environment variables")
        return False
    if not github_repo:
        print("❌ GITHUB_REPO not found in environment variables")
        return False
    
    print("✅ All GitHub environment variables are set")
    
    # Test 2: Test GitHub issue creation
    print("\n2. Testing GitHub issue creation...")
    github_creator = GitHubIssueCreator()
    
    test_title = "🧪 Test Issue - GitHub Integration"
    test_body = """# Test Issue

This is a test issue created by the Adaptive Threat Modeler GitHub integration.

## Test Details
- **Test Time**: Test run
- **Purpose**: Verify GitHub integration functionality
- **Status**: Testing

## Test Findings
- GitHub API connection: ✅ Working
- Issue creation: ✅ Working
- Label assignment: ✅ Working

---
*This is a test issue and can be safely deleted*
"""
    
    issue_url = github_creator.create_github_issue(
        title=test_title,
        body=test_body,
        labels=["test", "integration"]
    )
    
    if issue_url:
        print(f"✅ GitHub issue created successfully!")
        print(f"   Issue URL: {issue_url}")
    else:
        print("❌ Failed to create GitHub issue")
        return False
    
    # Test 3: Test Slack integration with GitHub issue
    print("\n3. Testing Slack integration with GitHub issue...")
    
    # Sample security findings
    sample_findings = [
        {
            "severity": "critical",
            "title": "Test Critical Vulnerability",
            "description": "This is a test critical vulnerability",
            "recommendation": "Fix this immediately"
        },
        {
            "severity": "high",
            "title": "Test High Vulnerability", 
            "description": "This is a test high vulnerability",
            "recommendation": "Address this soon"
        }
    ]
    
    sample_report = """### Security Report for `test-file.tf`

#### Summary of Findings

The security scan identified several vulnerabilities in the test configuration file.

---

#### **Critical Issues**

1. **Test Critical Vulnerability**
   - **Issue**: This is a test critical vulnerability
   - **Recommendation**: Fix this immediately

#### **High Issues**

1. **Test High Vulnerability**
   - **Issue**: This is a test high vulnerability
   - **Recommendation**: Address this soon

---

#### Recommendations for Remediation

- **Immediate**: Address critical vulnerabilities
- **Short-term**: Fix high priority issues
- **Long-term**: Implement security best practices
"""
    
    # Test Slack integration
    slack_result = await send_to_slack_with_github_issue(
        message=sample_report,
        security_findings=sample_findings
    )
    
    if slack_result:
        print("✅ Slack integration with GitHub issue working!")
    else:
        print("❌ Slack integration failed")
        return False
    
    print("\n🎉 All tests passed! GitHub integration is working correctly.")
    return True

async def main():
    """Main test function"""
    try:
        success = await test_github_integration()
        if success:
            print("\n✅ GitHub integration test completed successfully!")
        else:
            print("\n❌ GitHub integration test failed!")
            return 1
    except Exception as e:
        print(f"\n❌ Test failed with error: {str(e)}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    exit(exit_code)
