#!/usr/bin/env python3
"""
Setup script for GitHub integration configuration
"""

import os
import getpass
from pathlib import Path

def setup_github_integration():
    """Interactive setup for GitHub integration"""
    
    print("🔧 GitHub Integration Setup")
    print("=" * 50)
    print("This script will help you configure GitHub integration for the Adaptive Threat Modeler.")
    print()
    
    # Check if .env file exists
    env_file = Path(".env")
    env_content = ""
    
    if env_file.exists():
        print("📁 Found existing .env file")
        with open(env_file, 'r') as f:
            env_content = f.read()
    else:
        print("📁 Creating new .env file")
    
    # Get GitHub configuration
    print("\n🔑 GitHub Configuration")
    print("-" * 30)
    
    # GitHub Token
    print("\n1. GitHub Personal Access Token")
    print("   Go to: https://github.com/settings/tokens")
    print("   Create a new token with 'repo' scope")
    print()
    
    github_token = getpass.getpass("Enter your GitHub token (hidden): ").strip()
    if not github_token:
        print("❌ GitHub token is required")
        return False
    
    # GitHub Owner
    print("\n2. GitHub Owner")
    print("   This can be your username or organization name")
    print()
    
    github_owner = input("Enter GitHub owner (username/org): ").strip()
    if not github_owner:
        print("❌ GitHub owner is required")
        return False
    
    # GitHub Repository
    print("\n3. GitHub Repository")
    print("   The repository where issues will be created")
    print()
    
    github_repo = input("Enter repository name: ").strip()
    if not github_repo:
        print("❌ Repository name is required")
        return False
    
    # Slack Webhook URL
    print("\n4. Slack Webhook URL")
    print("   Go to: https://api.slack.com/apps")
    print("   Create an app and add Incoming Webhooks")
    print()
    
    slack_webhook = input("Enter Slack webhook URL (optional): ").strip()
    
    # Build new .env content
    new_env_content = ""
    
    # Add existing content (excluding our new variables)
    lines = env_content.split('\n')
    for line in lines:
        if not any(line.startswith(var) for var in ['GITHUB_TOKEN=', 'GITHUB_OWNER=', 'GITHUB_REPO=', 'SLACK_WEBHOOK_URL=']):
            if line.strip():
                new_env_content += line + '\n'
    
    # Add new variables
    new_env_content += f"\n# GitHub Integration\n"
    new_env_content += f"GITHUB_TOKEN={github_token}\n"
    new_env_content += f"GITHUB_OWNER={github_owner}\n"
    new_env_content += f"GITHUB_REPO={github_repo}\n"
    
    if slack_webhook:
        new_env_content += f"\n# Slack Integration\n"
        new_env_content += f"SLACK_WEBHOOK_URL={slack_webhook}\n"
    
    # Write .env file
    try:
        with open(env_file, 'w') as f:
            f.write(new_env_content.strip() + '\n')
        
        print(f"\n✅ Configuration saved to {env_file}")
        
        # Test configuration
        print("\n🧪 Testing Configuration")
        print("-" * 30)
        
        # Test GitHub API access
        import requests
        
        headers = {
            "Authorization": f"token {github_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        # Test repository access
        repo_url = f"https://api.github.com/repos/{github_owner}/{github_repo}"
        response = requests.get(repo_url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            repo_data = response.json()
            print(f"✅ Repository access confirmed: {repo_data['full_name']}")
            print(f"   Description: {repo_data.get('description', 'No description')}")
        else:
            print(f"❌ Repository access failed: {response.status_code}")
            print(f"   Error: {response.text}")
            return False
        
        # Test issue creation permission
        issues_url = f"{repo_url}/issues"
        response = requests.get(issues_url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            print("✅ Issue creation permission confirmed")
        else:
            print(f"❌ Issue creation permission failed: {response.status_code}")
            print("   Make sure your token has 'repo' scope")
            return False
        
        print("\n🎉 Setup completed successfully!")
        print("\nNext steps:")
        print("1. Run the test script: python test_github_integration.py")
        print("2. Start using the enhanced Slack integration")
        print("3. Check the documentation: GITHUB_INTEGRATION.md")
        
        return True
        
    except Exception as e:
        print(f"❌ Error saving configuration: {str(e)}")
        return False

def main():
    """Main setup function"""
    try:
        success = setup_github_integration()
        if not success:
            print("\n❌ Setup failed. Please check the errors above.")
            return 1
    except KeyboardInterrupt:
        print("\n\n❌ Setup cancelled by user")
        return 1
    except Exception as e:
        print(f"\n❌ Setup failed with error: {str(e)}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
