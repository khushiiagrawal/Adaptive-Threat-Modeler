# Adaptive Threat Modeler - MCP Integration

This directory contains the Model Context Protocol (MCP) integration for the Adaptive Threat Modeler, providing AI-powered security analysis with automated GitHub issue creation and Slack notifications.

## Features

- **AI-Powered Security Analysis**: Uses GPT-4 with Semgrep for comprehensive vulnerability detection
- **Automated GitHub Issue Creation**: Creates detailed GitHub issues for security findings
- **Enhanced Slack Integration**: Interactive Slack messages with action buttons
- **Multi-Language Support**: Analyzes Go, Python, JavaScript, TypeScript, HCL, and more
- **Real-time Analysis**: Processes git commits and code changes automatically

## Quick Start

### 1. Setup Environment

```bash
# Install dependencies
pip install -r requirements.txt

# Run the interactive setup
python setup_github_integration.py
```

### 2. Configure Environment Variables

Create a `.env` file with the following variables:

```bash
# GitHub Integration
GITHUB_TOKEN=ghp_your_github_personal_access_token_here
GITHUB_OWNER=your_github_username_or_org
GITHUB_REPO=your_repository_name

# Slack Integration
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK

# OpenAI API Key (if using OpenAI models)
OPENAI_API_KEY=your_openai_api_key_here
```

### 3. Test the Integration

```bash
# Test GitHub integration
python test_github_integration.py

# Run the main analysis
python api.py
```

## How It Works

### Security Analysis Flow

1. **Code Discovery**: Fetches code from the backend API endpoint
2. **Semgrep Scanning**: Uses Semgrep rules to detect vulnerabilities
3. **AI Analysis**: GPT-4 analyzes findings and generates recommendations
4. **GitHub Issue Creation**: Automatically creates detailed GitHub issues
5. **Slack Notification**: Sends enhanced Slack messages with action buttons

### Enhanced Slack Messages

The Slack integration now includes:

- **Severity Summary**: Visual breakdown of vulnerability counts
- **Action Buttons**: 
  - "📋 View GitHub Issue" - Direct link to created issue
  - "🔍 View Full Report" - Link to detailed report
- **Enhanced Formatting**: Better visual presentation with emojis and sections

### GitHub Issue Format

Created issues include:

- **Structured Format**: Well-organized with sections and checklists
- **Severity Levels**: Clear categorization of vulnerabilities
- **Actionable Recommendations**: Specific steps for remediation
- **Automated Labels**: "security" and "automated-scan" labels

## Configuration

### GitHub Setup

1. **Create Personal Access Token**:
   - Go to GitHub Settings → Developer settings → Personal access tokens
   - Generate new token with `repo` scope
   - Copy the token

2. **Configure Repository**:
   - Set `GITHUB_OWNER` to your username or organization
   - Set `GITHUB_REPO` to the target repository name

### Slack Setup

1. **Create Slack App**:
   - Go to https://api.slack.com/apps
   - Create new app
   - Add Incoming Webhooks
   - Copy the webhook URL

2. **Configure Webhook**:
   - Set `SLACK_WEBHOOK_URL` in your `.env` file

## Usage Examples

### Basic Usage

```python
from api import send_to_slack_with_github_issue

# Send security report with GitHub issue creation
await send_to_slack_with_github_issue(
    message="Security findings report...",
    security_findings=[
        {
            "severity": "critical",
            "title": "SQL Injection Vulnerability",
            "description": "Direct string concatenation in SQL query",
            "recommendation": "Use parameterized queries"
        }
    ]
)
```

### Custom GitHub Issue Creation

```python
from api import GitHubIssueCreator

github_creator = GitHubIssueCreator()
issue_url = github_creator.create_github_issue(
    title="🚨 Security Alert",
    body="Detailed security report...",
    labels=["security", "critical", "automated"]
)
```

## Integration with Backend

This MCP integration works with the Adaptive Threat Modeler backend:

1. **API Endpoint**: Fetches code from `http://localhost:8000/api/v1/commits/latest`
2. **Analysis Results**: Processes security findings from the backend
3. **Real-time Updates**: Monitors git commits for new security issues

## Troubleshooting

### Common Issues

1. **GitHub Token Issues**:
   - Ensure token has `repo` scope
   - Check token expiration
   - Verify repository access

2. **Slack Integration Issues**:
   - Verify webhook URL is correct
   - Check Slack app permissions
   - Ensure webhook is enabled

3. **API Connection Issues**:
   - Verify backend is running on port 8000
   - Check network connectivity
   - Review API response format

### Debug Mode

Enable debug logging by setting environment variables:

```bash
export DEBUG=true
export LOG_LEVEL=DEBUG
```

## Security Considerations

- **Token Security**: Never commit GitHub tokens to version control
- **Repository Access**: Only grant access to necessary repositories
- **Webhook Security**: Use HTTPS for all webhook URLs
- **API Security**: Secure your backend API endpoints

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## Documentation

- [GitHub Integration Guide](GITHUB_INTEGRATION.md)
- [API Documentation](api.py)
- [Setup Instructions](setup_github_integration.py)

## License

This project is licensed under the MIT License - see the LICENSE file for details.
