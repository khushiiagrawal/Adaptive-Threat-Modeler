# Analysis Logs Feature

## Overview

The Adaptive Threat Modeler now includes a comprehensive logs viewing feature that allows users to view detailed analysis logs in an elegant and intuitive UI.

## How It Works

### 1. Analysis Completion
When a GitHub repository or ZIP file analysis completes, users will see:
- A success message showing the number of vulnerabilities found
- A **"View Logs"** button that redirects to the logs page

### 2. Logs Page Features
The logs page (`/logs/{analysisId}`) includes:

#### **Same Layout & Design**
- Navigation bar
- 3D brain animation background
- Particle effects
- Same color scheme and glassmorphism design

#### **Logs Display**
- **Syntax Highlighting**: Different log types are color-coded:
  - 🔴 **Critical vulnerabilities** - Red
  - 🟠 **High severity** - Orange  
  - 🟡 **Medium severity** - Yellow
  - 🔵 **Low severity** - Blue
  - 🟢 **File analysis progress** - Green
  - 🔵 **Analysis metadata** - Cyan
  - 🟣 **Risk scores & summaries** - Purple
  - ⚪ **Section headers** - Primary color with glow

#### **Interactive Features**
- **Copy to Clipboard**: Copy all logs with one click
- **Download Logs**: Download logs as a text file
- **Scrollable View**: Logs are contained in a scrollable area
- **Monospace Font**: Easy-to-read formatting

### 3. Sample Log Output

The logs include detailed information such as:

```
=== PROJECT ANALYSIS STARTED ===
Analysis ID: 3dc5edfe-a421-4815-92db-8efc75c6735b
Project Path: /tmp/analysis_3dc5edfe-a421-4815-92db-8efc75c6735b/repo
Detected Languages: [hcl python javascript shell]
Detected Frameworks: []
Services Found: 0
Dependencies: 0
Config Files: [IAC/Dockerfile secrets/.env]
===============================

Found 5 vulnerability(ies) in file: IAC/s3.tf
  - [critical] Publicly Accessible S3 Bucket at line 20
  - [critical] Publicly Accessible S3 Bucket at line 21
  - [critical] Publicly Accessible S3 Bucket at line 22
  - [critical] Publicly Accessible S3 Bucket at line 23
  - [critical] Command Injection in Shell Script at line 42

=== ANALYSIS COMPLETED ===
Analysis ID: 3dc5edfe-a421-4815-92db-8efc75c6735b
Total vulnerabilities found: 93

=== AST-STYLE JSON OUTPUT ===
{
  "errors": [],
  "paths": {
    "scanned": ["IAC/s3.tf", "IAC/security-group.tf", ...],
    "skipped": []
  },
  "results": [
    {
      "check_id": "92489b1e-cc6b-4a2c-89ae-b8c750c58841",
      "path": "IAC/s3.tf",
      "start": { "line": 20, "col": 3, "offset": 0 },
      "end": { "line": 0, "col": 0, "offset": 0 },
      "extra": {
        "message": "S3 bucket configured with public access",
        "severity": "CRITICAL",
        "category": "misconfiguration",
        "cwe": "CWE-200",
        "evidence": "block_public_acls = false",
        "impact": "Unauthorized access to sensitive data",
        "remediation": [
          "Set appropriate ACLs for S3 buckets",
          "Enable S3 bucket public access blocks",
          "Use IAM policies for access control"
        ]
      }
    }
  ],
  "version": "1.0.0"
}

=== VULNERABILITY SUMMARY ===
CRITICAL: 34 vulnerabilities
HIGH: 8 vulnerabilities
LOW: 51 vulnerabilities

=== ANALYSIS SUMMARY ===
Risk Score: 447.0
Security Posture: poor
Severity Breakdown:
  critical: 34
  high: 8
  low: 51
Category Breakdown:
  secrets: 5
  deserialization: 7
  misconfiguration: 12
  injection: 18
  code_quality: 51
Top Risks: []
Threat Map Components: 0
Threat Map Data Flows: 0
Recommendations: 2
==============================
```

## Technical Implementation

### Backend Changes
- **Log Capture**: Modified `analyzer.go` to capture all analysis output to a buffer
- **Log Storage**: Added in-memory storage for logs (can be replaced with database)
- **API Endpoint**: Added `/api/v1/analysis/{id}/logs` endpoint
- **Handler**: Created `GetAnalysisLogs` handler

### Frontend Changes
- **New Page**: Created `LogsPage.tsx` with full layout
- **Routing**: Added `/logs/:analysisId` route
- **API Integration**: Added `getAnalysisLogs` method to API service
- **UI Enhancement**: Added "View Logs" button to success message

## User Experience

1. **Start Analysis**: User enters GitHub URL or uploads ZIP file
2. **Wait for Completion**: Progress is shown during analysis
3. **View Results**: Success message appears with vulnerability count
4. **Access Logs**: Click "View Logs" button to see detailed analysis logs
5. **Interact with Logs**: Copy, download, or scroll through the formatted logs
6. **Return Home**: Easy navigation back to the main page

## Benefits

- **Transparency**: Users can see exactly what was analyzed
- **Debugging**: Developers can understand analysis results better
- **Documentation**: Logs can be saved for compliance or reporting
- **Trust**: Detailed logs build confidence in the analysis process
- **Accessibility**: Even naive users can understand the color-coded output

The logs feature provides complete visibility into the analysis process while maintaining the elegant, user-friendly design of the application.
