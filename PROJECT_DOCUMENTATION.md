# Adaptive Threat Modeler - Complete Project Documentation

## Table of Contents

1. [Project Overview](#project-overview)
2. [Architecture](#architecture)
3. [Backend System](#backend-system)
4. [Frontend System](#frontend-system)
5. [MCP Integration](#mcp-integration)
6. [Security Analysis Engine](#security-analysis-engine)
7. [API Endpoints](#api-endpoints)
8. [Data Models](#data-models)
9. [Configuration](#configuration)
10. [Deployment](#deployment)
11. [Development Guide](#development-guide)

## Project Overview

**Adaptive Threat Modeler** is a comprehensive, AI-powered security analysis platform that provides continuous threat modeling and vulnerability detection for codebases. The system combines static analysis, pattern matching, and AI-driven insights to identify security vulnerabilities across multiple programming languages and frameworks.

### Key Features

- **Multi-language Support**: Go, JavaScript, TypeScript, Python, Java, PHP, Ruby, C#, C++, Rust
- **Framework Detection**: Fiber, Gin, Echo, React, Vue, Angular, Express, FastAPI, Django, Spring
- **Advanced Analysis**: AST-based static analysis, pattern matching, taint analysis
- **GitHub Integration**: Direct repository cloning and analysis
- **File Upload**: ZIP file upload and analysis
- **Real-time Processing**: Asynchronous analysis with status tracking
- **Visual Threat Modeling**: Interactive threat maps and data flow visualization
- **Auto-fix Suggestions**: Automated remediation recommendations
- **MCP Integration**: AI-powered analysis with GitHub issue creation and Slack notifications

## Architecture

The project follows a microservices architecture with three main components:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │    │    Backend       │    │   MCP Service    │
│   (React/TS)    │◄──►│   (Go/Fiber)     │◄──►│   (Python/AI)    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   User Interface│    │  Analysis Engine│    │  AI Analysis    │
│   & UX          │    │  & Rule Engine  │    │  & Notifications│
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Technology Stack

**Backend:**
- **Language**: Go 1.21+
- **Framework**: Fiber (HTTP server)
- **Analysis**: AST parsing, regex pattern matching
- **Storage**: In-memory (can be extended to database)

**Frontend:**
- **Framework**: React 18 with TypeScript
- **Build Tool**: Vite
- **UI Library**: shadcn/ui components
- **Styling**: Tailwind CSS
- **State Management**: React Query
- **3D Graphics**: Three.js (Scene3D component)

**MCP Service:**
- **Language**: Python 3.8+
- **AI Framework**: LangChain, LangGraph
- **Security Tools**: Semgrep integration
- **Integrations**: GitHub API, Slack API
- **Protocol**: Model Context Protocol (MCP)

## Backend System

### Core Components

#### 1. Main Application (`main.go`)
```go
// Entry point with Fiber server setup
- CORS middleware configuration
- Error handling middleware
- Health check endpoint
- API route setup
- Commit storage initialization
```

#### 2. API Layer (`internal/api/routes.go`)
```go
// RESTful API endpoints
- POST /api/v1/analyze/github - GitHub repository analysis
- POST /api/v1/analyze/upload - ZIP file upload analysis
- POST /api/v1/analyze/commit - Git commit analysis
- GET /api/v1/analysis/{id} - Get analysis results
- GET /api/v1/analysis/{id}/status - Get analysis status
- POST /api/v1/detect/languages - Language detection
- POST /api/v1/detect/frameworks - Framework detection
- GET /api/v1/rules - Get available security rules
- GET /api/v1/rules/{language} - Get language-specific rules
- GET /api/v1/commits/* - Commit analysis endpoints
- GET /api/v1/info - System information
```

#### 3. Request Handlers (`internal/handlers/`)
```go
// HTTP request processing
- analysis.go - Main analysis endpoints
- commit_analysis.go - Git commit analysis
- detection.go - Language/framework detection
- rules.go - Security rules management
- system.go - System information endpoints
```

#### 4. Core Services (`internal/services/`)

##### Analyzer Service (`analyzer.go`)
```go
// Main analysis orchestration
- AnalyzeGitHubRepo() - Clone and analyze GitHub repos
- AnalyzeUpload() - Extract and analyze ZIP files
- analyzeProject() - Core project analysis logic
- analyzeSourceFiles() - File-by-file vulnerability scanning
- generateThreatMap() - Create visual threat models
- calculateSummary() - Generate analysis statistics
```

##### Project Detector (`detector.go`)
```go
// Project metadata detection
- DetectLanguages() - Identify programming languages
- DetectFrameworks() - Detect frameworks and libraries
- DetectServices() - Identify services and API endpoints
- ParseDependencies() - Extract project dependencies
- FindConfigFiles() - Locate configuration files
```

##### Rule Engine (`rules.go`)
```go
// Security rule management
- LoadRulesForProject() - Load relevant security rules
- Match() - Apply rules to code patterns
- GenerateAutoFix() - Create automated fix suggestions
- Built-in rules for multiple languages and frameworks
```

##### AST Parser (`ast_parser.go`)
```go
// Abstract Syntax Tree parsing
- ParseFile() - Parse source files into ASTs
- Language-specific parsing logic
- AST traversal for pattern matching
```

##### Pattern Matcher (`pattern_matcher.go`)
```go
// Advanced pattern matching
- Regex-based pattern matching
- AST-based pattern matching
- Semantic analysis patterns
- Metavariable support
```

##### Data Flow Analyzer (`dataflow.go`)
```go
// Taint analysis and data flow tracking
- Track data flows through applications
- Identify taint propagation
- Detect data leakage patterns
```

##### Git Service (`git_service.go`)
```go
// Git repository operations
- Clone repositories
- Analyze commit diffs
- Extract file changes
- Store commit analysis data
```

#### 5. Data Models (`internal/models/models.go`)
```go
// Core data structures
- AnalysisRequest - Input for threat analysis
- ProjectInfo - Detected project metadata
- Vulnerability - Security finding details
- ThreatMap - Visual threat model
- AnalysisResult - Complete analysis response
- CommitAnalysisData - Git commit analysis data
```

## Frontend System

### Architecture Overview

The frontend is built with React 18, TypeScript, and modern web technologies, providing an intuitive user interface for security analysis.

#### 1. Application Structure (`src/App.tsx`)
```typescript
// Main application component
- QueryClientProvider for state management
- BrowserRouter for routing
- TooltipProvider for UI components
- Toaster components for notifications
```

#### 2. Pages (`src/pages/`)
```typescript
// Page components
- Index.tsx - Main landing page with all sections
- NotFound.tsx - 404 error page
```

#### 3. Components (`src/components/`)

##### Hero Section (`HeroSection.tsx`)
```typescript
// Main landing page hero
- 3D brain animation with mouse tracking
- GitHub repository input
- ZIP file upload with drag & drop
- Real-time analysis status display
- Error and success message handling
```

##### Navigation (`Navigation.tsx`)
```typescript
// Main navigation component
- Responsive navigation menu
- Mobile menu support
- Smooth scrolling to sections
```

##### 3D Scene (`Scene3D.tsx`)
```typescript
// Three.js 3D brain visualization
- Interactive 3D brain model
- Mouse position tracking
- Particle effects
- Cyberpunk aesthetic
```

##### Other UI Components
```typescript
// Additional sections
- ProductSection.tsx - Product features showcase
- ServicesSection.tsx - Service offerings
- AboutSection.tsx - About information
- ContactSection.tsx - Contact form
- Footer.tsx - Footer component
```

#### 4. Hooks (`src/hooks/`)
```typescript
// Custom React hooks
- useAnalysis.ts - Analysis state management
- use-mobile.tsx - Mobile detection
- use-toast.ts - Toast notifications
```

##### Analysis Hook (`useAnalysis.ts`)
```typescript
// Analysis state management
- analyzeGitHubRepo() - GitHub repository analysis
- analyzeFile() - File upload analysis
- checkAnalysisStatus() - Status polling
- getAnalysisResult() - Result retrieval
- clearResults() - State cleanup
- checkBackendHealth() - Health check
```

#### 5. Services (`src/services/`)
```typescript
// API communication
- api.ts - Backend API service
- Type definitions for all API responses
- Error handling and response processing
```

##### API Service (`api.ts`)
```typescript
// Backend communication
- analyzeGitHubRepo() - Start GitHub analysis
- analyzeUpload() - Upload file for analysis
- getAnalysisResult() - Retrieve analysis results
- getAnalysisStatus() - Check analysis status
- pollAnalysisStatus() - Poll for completion
- checkHealth() - Backend health check
```

#### 6. UI Components (`src/components/ui/`)
```typescript
// shadcn/ui component library
- Complete set of reusable UI components
- Consistent design system
- Accessibility features
- Responsive design
```

## MCP Integration

The MCP (Model Context Protocol) service provides AI-powered security analysis with automated notifications and issue creation.

### Core Components

#### 1. Main API (`api.py`)
```python
# Main MCP service
- Multi-agent security analysis
- GitHub issue creation
- Slack notification system
- Semgrep integration
- LangChain/LangGraph workflow
```

#### 2. Agent Architecture
```python
# Multi-agent system
- Discovery Agent - Fetches code from backend API
- Code Processor Agent - Processes code snippets
- Report Generator Agent - Creates final reports
- Tool Node - Executes security tools (Semgrep)
```

#### 3. GitHub Integration
```python
# GitHubIssueCreator class
- create_github_issue() - Create detailed GitHub issues
- Automatic labeling (security, automated-scan)
- Structured issue format with checklists
- Severity-based categorization
```

#### 4. Slack Integration
```python
# Enhanced Slack notifications
- send_to_slack_with_github_issue() - Enhanced messaging
- Action buttons for GitHub issues and reports
- Severity summary with visual indicators
- Fallback messaging for reliability
```

#### 5. Security Analysis Flow
```python
# Analysis workflow
1. Fetch code from backend API endpoint
2. Process code snippets through Semgrep
3. AI analysis with GPT-4
4. Generate comprehensive security report
5. Create GitHub issue with findings
6. Send enhanced Slack notification
```

## Security Analysis Engine

### Analysis Pipeline

#### 1. Input Processing
```go
// Repository/File Processing
- GitHub repository cloning
- ZIP file extraction
- File filtering and validation
- Binary file detection
```

#### 2. Project Detection
```go
// Metadata Extraction
- Language detection by file extensions
- Framework detection by dependencies
- Service identification
- Configuration file discovery
```

#### 3. Rule Loading
```go
// Security Rules
- Language-specific rules
- Framework-specific rules
- Generic security rules
- Custom rule support
```

#### 4. Vulnerability Detection
```go
// Pattern Matching
- Regex-based pattern matching
- AST-based pattern matching
- Semantic analysis
- Taint analysis (optional)
```

#### 5. Result Generation
```go
// Analysis Output
- Vulnerability details with locations
- Threat map generation
- Risk score calculation
- Remediation recommendations
- Auto-fix suggestions
```

### Security Rules

#### Built-in Rules by Language

##### Go Rules
```go
// Go-specific security patterns
- SQL injection detection
- Hardcoded credentials
- Weak cryptographic algorithms
- Command injection
- Path traversal
```

##### Python Rules
```python
# Python security patterns
- SQL injection vulnerabilities
- Command injection
- Hardcoded secrets
- Insecure deserialization
- Path traversal
- SSRF vulnerabilities
- XSS vulnerabilities
- DNS exfiltration
```

##### JavaScript/TypeScript Rules
```javascript
// JS/TS security patterns
- XSS vulnerabilities
- eval() usage
- InnerHTML usage
- Command injection
```

##### HCL/Terraform Rules
```hcl
# Infrastructure security
- Publicly accessible S3 buckets
- Overly permissive security groups
- Unencrypted storage
- Open security group rules
```

##### Shell Script Rules
```bash
# Shell security patterns
- Command injection in variables
- Hardcoded secrets
- Unquoted variables
```

### Pattern Matching Types

#### 1. Regex Patterns
```go
// Regular expression matching
- String concatenation in SQL queries
- Hardcoded credential patterns
- Weak crypto algorithm usage
- Command injection patterns
```

#### 2. AST Patterns
```go
// Abstract Syntax Tree matching
- Function call analysis
- Variable usage tracking
- Control flow analysis
- Type checking
```

#### 3. Semantic Patterns
```go
// Semantic analysis
- Context-aware pattern matching
- Variable scope analysis
- Data flow tracking
- Taint propagation
```

## API Endpoints

### Analysis Endpoints

#### POST `/api/v1/analyze/github`
```json
{
  "repo_url": "https://github.com/user/repo",
  "branch": "main"
}
```
**Response:**
```json
{
  "analysis_id": "uuid",
  "status": "processing",
  "message": "Analysis started successfully"
}
```

#### POST `/api/v1/analyze/upload`
```multipart
file: <zip_file>
```
**Response:**
```json
{
  "analysis_id": "uuid",
  "status": "processing",
  "message": "Analysis started successfully",
  "filename": "project.zip"
}
```

#### GET `/api/v1/analysis/{id}`
**Response:**
```json
{
  "id": "analysis_id",
  "timestamp": "2024-01-01T00:00:00Z",
  "project_info": {
    "languages": ["go", "javascript"],
    "frameworks": ["fiber", "react"],
    "services": [...],
    "dependencies": {...},
    "config_files": [...]
  },
  "vulnerabilities": [...],
  "threat_map": {...},
  "summary": {...},
  "recommendations": [...],
  "status": "completed",
  "processing_time": "2.5s"
}
```

### Detection Endpoints

#### POST `/api/v1/detect/languages`
```json
{
  "project_path": "/path/to/project",
  "files": ["file1.go", "file2.js"]
}
```

#### POST `/api/v1/detect/frameworks`
```json
{
  "project_path": "/path/to/project",
  "languages": ["go", "javascript"]
}
```

### Rules Endpoints

#### GET `/api/v1/rules`
**Response:** All available security rules

#### GET `/api/v1/rules/{language}`
**Response:** Language-specific security rules

### System Endpoints

#### GET `/health`
**Response:**
```json
{
  "status": "healthy",
  "service": "adaptive-threat-modeler"
}
```

#### GET `/api/v1/info`
**Response:** System information and capabilities

## Data Models

### Core Data Structures

#### AnalysisRequest
```go
type AnalysisRequest struct {
    Type     string `json:"type" validate:"required,oneof=github zip"`
    RepoURL  string `json:"repo_url,omitempty"`
    ZipData  []byte `json:"zip_data,omitempty"`
    Filename string `json:"filename,omitempty"`
}
```

#### ProjectInfo
```go
type ProjectInfo struct {
    Languages    []string          `json:"languages"`
    Frameworks   []string          `json:"frameworks"`
    Services     []ServiceInfo     `json:"services"`
    Dependencies map[string]string `json:"dependencies"`
    ConfigFiles  []string          `json:"config_files"`
}
```

#### Vulnerability
```go
type Vulnerability struct {
    ID          string            `json:"id"`
    Title       string            `json:"title"`
    Description string            `json:"description"`
    Severity    string            `json:"severity"`
    Category    string            `json:"category"`
    CWE         string            `json:"cwe,omitempty"`
    OWASP       string            `json:"owasp,omitempty"`
    Location    Location          `json:"location"`
    Evidence    string            `json:"evidence"`
    Impact      string            `json:"impact"`
    Remediation []string          `json:"remediation"`
    AutoFix     *AutoFix          `json:"autofix,omitempty"`
    References  []string          `json:"references,omitempty"`
    Metadata    map[string]string `json:"metadata,omitempty"`
}
```

#### ThreatMap
```go
type ThreatMap struct {
    Components []Component `json:"components"`
    Flows      []DataFlow  `json:"flows"`
    TrustZones []TrustZone `json:"trust_zones"`
    Assets     []Asset     `json:"assets"`
}
```

#### AnalysisResult
```go
type AnalysisResult struct {
    ID              string          `json:"id"`
    Timestamp       time.Time       `json:"timestamp"`
    ProjectInfo     ProjectInfo     `json:"project_info"`
    Vulnerabilities []Vulnerability `json:"vulnerabilities"`
    ThreatMap       ThreatMap       `json:"threat_map"`
    Summary         Summary         `json:"summary"`
    Recommendations []string        `json:"recommendations"`
    Status          string          `json:"status"`
    ProcessingTime  string          `json:"processing_time"`
}
```

## Configuration

### Environment Variables

#### Backend Configuration
```bash
# Server Configuration
PORT=8080
TEMP_DIR=/tmp
MAX_FILE_SIZE=104857600  # 100MB

# CORS Configuration
ALLOWED_ORIGINS=*

# Analysis Configuration
ENABLE_DATAFLOW_ANALYSIS=true
MAX_ANALYSIS_TIME=300

# Git Configuration
GIT_TIMEOUT=300
```

#### MCP Service Configuration
```bash
# GitHub Integration
GITHUB_TOKEN=ghp_your_token_here
GITHUB_OWNER=your_username
GITHUB_REPO=your_repo

# Slack Integration
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL

# OpenAI Configuration
OPENAI_API_KEY=your_openai_key_here

# Debug Configuration
DEBUG=true
LOG_LEVEL=DEBUG
```

### Configuration Files

#### Backend Configuration (`internal/config/config.go`)
```go
type Config struct {
    Port                    string
    TempDir                 string
    MaxFileSize             int64
    AllowedOrigins          []string
    EnableDataflowAnalysis  bool
    MaxAnalysisTime         int
    GitTimeout              int
}
```

## Deployment

### Backend Deployment

#### Docker Deployment
```dockerfile
# Dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o threat-modeler .

FROM alpine:latest
RUN apk --no-cache add ca-certificates git
WORKDIR /root/
COPY --from=builder /app/threat-modeler .
EXPOSE 8080
CMD ["./threat-modeler"]
```

#### Local Development
```bash
# Backend setup
cd backend
go mod tidy
cp env.example .env
go run main.go
```

### Frontend Deployment

#### Development Server
```bash
# Frontend setup
cd frontend
npm install
npm run dev
```

#### Production Build
```bash
# Production build
npm run build
npm run preview
```

### MCP Service Deployment

#### Python Environment
```bash
# MCP service setup
cd mcp
pip install -r requirements.txt
python setup_github_integration.py
python api.py
```

#### Docker Compose
```yaml
# docker-compose.yml
version: '3.8'
services:
  backend:
    build: ./backend
    ports:
      - "8080:8080"
    environment:
      - PORT=8080
      
  frontend:
    build: ./frontend
    ports:
      - "3000:3000"
    depends_on:
      - backend
      
  mcp:
    build: ./mcp
    environment:
      - GITHUB_TOKEN=${GITHUB_TOKEN}
      - SLACK_WEBHOOK_URL=${SLACK_WEBHOOK_URL}
    depends_on:
      - backend
```

## Development Guide

### Setting Up Development Environment

#### Prerequisites
```bash
# Required software
- Go 1.21+
- Node.js 18+
- Python 3.8+
- Git
- Docker (optional)
```

#### Backend Development
```bash
# Clone and setup
git clone <repository>
cd backend
go mod tidy
go run main.go

# Run tests
go test ./...

# Build binary
go build -o threat-modeler .
```

#### Frontend Development
```bash
# Setup frontend
cd frontend
npm install
npm run dev

# Run tests
npm test

# Build for production
npm run build
```

#### MCP Service Development
```bash
# Setup MCP service
cd mcp
pip install -r requirements.txt
python setup_github_integration.py

# Run service
python api.py

# Test integration
python test_github_integration.py
```

### Adding New Features

#### Adding New Language Support
1. **Update Project Detector** (`detector.go`)
   - Add language patterns
   - Add file extensions
   - Add dependency parsing

2. **Add Security Rules** (`rules.go`)
   - Create language-specific rules
   - Add pattern matching
   - Include remediation steps

3. **Update AST Parser** (`ast_parser.go`)
   - Add language parsing logic
   - Implement AST traversal

#### Adding New Framework Detection
1. **Update Framework Patterns** (`detector.go`)
   - Add framework signatures
   - Add dependency patterns
   - Add code patterns

2. **Add Framework Rules** (`rules.go`)
   - Create framework-specific rules
   - Add security patterns

#### Adding New API Endpoints
1. **Create Handler** (`handlers/`)
   - Implement request processing
   - Add validation
   - Add error handling

2. **Update Routes** (`api/routes.go`)
   - Add route definition
   - Configure middleware

3. **Update Models** (`models/models.go`)
   - Add request/response models
   - Add validation tags

### Testing

#### Backend Testing
```bash
# Run all tests
go test ./...

# Run specific test
go test ./internal/services -v

# Run with coverage
go test ./... -cover
```

#### Frontend Testing
```bash
# Run tests
npm test

# Run with coverage
npm test -- --coverage

# Run specific test
npm test -- --testNamePattern="Analysis"
```

#### Integration Testing
```bash
# Test API endpoints
curl -X POST http://localhost:8080/api/v1/analyze/github \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/test/repo"}'

# Test health endpoint
curl http://localhost:8080/health
```

### Performance Optimization

#### Backend Optimization
```go
// Optimization strategies
- Parallel file processing
- Caching of analysis results
- Efficient AST parsing
- Memory management for large files
- Connection pooling
```

#### Frontend Optimization
```typescript
// Performance improvements
- Code splitting
- Lazy loading
- Memoization
- Virtual scrolling for large lists
- Image optimization
```

#### MCP Service Optimization
```python
# AI service optimization
- Batch processing
- Caching of AI responses
- Efficient tool calling
- Memory management
- Async processing
```

### Security Considerations

#### Backend Security
```go
// Security measures
- Input validation and sanitization
- CORS configuration
- Rate limiting
- File upload restrictions
- Secure error handling
```

#### Frontend Security
```typescript
// Security practices
- Input validation
- XSS prevention
- CSRF protection
- Secure API communication
- Content Security Policy
```

#### MCP Service Security
```python
# Security considerations
- Token management
- API key security
- Input sanitization
- Secure webhook handling
- Error message sanitization
```

## Conclusion

The Adaptive Threat Modeler is a comprehensive security analysis platform that combines static analysis, AI-powered insights, and automated workflows to provide continuous security monitoring for codebases. The system's modular architecture allows for easy extension and customization while maintaining high performance and reliability.

The platform successfully integrates multiple technologies and services to provide a complete security analysis solution, from code scanning to automated issue creation and team notifications. The combination of Go backend, React frontend, and Python MCP service creates a robust and scalable security analysis platform.
