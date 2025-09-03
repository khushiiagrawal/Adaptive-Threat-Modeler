# Adaptive Threat Modeler - Backend

A powerful Go-based backend for continuous threat modeling and security analysis of codebases.

## Features

- **Multi-language Support**: Go, JavaScript, TypeScript, Python, Java, PHP, Ruby, C#, C++
- **Framework Detection**: Fiber, Gin, Echo, React, Vue, Angular, Express, FastAPI, Django, Spring
- **Advanced Analysis**:
  - AST-based static analysis
  - Pattern matching with metavariables
  - Taint analysis for dataflow tracking
  - Vulnerability detection with CWE/OWASP mapping
- **GitHub Integration**: Clone and analyze repositories directly
- **File Upload**: Support for ZIP file uploads
- **Real-time Processing**: Asynchronous analysis with status tracking
- **Visual Threat Modeling**: Generate interactive threat maps
- **Auto-fix Suggestions**: Automated remediation recommendations

## Quick Start

### Prerequisites

- Go 1.21 or higher
- Git (for repository cloning)

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd adaptive-threat-modeler/backend
```

2. Install dependencies:
```bash
go mod tidy
```

3. Copy environment configuration:
```bash
cp env.example .env
```

4. Run the server:
```bash
go run main.go
```

The server will start on `http://localhost:8080`

### Docker

Build and run with Docker:

```bash
docker build -t adaptive-threat-modeler .
docker run -p 8080:8080 adaptive-threat-modeler
```

## API Endpoints

### Analysis Endpoints

#### Analyze GitHub Repository
```http
POST /api/v1/analyze/github
Content-Type: application/json

{
  "repo_url": "https://github.com/user/repo",
  "branch": "main" // optional
}
```

#### Analyze Uploaded File
```http
POST /api/v1/analyze/upload
Content-Type: multipart/form-data

file: <zip_file>
```

#### Get Analysis Result
```http
GET /api/v1/analysis/{id}
```

#### Get Analysis Status
```http
GET /api/v1/analysis/{id}/status
```

### Detection Endpoints

#### Detect Languages
```http
POST /api/v1/detect/languages
Content-Type: application/json

{
  "project_path": "/path/to/project",
  "files": ["file1.go", "file2.js"] // optional
}
```

#### Detect Frameworks
```http
POST /api/v1/detect/frameworks
Content-Type: application/json

{
  "project_path": "/path/to/project",
  "languages": ["go", "javascript"] // optional
}
```

### Rules Endpoints

#### Get All Rules
```http
GET /api/v1/rules
```

#### Get Rules for Language
```http
GET /api/v1/rules/{language}
```

### System Endpoints

#### Health Check
```http
GET /health
```

#### System Information
```http
GET /api/v1/info
```

## Response Format

### Analysis Result
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
  "vulnerabilities": [
    {
      "id": "vuln_id",
      "title": "SQL Injection",
      "description": "...",
      "severity": "high",
      "category": "injection",
      "cwe": "CWE-89",
      "owasp": "A03:2021",
      "location": {
        "file": "main.go",
        "line": 42,
        "column": 10
      },
      "evidence": "db.Query(query + userInput)",
      "impact": "...",
      "remediation": [...],
      "autofix": {
        "description": "Use parameterized queries",
        "old_code": "db.Query(query + userInput)",
        "new_code": "db.Query(query, userInput)",
        "confidence": "high"
      }
    }
  ],
  "threat_map": {
    "components": [...],
    "flows": [...],
    "trust_zones": [...],
    "assets": [...]
  },
  "summary": {
    "total_vulnerabilities": 5,
    "severity_breakdown": {
      "critical": 1,
      "high": 2,
      "medium": 2,
      "low": 0
    },
    "risk_score": 42.5,
    "security_posture": "fair"
  },
  "recommendations": [...],
  "status": "completed",
  "processing_time": "2.5s"
}
```

## Configuration

### Environment Variables

- `PORT`: Server port (default: 8080)
- `TEMP_DIR`: Temporary directory for analysis (default: /tmp)
- `MAX_FILE_SIZE`: Maximum upload size in bytes (default: 100MB)
- `ALLOWED_ORIGINS`: CORS allowed origins
- `ENABLE_DATAFLOW_ANALYSIS`: Enable taint analysis (default: true)
- `MAX_ANALYSIS_TIME`: Maximum analysis time in seconds (default: 300)

## Architecture

### Core Components

1. **API Layer** (`internal/api`): HTTP endpoints and routing
2. **Handlers** (`internal/handlers`): Request processing logic
3. **Services** (`internal/services`): Core business logic
   - `Analyzer`: Main analysis orchestration
   - `ProjectDetector`: Language and framework detection
   - `RuleEngine`: Security rule management
   - `ASTParser`: Abstract Syntax Tree parsing
   - `PatternMatcher`: Advanced pattern matching
   - `DataFlowAnalyzer`: Taint analysis and dataflow tracking
4. **Models** (`internal/models`): Data structures and types

### Analysis Flow

1. **Input Processing**: GitHub clone or ZIP extraction
2. **Project Detection**: Identify languages, frameworks, services
3. **Rule Loading**: Load relevant security rules
4. **AST Parsing**: Parse source files into ASTs
5. **Vulnerability Detection**: Apply rules and patterns
6. **Dataflow Analysis**: Track taint flows (optional)
7. **Result Aggregation**: Combine findings and generate report
8. **Threat Modeling**: Create visual threat map

## Security Rules

The system includes built-in security rules for:

- **Injection Attacks**: SQL injection, command injection, XSS
- **Authentication Issues**: Hardcoded credentials, weak authentication
- **Cryptographic Problems**: Weak algorithms, improper key management
- **Configuration Issues**: Missing security headers, improper CORS
- **Code Quality**: Debug code, TODO comments, insecure functions

### Custom Rules

You can add custom rules by implementing the `SecurityRule` interface:

```go
type SecurityRule struct {
    ID          string
    Title       string
    Description string
    Severity    string
    Category    string
    Language    string
    Pattern     RulePattern
    // ... other fields
}
```

## Development

### Running Tests

```bash
go test ./...
```

### Building

```bash
go build -o adaptive-threat-modeler .
```

### Adding New Languages

1. Add language detection patterns to `ProjectDetector`
2. Implement AST parsing in `ASTParser`
3. Add language-specific rules to `RuleEngine`
4. Update pattern matching in `PatternMatcher`

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

[License information here]

