
# Adaptive Threat Modeler

## Table of Contents

1. [Project Overview](#project-overview)
2. [Architecture](#architecture)
3. [Key Features](#key-features)
4. [Technology Stack](#technology-stack)
5. [MCP Integration](#mcp-integration)
6. [Security Analysis Engine](#security-analysis-engine)
7. [API Endpoints](#api-endpoints)
8. [Configuration](#configuration)
9. [Deployment](#deployment)
10. [Development Guide](#development-guide)

---

## Project Overview

**Adaptive Threat Modeler** is an AI-powered security analysis platform that continuously detects vulnerabilities in codebases. It combines static analysis, taint tracking, and AI-driven insights to identify security issues across multiple programming languages and frameworks.

---

## Key Features

* **Multi-language Support**: Go, Python, JavaScript, TypeScript, Java, PHP, C#, C++, Rust, Ruby
* **Framework Detection**: React, Vue, Angular, Express, Django, FastAPI, Spring, Fiber, Gin, Echo
* **Advanced Analysis**: AST parsing, regex-based rules, semantic/taint analysis
* **GitHub & File Uploads**: Scan repositories or upload ZIPs directly
* **Visual Threat Modeling**: Generate interactive threat maps
* **Auto-fix Suggestions**: Automated remediation recommendations
* **MCP Integration**: AI-powered analysis, GitHub issue creation, Slack alerts

---

## Architecture

The project follows a microservices architecture with three main components:
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │    │    Backend      │    │   MCP Service   │
│   (React/TS)    │◄──►│   (Go/Fiber)    │◄──►│   (Python/AI)   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   User Interface│    │  Analysis Engine│    │  AI Analysis    │
│   & UX          │    │  & Rule Engine  │    │  & Notifications│
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

---

## Technology Stack

* **Backend (Go + Fiber):** AST parsing, regex analysis, rule engine
* **Frontend (React + TS + Tailwind):** Interactive UI, 3D threat visualization (Three.js)
* **MCP Service (Python):** LangChain + Semgrep, GitHub & Slack integration

---

## MCP Integration

* **Multi-agent AI system** for security insights
* **GitHub automation**: creates structured issues with severity labels
* **Slack alerts**: severity-based notifications with action buttons
* **Security pipeline**:

  1. Fetch code from backend
  2. Run Semgrep checks
  3. AI analysis & reporting
  4. Create GitHub issues + notify via Slack

---

## Security Analysis Engine

* **Input Handling**: GitHub repos or ZIP uploads
* **Project Detection**: Languages, frameworks, dependencies
* **Rule Matching**: Language & framework-specific rules
* **Vulnerability Detection**: Regex, AST, semantic & taint analysis
* **Results**: Threat maps, risk scoring, remediation recommendations

---

## API Endpoints

* **POST `/api/v1/analyze/github`** – Analyze GitHub repo
* **POST `/api/v1/analyze/upload`** – Analyze ZIP upload
* **GET `/api/v1/analysis/{id}`** – Retrieve analysis results
* **POST `/api/v1/detect/languages`** – Detect languages
* **POST `/api/v1/detect/frameworks`** – Detect frameworks
* **GET `/health`** – Service health check

---

## Configuration

Set environment variables for:

* **Backend:** `PORT`, `MAX_FILE_SIZE`, `ENABLE_DATAFLOW_ANALYSIS`
* **MCP Service:** `GITHUB_TOKEN`, `SLACK_WEBHOOK_URL`, `OPENAI_API_KEY`

---

## Deployment

### Docker Compose

```yaml
version: '3.8'
services:
  backend:
    build: ./backend
    ports: ["8080:8080"]

  frontend:
    build: ./frontend
    ports: ["3000:3000"]
    depends_on: [backend]

  mcp:
    build: ./mcp
    environment:
      - GITHUB_TOKEN=${GITHUB_TOKEN}
      - SLACK_WEBHOOK_URL=${SLACK_WEBHOOK_URL}
    depends_on: [backend]
```

---

## Development Guide

### Prerequisites

* Go 1.21+
* Node.js 18+
* Python 3.8+
* Git & Docker

### Run Backend

```bash
cd backend
go run main.go
```

### Run Frontend

```bash
cd frontend
npm install
npm run dev
```

### Run MCP Service

```bash
cd mcp
pip install -r requirements.txt
python api.py
```

---

