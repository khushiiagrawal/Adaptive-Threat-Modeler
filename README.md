# Adaptive Threat Modeler


A powerful security analysis tool that scans codebases for vulnerabilities, generates visual threat maps, and provides actionable remediation steps. Simply point it at a GitHub repository or upload a ZIP file to get started.

---

## 📖 Table of Contents

- [Key Features](#-key-features)
- [Quick Start](#-quick-start)
- [Architecture](#-architecture)
- [Monitoring](#-monitoring)
- [Project Structure](#-project-structure)
- [API Reference](#-api-reference)
- [Configuration](#-configuration)
- [Tech Stack](#-tech-stack)
- [Development](#-development)
- [Documentation](#-documentation)

---

## ⭐️ Key Features

- **Comprehensive Security Scans**: Detects SQL injection, XSS, hardcoded secrets, and more.
- **Multi-Language Support**: Supports 10+ languages including Go, Python, JavaScript, TypeScript, Java, PHP, C#, C++, Rust, and Ruby.
- **Framework Detection**: Automatically identifies frameworks like React, Django, Spring, and more.
- **Visual Threat Mapping**: Generates interactive visual maps of your application's threat landscape.
- **Actionable Insights**: Provides suggested fixes for detected vulnerabilities.
- **Real-time Monitoring**: Integrated Prometheus and Grafana for system health and analysis metrics.

---

## ⚡ Quick Start

### Local Development

Run the backend and frontend in separate terminals:

```bash
# Backend
cd backend && go run main.go
```

```bash
# Frontend
cd frontend && npm install && npm run dev
```

Visit **[http://localhost:5173](http://localhost:5173)** to access the application.

### Docker Compose

Spin up the entire stack including Prometheus and Grafana:

```bash
docker-compose up -d
```

### Kubernetes (Minikube)

Deploy to a local Kubernetes cluster:

```bash
# Start cluster and enable ingress
minikube start
minikube addons enable ingress

# Build images
eval $(minikube docker-env)
docker build -t threat-modeler-backend:latest ./backend
docker build -t threat-modeler-frontend:latest ./frontend

# Deploy with Helm
helm install threat-modeler ./helm/threat-modeler -n threat-modeler --create-namespace

# Port forward frontend
kubectl port-forward svc/frontend 3000:80 -n threat-modeler
```

Visit **[http://localhost:3000](http://localhost:3000)**.

---

## 🏗 Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                         Kubernetes Cluster                           │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │                    Ingress Controller                          │  │
│  │              (threat-modeler.local)                            │  │
│  └─────────────────────────┬──────────────────────────────────────┘  │
│                            │                                         │
│         ┌──────────────────┴──────────────────┐                      │
│         │                                      │                     │
│         ▼                                      ▼                     │
│  ┌─────────────────┐                   ┌─────────────────┐           │
│  │    Frontend     │                   │    Backend      │           │
│  │   (React/Nginx) │                   │   (Go/Fiber)    │           │
│  │     Port 80     │                   │    Port 8080    │           │
│  └─────────────────┘                   └────────┬────────┘           │
│                                                  │                   │
│                           ┌──────────────────────┤                   │
│                           │                      │                   │
│                           ▼                      ▼                   │
│                    ┌─────────────┐        ┌─────────────┐            │
│                    │ Prometheus  │◄───────│  /metrics   │            │
│                    │   :9090     │        └─────────────┘            │
│                    └──────┬──────┘                                   │
│                           │                                          │
│                           ▼                                          │
│                    ┌─────────────┐                                   │
│                    │   Grafana   │                                   │
│                    │    :3000    │                                   │
│                    └─────────────┘                                   │
│                                                                      │
│                   Namespace: threat-modeler                          │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

**Request Flow:**
1. **Ingress**: Routes `/api/*` to the Backend and all other traffic to the Frontend.
2. **Frontend**: Serves the React application.
3. **Backend**: Handles repository cloning, rule execution, and results generation.
4. **Monitoring**: Prometheus scrapes metrics from the Backend; Grafana visualizes them.

---

## 📊 Monitoring

The stack comes pre-configured with **Prometheus** and **Grafana** for real-time monitoring and alerting.

### Dashboard Preview

<!-- POST_SCREENSHOT_HERE: Add a screenshot of the Grafana dashboard showing request latency, error rates, and analysis metrics. -->
![alt text](<Screenshot 2026-02-02 at 1.57.15 AM.png>) ![alt text](<Screenshot 2026-02-02 at 1.56.49 AM.png>) ![alt text](<Screenshot 2026-02-02 at 1.57.39 AM.png>)

### Key Metrics
- **`http_requests_total`**: Request counts by endpoint and status.
- **`http_request_duration_seconds`**: Latency distribution histograms.
- **`analysis_total`**: Count of analysis runs broken down by type and status.
- **`vulnerabilities_detected_total`**: Findings aggregated by severity and category.

### Accessing Dashboards
Once deployed to Kubernetes:

```bash
# Grafana (default creds: admin/admin)
kubectl port-forward svc/grafana 3001:80 -n threat-modeler

# Prometheus
kubectl port-forward svc/prometheus 9090:9090 -n threat-modeler
```

---

## 📂 Project Structure

```bash
.
├── backend/                 # Go API server
│   ├── internal/rules/      # Security detection rules
│   └── internal/metrics/    # Prometheus metrics configuration
├── frontend/                # React + Vite + TypeScript application
├── helm/threat-modeler/     # Helm chart for K8s deployment
├── k8s/base/                # Raw Kubernetes manifests
├── docker-compose.yml       # Local development orchestration
└── grafana-dashboard.json   # Pre-configured Grafana dashboard
```

---

## 🔌 API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/analyze/github` | `POST` | Trigger analysis for a GitHub repository. |
| `/api/v1/analyze/upload` | `POST` | Analyze an uploaded ZIP file. |
| `/api/v1/analysis/{id}` | `GET` | Retrieve results for a specific analysis. |
| `/health` | `GET` | Service health check. |
| `/metrics` | `GET` | Prometheus metrics endpoint. |

**Example Request:**

```bash
curl -X POST http://localhost:8080/api/v1/analyze/github \
  -H "Content-Type: application/json" \
  -d '{"url": "https://github.com/owner/repo"}'
```

---

## ⚙️ Configuration

### Backend Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | Server listening port. |
| `MAX_FILE_SIZE` | `100MB` | Maximum allowed upload size. |
| `LOG_LEVEL` | `info` | Logging verbosity (debug, info, warn, error). |

### Helm Values (`helm/threat-modeler/values.yaml`)

```yaml
backend:
  replicaCount: 1      # Uses in-memory state, easier with 1 replica
  image:
    repository: threat-modeler-backend
    tag: latest

frontend:
  replicaCount: 2

ingress:
  enabled: true
  host: threat-modeler.local
```

---

## 🛠 Tech Stack

| Domain | Technologies |
|--------|--------------|
| **Backend** | Go 1.23, Fiber, Prometheus Client |
| **Frontend** | React 18, Vite, TypeScript, Tailwind CSS |
| **Infrastructure** | Kubernetes, Helm, Nginx Ingress |
| **Monitoring** | Prometheus, Grafana |
| **DevOps** | Docker, Multi-stage builds |

---

## 💻 Development

### Prerequisites
- **Go** 1.21+
- **Node.js** 18+
- **Docker**
- **kubectl** & **Helm**

### Running Tests

```bash
# Backend Tests
cd backend && go test ./...

# Frontend Tests
cd frontend && npm test
```

### Building Images

```bash
docker build -t threat-modeler-backend:latest ./backend
docker build -t threat-modeler-frontend:latest ./frontend
```

---

## 📚 Documentation

- [**KUBERNETES.md**](./KUBERNETES.md): Detailed guide for Kubernetes deployment.
- [**MONITORING.md**](./MONITORING.md): Comprehensive documentation on metrics, dashboards, and alerting.
