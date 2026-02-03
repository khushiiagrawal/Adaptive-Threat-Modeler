# Deployment, Monitoring & Features Guide

This comprehensive guide covers Kubernetes deployment, monitoring setup, and features of the Adaptive Threat Modeler.

---

## Table of Contents

1. [Docker Hub Deployment](#docker-hub-deployment)
2. [Understanding the Components](#understanding-the-components)
3. [Kubernetes Deployment](#kubernetes-deployment)
4. [Monitoring with Prometheus & Grafana](#monitoring-with-prometheus--grafana)
5. [Analysis Logs Feature](#analysis-logs-feature)

---

## Docker Hub Deployment

### 📦 Published Images

The project images are available on Docker Hub:
- **Backend**: [khushiiagrawal/threat-modeler-backend](https://hub.docker.com/r/khushiiagrawal/threat-modeler-backend)
- **Frontend**: [khushiiagrawal/threat-modeler-frontend](https://hub.docker.com/r/khushiiagrawal/threat-modeler-frontend)

### 🔄 How to Update Images

When you make changes to the code, follow these steps to build and push new versions:

**1. Build the images**:
```bash
cd /path/to/Adaptive-Threat-Modeler

# Build backend
docker build -t khushiiagrawal/threat-modeler-backend:latest \
             -t khushiiagrawal/threat-modeler-backend:v1.0.1 \
             ./backend

# Build frontend
docker build -t khushiiagrawal/threat-modeler-frontend:latest \
             -t khushiiagrawal/threat-modeler-frontend:v1.0.1 \
             ./frontend
```

**2. Login to Docker Hub**:
```bash
docker login
# Enter your Docker Hub username and password
```

**3. Push to Docker Hub**:
```bash
# Push backend
docker push khushiiagrawal/threat-modeler-backend:latest
docker push khushiiagrawal/threat-modeler-backend:v1.0.1

# Push frontend
docker push khushiiagrawal/threat-modeler-frontend:latest
docker push khushiiagrawal/threat-modeler-frontend:v1.0.1
```

**4. Update Kubernetes to use new version**:
```bash
# Option 1: Edit k8s/base/backend.yaml and frontend.yaml
# Change: image: khushiiagrawal/threat-modeler-backend:v1.0.1

# Option 2: Use Helm with new values
helm upgrade threat-modeler ./helm/threat-modeler \
  --set backend.image.tag=v1.0.1 \
  --set frontend.image.tag=v1.0.1 \
  -n threat-modeler
```

### 📍 Where Docker Images are Used

**1. Kubernetes Manifests (`k8s/base/`)**:
- `backend.yaml`: Uses `khushiiagrawal/threat-modeler-backend:v1.0.0`
- `frontend.yaml`: Uses `khushiiagrawal/threat-modeler-frontend:v1.0.0`

**2. Helm Chart (`helm/threat-modeler/values.yaml`)**:
```yaml
backend:
  image:
    repository: khushiiagrawal/threat-modeler-backend
    tag: v1.0.0
    
frontend:
  image:
    repository: khushiiagrawal/threat-modeler-frontend
    tag: v1.0.0
```

**3. Docker Compose** (for local dev - still uses local builds):
- Uses locally built images for development

### 🎯 Benefits of Using Docker Hub

| Benefit | Description |
|---------|-------------|
| **Public Access** | Anyone can deploy your app without building from source |
| **Version Control** | Track different versions with tags (v1.0.0, v1.0.1, etc.) |
| **Fast Deployment** | Kubernetes pulls pre-built images instead of building |
| **CI/CD Ready** | Automated pipelines can push images after tests pass |
| **Rollback** | Easy to revert to previous versions by changing tag |

---

## Understanding the Components

This section explains all the DevOps tools and technologies used in this project, why they're needed, and what each file does.

### 🐳 Docker

**What it is**: Docker packages your application and its dependencies into containers - lightweight, standalone executable units.

**Why we use it**: 
- Ensures the app runs the same everywhere (your laptop, server, cloud)
- No more "works on my machine" problems
- Easy to build, share, and deploy

**Files in this project**:

| File | Purpose |
|------|---------|
| `backend/Dockerfile` | Builds the Go API server image |
| `frontend/Dockerfile` | Builds the React app image (served via Nginx) |
| `docker-compose.yml` | Runs everything locally with one command |

---

### ☸️ Kubernetes (K8s)

**What it is**: Kubernetes is a container orchestration platform. It manages, scales, and heals your containers automatically.

**Why we use it**:
- **Scaling**: Run multiple copies of your app to handle more traffic
- **Self-healing**: If a container crashes, K8s restarts it automatically
- **Load balancing**: Distributes traffic across all your app instances
- **Rolling updates**: Deploy new versions without downtime

**Key Concepts**:

| Concept | What it does |
|---------|--------------|
| **Pod** | Smallest unit - one or more containers running together |
| **Deployment** | Manages pods - ensures desired number are always running |
| **Service** | Stable network endpoint to access pods (pods have changing IPs) |
| **ConfigMap** | Stores configuration (env variables) separate from code |
| **Ingress** | Routes external HTTP traffic to services inside the cluster |
| **Namespace** | Logical isolation - like folders for your K8s resources |

**Files in `k8s/base/`**:

| File | What it creates | Purpose |
|------|-----------------|---------|
| `namespace.yaml` | Namespace | Creates `threat-modeler` namespace to isolate our resources |
| `backend-configmap.yaml` | ConfigMap | Environment variables for the backend (PORT, LOG_LEVEL, etc.) |
| `backend.yaml` | Deployment + Service | Runs Go API pods and exposes them internally on port 8080 |
| `frontend.yaml` | Deployment + Service | Runs React/Nginx pods and exposes them internally on port 80 |
| `ingress.yaml` | Ingress | Routes `threat-modeler.local` traffic to frontend/backend |
| `kustomization.yaml` | Kustomize config | Lists all files to apply together |

---

### 📦 Kustomize

**What it is**: A Kubernetes-native configuration management tool. It's built into `kubectl`.

**Why we use it**:
- Apply multiple YAML files in order with one command
- Add common labels to all resources
- No templating - just plain YAML with patches

**How it works**:
```bash
# Instead of applying files one by one:
kubectl apply -f namespace.yaml
kubectl apply -f configmap.yaml
kubectl apply -f backend.yaml
# ...

# Just run:
kubectl apply -k k8s/base/
```

**Our `kustomization.yaml`**:
```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
namespace: threat-modeler
resources:
  - namespace.yaml
  - backend-configmap.yaml
  - backend.yaml
  - frontend.yaml
  - ingress.yaml
commonLabels:
  project: adaptive-threat-modeler
```

**When to use Kustomize vs Helm**:
- **Kustomize**: Simple deployments, no templating needed, quick testing
- **Helm**: Complex apps, need variables/templating, multiple environments

---

### ⎈ Helm

**What it is**: A package manager for Kubernetes - like `npm` for Node.js or `apt` for Ubuntu.

**Why we use it**:
- **Templating**: Use variables instead of hardcoding values
- **Reusability**: One chart, many environments (dev, staging, prod)
- **Versioning**: Track chart versions, easy rollback
- **One command**: Install/upgrade/uninstall entire applications

**Helm vs Raw Manifests**:

| Raw YAML | Helm |
|----------|------|
| `replicas: 2` (hardcoded) | `replicas: {{ .Values.backend.replicaCount }}` |
| Edit files to change config | `helm upgrade --set backend.replicaCount=5` |
| No versioning | `helm rollback threat-modeler 1` |

**Files in `helm/threat-modeler/`**:

| File | Purpose |
|------|---------|
| `Chart.yaml` | Chart metadata (name, version, description) |
| `values.yaml` | Default configuration values |
| `templates/` | Kubernetes YAML templates with `{{ }}` placeholders |

**Templates in `helm/threat-modeler/templates/`**:

| Template | Creates | Purpose |
|----------|---------|---------|
| `_helpers.tpl` | Nothing | Helper functions for naming, labels (reusable snippets) |
| `namespace.yaml` | Namespace | Creates the namespace |
| `backend-configmap.yaml` | ConfigMap | Backend environment variables from `values.yaml` |
| `backend.yaml` | Deployment + Service | Backend pods with configurable replicas, resources |
| `frontend.yaml` | Deployment + Service | Frontend pods with configurable replicas |
| `ingress.yaml` | Ingress | Configurable host and annotations |
| `prometheus-configmap.yaml` | ConfigMap | Prometheus scrape configuration |
| `prometheus.yaml` | Deployment + Service | Prometheus server |
| `grafana.yaml` | Deployment + Service | Grafana dashboard server |
| `grafana-datasource-config.yaml` | ConfigMap | Tells Grafana where Prometheus is |
| `grafana-dashboard-config.yaml` | ConfigMap | Pre-built dashboard JSON |
| `grafana-provider-config.yaml` | ConfigMap | Dashboard auto-loading config |

**Example - How templating works**:

`values.yaml`:
```yaml
backend:
  replicaCount: 2
  image:
    repository: threat-modeler-backend
    tag: latest
```

`templates/backend.yaml`:
```yaml
spec:
  replicas: {{ .Values.backend.replicaCount }}
  template:
    spec:
      containers:
      - name: backend
        image: {{ .Values.backend.image.repository }}:{{ .Values.backend.image.tag }}
```

**Result after `helm install`**:
```yaml
spec:
  replicas: 2
  template:
    spec:
      containers:
      - name: backend
        image: threat-modeler-backend:latest
```

---

### 📊 Prometheus

**What it is**: An open-source monitoring and alerting system. It collects and stores metrics as time-series data.

**Why we use it**:
- **Pull-based**: Prometheus scrapes metrics from your app's `/metrics` endpoint
- **Powerful queries**: PromQL language for analyzing metrics
- **Alerting**: Define rules to get notified when things go wrong
- **Industry standard**: Works with everything, huge ecosystem

**How it works**:
```
┌─────────────┐     scrapes /metrics     ┌─────────────┐
│  Backend    │ ◄──────────────────────  │ Prometheus  │
│  (Go API)   │      every 15 seconds    │   Server    │
└─────────────┘                          └──────┬──────┘
                                                │
                                                ▼
                                         Stores metrics
                                         in time-series DB
```

**Files for Prometheus**:

| File | Purpose |
|------|---------|
| `prometheus.yml` | Main config - what to scrape and how often |
| `alert_rules.yml` | Alert definitions (e.g., "alert if error rate > 10/sec") |
| `helm/templates/prometheus.yaml` | K8s Deployment + Service for Prometheus |
| `helm/templates/prometheus-configmap.yaml` | Prometheus config as ConfigMap |

**What `prometheus.yml` does**:
```yaml
global:
  scrape_interval: 15s          # How often to collect metrics

scrape_configs:
  - job_name: 'threat-modeler-backend'
    static_configs:
      - targets: ['backend:8080']  # Where to scrape from
```

---

### 📈 Grafana

**What it is**: A visualization platform that turns metrics into beautiful, actionable dashboards.

**Why we use it**:
- **Visualize**: Graphs, charts, gauges for your metrics
- **Dashboards**: Pre-built or custom dashboards
- **Alerts**: Visual alerting integrated with Prometheus
- **Multi-source**: Can pull from Prometheus, databases, logs, etc.

**How it connects**:
```
┌─────────────┐      queries       ┌─────────────┐     visualizes    ┌─────────────┐
│ Prometheus  │ ◄────────────────  │   Grafana   │ ────────────────► │  Dashboard  │
│  (metrics)  │     via PromQL     │   Server    │                   │   (UI)      │
└─────────────┘                    └─────────────┘                   └─────────────┘
```

**Files for Grafana**:

| File | Purpose |
|------|---------|
| `grafana-dashboard.json` | Pre-built dashboard with panels for our metrics |
| `grafana/provisioning/` | Auto-configuration on startup |
| `helm/templates/grafana.yaml` | K8s Deployment + Service |
| `helm/templates/grafana-datasource-config.yaml` | Connects Grafana → Prometheus |
| `helm/templates/grafana-dashboard-config.yaml` | Loads our dashboard JSON |
| `helm/templates/grafana-provider-config.yaml` | Tells Grafana where dashboards are |

**Grafana provisioning files explained**:

| Config | What it does |
|--------|--------------|
| `datasources/` | Defines data sources (Prometheus URL, auth, etc.) |
| `dashboards/` | Points to dashboard JSON files to auto-import |

---

### 🐙 Docker Compose

**What it is**: A tool for defining and running multi-container Docker applications locally.

**Why we use it**:
- **Local development**: Run entire stack with one command
- **No K8s needed**: Great for testing before deploying to Kubernetes
- **Includes monitoring**: Backend + Prometheus + Grafana together

**Our `docker-compose.yml`**:
```yaml
services:
  prometheus:
    image: prom/prometheus
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
    ports:
      - "9090:9090"
      
  grafana:
    image: grafana/grafana
    volumes:
      - ./grafana/provisioning:/etc/grafana/provisioning
    ports:
      - "3001:3000"
```

---

### 📁 Complete File Structure Explained

```
.
├── docker-compose.yml           # Local dev: runs Prometheus + Grafana
├── prometheus.yml               # Prometheus scrape configuration
├── alert_rules.yml              # Prometheus alerting rules
├── grafana-dashboard.json       # Pre-built Grafana dashboard
│
├── grafana/
│   └── provisioning/
│       ├── dashboards/          # Dashboard auto-import config
│       └── datasources/         # Prometheus datasource config
│
├── k8s/
│   └── base/                    # Raw Kubernetes manifests
│       ├── namespace.yaml       # Creates threat-modeler namespace
│       ├── backend-configmap.yaml   # Backend env vars
│       ├── backend.yaml         # Backend Deployment + Service
│       ├── frontend.yaml        # Frontend Deployment + Service
│       ├── ingress.yaml         # Routes external traffic
│       └── kustomization.yaml   # Kustomize config
│
└── helm/
    └── threat-modeler/          # Helm chart
        ├── Chart.yaml           # Chart metadata
        ├── values.yaml          # Configurable values
        └── templates/           # K8s templates
            ├── _helpers.tpl     # Helper functions
            ├── namespace.yaml
            ├── backend-configmap.yaml
            ├── backend.yaml
            ├── frontend.yaml
            ├── ingress.yaml
            ├── prometheus.yaml
            ├── prometheus-configmap.yaml
            ├── grafana.yaml
            ├── grafana-datasource-config.yaml
            ├── grafana-dashboard-config.yaml
            └── grafana-provider-config.yaml
```

---

### 🤔 When to Use What?

| Scenario | Use |
|----------|-----|
| Quick local testing | `docker-compose up` |
| Simple K8s deployment | `kubectl apply -k k8s/base/` |
| Production / multiple envs | Helm chart |
| Need to change config often | Helm with `--set` or custom `values.yaml` |
| CI/CD pipelines | Helm (versioned releases, easy rollback) |

---

## Kubernetes Deployment

### Prerequisites

- Docker installed
- kubectl configured with cluster access
- For local development: [minikube](https://minikube.sigs.k8s.io/) or [kind](https://kind.sigs.k8s.io/)
- For Helm: [Helm 3.x](https://helm.sh/docs/intro/install/)

### Quick Start with Minikube

```bash
# 1. Start minikube with ingress addon
minikube start
minikube addons enable ingress

# 2. Point Docker to minikube's daemon (so images are available in cluster)
eval $(minikube docker-env)

# 3. Build the Docker images
docker build -t threat-modeler-backend:latest ./backend
docker build -t threat-modeler-frontend:latest ./frontend

# 4. Deploy using Helm
cd helm/threat-modeler
helm install threat-modeler . --namespace threat-modeler --create-namespace

# 5. Add host entry (for ingress to work)
echo "$(minikube ip) threat-modeler.local" | sudo tee -a /etc/hosts

# 6. Open in browser
open http://threat-modeler.local
```

### Directory Structure

```
k8s/
├── base/                          # Raw Kubernetes manifests
│   ├── namespace.yaml             # Namespace definition
│   ├── backend-configmap.yaml     # Backend configuration
│   ├── backend.yaml               # Backend Deployment + Service
│   ├── frontend.yaml              # Frontend Deployment + Service
│   ├── ingress.yaml               # Ingress routing rules
│   └── kustomization.yaml         # Kustomize config

helm/
└── threat-modeler/                # Helm chart
    ├── Chart.yaml                 # Chart metadata
    ├── values.yaml                # Default configuration
    └── templates/                 # Kubernetes templates
```

### Option 1: Deploy with Kustomize (Raw Manifests)

```bash
# Build images first
docker build -t threat-modeler-backend:latest ./backend
docker build -t threat-modeler-frontend:latest ./frontend

# Apply all manifests
kubectl apply -k k8s/base/

# Check status
kubectl get all -n threat-modeler
```

### Option 2: Deploy with Helm

```bash
# Build images first
docker build -t threat-modeler-backend:latest ./backend
docker build -t threat-modeler-frontend:latest ./frontend

# Install the chart
helm install threat-modeler ./helm/threat-modeler \
  --namespace threat-modeler \
  --create-namespace

# Check status
kubectl get all -n threat-modeler

# View deployed values
helm get values threat-modeler -n threat-modeler

# Upgrade with new values
helm upgrade threat-modeler ./helm/threat-modeler \
  --namespace threat-modeler \
  --set backend.replicaCount=3

# Uninstall
helm uninstall threat-modeler -n threat-modeler
```

### Customizing with Helm Values

Create a custom `values-override.yaml`:

```yaml
# Production overrides
backend:
  replicaCount: 3
  resources:
    limits:
      memory: "1Gi"
      cpu: "1000m"

frontend:
  replicaCount: 3

ingress:
  host: threat-modeler.yourdomain.com
```

Then deploy with:
```bash
helm install threat-modeler ./helm/threat-modeler -f values-override.yaml
```

### Verifying the Deployment

```bash
# Check all pods are running
kubectl get pods -n threat-modeler

# Check services
kubectl get svc -n threat-modeler

# Check ingress
kubectl get ingress -n threat-modeler

# View pod logs
kubectl logs -l app=backend -n threat-modeler
kubectl logs -l app=frontend -n threat-modeler

# Port-forward to test locally (without ingress)
kubectl port-forward svc/backend 8080:8080 -n threat-modeler
kubectl port-forward svc/frontend 3000:80 -n threat-modeler
```

### Troubleshooting Kubernetes

#### Pods in CrashLoopBackOff
```bash
# Check logs
kubectl logs <pod-name> -n threat-modeler

# Describe pod for events
kubectl describe pod <pod-name> -n threat-modeler
```

#### Ingress not working
```bash
# Ensure ingress controller is running
kubectl get pods -n ingress-nginx

# Check ingress status
kubectl describe ingress threat-modeler-ingress -n threat-modeler
```

#### Image pull errors
```bash
# If using minikube, ensure images are built in minikube's Docker
eval $(minikube docker-env)
docker build -t threat-modeler-backend:latest ./backend
```

### Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    Kubernetes Cluster                        │
│                                                              │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              Ingress Controller (nginx)              │   │
│  └──────────────────────┬──────────────────────────────┘   │
│                         │                                    │
│    ┌────────────────────┼────────────────────┐              │
│    │                    │                    │              │
│    ▼                    ▼                    ▼              │
│  /api/*             /health            / (everything else)  │
│  /metrics                                                    │
│    │                    │                    │              │
│    ▼                    ▼                    ▼              │
│  ┌─────────────────────────┐  ┌─────────────────────────┐  │
│  │   Backend Service       │  │   Frontend Service       │  │
│  │   (ClusterIP:8080)      │  │   (ClusterIP:80)        │  │
│  └───────────┬─────────────┘  └───────────┬─────────────┘  │
│              │                            │                 │
│              ▼                            ▼                 │
│  ┌─────────────────────────┐  ┌─────────────────────────┐  │
│  │   Backend Pods          │  │   Frontend Pods         │  │
│  │   (Go/Fiber API)        │  │   (Nginx + React)       │  │
│  │   Replicas: 2           │  │   Replicas: 2           │  │
│  └─────────────────────────┘  └─────────────────────────┘  │
│                                                              │
│  Namespace: threat-modeler                                  │
└─────────────────────────────────────────────────────────────┘
```

---

## Monitoring with Prometheus & Grafana

### Overview

The monitoring stack includes:
- **Prometheus**: Metrics collection and storage
- **Grafana**: Visualization and dashboards
- **Alert Rules**: Automated alerting for critical events

### Quick Start

```bash
# Start all services (backend + monitoring)
docker-compose up -d

# View logs
docker-compose logs -f
```

### Access the Services

| Service | URL | Credentials |
|---------|-----|-------------|
| Backend API | http://localhost:8080 | - |
| Prometheus | http://localhost:9090 | - |
| Grafana | http://localhost:3001 | admin / admin |
| Metrics Endpoint | http://localhost:8080/metrics | - |

### Kubernetes Monitoring Access

```bash
# Port forward Grafana
kubectl port-forward svc/grafana 3000:80 -n threat-modeler

# Port forward Prometheus
kubectl port-forward svc/prometheus 9090:9090 -n threat-modeler
```

### Monitored Metrics

#### HTTP/API Metrics
- `http_requests_total` - Total HTTP requests by method, endpoint, and status
- `http_request_duration_seconds` - Request latency by endpoint (P50, P95, P99)
- `http_request_size_bytes` - Request payload sizes
- `http_response_size_bytes` - Response payload sizes

#### Analysis Engine Metrics
- `analysis_total` - Total analyses by type (github/upload) and status
- `analysis_duration_seconds` - Analysis duration histograms
- `analysis_in_progress` - Current number of running analyses
- `analysis_queue_depth` - Pending analyses in queue

#### Vulnerability Detection Metrics
- `vulnerabilities_detected_total` - Vulnerabilities by severity and category
- `vulnerabilities_by_language_total` - Vulnerabilities per programming language
- `vulnerabilities_by_framework_total` - Vulnerabilities per framework

#### System Resource Metrics
- `active_goroutines` - Active goroutine count
- `memory_usage_bytes` - Memory consumption
- `gc_pause_duration_seconds` - Garbage collection pause times

### Alert Rules

Pre-configured alerts in `alert_rules.yml`:

| Alert | Severity | Description |
|-------|----------|-------------|
| BackendServiceDown | Critical | Service unavailable for >1 minute |
| HighErrorRate | Critical | Error rate >10 errors/sec for 5 minutes |
| HighMemoryUsage | Critical | Memory usage >4GB for 5 minutes |
| HighAnalysisFailureRate | Warning | >20% analyses failing |
| HighAPILatency | Warning | P95 latency >5s for 10 minutes |
| HighGoroutineCount | Warning | >1000 goroutines for 10 minutes |

### Grafana Dashboard

The pre-built dashboard includes:
1. **System Overview** - Service status, request rate, analyses in progress
2. **Analysis Metrics** - Throughput, duration percentiles
3. **Vulnerability Detection** - By severity, category, language
4. **Performance Metrics** - API latency, HTTP status codes
5. **Resource Utilization** - Memory, goroutines, GC pauses

### PromQL Examples

```promql
# Request rate per endpoint
rate(http_requests_total[5m])

# Error percentage
rate(http_requests_total{status=~"5xx"}[5m]) / rate(http_requests_total[5m]) * 100

# P95 analysis duration
histogram_quantile(0.95, rate(analysis_duration_seconds_bucket[5m]))

# Top vulnerabilities by severity
topk(10, sum(increase(vulnerabilities_detected_total[1h])) by (severity, category))
```

### Stopping the Monitoring Stack

```bash
# Stop all services
docker-compose down

# Stop and remove volumes (deletes all metrics data)
docker-compose down -v
```

---

## Analysis Logs Feature

### Overview

The logs viewing feature allows users to view detailed analysis logs in an elegant UI after vulnerability scanning completes.

### How It Works

1. **Analysis Completion**: When analysis completes, users see:
   - Success message with vulnerability count
   - **"View Logs"** button redirecting to logs page

2. **Logs Page** (`/logs/{analysisId}`) includes:
   - Same layout with 3D brain animation
   - Syntax-highlighted logs
   - Copy to clipboard & download options

### Log Color Coding

| Color | Meaning |
|-------|---------|
| 🔴 Red | Critical vulnerabilities |
| 🟠 Orange | High severity |
| 🟡 Yellow | Medium severity |
| 🔵 Blue | Low severity |
| 🟢 Green | File analysis progress |
| 🟣 Purple | Risk scores & summaries |
| ⚪ Primary | Section headers |

### Sample Log Output

```
=== PROJECT ANALYSIS STARTED ===
Analysis ID: 3dc5edfe-a421-4815-92db-8efc75c6735b
Detected Languages: [hcl python javascript shell]
Config Files: [IAC/Dockerfile secrets/.env]
===============================

Found 5 vulnerability(ies) in file: IAC/s3.tf
  - [critical] Publicly Accessible S3 Bucket at line 20
  - [critical] Command Injection in Shell Script at line 42

=== ANALYSIS COMPLETED ===
Total vulnerabilities found: 93

=== VULNERABILITY SUMMARY ===
CRITICAL: 34 vulnerabilities
HIGH: 8 vulnerabilities
LOW: 51 vulnerabilities

=== ANALYSIS SUMMARY ===
Risk Score: 447.0
Security Posture: poor
==============================
```

### User Experience

1. **Start Analysis** → Enter GitHub URL or upload ZIP file
2. **Wait for Completion** → Progress shown during analysis
3. **View Results** → Success message with vulnerability count
4. **Access Logs** → Click "View Logs" for detailed output
5. **Interact** → Copy, download, or scroll through logs
6. **Return Home** → Easy navigation back

---

## Additional Resources

- [Prometheus Documentation](https://prometheus.io/docs/)
- [Grafana Documentation](https://grafana.com/docs/)
- [Kubernetes Documentation](https://kubernetes.io/docs/)
- [Helm Documentation](https://helm.sh/docs/)
