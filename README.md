# Adaptive Threat Modeler

A security analysis tool that scans codebases for vulnerabilities, generates threat maps, and helps you fix issues before they become problems. Just paste a GitHub URL or upload a ZIP file and let it do its thing.

---

## ✨ What It Does

- **Finds Security Issues**: Catches things like SQL injection, XSS, hardcoded secrets, insecure configurations, and more
- **Works with Multiple Languages**: Go, Python, JavaScript, TypeScript, Java, PHP, Rust, Ruby, C#, C++, and HCL (Terraform)
- **Detects Frameworks**: Recognizes React, Django, Spring, Express, and others automatically
- **Shows You What's Wrong**: Visual threat maps and clear explanations of each vulnerability
- **Tells You How to Fix It**: Actionable remediation steps for every finding
- **Tracks Everything**: Built-in monitoring with Prometheus and Grafana
- **MCP Integration**: AI-powered analysis with automated GitHub issue creation and Slack notifications

---

## 🚀 Getting Started

### Option 1: Local Development

Run backend and frontend in separate terminals:

```bash
# Terminal 1 - Backend
cd backend
go run main.go
```

```bash
# Terminal 2 - Frontend
cd frontend
npm install
npm run dev
```

Open **http://localhost:3000** in your browser.

### Option 2: Docker Compose

This spins up everything including monitoring:

```bash
docker-compose up -d
```

- App: http://localhost:3000
- Prometheus: http://localhost:9090
- Grafana: http://localhost:3001 (admin/admin)

### Option 3: Kubernetes (Production Ready)

Images are available on Docker Hub - no need to build locally!

```bash
# Start your cluster
minikube start  # or use any K8s cluster
minikube addons enable ingress

# Deploy using Helm (pulls images from Docker Hub)
helm install threat-modeler ./helm/threat-modeler -n threat-modeler --create-namespace

# For minikube - add to /etc/hosts
echo "$(minikube ip) threat-modeler.local" | sudo tee -a /etc/hosts
```

**Docker Hub Images**:
- `khushiiagrawal/threat-modeler-backend:latest`
- `khushiiagrawal/threat-modeler-frontend:latest`

Open **http://threat-modeler.local**

---

## ⚙️ How It Works

```
┌─────────────────────────────────────────────────────────────┐
│                        User                                 │
│            (GitHub URL or ZIP upload)                       │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                    Frontend (React)                         │
│              UI with 3D visuals                             │   
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                    Backend (Go/Fiber)                       │
│                                                             │
│  1. Clone repo / Extract ZIP                                │
│  2. Detect languages & frameworks                           │
│  3. Run security rules against code                         │
│  4. Generate threat map                                     │
│  5. Return results with fixes                               │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                    Monitoring                               │
│         Prometheus (metrics) → Grafana (dashboards)         │
└─────────────────────────────────────────────────────────────┘
```

The backend does the heavy lifting - it clones your repo, figures out what languages and frameworks you're using, runs a bunch of security rules, and gives you a nice report with everything it found.

---

## 📂 Project Structure

```
.
├── backend/                 # Go API server
│   ├── internal/
│   │   ├── handlers/        # API endpoint handlers
│   │   ├── services/        # Core analysis logic
│   │   └── metrics/         # Prometheus instrumentation
│   └── main.go
│
├── frontend/                # React + TypeScript app
│   └── src/
│       ├── components/      # UI components
│       ├── pages/           # Page views
│       └── services/        # API client
│
├── mcp/                     # MCP integration (AI + GitHub + Slack)
├── k8s/base/                # Kubernetes manifests
├── helm/threat-modeler/     # Helm chart
├── grafana/                 # Grafana provisioning
├── docker-compose.yml       # Local dev with monitoring
├── prometheus.yml           # Prometheus config
└── alert_rules.yml          # Alerting rules
```

---

## 🔌 API Endpoints

| Endpoint | Method | What it does |
|----------|--------|--------------|
| `/api/v1/analyze/github` | POST | Analyze a GitHub repo |
| `/api/v1/analyze/upload` | POST | Analyze an uploaded ZIP |
| `/api/v1/analysis/{id}` | GET | Get analysis results |
| `/api/v1/analysis/{id}/logs` | GET | Get detailed analysis logs |
| `/health` | GET | Health check |
| `/metrics` | GET | Prometheus metrics |

**Quick example:**

```bash
curl -X POST http://localhost:8080/api/v1/analyze/github \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/owner/repo"}'
```

---

## 🤖 MCP Integration (AI-Powered Analysis)

The MCP (Model Context Protocol) integration adds AI-powered security analysis with automated workflows.

### Features

- **GPT-4 + Semgrep**: AI-enhanced vulnerability detection
- **GitHub Integration**: Auto-creates issues for security findings
- **Slack Notifications**: Real-time alerts with action buttons

### Setup

```bash
cd mcp

# Install dependencies
pip install -r requirements.txt

# Run interactive setup
python setup_github_integration.py
```

### Environment Variables

Create a `.env` file in the `mcp/` directory:

```bash
# Required
OPENAI_API_KEY=your_openai_api_key

# GitHub Integration (optional)
GITHUB_TOKEN=ghp_your_personal_access_token
GITHUB_OWNER=your_username_or_org
GITHUB_REPO=your_repository_name

# Slack Integration (optional)
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK
```

### Running

```bash
# Test GitHub integration
python test_github_integration.py

# Run the analysis API
python api.py
```

See [mcp/README.md](./mcp/README.md) for detailed configuration and usage.

---

## 📊 Monitoring

Grafana dashboards show you:
- Request rates and latencies
- Analysis throughput
- Vulnerabilities found (by severity)
- System resources

Access after deployment:
```bash
# Grafana
kubectl port-forward svc/grafana 3001:80 -n threat-modeler
# Open http://localhost:3001 (admin/admin)

# Prometheus
kubectl port-forward svc/prometheus 9090:9090 -n threat-m<img width="1470" height="801" alt="Screenshot 2026-02-02 at 1 57 15 AM" src="https://github.com/user-attachments/assets/b0f33228-2adf-44c8-8899-7a843d71d57b" />
odeler
```



<img width="1470" height="801" alt="Screenshot 2026-02-02 at 1 57 15 AM" src="https://github.com/user-attachments/assets/36a645e8-251c-45db-a57c-1a05e92d672a" />

<img width="1470" height="801" alt="Screenshot 2026-02-02 at 1 57 39 AM" src="https://github.com/user-attachments/assets/5be619b8-0563-4137-839a-d54766715640" />
<img width="1470" height="801" alt="Screenshot 2026-02-02 at 1 56 49 AM" src="https://github.com/user-attachments/assets/0ec7dd1c-eb75-435c-95aa-2f6a8a2c03f2" />



---


## ⚙️ Configuration

Key environment variables for the backend:

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | Server port |
| `MAX_FILE_SIZE` | `100MB` | Max upload size |
| `LOG_LEVEL` | `info` | debug, info, warn, error |
| `ALLOWED_ORIGINS` | `localhost:3000` | CORS origins |

For Kubernetes, these are set in `k8s/base/backend-configmap.yaml`.

---

## 🛠 Tech Stack

**Backend**: Go 1.23, Fiber, Prometheus client  
**Frontend**: React 18, TypeScript, Vite, Tailwind CSS, Three.js  
**Infrastructure**: Docker, Kubernetes, Helm, Nginx Ingress  
**Monitoring**: Prometheus, Grafana

---

## 💻 Development

### Prerequisites
- Go 1.21+
- Node.js 18+
- Docker
- kubectl & Helm (for K8s deployment)

### Running Tests

```bash
# Backend
cd backend && go test ./...

# Frontend
cd frontend && npm test
```

### Building & Publishing Docker Images

**Build locally**:
```bash
docker build -t khushiiagrawal/threat-modeler-backend:latest ./backend
docker build -t khushiiagrawal/threat-modeler-frontend:latest ./frontend
```

**Push to Docker Hub**:
```bash
docker login
docker push khushiiagrawal/threat-modeler-backend:latest
docker push khushiiagrawal/threat-modeler-frontend:latest
```

**Public Images**: Available at [Docker Hub](https://hub.docker.com/u/khushiiagrawal)

---

## 📚 More Info

Check out [DEPLOYMENT.md](./DEPLOYMENT.md) for detailed docs on:
- Docker Hub deployment and image management
- Understanding all components (Docker, Kubernetes, Helm, Prometheus, Grafana)
- Kubernetes deployment options
- Monitoring setup and metrics
- Analysis logs feature
