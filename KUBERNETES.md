# Kubernetes Deployment Guide

This guide explains how to deploy Adaptive Threat Modeler to Kubernetes using either raw manifests or Helm charts.

## Prerequisites

- Docker installed
- kubectl configured with cluster access
- For local development: [minikube](https://minikube.sigs.k8s.io/) or [kind](https://kind.sigs.k8s.io/)
- For Helm: [Helm 3.x](https://helm.sh/docs/intro/install/)

## Quick Start with Minikube

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

## Directory Structure

```
k8s/
├── base/                          # Raw Kubernetes manifests
│   ├── namespace.yaml             # Namespace definition
│   ├── backend-configmap.yaml     # Backend configuration
│   ├── backend.yaml               # Backend Deployment + Service
│   ├── frontend.yaml              # Frontend Deployment + Service
│   ├── ingress.yaml               # Ingress routing rules
│   └── kustomization.yaml         # Kustomize config
│
helm/
└── threat-modeler/                # Helm chart
    ├── Chart.yaml                 # Chart metadata
    ├── values.yaml                # Default configuration
    └── templates/                 # Kubernetes templates
        ├── _helpers.tpl           # Template helpers
        ├── namespace.yaml
        ├── backend-configmap.yaml
        ├── backend.yaml
        ├── frontend.yaml
        └── ingress.yaml
```

## Option 1: Deploy with Kustomize (Raw Manifests)

```bash
# Build images first
docker build -t threat-modeler-backend:latest ./backend
docker build -t threat-modeler-frontend:latest ./frontend

# Apply all manifests
kubectl apply -k k8s/base/

# Check status
kubectl get all -n threat-modeler
```

## Option 2: Deploy with Helm

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

## Customizing with Helm Values

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

## Verifying the Deployment

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

### Monitoring Access

The deployment includes Prometheus and Grafana for monitoring.

**Access Grafana:**
1. **Port Forward:**
   ```bash
   kubectl port-forward svc/grafana 3000:80 -n threat-modeler
   ```
2. Open [http://localhost:3000](http://localhost:3000)
3. Login: `admin` / `admin`

**Access Prometheus:**
1. **Port Forward:**
   ```bash
   kubectl port-forward svc/prometheus 9090:9090 -n threat-modeler
   ```
2. Open [http://localhost:9090](http://localhost:9090)

---
## Troubleshooting

### Pods in CrashLoopBackOff
```bash
# Check logs
kubectl logs <pod-name> -n threat-modeler

# Describe pod for events
kubectl describe pod <pod-name> -n threat-modeler
```

### Ingress not working
```bash
# Ensure ingress controller is running
kubectl get pods -n ingress-nginx

# Check ingress status
kubectl describe ingress threat-modeler-ingress -n threat-modeler
```

### Image pull errors
```bash
# If using minikube, ensure images are built in minikube's Docker
eval $(minikube docker-env)
docker build -t threat-modeler-backend:latest ./backend
```

## Architecture Diagram

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
