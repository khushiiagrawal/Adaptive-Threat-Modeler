#!/bin/bash
# deploy.sh - Quick deployment script for local development with minikube

set -e

echo "🚀 Adaptive Threat Modeler - Kubernetes Deployment"
echo "=================================================="

# Check if minikube is running
if ! minikube status | grep -q "Running"; then
    echo "📦 Starting minikube..."
    minikube start
fi

# Enable ingress addon
echo "🔌 Enabling ingress addon..."
minikube addons enable ingress

# Switch to minikube's Docker daemon
echo "🐳 Configuring Docker to use minikube..."
eval $(minikube docker-env)

# Build Docker images
echo "🔨 Building backend image..."
docker build -t threat-modeler-backend:latest ./backend

echo "🔨 Building frontend image..."
docker build -t threat-modeler-frontend:latest ./frontend

# Deploy with Helm
echo "⎈ Deploying with Helm..."
if helm list -n threat-modeler | grep -q threat-modeler; then
    echo "   Upgrading existing release..."
    helm upgrade threat-modeler ./helm/threat-modeler --namespace threat-modeler
else
    echo "   Installing new release..."
    helm install threat-modeler ./helm/threat-modeler --namespace threat-modeler --create-namespace
fi

# Wait for pods to be ready
echo "⏳ Waiting for pods to be ready..."
kubectl wait --for=condition=ready pod -l app=backend -n threat-modeler --timeout=120s
kubectl wait --for=condition=ready pod -l app=frontend -n threat-modeler --timeout=120s

# Get minikube IP
MINIKUBE_IP=$(minikube ip)

# Check if host entry exists
if ! grep -q "threat-modeler.local" /etc/hosts; then
    echo "📝 Adding host entry (requires sudo)..."
    echo "$MINIKUBE_IP threat-modeler.local" | sudo tee -a /etc/hosts
fi

echo ""
echo "✅ Deployment complete!"
echo ""
echo "🌐 Access the application at: http://threat-modeler.local"
echo ""
echo "📊 Useful commands:"
echo "   kubectl get pods -n threat-modeler     # View pods"
echo "   kubectl logs -l app=backend -n threat-modeler  # Backend logs"
echo "   helm uninstall threat-modeler -n threat-modeler  # Uninstall"
