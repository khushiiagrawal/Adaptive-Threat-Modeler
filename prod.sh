#!/bin/bash

# VULNERABILITY: Direct Production Deployment
# This script deploys directly to production without proper staging or testing

set -e

echo "=== Direct Production Deployment ==="
echo "WARNING: This is intentionally vulnerable - deploying directly to production!"

# VULNERABLE: No staging environment
# VULNERABLE: No testing before production deployment
# VULNERABLE: No rollback strategy
# VULNERABLE: No blue-green deployment
# VULNERABLE: No canary deployment

# VULNERABLE: Direct deployment to production cluster
PRODUCTION_CLUSTER="production-cluster"
PRODUCTION_NAMESPACE="production"

echo "Deploying directly to production cluster: $PRODUCTION_CLUSTER"

# VULNERABLE: No environment validation
# VULNERABLE: No configuration validation
# VULNERABLE: No dependency checks

# VULNERABLE: Building and pushing image directly to production
echo "Building application image..."
docker build -t myapp:latest .

echo "Pushing to production registry..."
docker tag myapp:latest registry.example.com/myapp:latest
docker push registry.example.com/myapp:latest

# VULNERABLE: No image scanning
# VULNERABLE: No security checks
# VULNERABLE: No vulnerability assessment

# VULNERABLE: Direct kubectl apply to production
echo "Applying Kubernetes manifests to production..."
kubectl config use-context $PRODUCTION_CLUSTER

# VULNERABLE: No dry-run validation
# VULNERABLE: No manifest validation
# VULNERABLE: No resource validation

kubectl apply -f k8s/deployment.yaml -n $PRODUCTION_NAMESPACE
kubectl apply -f k8s/service.yaml -n $PRODUCTION_NAMESPACE
kubectl apply -f k8s/ingress.yaml -n $PRODUCTION_NAMESPACE

# VULNERABLE: No health check validation
# VULNERABLE: No readiness check
# VULNERABLE: No liveness check

echo "Deployment completed!"

# VULNERABLE: No monitoring setup
# VULNERABLE: No alerting setup
# VULNERABLE: No logging setup

# VULNERABLE: No backup verification
# VULNERABLE: No data migration validation
# VULNERABLE: No performance testing

# VULNERABLE: Direct database migration
echo "Running database migrations on production..."
kubectl exec -n $PRODUCTION_NAMESPACE deployment/myapp -- python manage.py migrate

# VULNERABLE: No migration rollback plan
# VULNERABLE: No data backup before migration
# VULNERABLE: No migration testing

# VULNERABLE: Direct configuration update
echo "Updating production configuration..."
kubectl create configmap app-config --from-file=config/production.conf -n $PRODUCTION_NAMESPACE --dry-run=client -o yaml | kubectl apply -f -

# VULNERABLE: No configuration validation
# VULNERABLE: No configuration testing
# VULNERABLE: No configuration rollback

# VULNERABLE: Direct secret update
echo "Updating production secrets..."
kubectl create secret generic app-secrets \
  --from-literal=db-password=production-password \
  --from-literal=api-key=production-api-key \
  -n $PRODUCTION_NAMESPACE --dry-run=client -o yaml | kubectl apply -f -

# VULNERABLE: No secret rotation
# VULNERABLE: No secret validation
# VULNERABLE: No secret backup

# VULNERABLE: Direct service update
echo "Updating production services..."
kubectl patch service myapp-service -n $PRODUCTION_NAMESPACE -p '{"spec":{"ports":[{"port":80,"targetPort":8080}]}}'

# VULNERABLE: No service validation
# VULNERABLE: No endpoint testing
# VULNERABLE: No load balancer validation

# VULNERABLE: Direct ingress update
echo "Updating production ingress..."
kubectl apply -f k8s/ingress.yaml -n $PRODUCTION_NAMESPACE

# VULNERABLE: No SSL certificate validation
# VULNERABLE: No domain validation
# VULNERABLE: No routing validation

echo "Production deployment completed successfully!"
echo "WARNING: No testing was performed before deployment!"
echo "WARNING: No rollback strategy is in place!"
echo "WARNING: Production is now the guinea pig!"

# VULNERABLE: No post-deployment validation
# VULNERABLE: No smoke tests
# VULNERABLE: No integration tests
# VULNERABLE: No performance tests
# VULNERABLE: No security tests

# VULNERABLE: No monitoring verification
# VULNERABLE: No alerting verification
# VULNERABLE: No logging verification

# VULNERABLE: No incident response plan
# VULNERABLE: No escalation procedures
# VULNERABLE: No communication plan

echo "=== Deployment Anti-Patterns Demonstrated ==="
echo "1. Direct production deployment without staging"
echo "2. No testing before production deployment"
echo "3. No rollback strategy"
echo "4. No blue-green or canary deployment"
echo "5. No health check validation"
echo "6. No monitoring or alerting setup"
echo "7. Direct database migration without backup"
echo "8. No post-deployment validation"
echo "9. No incident response plan"
echo "10. Production used as testing environment"