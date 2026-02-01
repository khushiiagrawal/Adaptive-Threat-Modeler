# Prometheus & Grafana Monitoring Setup

This guide explains how to set up and use Prometheus and Grafana for monitoring the Adaptive Threat Modeler.

## Overview

The monitoring stack includes:
- **Prometheus**: Metrics collection and storage
- **Grafana**: Visualization and dashboards
- **Alert Rules**: Automated alerting for critical events

## Quick Start

### 1. Start the Monitoring Stack

```bash
# Start all services (backend + monitoring)
docker-compose -f docker-compose.monitoring.yml up -d

# View logs
docker-compose -f docker-compose.monitoring.yml logs -f
```

### 2. Access the Services

- **Backend API**: http://localhost:8080
- **Prometheus**: http://localhost:9090
- **Grafana**: http://localhost:3000
  - Default credentials: `admin` / `admin`

### 3. View Metrics

**Prometheus Metrics Endpoint**: http://localhost:8080/metrics

**Grafana Dashboard**: 
1. Navigate to http://localhost:3000
2. Login with admin/admin
3. The "Adaptive Threat Modeler - Monitoring Dashboard" is automatically provisioned

## Monitored Metrics

### HTTP/API Metrics
- `http_requests_total` - Total HTTP requests by method, endpoint, and status
- `http_request_duration_seconds` - Request latency by endpoint (P50, P95, P99)
- `http_request_size_bytes` - Request payload sizes
- `http_response_size_bytes` - Response payload sizes

### Analysis Engine Metrics
- `analysis_total` - Total analyses by type (github/upload) and status
- `analysis_duration_seconds` - Analysis duration histograms
- `analysis_in_progress` - Current number of running analyses
- `analysis_queue_depth` - Pending analyses in queue

### Vulnerability Detection Metrics
- `vulnerabilities_detected_total` - Vulnerabilities by severity and category
- `vulnerabilities_by_language_total` - Vulnerabilities per programming language
- `vulnerabilities_by_framework_total` - Vulnerabilities per framework

### File Processing Metrics
- `files_processed_total` - Files processed by language
- `file_processing_duration_seconds` - File processing times

### Repository Operations
- `repository_clone_duration_seconds` - Git clone times
- `repository_clone_total` - Clone success/failure counts
- `repository_size_bytes` - Repository sizes

### AST Parser Metrics
- `ast_parsing_total` - AST parsing operations by language and status
- `ast_parsing_duration_seconds` - AST parsing times

### Rule Engine Metrics
- `rules_executed_total` - Rules executed by type
- `rule_matches_total` - Rule matches by rule ID
- `rule_execution_duration_seconds` - Rule execution times

### Error Metrics
- `errors_total` - Errors by type and component

### System Resource Metrics
- `active_goroutines` - Active goroutine count
- `memory_usage_bytes` - Memory consumption
- `gc_pause_duration_seconds` - Garbage collection pause times

### Language & Framework Detection
- `languages_detected_total` - Languages detected per analysis
- `frameworks_detected_total` - Frameworks detected per analysis

## Alert Rules

The following alerts are pre-configured in `alert_rules.yml`:

### Critical Alerts
- **BackendServiceDown**: Service unavailable for >1 minute
- **HighErrorRate**: Error rate >10 errors/sec for 5 minutes
- **HighMemoryUsage**: Memory usage >4GB for 5 minutes

### Warning Alerts
- **HighAnalysisFailureRate**: >20% analyses failing
- **HighAPILatency**: P95 latency >5s for 10 minutes
- **HighGoroutineCount**: >1000 goroutines for 10 minutes
- **AnalysisQueueBacklog**: >50 analyses queued for 15 minutes
- **RepositoryCloneFailures**: High clone failure rate

### Info Alerts
- **LongRunningAnalyses**: >10 analyses running >30 minutes
- **CriticalVulnerabilitiesDetected**: >100 critical vulns in 1 hour

## Grafana Dashboard

The pre-built dashboard includes:

### 1. System Overview
- Service status
- Request rate by endpoint
- Analyses in progress

### 2. Analysis Metrics
- Analysis throughput (completed/failed)
- Analysis duration percentiles (P50/P95/P99)

### 3. Vulnerability Detection
- Vulnerabilities by severity (pie chart)
- Vulnerabilities by category
- Vulnerabilities by language

### 4. Performance Metrics
- API latency by endpoint
- HTTP status codes distribution

### 5. Resource Utilization
- Memory usage
- Active goroutines
- GC pause duration

## Customization

### Adding Custom Metrics

1. Define metrics in `backend/internal/metrics/metrics.go`:

```go
var MyCustomMetric = promauto.NewCounter(
    prometheus.CounterOpts{
        Name: "my_custom_metric_total",
        Help: "Description of my metric",
    },
)
```

2. Record metrics in your code:

```go
import "adaptive-threat-modeler/internal/metrics"

metrics.MyCustomMetric.Inc()
```

### Creating Custom Dashboards

1. Create dashboard in Grafana UI
2. Export as JSON
3. Save to `grafana/provisioning/dashboards/`
4. Restart Grafana

### Modifying Alert Rules

Edit `alert_rules.yml` and reload Prometheus:

```bash
docker-compose -f docker-compose.monitoring.yml restart prometheus
```

## Production Recommendations

### 1. Security
- Change default Grafana credentials
- Enable authentication on Prometheus
- Use TLS/HTTPS for all services
- Restrict network access

### 2. Data Retention
- Adjust Prometheus retention: `--storage.tsdb.retention.time=30d`
- Configure Grafana data source query timeout
- Set up remote storage for long-term metrics

### 3. Scaling
- Use Prometheus federation for multiple instances
- Configure Grafana for high availability
- Set up external Alertmanager

### 4. Alerting
- Configure Alertmanager for notifications (email, Slack, PagerDuty)
- Set up alert routing and grouping
- Define on-call schedules

## Troubleshooting

### Metrics Not Appearing
1. Check backend is exposing `/metrics`: `curl http://localhost:8080/metrics`
2. Verify Prometheus is scraping: http://localhost:9090/targets
3. Check Prometheus logs: `docker logs prometheus`

### Dashboard Not Loading
1. Verify Grafana provisioning: `docker logs grafana`
2. Check datasource configuration: http://localhost:3000/datasources
3. Manually import dashboard JSON if needed

### High Memory Usage
1. Reduce Prometheus retention period
2. Decrease scrape frequency
3. Limit metric cardinality (fewer labels)

## Example Queries

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

# Memory growth rate
deriv(memory_usage_bytes[5m])
```

## Stopping the Stack

```bash
# Stop all services
docker-compose -f docker-compose.monitoring.yml down

# Stop and remove volumes (deletes all metrics data)
docker-compose -f docker-compose.monitoring.yml down -v
```

## Additional Resources

- [Prometheus Documentation](https://prometheus.io/docs/)
- [Grafana Documentation](https://grafana.com/docs/)
- [PromQL Guide](https://prometheus.io/docs/prometheus/latest/querying/basics/)
- [Grafana Dashboard Best Practices](https://grafana.com/docs/grafana/latest/best-practices/)
