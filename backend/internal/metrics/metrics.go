package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// HTTP Metrics
	HTTPRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "endpoint", "status"},
	)

	HTTPRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "HTTP request latencies in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "endpoint"},
	)

	HTTPRequestSize = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_size_bytes",
			Help:    "HTTP request size in bytes",
			Buckets: prometheus.ExponentialBuckets(100, 10, 8),
		},
		[]string{"method", "endpoint"},
	)

	HTTPResponseSize = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_response_size_bytes",
			Help:    "HTTP response size in bytes",
			Buckets: prometheus.ExponentialBuckets(100, 10, 8),
		},
		[]string{"method", "endpoint"},
	)

	// Analysis Metrics
	AnalysisTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "analysis_total",
			Help: "Total number of analyses performed",
		},
		[]string{"type", "status"},
	)

	AnalysisDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "analysis_duration_seconds",
			Help:    "Analysis duration in seconds",
			Buckets: []float64{1, 5, 10, 30, 60, 120, 300, 600},
		},
		[]string{"type"},
	)

	AnalysisInProgress = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "analysis_in_progress",
			Help: "Number of analyses currently in progress",
		},
	)

	AnalysisQueueDepth = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "analysis_queue_depth",
			Help: "Number of analyses waiting in queue",
		},
	)

	// Vulnerability Detection Metrics
	VulnerabilitiesDetected = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "vulnerabilities_detected_total",
			Help: "Total number of vulnerabilities detected",
		},
		[]string{"severity", "category"},
	)

	VulnerabilitiesByLanguage = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "vulnerabilities_by_language_total",
			Help: "Total vulnerabilities detected by programming language",
		},
		[]string{"language", "severity"},
	)

	VulnerabilitiesByFramework = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "vulnerabilities_by_framework_total",
			Help: "Total vulnerabilities detected by framework",
		},
		[]string{"framework", "severity"},
	)

	// File Processing Metrics
	FilesProcessed = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "files_processed_total",
			Help: "Total number of files processed",
		},
		[]string{"language"},
	)

	FileProcessingDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "file_processing_duration_seconds",
			Help:    "File processing duration in seconds",
			Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5},
		},
	)

	// Repository Operations
	RepositoryCloneDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "repository_clone_duration_seconds",
			Help:    "Repository clone duration in seconds",
			Buckets: []float64{1, 5, 10, 30, 60, 120, 300},
		},
	)

	RepositoryCloneTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "repository_clone_total",
			Help: "Total number of repository clones",
		},
		[]string{"status"},
	)

	RepositorySizeBytes = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "repository_size_bytes",
			Help:    "Repository size in bytes",
			Buckets: prometheus.ExponentialBuckets(1024, 10, 8),
		},
	)

	// AST Parser Metrics
	ASTParsingTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ast_parsing_total",
			Help: "Total number of AST parsing operations",
		},
		[]string{"language", "status"},
	)

	ASTParsingDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "ast_parsing_duration_seconds",
			Help:    "AST parsing duration in seconds",
			Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1},
		},
		[]string{"language"},
	)

	// Rule Engine Metrics
	RulesExecuted = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "rules_executed_total",
			Help: "Total number of rules executed",
		},
		[]string{"rule_type"},
	)

	RuleMatchesTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "rule_matches_total",
			Help: "Total number of rule matches",
		},
		[]string{"rule_id"},
	)

	RuleExecutionDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "rule_execution_duration_seconds",
			Help:    "Rule execution duration in seconds",
			Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1},
		},
	)

	// Error Metrics
	ErrorsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "errors_total",
			Help: "Total number of errors",
		},
		[]string{"type", "component"},
	)

	// Commit Storage Metrics
	CommitStorageOperations = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "commit_storage_operations_total",
			Help: "Total number of commit storage operations",
		},
		[]string{"operation", "status"},
	)

	CommitStorageSize = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "commit_storage_size_bytes",
			Help: "Total size of commit storage in bytes",
		},
	)

	// Language & Framework Detection
	LanguagesDetected = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "languages_detected_total",
			Help: "Total number of languages detected",
		},
		[]string{"language"},
	)

	FrameworksDetected = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "frameworks_detected_total",
			Help: "Total number of frameworks detected",
		},
		[]string{"framework"},
	)

	// System Resource Metrics
	ActiveGoroutines = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "active_goroutines",
			Help: "Number of active goroutines",
		},
	)

	MemoryUsageBytes = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "memory_usage_bytes",
			Help: "Memory usage in bytes",
		},
	)

	GCPauseDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "gc_pause_duration_seconds",
			Help:    "Garbage collection pause duration in seconds",
			Buckets: []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1},
		},
	)
)
