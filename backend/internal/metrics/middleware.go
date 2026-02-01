package metrics

import (
	"fmt"
	"runtime"
	"time"

	"github.com/gofiber/fiber/v2"
)

// PrometheusMiddleware creates a Fiber middleware for Prometheus metrics
func PrometheusMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		start := time.Now()

		// Process request
		err := c.Next()

		// Record metrics after request is processed
		duration := time.Since(start).Seconds()
		status := c.Response().StatusCode()
		method := c.Method()
		endpoint := c.Route().Path

		// Format status code as category (2xx, 3xx, 4xx, 5xx)
		statusCategory := fmt.Sprintf("%dxx", status/100)

		// HTTP request metrics
		HTTPRequestsTotal.WithLabelValues(method, endpoint, statusCategory).Inc()
		HTTPRequestDuration.WithLabelValues(method, endpoint).Observe(duration)
		HTTPRequestSize.WithLabelValues(method, endpoint).Observe(float64(len(c.Request().Body())))
		HTTPResponseSize.WithLabelValues(method, endpoint).Observe(float64(len(c.Response().Body())))

		return err
	}
}

// RecordAnalysis records analysis-related metrics
func RecordAnalysis(analysisType string, duration time.Duration, status string, vulnCount int, vulnsBySeverity map[string]int) {
	AnalysisTotal.WithLabelValues(analysisType, status).Inc()
	AnalysisDuration.WithLabelValues(analysisType).Observe(duration.Seconds())

	for severity, count := range vulnsBySeverity {
		for i := 0; i < count; i++ {
			VulnerabilitiesDetected.WithLabelValues(severity, "general").Inc()
		}
	}
}

// RecordVulnerability records a detected vulnerability
func RecordVulnerability(severity, category, language, framework string) {
	VulnerabilitiesDetected.WithLabelValues(severity, category).Inc()
	if language != "" {
		VulnerabilitiesByLanguage.WithLabelValues(language, severity).Inc()
	}
	if framework != "" {
		VulnerabilitiesByFramework.WithLabelValues(framework, severity).Inc()
	}
}

// RecordFileProcessing records file processing metrics
func RecordFileProcessing(language string, duration time.Duration) {
	FilesProcessed.WithLabelValues(language).Inc()
	FileProcessingDuration.Observe(duration.Seconds())
}

// RecordRepositoryClone records repository clone metrics
func RecordRepositoryClone(duration time.Duration, sizeBytes int64, success bool) {
	status := "success"
	if !success {
		status = "failure"
	}
	RepositoryCloneTotal.WithLabelValues(status).Inc()
	RepositoryCloneDuration.Observe(duration.Seconds())
	if success {
		RepositorySizeBytes.Observe(float64(sizeBytes))
	}
}

// RecordASTParsing records AST parsing metrics
func RecordASTParsing(language string, duration time.Duration, success bool) {
	status := "success"
	if !success {
		status = "failure"
	}
	ASTParsingTotal.WithLabelValues(language, status).Inc()
	ASTParsingDuration.WithLabelValues(language).Observe(duration.Seconds())
}

// RecordRuleExecution records rule engine metrics
func RecordRuleExecution(ruleType, ruleID string, duration time.Duration, matched bool) {
	RulesExecuted.WithLabelValues(ruleType).Inc()
	RuleExecutionDuration.Observe(duration.Seconds())
	if matched {
		RuleMatchesTotal.WithLabelValues(ruleID).Inc()
	}
}

// RecordError records error metrics
func RecordError(errorType, component string) {
	ErrorsTotal.WithLabelValues(errorType, component).Inc()
}

// RecordCommitStorage records commit storage metrics
func RecordCommitStorage(operation string, success bool) {
	status := "success"
	if !success {
		status = "failure"
	}
	CommitStorageOperations.WithLabelValues(operation, status).Inc()
}

// RecordLanguageDetection records language detection metrics
func RecordLanguageDetection(language string) {
	LanguagesDetected.WithLabelValues(language).Inc()
}

// RecordFrameworkDetection records framework detection metrics
func RecordFrameworkDetection(framework string) {
	FrameworksDetected.WithLabelValues(framework).Inc()
}

// UpdateSystemMetrics updates system resource metrics
func UpdateSystemMetrics() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	ActiveGoroutines.Set(float64(runtime.NumGoroutine()))
	MemoryUsageBytes.Set(float64(m.Alloc))

	// Record GC pause times
	if len(m.PauseNs) > 0 {
		lastPause := m.PauseNs[(m.NumGC+255)%256]
		GCPauseDuration.Observe(float64(lastPause) / 1e9)
	}
}

// StartSystemMetricsCollector starts a background goroutine to collect system metrics
func StartSystemMetricsCollector(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			UpdateSystemMetrics()
		}
	}()
}

// RegisterCustomCollectors registers custom Prometheus collectors
func RegisterCustomCollectors() {
	// Start system metrics collection every 15 seconds
	StartSystemMetricsCollector(15 * time.Second)

	// Initialize metrics with zero values so they appear in Prometheus immediately
	initializeMetrics()
}

// initializeMetrics pre-populates metrics so they appear in Prometheus output
func initializeMetrics() {
	// Initialize analysis metrics
	for _, analysisType := range []string{"github", "upload"} {
		for _, status := range []string{"completed", "failed", "processing"} {
			AnalysisTotal.WithLabelValues(analysisType, status).Add(0)
		}
		// Initialize histogram by observing 0 (won't affect real data)
		AnalysisDuration.WithLabelValues(analysisType)
	}

	// Initialize vulnerability metrics
	for _, severity := range []string{"critical", "high", "medium", "low", "info"} {
		for _, category := range []string{"general", "injection", "xss", "hardcoded_secret", "insecure_config", "authentication", "authorization"} {
			VulnerabilitiesDetected.WithLabelValues(severity, category).Add(0)
		}
	}

	// Initialize language metrics
	for _, lang := range []string{"go", "javascript", "typescript", "python", "java", "php", "ruby", "csharp", "cpp", "rust"} {
		LanguagesDetected.WithLabelValues(lang).Add(0)
		FilesProcessed.WithLabelValues(lang).Add(0)
		for _, severity := range []string{"critical", "high", "medium", "low", "info"} {
			VulnerabilitiesByLanguage.WithLabelValues(lang, severity).Add(0)
		}
	}

	// Initialize repository metrics
	for _, status := range []string{"success", "failure"} {
		RepositoryCloneTotal.WithLabelValues(status).Add(0)
	}

	// Initialize error metrics
	for _, errType := range []string{"temp_dir_creation", "git_clone", "zip_extraction", "analysis", "parsing"} {
		ErrorsTotal.WithLabelValues(errType, "analyzer").Add(0)
	}

	// Initialize commit storage metrics
	for _, op := range []string{"read", "write", "delete"} {
		for _, status := range []string{"success", "failure"} {
			CommitStorageOperations.WithLabelValues(op, status).Add(0)
		}
	}
}
