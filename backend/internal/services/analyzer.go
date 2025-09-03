package services

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/google/uuid"

	"adaptive-threat-modeler/internal/models"
)

type Analyzer struct {
	tempDir       string
	detector      *ProjectDetector
	ruleEngine    *RuleEngine
	astParser     *ASTParser
	resultStore   map[string]*models.AnalysisResult
}

// NewAnalyzer creates a new analyzer instance
func NewAnalyzer() *Analyzer {
	return &Analyzer{
		tempDir:     "/tmp",
		detector:    NewProjectDetector(),
		ruleEngine:  NewRuleEngine(),
		astParser:   NewASTParser(),
		resultStore: make(map[string]*models.AnalysisResult),
	}
}

// AnalyzeGitHubRepo clones and analyzes a GitHub repository
func (a *Analyzer) AnalyzeGitHubRepo(analysisID, repoURL, branch string) (*models.AnalysisResult, error) {
	startTime := time.Now()

	// Create temporary directory for this analysis
	tempDir := filepath.Join(a.tempDir, "analysis_"+analysisID)
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tempDir)

	// Clone repository
	repoPath := filepath.Join(tempDir, "repo")
	if err := a.cloneRepository(repoURL, repoPath, branch); err != nil {
		return nil, fmt.Errorf("failed to clone repository: %w", err)
	}

	// Perform analysis
	result, err := a.analyzeProject(analysisID, repoPath)
	if err != nil {
		return nil, fmt.Errorf("analysis failed: %w", err)
	}

	result.ProcessingTime = time.Since(startTime).String()
	result.Status = "completed"

	return result, nil
}

// AnalyzeUpload extracts and analyzes an uploaded zip file
func (a *Analyzer) AnalyzeUpload(analysisID string, file *multipart.FileHeader) (*models.AnalysisResult, error) {
	startTime := time.Now()

	// Create temporary directory for this analysis
	tempDir := filepath.Join(a.tempDir, "analysis_"+analysisID)
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tempDir)

	// Extract zip file
	projectPath := filepath.Join(tempDir, "project")
	if err := a.extractZipFile(file, projectPath); err != nil {
		return nil, fmt.Errorf("failed to extract zip file: %w", err)
	}

	// Perform analysis
	result, err := a.analyzeProject(analysisID, projectPath)
	if err != nil {
		return nil, fmt.Errorf("analysis failed: %w", err)
	}

	result.ProcessingTime = time.Since(startTime).String()
	result.Status = "completed"

	return result, nil
}

// cloneRepository clones a Git repository to the specified path
func (a *Analyzer) cloneRepository(repoURL, path, branch string) error {
	cloneOptions := &git.CloneOptions{
		URL:      repoURL,
		Progress: os.Stdout,
		Depth:    1, // Shallow clone for faster processing
	}

	if branch != "" {
cloneOptions.ReferenceName = plumbing.ReferenceName("refs/heads/" + branch)
		cloneOptions.SingleBranch = true
	}

	_, err := git.PlainClone(path, false, cloneOptions)
	return err
}

// extractZipFile extracts a zip file to the specified directory
func (a *Analyzer) extractZipFile(fileHeader *multipart.FileHeader, destPath string) error {
	// Open the uploaded file
	src, err := fileHeader.Open()
	if err != nil {
		return err
	}
	defer src.Close()

	// Create a temporary file to store the zip content
	tempZip := filepath.Join(a.tempDir, uuid.New().String()+".zip")
	dst, err := os.Create(tempZip)
	if err != nil {
		return err
	}
	defer os.Remove(tempZip)

	// Copy uploaded file to temp file
	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		return err
	}
	dst.Close()

	// Open zip file for reading
	zipReader, err := zip.OpenReader(tempZip)
	if err != nil {
		return err
	}
	defer zipReader.Close()

	// Create destination directory
	if err := os.MkdirAll(destPath, 0755); err != nil {
		return err
	}

	// Extract files
	for _, file := range zipReader.File {
		if err := a.extractFile(file, destPath); err != nil {
			return err
		}
	}

	return nil
}

// extractFile extracts a single file from zip archive
func (a *Analyzer) extractFile(file *zip.File, destPath string) error {
	// Clean and validate the file path
	cleanPath := filepath.Clean(file.Name)
	if strings.Contains(cleanPath, "..") {
		return fmt.Errorf("invalid file path: %s", file.Name)
	}

	filePath := filepath.Join(destPath, cleanPath)

	// Create directory if needed
	if file.FileInfo().IsDir() {
		return os.MkdirAll(filePath, file.FileInfo().Mode())
	}

	// Create parent directories
	if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
		return err
	}

	// Extract file content
	fileReader, err := file.Open()
	if err != nil {
		return err
	}
	defer fileReader.Close()

	targetFile, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.FileInfo().Mode())
	if err != nil {
		return err
	}
	defer targetFile.Close()

	_, err = io.Copy(targetFile, fileReader)
	return err
}

// analyzeProject performs the main analysis on a project directory
func (a *Analyzer) analyzeProject(analysisID, projectPath string) (*models.AnalysisResult, error) {
	result := &models.AnalysisResult{
		ID:        analysisID,
		Timestamp: time.Now(),
		Status:    "processing",
	}

	// Detect project information
	projectInfo, err := a.detector.AnalyzeProject(projectPath)
	if err != nil {
		return nil, fmt.Errorf("project detection failed: %w", err)
	}
	result.ProjectInfo = *projectInfo
	
	// Log project information
	fmt.Printf("\n=== PROJECT ANALYSIS STARTED ===\n")
	fmt.Printf("Analysis ID: %s\n", analysisID)
	fmt.Printf("Project Path: %s\n", projectPath)
	fmt.Printf("Detected Languages: %v\n", projectInfo.Languages)
	fmt.Printf("Detected Frameworks: %v\n", projectInfo.Frameworks)
	fmt.Printf("Services Found: %d\n", len(projectInfo.Services))
	fmt.Printf("Dependencies: %d\n", len(projectInfo.Dependencies))
	fmt.Printf("Config Files: %v\n", projectInfo.ConfigFiles)
	fmt.Printf("===============================\n")

	// Load relevant rules based on detected languages and frameworks
	rules := a.ruleEngine.LoadRulesForProject(projectInfo)

	// Parse source files and detect vulnerabilities
	vulnerabilities, err := a.analyzeSourceFiles(projectPath, projectInfo, rules)
	if err != nil {
		return nil, fmt.Errorf("source analysis failed: %w", err)
	}
	result.Vulnerabilities = vulnerabilities

	// Log detailed vulnerability information in AST-style JSON format
	fmt.Printf("\n=== ANALYSIS COMPLETED ===\n")
	fmt.Printf("Analysis ID: %s\n", analysisID)
	fmt.Printf("Total vulnerabilities found: %d\n", len(vulnerabilities))
	
	// Create AST-style output
	astOutput := map[string]interface{}{
		"results": []map[string]interface{}{},
		"errors":  []map[string]interface{}{},
		"paths": map[string]interface{}{
			"scanned": []string{},
			"skipped": []map[string]interface{}{},
		},
		"version": "1.0.0",
	}
	
	// Convert vulnerabilities to AST format
	var results []map[string]interface{}
	var scannedPaths []string
	
	for _, vuln := range vulnerabilities {
		result := map[string]interface{}{
			"check_id": vuln.ID,
			"path":     vuln.Location.File,
			"start": map[string]interface{}{
				"line":   vuln.Location.Line,
				"col":    vuln.Location.Column,
				"offset": 0, // We don't calculate offset in our current implementation
			},
			"end": map[string]interface{}{
				"line":   vuln.Location.EndLine,
				"col":    vuln.Location.EndColumn,
				"offset": 0,
			},
			"extra": map[string]interface{}{
				"message":  vuln.Description,
				"severity": strings.ToUpper(vuln.Severity),
				"category": vuln.Category,
				"cwe":      vuln.CWE,
				"owasp":    vuln.OWASP,
				"evidence": vuln.Evidence,
				"impact":   vuln.Impact,
				"remediation": vuln.Remediation,
			},
		}
		
		// Add autofix if available
		if vuln.AutoFix != nil {
			result["extra"].(map[string]interface{})["fix"] = vuln.AutoFix.NewCode
			result["extra"].(map[string]interface{})["fix_confidence"] = vuln.AutoFix.Confidence
		}
		
		results = append(results, result)
		
		// Track scanned files
		if !contains(scannedPaths, vuln.Location.File) {
			scannedPaths = append(scannedPaths, vuln.Location.File)
		}
	}
	
	astOutput["results"] = results
	astOutput["paths"].(map[string]interface{})["scanned"] = scannedPaths
	
	// Pretty print JSON
	jsonBytes, err := json.MarshalIndent(astOutput, "", "  ")
	if err == nil {
		fmt.Printf("\n=== AST-STYLE JSON OUTPUT ===\n")
		fmt.Println(string(jsonBytes))
	}
	
	// Also print summary for convenience
	if len(vulnerabilities) > 0 {
		fmt.Printf("\n=== VULNERABILITY SUMMARY ===\n")
		
		// Group vulnerabilities by severity
		severityGroups := make(map[string][]models.Vulnerability)
		for _, vuln := range vulnerabilities {
			severityGroups[vuln.Severity] = append(severityGroups[vuln.Severity], vuln)
		}
		
		// Print by severity (critical first)
		severityOrder := []string{"critical", "high", "medium", "low", "info"}
		for _, severity := range severityOrder {
			if vulns, exists := severityGroups[severity]; exists {
				fmt.Printf("%s: %d vulnerabilities\n", strings.ToUpper(severity), len(vulns))
			}
		}
	}
	
	fmt.Printf("\n=== ANALYSIS SUMMARY ===\n")

	// Generate threat map
	threatMap := a.generateThreatMap(projectInfo, vulnerabilities)
	result.ThreatMap = threatMap

	// Calculate summary and recommendations
	result.Summary = a.calculateSummary(vulnerabilities)
	result.Recommendations = a.generateRecommendations(projectInfo, vulnerabilities)
	
	// Log final summary
	fmt.Printf("Risk Score: %.1f\n", result.Summary.RiskScore)
	fmt.Printf("Security Posture: %s\n", result.Summary.SecurityPosture)
	fmt.Printf("Severity Breakdown:\n")
	for severity, count := range result.Summary.SeverityBreakdown {
		if count > 0 {
			fmt.Printf("  %s: %d\n", severity, count)
		}
	}
	fmt.Printf("Category Breakdown:\n")
	for category, count := range result.Summary.CategoryBreakdown {
		if count > 0 {
			fmt.Printf("  %s: %d\n", category, count)
		}
	}
	fmt.Printf("Top Risks: %v\n", result.Summary.TopRisks)
	fmt.Printf("Threat Map Components: %d\n", len(result.ThreatMap.Components))
	fmt.Printf("Threat Map Data Flows: %d\n", len(result.ThreatMap.Flows))
	fmt.Printf("Recommendations: %d\n", len(result.Recommendations))
	fmt.Printf("==============================\n")

	return result, nil
}

// analyzeSourceFiles parses and analyzes source files for vulnerabilities
func (a *Analyzer) analyzeSourceFiles(projectPath string, projectInfo *models.ProjectInfo, rules []SecurityRule) ([]models.Vulnerability, error) {
	var vulnerabilities []models.Vulnerability

	// Walk through project files
	err := filepath.Walk(projectPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories and non-source files
		if info.IsDir() || !a.isSourceFile(path, projectInfo.Languages) {
			return nil
		}

		// Parse file and check for vulnerabilities
		fileVulns, err := a.analyzeFile(path, projectPath, rules)
		if err != nil {
			// Log error but continue with other files
			fmt.Printf("Error analyzing file %s: %v\n", path, err)
			return nil
		}

		// Log findings for this file
		if len(fileVulns) > 0 {
			relPath, _ := filepath.Rel(projectPath, path)
			fmt.Printf("Found %d vulnerability(ies) in file: %s\n", len(fileVulns), relPath)
			for _, vuln := range fileVulns {
				fmt.Printf("  - [%s] %s at line %d\n", vuln.Severity, vuln.Title, vuln.Location.Line)
			}
		}

		vulnerabilities = append(vulnerabilities, fileVulns...)
		return nil
	})

	return vulnerabilities, err
}

// analyzeFile analyzes a single source file
func (a *Analyzer) analyzeFile(filePath, projectRoot string, rules []SecurityRule) ([]models.Vulnerability, error) {
	// Read file content
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	// Get relative path for reporting
	relPath, _ := filepath.Rel(projectRoot, filePath)

	// Parse file into AST
	ast, err := a.astParser.ParseFile(filePath, string(content))
	if err != nil {
		return nil, err
	}

	// Apply security rules
	var vulnerabilities []models.Vulnerability
	for _, rule := range rules {
		if matches := rule.Match(ast, string(content)); len(matches) > 0 {
			for _, match := range matches {
				vuln := models.Vulnerability{
					ID:          uuid.New().String(),
					Title:       rule.Title,
					Description: rule.Description,
					Severity:    rule.Severity,
					Category:    rule.Category,
					CWE:         rule.CWE,
					OWASP:       rule.OWASP,
					Location: models.Location{
						File:     relPath,
						Line:     match.Line,
						Column:   match.Column,
						Function: match.Function,
					},
					Evidence:    match.Evidence,
					Impact:      rule.Impact,
					Remediation: rule.Remediation,
					References:  rule.References,
				}

				// Add autofix if available
				if autofix := rule.GenerateAutoFix(match); autofix != nil {
					vuln.AutoFix = autofix
				}

				vulnerabilities = append(vulnerabilities, vuln)
			}
		}
	}

	return vulnerabilities, nil
}

// isSourceFile checks if a file is a source code file
func (a *Analyzer) isSourceFile(filePath string, languages []string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	
	// Common source file extensions
	sourceExts := map[string][]string{
		"go":         {".go"},
		"javascript": {".js", ".jsx", ".mjs"},
		"typescript": {".ts", ".tsx"},
		"python":     {".py", ".pyw"},
		"hcl":        {".tf", ".hcl"},
		"shell":      {".sh", ".bash"},
		"java":       {".java"},
		"php":        {".php", ".php3", ".php4", ".php5", ".phtml"},
		"ruby":       {".rb", ".ruby"},
		"csharp":     {".cs"},
		"cpp":        {".cpp", ".cc", ".cxx", ".c++", ".hpp", ".h"},
		"c":          {".c", ".h"},
	}

	for _, lang := range languages {
		if exts, exists := sourceExts[lang]; exists {
			for _, validExt := range exts {
				if ext == validExt {
					return true
				}
			}
		}
	}

	return false
}

// generateThreatMap creates a visual threat model from project info and vulnerabilities
func (a *Analyzer) generateThreatMap(projectInfo *models.ProjectInfo, vulnerabilities []models.Vulnerability) models.ThreatMap {
	// This is a simplified implementation - in a real system, this would be more sophisticated
	threatMap := models.ThreatMap{
		Components: []models.Component{},
		Flows:      []models.DataFlow{},
		TrustZones: []models.TrustZone{},
		Assets:     []models.Asset{},
	}

	// Create components based on detected services
	for _, service := range projectInfo.Services {
		component := models.Component{
			ID:         uuid.New().String(),
			Name:       service.Name,
			Type:       service.Type,
			TrustZone:  "internal",
			Properties: service.Config,
			Threats:    []string{},
		}

		// Associate vulnerabilities with components
		for _, vuln := range vulnerabilities {
			if strings.Contains(vuln.Location.File, service.Name) {
				component.Threats = append(component.Threats, vuln.ID)
			}
		}

		threatMap.Components = append(threatMap.Components, component)
	}

	// Create default trust zones
	threatMap.TrustZones = []models.TrustZone{
		{
			ID:          "internet",
			Name:        "Internet",
			TrustLevel:  "untrusted",
			Description: "External internet traffic",
		},
		{
			ID:          "internal",
			Name:        "Internal Network",
			TrustLevel:  "trusted",
			Description: "Internal application components",
		},
	}

	return threatMap
}

// calculateSummary generates analysis summary statistics
func (a *Analyzer) calculateSummary(vulnerabilities []models.Vulnerability) models.Summary {
	summary := models.Summary{
		TotalVulnerabilities: len(vulnerabilities),
		SeverityBreakdown:    make(map[string]int),
		CategoryBreakdown:    make(map[string]int),
		TopRisks:            []string{},
	}

	// Calculate breakdowns
	for _, vuln := range vulnerabilities {
		summary.SeverityBreakdown[vuln.Severity]++
		summary.CategoryBreakdown[vuln.Category]++
	}

	// Calculate risk score (0-100)
	riskScore := 0.0
	riskScore += float64(summary.SeverityBreakdown["critical"]) * 10.0
	riskScore += float64(summary.SeverityBreakdown["high"]) * 7.0
	riskScore += float64(summary.SeverityBreakdown["medium"]) * 4.0
	riskScore += float64(summary.SeverityBreakdown["low"]) * 1.0

	summary.RiskScore = riskScore

	// Determine security posture
	if riskScore >= 50 {
		summary.SecurityPosture = "poor"
	} else if riskScore >= 25 {
		summary.SecurityPosture = "fair"
	} else if riskScore >= 10 {
		summary.SecurityPosture = "good"
	} else {
		summary.SecurityPosture = "excellent"
	}

	return summary
}

// generateRecommendations creates actionable security recommendations
func (a *Analyzer) generateRecommendations(projectInfo *models.ProjectInfo, vulnerabilities []models.Vulnerability) []string {
	recommendations := []string{}

	// High-level recommendations based on findings
	if len(vulnerabilities) > 0 {
		recommendations = append(recommendations, "Implement a security code review process")
		recommendations = append(recommendations, "Set up automated security scanning in CI/CD pipeline")
	}

	// Framework-specific recommendations
	for _, framework := range projectInfo.Frameworks {
		switch framework {
		case "express":
			recommendations = append(recommendations, "Enable Express.js security middleware (helmet, cors)")
		case "react":
			recommendations = append(recommendations, "Implement Content Security Policy (CSP)")
		case "fiber":
			recommendations = append(recommendations, "Use Fiber's built-in security middleware")
		}
	}

	return recommendations
}

// Storage functions (in a real implementation, this would use a database)
var analysisStore = make(map[string]*models.AnalysisResult)

func StoreAnalysisResult(id string, result *models.AnalysisResult) {
	analysisStore[id] = result
}

func GetAnalysisResult(id string) (*models.AnalysisResult, bool) {
	result, exists := analysisStore[id]
	return result, exists
}

// contains checks if a string slice contains a specific string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

