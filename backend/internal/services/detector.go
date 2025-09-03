package services

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"adaptive-threat-modeler/internal/models"
)

type ProjectDetector struct {
	languagePatterns   map[string][]string
	frameworkPatterns  map[string]FrameworkPattern
	configFilePatterns map[string]string
}

type FrameworkPattern struct {
	Files        []string            `json:"files"`
	Dependencies []string            `json:"dependencies"`
	Patterns     []string            `json:"patterns"`
	Language     string              `json:"language"`
	Metadata     map[string]string   `json:"metadata"`
}

// NewProjectDetector creates a new project detector instance
func NewProjectDetector() *ProjectDetector {
	return &ProjectDetector{
		languagePatterns: map[string][]string{
			"go":         {"*.go", "go.mod", "go.sum"},
			"javascript": {"*.js", "*.jsx", "*.mjs", "package.json", "yarn.lock"},
			"typescript": {"*.ts", "*.tsx", "tsconfig.json"},
			"python":     {"*.py", "*.pyw", "requirements.txt", "setup.py", "pyproject.toml"},
			"hcl":        {"*.tf", "*.hcl", "terraform.tfvars", "*.tfvars"},
			"shell":      {"*.sh", "*.bash", "Dockerfile"},
			"java":       {"*.java", "pom.xml", "build.gradle", "gradle.properties"},
			"php":        {"*.php", "composer.json", "composer.lock"},
			"ruby":       {"*.rb", "Gemfile", "Gemfile.lock"},
			"csharp":     {"*.cs", "*.csproj", "*.sln"},
			"cpp":        {"*.cpp", "*.cc", "*.cxx", "*.hpp", "CMakeLists.txt", "Makefile"},
			"rust":       {"*.rs", "Cargo.toml", "Cargo.lock"},
		},
		frameworkPatterns: map[string]FrameworkPattern{
			"fiber": {
				Files:        []string{"main.go"},
				Dependencies: []string{"github.com/gofiber/fiber"},
				Patterns:     []string{`fiber\.New\(`, `app\.Listen\(`},
				Language:     "go",
				Metadata:     map[string]string{"type": "web_framework"},
			},
			"gin": {
				Files:        []string{"main.go"},
				Dependencies: []string{"github.com/gin-gonic/gin"},
				Patterns:     []string{`gin\.Default\(`, `gin\.New\(`},
				Language:     "go",
				Metadata:     map[string]string{"type": "web_framework"},
			},
			"echo": {
				Files:        []string{"main.go"},
				Dependencies: []string{"github.com/labstack/echo"},
				Patterns:     []string{`echo\.New\(`, `e\.Start\(`},
				Language:     "go",
				Metadata:     map[string]string{"type": "web_framework"},
			},
			"react": {
				Files:        []string{"package.json"},
				Dependencies: []string{"react", "react-dom"},
				Patterns:     []string{`import.*React`, `from.*react`},
				Language:     "javascript",
				Metadata:     map[string]string{"type": "frontend_framework"},
			},
			"vue": {
				Files:        []string{"package.json"},
				Dependencies: []string{"vue"},
				Patterns:     []string{`import.*Vue`, `from.*vue`},
				Language:     "javascript",
				Metadata:     map[string]string{"type": "frontend_framework"},
			},
			"angular": {
				Files:        []string{"package.json", "angular.json"},
				Dependencies: []string{"@angular/core"},
				Patterns:     []string{`@Component`, `@Injectable`},
				Language:     "typescript",
				Metadata:     map[string]string{"type": "frontend_framework"},
			},
			"express": {
				Files:        []string{"package.json"},
				Dependencies: []string{"express"},
				Patterns:     []string{`require\(['"]express['"]`, `from.*express`},
				Language:     "javascript",
				Metadata:     map[string]string{"type": "web_framework"},
			},
			"fastapi": {
				Files:        []string{"requirements.txt", "pyproject.toml"},
				Dependencies: []string{"fastapi"},
				Patterns:     []string{`from fastapi import`, `FastAPI\(`},
				Language:     "python",
				Metadata:     map[string]string{"type": "web_framework"},
			},
			"django": {
				Files:        []string{"requirements.txt", "manage.py"},
				Dependencies: []string{"django"},
				Patterns:     []string{`from django`, `DJANGO_SETTINGS_MODULE`},
				Language:     "python",
				Metadata:     map[string]string{"type": "web_framework"},
			},
			"spring": {
				Files:        []string{"pom.xml", "build.gradle"},
				Dependencies: []string{"spring-boot", "spring-core"},
				Patterns:     []string{`@SpringBootApplication`, `@RestController`},
				Language:     "java",
				Metadata:     map[string]string{"type": "web_framework"},
			},
		},
		configFilePatterns: map[string]string{
			"docker":     "Dockerfile",
			"kubernetes": "*.yaml,*.yml",
			"terraform":  "*.tf",
			"ansible":    "playbook.yml,inventory",
		},
	}
}

// AnalyzeProject performs comprehensive project analysis
func (pd *ProjectDetector) AnalyzeProject(projectPath string) (*models.ProjectInfo, error) {
	projectInfo := &models.ProjectInfo{
		Languages:    []string{},
		Frameworks:   []string{},
		Services:     []models.ServiceInfo{},
		Dependencies: make(map[string]string),
		ConfigFiles:  []string{},
	}

	// Detect languages
	languages, err := pd.DetectLanguages(projectPath, nil)
	if err != nil {
		return nil, err
	}
	projectInfo.Languages = languages

	// Detect frameworks
	frameworks, err := pd.DetectFrameworks(projectPath, languages)
	if err != nil {
		return nil, err
	}
	projectInfo.Frameworks = frameworks

	// Detect services and endpoints
	services, err := pd.DetectServices(projectPath, frameworks)
	if err != nil {
		return nil, err
	}
	projectInfo.Services = services

	// Parse dependencies
	dependencies, err := pd.ParseDependencies(projectPath, languages)
	if err != nil {
		return nil, err
	}
	projectInfo.Dependencies = dependencies

	// Find configuration files
	configFiles, err := pd.FindConfigFiles(projectPath)
	if err != nil {
		return nil, err
	}
	projectInfo.ConfigFiles = configFiles

	return projectInfo, nil
}

// DetectLanguages identifies programming languages used in the project
func (pd *ProjectDetector) DetectLanguages(projectPath string, files []string) ([]string, error) {
	languageCount := make(map[string]int)

	// If specific files are provided, analyze only those
	if len(files) > 0 {
		for _, file := range files {
			lang := pd.detectLanguageByExtension(file)
			if lang != "" {
				languageCount[lang]++
			}
		}
	} else {
		// Walk through project directory
		err := filepath.Walk(projectPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if info.IsDir() {
				return nil
			}

			// Skip hidden files and directories
			if strings.HasPrefix(info.Name(), ".") {
				return nil
			}

			// Skip common non-source directories
			relPath, _ := filepath.Rel(projectPath, path)
			if pd.shouldSkipPath(relPath) {
				return nil
			}

			lang := pd.detectLanguageByExtension(path)
			if lang != "" {
				languageCount[lang]++
			}

			// Also check for language-specific files
			for language, patterns := range pd.languagePatterns {
				for _, pattern := range patterns {
					if matched, _ := filepath.Match(pattern, info.Name()); matched {
						languageCount[language]++
					}
				}
			}

			return nil
		})

		if err != nil {
			return nil, err
		}
	}

	// Convert to sorted list (by count)
	var languages []string
	for lang := range languageCount {
		if languageCount[lang] > 0 {
			languages = append(languages, lang)
		}
	}

	return languages, nil
}

// DetectFrameworks identifies frameworks and libraries used in the project
func (pd *ProjectDetector) DetectFrameworks(projectPath string, languages []string) ([]string, error) {
	var frameworks []string

	for frameworkName, pattern := range pd.frameworkPatterns {
		// Skip if framework language is not detected
		if len(languages) > 0 && !detectorContains(languages, pattern.Language) {
			continue
		}

		detected, err := pd.detectFramework(projectPath, frameworkName, pattern)
		if err != nil {
			continue // Skip on error, don't fail entire detection
		}

		if detected {
			frameworks = append(frameworks, frameworkName)
		}
	}

	return frameworks, nil
}

// DetectServices identifies services and API endpoints
func (pd *ProjectDetector) DetectServices(projectPath string, frameworks []string) ([]models.ServiceInfo, error) {
	var services []models.ServiceInfo

	for _, framework := range frameworks {
		switch framework {
		case "fiber", "gin", "echo", "express", "fastapi", "django", "spring":
			service, err := pd.analyzeWebService(projectPath, framework)
			if err == nil {
				services = append(services, service)
			}
		}
	}

	return services, nil
}

// ParseDependencies extracts project dependencies
func (pd *ProjectDetector) ParseDependencies(projectPath string, languages []string) (map[string]string, error) {
	dependencies := make(map[string]string)

	for _, language := range languages {
		switch language {
		case "go":
			deps, err := pd.parseGoModDependencies(projectPath)
			if err == nil {
				for k, v := range deps {
					dependencies[k] = v
				}
			}
		case "javascript", "typescript":
			deps, err := pd.parsePackageJsonDependencies(projectPath)
			if err == nil {
				for k, v := range deps {
					dependencies[k] = v
				}
			}
		case "python":
			deps, err := pd.parsePythonDependencies(projectPath)
			if err == nil {
				for k, v := range deps {
					dependencies[k] = v
				}
			}
		}
	}

	return dependencies, nil
}

// FindConfigFiles locates configuration files
func (pd *ProjectDetector) FindConfigFiles(projectPath string) ([]string, error) {
	var configFiles []string

	err := filepath.Walk(projectPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		relPath, _ := filepath.Rel(projectPath, path)
		
		// Check for common config file patterns
		if pd.isConfigFile(info.Name()) {
			configFiles = append(configFiles, relPath)
		}

		return nil
	})

	return configFiles, err
}

// Helper methods

func (pd *ProjectDetector) detectLanguageByExtension(filename string) string {
	ext := strings.ToLower(filepath.Ext(filename))
	
	extensionMap := map[string]string{
		".go":   "go",
		".js":   "javascript",
		".jsx":  "javascript",
		".mjs":  "javascript",
		".ts":   "typescript",
		".tsx":  "typescript",
		".py":   "python",
		".pyw":  "python",
		".java": "java",
		".php":  "php",
		".rb":   "ruby",
		".cs":   "csharp",
		".cpp":  "cpp",
		".cc":   "cpp",
		".cxx":  "cpp",
		".c":    "c",
		".rs":   "rust",
	}

	return extensionMap[ext]
}

func (pd *ProjectDetector) shouldSkipPath(path string) bool {
	skipDirs := []string{
		"node_modules", "vendor", ".git", ".svn", "target", "build",
		"dist", "__pycache__", ".pytest_cache", "venv", ".venv",
	}

	for _, skipDir := range skipDirs {
		if strings.Contains(path, skipDir) {
			return true
		}
	}

	return false
}

func (pd *ProjectDetector) detectFramework(projectPath, frameworkName string, pattern FrameworkPattern) (bool, error) {
	// Check dependency files
	for _, dep := range pattern.Dependencies {
		if pd.hasDependency(projectPath, dep, pattern.Language) {
			return true, nil
		}
	}

	// Check file patterns
	for _, filePattern := range pattern.Files {
		filePath := filepath.Join(projectPath, filePattern)
		if _, err := os.Stat(filePath); err == nil {
			// File exists, check for code patterns
			content, err := os.ReadFile(filePath)
			if err != nil {
				continue
			}

			for _, codePattern := range pattern.Patterns {
				matched, _ := regexp.MatchString(codePattern, string(content))
				if matched {
					return true, nil
				}
			}
		}
	}

	return false, nil
}

func (pd *ProjectDetector) hasDependency(projectPath, dependency, language string) bool {
	switch language {
	case "go":
		return pd.hasGoDependency(projectPath, dependency)
	case "javascript", "typescript":
		return pd.hasNpmDependency(projectPath, dependency)
	case "python":
		return pd.hasPythonDependency(projectPath, dependency)
	case "java":
		return pd.hasJavaDependency(projectPath, dependency)
	}
	return false
}

func (pd *ProjectDetector) hasGoDependency(projectPath, dependency string) bool {
	goModPath := filepath.Join(projectPath, "go.mod")
	content, err := os.ReadFile(goModPath)
	if err != nil {
		return false
	}

	return strings.Contains(string(content), dependency)
}

func (pd *ProjectDetector) hasNpmDependency(projectPath, dependency string) bool {
	packageJsonPath := filepath.Join(projectPath, "package.json")
	content, err := os.ReadFile(packageJsonPath)
	if err != nil {
		return false
	}

	var packageJson map[string]interface{}
	if err := json.Unmarshal(content, &packageJson); err != nil {
		return false
	}

	// Check dependencies and devDependencies
	if deps, ok := packageJson["dependencies"].(map[string]interface{}); ok {
		if _, exists := deps[dependency]; exists {
			return true
		}
	}

	if devDeps, ok := packageJson["devDependencies"].(map[string]interface{}); ok {
		if _, exists := devDeps[dependency]; exists {
			return true
		}
	}

	return false
}

func (pd *ProjectDetector) hasPythonDependency(projectPath, dependency string) bool {
	// Check requirements.txt
	reqPath := filepath.Join(projectPath, "requirements.txt")
	if content, err := os.ReadFile(reqPath); err == nil {
		return strings.Contains(string(content), dependency)
	}

	// Check pyproject.toml
	pyprojectPath := filepath.Join(projectPath, "pyproject.toml")
	if content, err := os.ReadFile(pyprojectPath); err == nil {
		return strings.Contains(string(content), dependency)
	}

	return false
}

func (pd *ProjectDetector) hasJavaDependency(projectPath, dependency string) bool {
	// Check pom.xml
	pomPath := filepath.Join(projectPath, "pom.xml")
	if content, err := os.ReadFile(pomPath); err == nil {
		return strings.Contains(string(content), dependency)
	}

	// Check build.gradle
	gradlePath := filepath.Join(projectPath, "build.gradle")
	if content, err := os.ReadFile(gradlePath); err == nil {
		return strings.Contains(string(content), dependency)
	}

	return false
}

func (pd *ProjectDetector) analyzeWebService(projectPath, framework string) (models.ServiceInfo, error) {
	service := models.ServiceInfo{
		Name:      framework + "_service",
		Type:      "api",
		Endpoints: []models.EndpointInfo{},
		Config:    make(map[string]string),
	}

	// Framework-specific endpoint detection
	switch framework {
	case "fiber":
		endpoints, err := pd.analyzeFiberEndpoints(projectPath)
		if err == nil {
			service.Endpoints = endpoints
		}
	case "express":
		endpoints, err := pd.analyzeExpressEndpoints(projectPath)
		if err == nil {
			service.Endpoints = endpoints
		}
	}

	return service, nil
}

func (pd *ProjectDetector) analyzeFiberEndpoints(projectPath string) ([]models.EndpointInfo, error) {
	var endpoints []models.EndpointInfo

	err := filepath.Walk(projectPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || !strings.HasSuffix(path, ".go") {
			return err
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		// Look for Fiber route patterns
		routePatterns := []string{
			`app\.Get\("([^"]+)"`,
			`app\.Post\("([^"]+)"`,
			`app\.Put\("([^"]+)"`,
			`app\.Delete\("([^"]+)"`,
			`app\.Patch\("([^"]+)"`,
		}

		for _, pattern := range routePatterns {
			re := regexp.MustCompile(pattern)
			matches := re.FindAllStringSubmatch(string(content), -1)
			
			for _, match := range matches {
				if len(match) > 1 {
					method := strings.ToUpper(strings.Split(pattern, `\.`)[1][:strings.Index(strings.Split(pattern, `\.`)[1], `\(`)])
					endpoint := models.EndpointInfo{
						Path:     match[1],
						Method:   method,
						Handler:  "handler_" + strings.ReplaceAll(match[1], "/", "_"),
						AuthReq:  false, // Would need more sophisticated analysis
					}
					endpoints = append(endpoints, endpoint)
				}
			}
		}

		return nil
	})

	return endpoints, err
}

func (pd *ProjectDetector) analyzeExpressEndpoints(projectPath string) ([]models.EndpointInfo, error) {
	var endpoints []models.EndpointInfo

	err := filepath.Walk(projectPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || (!strings.HasSuffix(path, ".js") && !strings.HasSuffix(path, ".ts")) {
			return err
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		// Look for Express route patterns
		routePatterns := []string{
			`app\.get\(['"]([^'"]+)['"]`,
			`app\.post\(['"]([^'"]+)['"]`,
			`app\.put\(['"]([^'"]+)['"]`,
			`app\.delete\(['"]([^'"]+)['"]`,
			`router\.get\(['"]([^'"]+)['"]`,
			`router\.post\(['"]([^'"]+)['"]`,
		}

		for _, pattern := range routePatterns {
			re := regexp.MustCompile(pattern)
			matches := re.FindAllStringSubmatch(string(content), -1)
			
			for _, match := range matches {
				if len(match) > 1 {
					methodStart := strings.Index(pattern, `\.`) + 1
					methodEnd := strings.Index(pattern[methodStart:], `\(`)
					method := strings.ToUpper(pattern[methodStart : methodStart+methodEnd])
					
					endpoint := models.EndpointInfo{
						Path:     match[1],
						Method:   method,
						Handler:  "handler_" + strings.ReplaceAll(match[1], "/", "_"),
						AuthReq:  false,
					}
					endpoints = append(endpoints, endpoint)
				}
			}
		}

		return nil
	})

	return endpoints, err
}

func (pd *ProjectDetector) parseGoModDependencies(projectPath string) (map[string]string, error) {
	dependencies := make(map[string]string)
	
	goModPath := filepath.Join(projectPath, "go.mod")
	content, err := os.ReadFile(goModPath)
	if err != nil {
		return dependencies, err
	}

	// Simple go.mod parsing (would use proper parser in production)
	lines := strings.Split(string(content), "\n")
	inRequire := false
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		if strings.HasPrefix(line, "require (") {
			inRequire = true
			continue
		}
		
		if inRequire && line == ")" {
			inRequire = false
			continue
		}
		
		if inRequire || strings.HasPrefix(line, "require ") {
			// Parse dependency line
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				name := parts[0]
				version := parts[1]
				if strings.HasPrefix(line, "require ") {
					name = parts[1]
					version = parts[2]
				}
				dependencies[name] = version
			}
		}
	}

	return dependencies, nil
}

func (pd *ProjectDetector) parsePackageJsonDependencies(projectPath string) (map[string]string, error) {
	dependencies := make(map[string]string)
	
	packageJsonPath := filepath.Join(projectPath, "package.json")
	content, err := os.ReadFile(packageJsonPath)
	if err != nil {
		return dependencies, err
	}

	var packageJson map[string]interface{}
	if err := json.Unmarshal(content, &packageJson); err != nil {
		return dependencies, err
	}

	// Parse dependencies
	if deps, ok := packageJson["dependencies"].(map[string]interface{}); ok {
		for name, version := range deps {
			if v, ok := version.(string); ok {
				dependencies[name] = v
			}
		}
	}

	// Parse devDependencies
	if devDeps, ok := packageJson["devDependencies"].(map[string]interface{}); ok {
		for name, version := range devDeps {
			if v, ok := version.(string); ok {
				dependencies[name+"(dev)"] = v
			}
		}
	}

	return dependencies, nil
}

func (pd *ProjectDetector) parsePythonDependencies(projectPath string) (map[string]string, error) {
	dependencies := make(map[string]string)
	
	// Try requirements.txt first
	reqPath := filepath.Join(projectPath, "requirements.txt")
	if content, err := os.ReadFile(reqPath); err == nil {
		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			
			// Parse requirement line (package==version or package>=version)
			for _, sep := range []string{"==", ">=", "<=", ">", "<", "~="} {
				if strings.Contains(line, sep) {
					parts := strings.Split(line, sep)
					if len(parts) >= 2 {
						dependencies[parts[0]] = parts[1]
						break
					}
				}
			}
		}
	}

	return dependencies, nil
}

func (pd *ProjectDetector) isConfigFile(filename string) bool {
	configFiles := []string{
		"config.json", "config.yaml", "config.yml", "appsettings.json",
		".env", ".env.local", ".env.production", "docker-compose.yml",
		"Dockerfile", "nginx.conf", "apache.conf", "web.config",
	}

	for _, configFile := range configFiles {
		if filename == configFile {
			return true
		}
	}

	// Check extensions
	configExts := []string{".conf", ".config", ".ini", ".properties", ".toml"}
	ext := strings.ToLower(filepath.Ext(filename))
	for _, configExt := range configExts {
		if ext == configExt {
			return true
		}
	}

	return false
}

func detectorContains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

