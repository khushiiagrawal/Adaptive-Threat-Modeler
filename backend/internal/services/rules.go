package services

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"regexp"
	"strings"

	"adaptive-threat-modeler/internal/models"
)

// SecurityRule represents a security rule for vulnerability detection
type SecurityRule struct {
	ID          string            `json:"id"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Severity    string            `json:"severity"`
	Category    string            `json:"category"`
	CWE         string            `json:"cwe,omitempty"`
	OWASP       string            `json:"owasp,omitempty"`
	Language    string            `json:"language"`
	Framework   string            `json:"framework,omitempty"`
	Pattern     RulePattern       `json:"pattern"`
	Impact      string            `json:"impact"`
	Remediation []string          `json:"remediation"`
	References  []string          `json:"references"`
	Metadata    map[string]string `json:"metadata"`
}

// RulePattern defines how to match code patterns
type RulePattern struct {
	Type        string            `json:"type"` // regex, ast, semantic
	Patterns    []string          `json:"patterns"`
	Antipatterns []string         `json:"antipatterns,omitempty"`
	Conditions  []Condition       `json:"conditions,omitempty"`
	Variables   map[string]string `json:"variables,omitempty"`
}

// Condition represents a condition for rule matching
type Condition struct {
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
}

// RuleMatch represents a match found by a security rule
type RuleMatch struct {
	Line     int    `json:"line"`
	Column   int    `json:"column"`
	Evidence string `json:"evidence"`
	Function string `json:"function,omitempty"`
	Context  string `json:"context,omitempty"`
}

type RuleEngine struct {
	rules          map[string][]SecurityRule
	languageRules  map[string][]SecurityRule
	frameworkRules map[string][]SecurityRule
}

// NewRuleEngine creates a new rule engine instance
func NewRuleEngine() *RuleEngine {
	engine := &RuleEngine{
		rules:          make(map[string][]SecurityRule),
		languageRules:  make(map[string][]SecurityRule),
		frameworkRules: make(map[string][]SecurityRule),
	}
	
	// Load built-in rules
	engine.loadBuiltInRules()
	
	return engine
}

// LoadRulesForProject loads relevant rules based on project information
func (re *RuleEngine) LoadRulesForProject(projectInfo *models.ProjectInfo) []SecurityRule {
	var allRules []SecurityRule
	
	// Load language-specific rules
	for _, language := range projectInfo.Languages {
		if rules, exists := re.languageRules[language]; exists {
			allRules = append(allRules, rules...)
		}
	}
	
	// Load framework-specific rules
	for _, framework := range projectInfo.Frameworks {
		if rules, exists := re.frameworkRules[framework]; exists {
			allRules = append(allRules, rules...)
		}
	}
	
	// Load generic rules
	if rules, exists := re.rules["generic"]; exists {
		allRules = append(allRules, rules...)
	}
	
	return allRules
}

// GetAllRules returns all available security rules
func (re *RuleEngine) GetAllRules() []SecurityRule {
	var allRules []SecurityRule
	
	for _, rules := range re.rules {
		allRules = append(allRules, rules...)
	}
	
	for _, rules := range re.languageRules {
		allRules = append(allRules, rules...)
	}
	
	for _, rules := range re.frameworkRules {
		allRules = append(allRules, rules...)
	}
	
	return allRules
}

// GetRulesForLanguage returns rules for a specific language
func (re *RuleEngine) GetRulesForLanguage(language string) []SecurityRule {
	if rules, exists := re.languageRules[language]; exists {
		return rules
	}
	return []SecurityRule{}
}

// Match checks if a rule matches against the given AST and source code
func (rule *SecurityRule) Match(astNode interface{}, sourceCode string) []RuleMatch {
	var matches []RuleMatch
	
	switch rule.Pattern.Type {
	case "regex":
		matches = rule.matchRegex(sourceCode)
	case "ast":
		matches = rule.matchAST(astNode, sourceCode)
	case "semantic":
		matches = rule.matchSemantic(astNode, sourceCode)
	default:
		// Default to regex matching
		matches = rule.matchRegex(sourceCode)
	}
	
	return matches
}

// GenerateAutoFix generates an automatic fix for a vulnerability match
func (rule *SecurityRule) GenerateAutoFix(match RuleMatch) *models.AutoFix {
	// This is a simplified implementation
	// In a real system, this would be much more sophisticated
	
	if rule.Category == "injection" && strings.Contains(rule.ID, "sql") {
		return &models.AutoFix{
			Description: "Use parameterized queries to prevent SQL injection",
			OldCode:     match.Evidence,
			NewCode:     "// Use parameterized query here",
			Confidence:  "medium",
		}
	}
	
	if rule.Category == "crypto" && strings.Contains(rule.ID, "weak") {
		return &models.AutoFix{
			Description: "Replace with stronger cryptographic algorithm",
			OldCode:     match.Evidence,
			NewCode:     "// Use AES-256 or other strong encryption",
			Confidence:  "high",
		}
	}
	
	return nil
}

// matchRegex performs regex-based pattern matching
func (rule *SecurityRule) matchRegex(sourceCode string) []RuleMatch {
	var matches []RuleMatch
	
	lines := strings.Split(sourceCode, "\n")
	
	for _, pattern := range rule.Pattern.Patterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}
		
		for lineNum, line := range lines {
			if match := re.FindString(line); match != "" {
				// Check antipatterns
				skip := false
				for _, antipattern := range rule.Pattern.Antipatterns {
					if antiRe, err := regexp.Compile(antipattern); err == nil {
						if antiRe.MatchString(line) {
							skip = true
							break
						}
					}
				}
				
				if !skip {
					matches = append(matches, RuleMatch{
						Line:     lineNum + 1,
						Column:   strings.Index(line, match) + 1,
						Evidence: match,
						Context:  line,
					})
				}
			}
		}
	}
	
	return matches
}

// matchAST performs AST-based pattern matching
func (rule *SecurityRule) matchAST(astNode interface{}, sourceCode string) []RuleMatch {
	var matches []RuleMatch
	
	// This is a simplified AST matching implementation
	// In a real system, this would use proper AST traversal and pattern matching
	
	if goAST, ok := astNode.(*ast.File); ok {
		ast.Inspect(goAST, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.CallExpr:
				if ident, ok := node.Fun.(*ast.Ident); ok {
					for _, pattern := range rule.Pattern.Patterns {
						if strings.Contains(pattern, ident.Name) {
							matches = append(matches, RuleMatch{
								Line:     int(node.Pos()),
								Column:   1,
								Evidence: ident.Name,
								Function: ident.Name,
							})
						}
					}
				}
			}
			return true
		})
	}
	
	return matches
}

// matchSemantic performs semantic analysis for pattern matching
func (rule *SecurityRule) matchSemantic(astNode interface{}, sourceCode string) []RuleMatch {
	// This would implement more sophisticated semantic analysis
	// For now, fall back to regex matching
	return rule.matchRegex(sourceCode)
}

// loadBuiltInRules loads the built-in security rules
func (re *RuleEngine) loadBuiltInRules() {
	// Go language rules
	re.languageRules["go"] = []SecurityRule{
		{
			ID:          "go-sql-injection",
			Title:       "Potential SQL Injection",
			Description: "Direct string concatenation in SQL queries can lead to SQL injection",
			Severity:    "high",
			Category:    "injection",
			CWE:         "CWE-89",
			OWASP:       "A03:2021",
			Language:    "go",
			Pattern: RulePattern{
				Type: "regex",
				Patterns: []string{
					`db\.Query\([^,)]*\+[^)]*\)`,
					`db\.Exec\([^,)]*\+[^)]*\)`,
					`fmt\.Sprintf.*SELECT.*\+`,
				},
				Antipatterns: []string{
					`db\.Query\([^+)]*\$\d+`,
					`db\.QueryRow\([^+)]*\$\d+`,
				},
			},
			Impact:      "Attackers can execute arbitrary SQL commands",
			Remediation: []string{
				"Use parameterized queries with placeholders ($1, $2, etc.)",
				"Validate and sanitize user input",
				"Use an ORM or query builder",
			},
			References: []string{
				"https://owasp.org/www-community/attacks/SQL_Injection",
				"https://golang.org/pkg/database/sql/",
			},
		},
		{
			ID:          "go-hardcoded-credentials",
			Title:       "Hardcoded Credentials",
			Description: "Credentials should not be hardcoded in source code",
			Severity:    "critical",
			Category:    "auth",
			CWE:         "CWE-798",
			OWASP:       "A07:2021",
			Language:    "go",
			Pattern: RulePattern{
				Type: "regex",
				Patterns: []string{
					`password\s*:=\s*"[^"]+`,
					`apiKey\s*:=\s*"[^"]+`,
					`secret\s*:=\s*"[^"]+`,
					`token\s*:=\s*"[^"]+`,
				},
			},
			Impact:      "Exposed credentials can be used by attackers",
			Remediation: []string{
				"Use environment variables for credentials",
				"Use a secrets management system",
				"Never commit credentials to version control",
			},
		},
		{
			ID:          "go-weak-crypto",
			Title:       "Weak Cryptographic Algorithm",
			Description: "Use of weak or deprecated cryptographic algorithms",
			Severity:    "medium",
			Category:    "crypto",
			CWE:         "CWE-327",
			Language:    "go",
			Pattern: RulePattern{
				Type: "regex",
				Patterns: []string{
					`crypto/md5`,
					`crypto/sha1`,
					`crypto/des`,
					`crypto/rc4`,
				},
			},
			Impact:      "Weak encryption can be broken by attackers",
			Remediation: []string{
				"Use SHA-256 or SHA-3 instead of MD5/SHA1",
				"Use AES instead of DES or RC4",
				"Use bcrypt for password hashing",
			},
		},
	}
	
	// Python language rules
	re.languageRules["python"] = []SecurityRule{
		{
			ID:          "python-sql-injection",
			Title:       "SQL Injection Vulnerability",
			Description: "Raw SQL queries with string formatting can lead to SQL injection",
			Severity:    "critical",
			Category:    "injection",
			CWE:         "CWE-89",
			OWASP:       "A03:2021",
			Language:    "python",
			Pattern: RulePattern{
				Type: "regex",
				Patterns: []string{
					`cursor\.execute\([^,)]*%[^)]*\)`,
					`cursor\.execute\([^,)]*\+[^)]*\)`,
					`cursor\.execute\([^,)]*\.format\([^)]*\)\)`,
					`cursor\.execute\(f["'][^"']*\{[^}]*\}`,
					`\.execute\([^,)]*%[^)]*\)`,
					`\.execute\([^,)]*\+[^)]*\)`,
					`SELECT.*\+.*user`,
					`INSERT.*\+.*user`,
					`UPDATE.*\+.*user`,
					`DELETE.*\+.*user`,
				},
				Antipatterns: []string{
					`cursor\.execute\([^,)]*,\s*\([^)]*\)\)`,
					`\.execute\([^,)]*,\s*\([^)]*\)\)`,
				},
			},
			Impact:      "Complete database compromise, data theft, data manipulation",
			Remediation: []string{
				"Use parameterized queries with cursor.execute(query, params)",
				"Validate and sanitize user input",
				"Use an ORM like SQLAlchemy",
			},
		},
		{
			ID:          "python-command-injection",
			Title:       "Command Injection Vulnerability",
			Description: "Executing system commands with user input can lead to command injection",
			Severity:    "critical",
			Category:    "injection",
			CWE:         "CWE-78",
			OWASP:       "A03:2021",
			Language:    "python",
			Pattern: RulePattern{
				Type: "regex",
				Patterns: []string{
					`os\.system\([^)]*\+[^)]*\)`,
					`subprocess\.call\([^)]*\+[^)]*\)`,
					`subprocess\.run\([^)]*\+[^)]*\)`,
					`subprocess\.Popen\([^)]*\+[^)]*\)`,
					`os\.popen\([^)]*\+[^)]*\)`,
					`commands\.getoutput\([^)]*\+[^)]*\)`,
					`eval\([^)]*input\([^)]*\)\)`,
					`exec\([^)]*input\([^)]*\)\)`,
				},
			},
			Impact:      "Arbitrary command execution, system compromise",
			Remediation: []string{
				"Use subprocess with shell=False and argument lists",
				"Validate and sanitize user input",
				"Use whitelisting for allowed commands",
			},
		},
		{
			ID:          "python-hardcoded-secrets",
			Title:       "Hardcoded Secrets",
			Description: "Secrets and credentials should not be hardcoded in source code",
			Severity:    "critical",
			Category:    "secrets",
			CWE:         "CWE-798",
			OWASP:       "A07:2021",
			Language:    "python",
			Pattern: RulePattern{
				Type: "regex",
				Patterns: []string{
					`password\s*=\s*["'][^"']{8,}["']`,
					`api_key\s*=\s*["'][^"']{16,}["']`,
					`secret\s*=\s*["'][^"']{16,}["']`,
					`token\s*=\s*["'][^"']{16,}["']`,
					`SECRET_KEY\s*=\s*["'][^"']{16,}["']`,
					`API_KEY\s*=\s*["'][^"']{16,}["']`,
					`DATABASE_URL\s*=\s*["'].*://.*:.*@`,
					`aws_access_key_id\s*=\s*["'][^"']+["']`,
					`aws_secret_access_key\s*=\s*["'][^"']+["']`,
				},
			},
			Impact:      "Credential exposure, unauthorized access",
			Remediation: []string{
				"Use environment variables for secrets",
				"Use a secrets management system",
				"Never commit secrets to version control",
			},
		},
		{
			ID:          "python-pickle-deserialization",
			Title:       "Insecure Deserialization",
			Description: "Using pickle.loads on untrusted data can lead to code execution",
			Severity:    "critical",
			Category:    "deserialization",
			CWE:         "CWE-502",
			OWASP:       "A08:2021",
			Language:    "python",
			Pattern: RulePattern{
				Type: "regex",
				Patterns: []string{
					`pickle\.loads\(`,
					`pickle\.load\([^)]*request`,
					`cPickle\.loads\(`,
					`dill\.loads\(`,
					`yaml\.load\([^,)]*\)`,
					`yaml\.unsafe_load\(`,
				},
				Antipatterns: []string{
					`yaml\.safe_load\(`,
				},
			},
			Impact:      "Arbitrary code execution, complete system compromise",
			Remediation: []string{
				"Use json.loads() for data serialization",
				"Use yaml.safe_load() instead of yaml.load()",
				"Validate data before deserialization",
			},
		},
		{
			ID:          "python-path-traversal",
			Title:       "Path Traversal Vulnerability",
			Description: "File operations with user input can lead to path traversal attacks",
			Severity:    "high",
			Category:    "injection",
			CWE:         "CWE-22",
			OWASP:       "A01:2021",
			Language:    "python",
			Pattern: RulePattern{
				Type: "regex",
				Patterns: []string{
					`open\([^,)]*\+[^)]*\)`,
					`open\([^,)]*request\.[^,)]*\)`,
					`open\([^,)]*input\([^)]*\)\)`,
					`with\s+open\([^,)]*\+[^)]*\)`,
					`os\.path\.join\([^,)]*request\.[^,)]*\)`,
				},
			},
			Impact:      "Unauthorized file access, information disclosure",
			Remediation: []string{
				"Validate file paths against a whitelist",
				"Use os.path.join() and os.path.abspath() safely",
				"Restrict file operations to specific directories",
			},
		},
		{
			ID:          "python-weak-crypto",
			Title:       "Weak Cryptographic Hash",
			Description: "MD5 and SHA1 are cryptographically weak hash functions",
			Severity:    "medium",
			Category:    "crypto",
			CWE:         "CWE-327",
			Language:    "python",
			Pattern: RulePattern{
				Type: "regex",
				Patterns: []string{
					`hashlib\.md5\(`,
					`hashlib\.sha1\(`,
					`import md5`,
					`from md5 import`,
				},
			},
			Impact:      "Hash collision attacks, data integrity issues",
			Remediation: []string{
				"Use SHA-256 or SHA-3 instead of MD5/SHA1",
				"Use bcrypt or scrypt for password hashing",
				"Use HMAC for message authentication",
			},
		},
		{
			ID:          "python-ssrf",
			Title:       "Server-Side Request Forgery (SSRF)",
			Description: "Making HTTP requests with user-controlled URLs can lead to SSRF",
			Severity:    "high",
			Category:    "injection",
			CWE:         "CWE-918",
			OWASP:       "A10:2021",
			Language:    "python",
			Pattern: RulePattern{
				Type: "regex",
				Patterns: []string{
					`requests\.get\([^,)]*request\.[^,)]*\)`,
					`requests\.post\([^,)]*request\.[^,)]*\)`,
					`urllib\.request\.urlopen\([^,)]*request\.[^,)]*\)`,
					`urllib2\.urlopen\([^,)]*request\.[^,)]*\)`,
					`httplib\.HTTPConnection\([^,)]*request\.[^,)]*\)`,
				},
			},
			Impact:      "Access to internal services, data exfiltration",
			Remediation: []string{
				"Validate and whitelist allowed URLs",
				"Use URL parsing to check domains",
				"Implement network-level restrictions",
			},
		},
		{
			ID:          "python-xss",
			Title:       "Cross-Site Scripting (XSS)",
			Description: "Rendering user input without escaping can lead to XSS",
			Severity:    "high",
			Category:    "injection",
			CWE:         "CWE-79",
			OWASP:       "A03:2021",
			Language:    "python",
			Pattern: RulePattern{
				Type: "regex",
				Patterns: []string{
					`render_template_string\([^,)]*request\.[^,)]*\)`,
					`Markup\([^,)]*request\.[^,)]*\)`,
					`return\s+[^,)]*request\.[^,)]*[^,)]*%`,
					`\.format\([^,)]*request\.[^,)]*\)`,
				},
			},
			Impact:      "Client-side code execution, session hijacking",
			Remediation: []string{
				"Use template engines with auto-escaping",
				"Escape user input before rendering",
				"Use Content Security Policy (CSP)",
			},
		},
		{
			ID:          "python-dns-exfiltration",
			Title:       "DNS Exfiltration",
			Description: "DNS queries with sensitive data can be used for data exfiltration",
			Severity:    "high",
			Category:    "exfiltration",
			CWE:         "CWE-200",
			Language:    "python",
			Pattern: RulePattern{
				Type: "regex",
				Patterns: []string{
					`socket\.gethostbyname\([^,)]*base64\.[^,)]*\)`,
					`socket\.gethostbyname\([^,)]*\.encode\([^)]*\)\.[^,)]*\)`,
					`dns\.resolver\.query\([^,)]*base64\.[^,)]*\)`,
					`subprocess.*nslookup.*base64`,
				},
			},
			Impact:      "Data exfiltration via DNS queries",
			Remediation: []string{
				"Monitor DNS queries for suspicious patterns",
				"Implement DNS filtering",
				"Use secure communication channels",
			},
		},
	}
	
	// HCL/Terraform rules
	re.languageRules["hcl"] = []SecurityRule{
		{
			ID:          "terraform-public-s3",
			Title:       "Publicly Accessible S3 Bucket",
			Description: "S3 bucket configured with public access",
			Severity:    "critical",
			Category:    "misconfiguration",
			CWE:         "CWE-200",
			Language:    "hcl",
			Pattern: RulePattern{
				Type: "regex",
				Patterns: []string{
					`acl\s*=\s*["']public-read["']`,
					`acl\s*=\s*["']public-read-write["']`,
					`block_public_acls\s*=\s*false`,
					`block_public_policy\s*=\s*false`,
					`ignore_public_acls\s*=\s*false`,
					`restrict_public_buckets\s*=\s*false`,
				},
			},
			Impact:      "Unauthorized access to sensitive data",
			Remediation: []string{
				"Set appropriate ACLs for S3 buckets",
				"Enable S3 bucket public access blocks",
				"Use IAM policies for access control",
			},
		},
		{
			ID:          "terraform-open-security-group",
			Title:       "Overly Permissive Security Group",
			Description: "Security group allows access from anywhere (0.0.0.0/0)",
			Severity:    "high",
			Category:    "misconfiguration",
			CWE:         "CWE-200",
			Language:    "hcl",
			Pattern: RulePattern{
				Type: "regex",
				Patterns: []string{
					`cidr_blocks\s*=\s*\[["']0\.0\.0\.0/0["']\]`,
					`from_port\s*=\s*0.*to_port\s*=\s*65535`,
					`protocol\s*=\s*["']-1["'].*cidr_blocks.*0\.0\.0\.0/0`,
				},
			},
			Impact:      "Unrestricted network access to resources",
			Remediation: []string{
				"Restrict CIDR blocks to specific IP ranges",
				"Use specific ports instead of all ports",
				"Implement least privilege access",
			},
		},
		{
			ID:          "terraform-unencrypted-storage",
			Title:       "Unencrypted Storage",
			Description: "Storage resources without encryption enabled",
			Severity:    "high",
			Category:    "crypto",
			CWE:         "CWE-311",
			Language:    "hcl",
			Pattern: RulePattern{
				Type: "regex",
				Patterns: []string{
					`resource\s+["']aws_db_instance["'].*(?!.*encrypted\s*=\s*true)`,
					`resource\s+["']aws_ebs_volume["'].*(?!.*encrypted\s*=\s*true)`,
					`resource\s+["']aws_rds_cluster["'].*(?!.*storage_encrypted\s*=\s*true)`,
				},
			},
			Impact:      "Data exposure, compliance violations",
			Remediation: []string{
				"Enable encryption for all storage resources",
				"Use AWS KMS for key management",
				"Set encryption as default policy",
			},
		},
	}

	// Shell script rules  
	re.languageRules["shell"] = []SecurityRule{
		{
			ID:          "shell-command-injection",
			Title:       "Command Injection in Shell Script",
			Description: "Unquoted variables in shell commands can lead to injection",
			Severity:    "critical",
			Category:    "injection",
			CWE:         "CWE-78",
			Language:    "shell",
			Pattern: RulePattern{
				Type: "regex",
				Patterns: []string{
					`\$\{[^}]*\}[^"']`,
					`\$[A-Za-z_][A-Za-z0-9_]*[^"'\s]`,
					`eval.*\$`,
					`exec.*\$`,
					`system.*\$`,
				},
			},
			Impact:      "Command injection, arbitrary code execution",
			Remediation: []string{
				"Quote all variables: \"$variable\"",
				"Use arrays for command arguments",
				"Validate input before using in commands",
			},
		},
		{
			ID:          "shell-hardcoded-secrets",
			Title:       "Hardcoded Secrets in Shell Script",
			Description: "Secrets should not be hardcoded in shell scripts",
			Severity:    "critical",
			Category:    "secrets",
			CWE:         "CWE-798",
			Language:    "shell",
			Pattern: RulePattern{
				Type: "regex",
				Patterns: []string{
					`PASSWORD\s*=\s*["'][^"']{8,}["']`,
					`API_KEY\s*=\s*["'][^"']{16,}["']`,
					`SECRET\s*=\s*["'][^"']{16,}["']`,
					`TOKEN\s*=\s*["'][^"']{16,}["']`,
					`password\s*=\s*["'][^"']{8,}["']`,
					`api_key\s*=\s*["'][^"']{16,}["']`,
				},
			},
			Impact:      "Credential exposure",
			Remediation: []string{
				"Use environment variables for secrets",
				"Use external secret management systems",
				"Never commit secrets to version control",
			},
		},
	}

	// JavaScript/TypeScript rules
	re.languageRules["javascript"] = []SecurityRule{
		{
			ID:          "js-xss-vulnerability",
			Title:       "Cross-Site Scripting (XSS)",
			Description: "Potential XSS vulnerability through innerHTML usage",
			Severity:    "high",
			Category:    "injection",
			CWE:         "CWE-79",
			OWASP:       "A03:2021",
			Language:    "javascript",
			Pattern: RulePattern{
				Type: "regex",
				Patterns: []string{
					`\.innerHTML\s*=\s*[^"'][^;]*`,
					`document\.write\([^)]*\+`,
					`\$\([^)]*\)\.html\([^)]*\+`,
				},
			},
			Impact:      "Attackers can execute malicious scripts in user browsers",
			Remediation: []string{
				"Use textContent instead of innerHTML",
				"Sanitize user input before rendering",
				"Use a templating engine with auto-escaping",
			},
		},
		{
			ID:          "js-eval-usage",
			Title:       "Use of eval() Function",
			Description: "The eval() function can execute arbitrary code",
			Severity:    "high",
			Category:    "injection",
			CWE:         "CWE-95",
			Language:    "javascript",
			Pattern: RulePattern{
				Type: "regex",
				Patterns: []string{
					`eval\s*\(`,
					`new\s+Function\s*\(`,
					`setTimeout\s*\(\s*["'][^"']*["']`,
				},
			},
			Impact:      "Code injection and arbitrary code execution",
			Remediation: []string{
				"Avoid using eval() entirely",
				"Use JSON.parse() for JSON data",
				"Use proper parsing libraries",
			},
		},
	}
	
	// Framework-specific rules
	re.frameworkRules["express"] = []SecurityRule{
		{
			ID:          "express-missing-helmet",
			Title:       "Missing Security Headers",
			Description: "Express app should use Helmet for security headers",
			Severity:    "medium",
			Category:    "config",
			Framework:   "express",
			Pattern: RulePattern{
				Type: "regex",
				Patterns: []string{
					`express\(\)`,
				},
				Antipatterns: []string{
					`helmet\(\)`,
					`app\.use\(helmet`,
				},
			},
			Impact:      "Missing security headers can lead to various attacks",
			Remediation: []string{
				"Install and use helmet middleware",
				"Configure appropriate security headers",
			},
		},
	}
	
	re.frameworkRules["fiber"] = []SecurityRule{
		{
			ID:          "fiber-missing-cors",
			Title:       "Missing CORS Configuration",
			Description: "Fiber app should configure CORS properly",
			Severity:    "medium",
			Category:    "config",
			Framework:   "fiber",
			Pattern: RulePattern{
				Type: "regex",
				Patterns: []string{
					`fiber\.New\(\)`,
				},
				Antipatterns: []string{
					`cors\.New\(\)`,
					`app\.Use\(cors`,
				},
			},
			Impact:      "Improper CORS configuration can lead to security issues",
			Remediation: []string{
				"Configure CORS middleware with appropriate origins",
				"Restrict CORS to necessary domains only",
			},
		},
	}
	
	// Generic rules
	re.rules["generic"] = []SecurityRule{
		{
			ID:          "generic-todo-fixme",
			Title:       "TODO/FIXME Comments",
			Description: "TODO and FIXME comments may indicate incomplete security implementations",
			Severity:    "info",
			Category:    "code_quality",
			Language:    "generic",
			Pattern: RulePattern{
				Type: "regex",
				Patterns: []string{
					`(?i)//.*todo.*security`,
					`(?i)//.*fixme.*security`,
					`(?i)//.*hack.*security`,
				},
			},
			Impact:      "Incomplete security implementations",
			Remediation: []string{
				"Review and complete security-related TODOs",
				"Remove or address FIXME comments",
			},
		},
		{
			ID:          "generic-debug-code",
			Title:       "Debug Code in Production",
			Description: "Debug statements should not be present in production code",
			Severity:    "low",
			Category:    "code_quality",
			Language:    "generic",
			Pattern: RulePattern{
				Type: "regex",
				Patterns: []string{
					`console\.log\(`,
					`print\(`,
					`println\(`,
					`debug\(`,
				},
			},
			Impact:      "Information disclosure and performance issues",
			Remediation: []string{
				"Remove debug statements from production code",
				"Use proper logging frameworks",
				"Configure log levels appropriately",
			},
		},
	}
}

// AddCustomRule adds a custom security rule
func (re *RuleEngine) AddCustomRule(rule SecurityRule) {
	if rule.Language != "" {
		re.languageRules[rule.Language] = append(re.languageRules[rule.Language], rule)
	} else if rule.Framework != "" {
		re.frameworkRules[rule.Framework] = append(re.frameworkRules[rule.Framework], rule)
	} else {
		re.rules["custom"] = append(re.rules["custom"], rule)
	}
}

// LoadRulesFromJSON loads rules from JSON configuration
func (re *RuleEngine) LoadRulesFromJSON(jsonData []byte) error {
	var rules []SecurityRule
	
	if err := json.Unmarshal(jsonData, &rules); err != nil {
		return fmt.Errorf("failed to parse rules JSON: %w", err)
	}
	
	for _, rule := range rules {
		re.AddCustomRule(rule)
	}
	
	return nil
}

