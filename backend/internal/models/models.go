package models

import "time"

// AnalysisRequest represents the input for threat analysis
type AnalysisRequest struct {
	Type     string `json:"type" validate:"required,oneof=github zip"`
	RepoURL  string `json:"repo_url,omitempty"`
	ZipData  []byte `json:"zip_data,omitempty"`
	Filename string `json:"filename,omitempty"`
}

// ProjectInfo contains detected project metadata
type ProjectInfo struct {
	Languages   []string          `json:"languages"`
	Frameworks  []string          `json:"frameworks"`
	Services    []ServiceInfo     `json:"services"`
	Dependencies map[string]string `json:"dependencies"`
	ConfigFiles []string          `json:"config_files"`
}

// ServiceInfo represents a detected service/component
type ServiceInfo struct {
	Name      string            `json:"name"`
	Type      string            `json:"type"` // api, database, storage, etc.
	Endpoints []EndpointInfo    `json:"endpoints,omitempty"`
	Config    map[string]string `json:"config,omitempty"`
}

// EndpointInfo represents an API endpoint
type EndpointInfo struct {
	Path     string   `json:"path"`
	Method   string   `json:"method"`
	Handler  string   `json:"handler"`
	Params   []string `json:"params,omitempty"`
	AuthReq  bool     `json:"auth_required"`
}

// Vulnerability represents a security finding
type Vulnerability struct {
	ID          string            `json:"id"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Severity    string            `json:"severity"` // critical, high, medium, low, info
	Category    string            `json:"category"` // injection, auth, crypto, etc.
	CWE         string            `json:"cwe,omitempty"`
	OWASP       string            `json:"owasp,omitempty"`
	Location    Location          `json:"location"`
	Evidence    string            `json:"evidence"`
	Impact      string            `json:"impact"`
	Remediation []string          `json:"remediation"`
	AutoFix     *AutoFix          `json:"autofix,omitempty"`
	References  []string          `json:"references,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// Location represents where a vulnerability was found
type Location struct {
	File      string `json:"file"`
	Line      int    `json:"line"`
	Column    int    `json:"column"`
	EndLine   int    `json:"end_line,omitempty"`
	EndColumn int    `json:"end_column,omitempty"`
	Function  string `json:"function,omitempty"`
	Class     string `json:"class,omitempty"`
}

// AutoFix represents an automated fix suggestion
type AutoFix struct {
	Description string `json:"description"`
	OldCode     string `json:"old_code"`
	NewCode     string `json:"new_code"`
	Confidence  string `json:"confidence"` // high, medium, low
}

// ThreatMap represents the visual threat model
type ThreatMap struct {
	Components []Component  `json:"components"`
	Flows      []DataFlow   `json:"flows"`
	TrustZones []TrustZone  `json:"trust_zones"`
	Assets     []Asset      `json:"assets"`
}

// Component represents a system component
type Component struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Type        string            `json:"type"` // process, datastore, external_entity
	TrustZone   string            `json:"trust_zone"`
	Properties  map[string]string `json:"properties"`
	Threats     []string          `json:"threats"` // vulnerability IDs
}

// DataFlow represents data movement between components
type DataFlow struct {
	ID          string            `json:"id"`
	Source      string            `json:"source"`      // component ID
	Destination string            `json:"destination"` // component ID
	Protocol    string            `json:"protocol"`
	Data        string            `json:"data"`
	Encrypted   bool              `json:"encrypted"`
	Threats     []string          `json:"threats"`
	Properties  map[string]string `json:"properties"`
}

// TrustZone represents a security boundary
type TrustZone struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	TrustLevel  string   `json:"trust_level"` // trusted, semi-trusted, untrusted
	Description string   `json:"description"`
	Components  []string `json:"components"` // component IDs
}

// Asset represents a valuable resource
type Asset struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Type         string   `json:"type"` // data, service, infrastructure
	Sensitivity  string   `json:"sensitivity"` // public, internal, confidential, restricted
	Components   []string `json:"components"` // component IDs that handle this asset
	Threats      []string `json:"threats"`
}

// AnalysisResult is the final response structure
type AnalysisResult struct {
	ID             string            `json:"id"`
	Timestamp      time.Time         `json:"timestamp"`
	ProjectInfo    ProjectInfo       `json:"project_info"`
	Vulnerabilities []Vulnerability  `json:"vulnerabilities"`
	ThreatMap      ThreatMap         `json:"threat_map"`
	Summary        Summary           `json:"summary"`
	Recommendations []string         `json:"recommendations"`
	Status         string            `json:"status"`
	ProcessingTime string            `json:"processing_time"`
}

// Summary provides high-level statistics
type Summary struct {
	TotalVulnerabilities int                    `json:"total_vulnerabilities"`
	SeverityBreakdown    map[string]int         `json:"severity_breakdown"`
	CategoryBreakdown    map[string]int         `json:"category_breakdown"`
	RiskScore           float64                 `json:"risk_score"`
	SecurityPosture     string                  `json:"security_posture"` // excellent, good, fair, poor
	TopRisks            []string                `json:"top_risks"`
}

