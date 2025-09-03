package services

import (
	"fmt"
	"go/ast"
	"strings"
)

// DataFlowAnalyzer performs taint analysis to track data flows
type DataFlowAnalyzer struct {
	parser       *ASTParser
	taintSources map[string]TaintSource
	taintSinks   map[string]TaintSink
	sanitizers   map[string]Sanitizer
}

// TaintSource represents a source of potentially dangerous data
type TaintSource struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Language    string   `json:"language"`
	Patterns    []string `json:"patterns"`
	TaintType   string   `json:"taint_type"` // user_input, file_input, network_input, etc.
}

// TaintSink represents a dangerous operation that shouldn't receive tainted data
type TaintSink struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Language    string   `json:"language"`
	Patterns    []string `json:"patterns"`
	SinkType    string   `json:"sink_type"` // sql_query, command_exec, file_write, etc.
	Dangerous   bool     `json:"dangerous"`
}

// Sanitizer represents a function that cleans tainted data
type Sanitizer struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Language    string   `json:"language"`
	Patterns    []string `json:"patterns"`
	Effectiveness string `json:"effectiveness"` // full, partial, weak
}

// TaintFlow represents a flow of tainted data from source to sink
type TaintFlow struct {
	ID          string      `json:"id"`
	Source      FlowNode    `json:"source"`
	Sink        FlowNode    `json:"sink"`
	Path        []FlowNode  `json:"path"`
	TaintType   string      `json:"taint_type"`
	Sanitizers  []FlowNode  `json:"sanitizers"`
	Confidence  float64     `json:"confidence"`
	Severity    string      `json:"severity"`
	Description string      `json:"description"`
}

// FlowNode represents a node in the data flow
type FlowNode struct {
	Type        string   `json:"type"` // source, sink, sanitizer, intermediate
	Name        string   `json:"name"`
	Position    Position `json:"position"`
	Code        string   `json:"code"`
	Function    string   `json:"function,omitempty"`
	Variable    string   `json:"variable,omitempty"`
}

// Variable represents a variable in the data flow analysis
type Variable struct {
	Name     string
	Tainted  bool
	TaintType string
	Position Position
	Function string
}

// NewDataFlowAnalyzer creates a new data flow analyzer
func NewDataFlowAnalyzer() *DataFlowAnalyzer {
	analyzer := &DataFlowAnalyzer{
		parser:       NewASTParser(),
		taintSources: make(map[string]TaintSource),
		taintSinks:   make(map[string]TaintSink),
		sanitizers:   make(map[string]Sanitizer),
	}
	
	analyzer.loadBuiltInSources()
	analyzer.loadBuiltInSinks()
	analyzer.loadBuiltInSanitizers()
	
	return analyzer
}

// AnalyzeDataFlow performs taint analysis on the given AST
func (dfa *DataFlowAnalyzer) AnalyzeDataFlow(astNode interface{}, sourceCode string, language string) ([]TaintFlow, error) {
	switch language {
	case "go":
		if goAST, ok := astNode.(*ast.File); ok {
			return dfa.analyzeGoDataFlow(goAST, sourceCode)
		}
	case "javascript", "typescript":
		if jsAST, ok := astNode.(*JSASTNode); ok {
			return dfa.analyzeJSDataFlow(jsAST, sourceCode)
		}
	}
	
	return []TaintFlow{}, fmt.Errorf("unsupported language for data flow analysis: %s", language)
}

// analyzeGoDataFlow analyzes data flow in Go code
func (dfa *DataFlowAnalyzer) analyzeGoDataFlow(goAST *ast.File, sourceCode string) ([]TaintFlow, error) {
	var flows []TaintFlow
	
	// Track variables and their taint status
	variables := make(map[string]*Variable)
	
	// Find all functions in the file
	for _, decl := range goAST.Decls {
		if funcDecl, ok := decl.(*ast.FuncDecl); ok {
			funcFlows := dfa.analyzeGoFunction(funcDecl, sourceCode, variables)
			flows = append(flows, funcFlows...)
		}
	}
	
	return flows, nil
}

// analyzeGoFunction analyzes data flow within a Go function
func (dfa *DataFlowAnalyzer) analyzeGoFunction(funcDecl *ast.FuncDecl, sourceCode string, variables map[string]*Variable) []TaintFlow {
	var flows []TaintFlow
	funcName := funcDecl.Name.Name
	
	// Track local variables
	localVars := make(map[string]*Variable)
	
	// Copy global variables
	for k, v := range variables {
		localVars[k] = v
	}
	
	// Analyze function body
	if funcDecl.Body != nil {
		ast.Inspect(funcDecl.Body, func(node ast.Node) bool {
			switch n := node.(type) {
			case *ast.AssignStmt:
				dfa.analyzeGoAssignment(n, funcName, localVars, &flows)
			case *ast.CallExpr:
				dfa.analyzeGoFunctionCall(n, funcName, localVars, &flows)
			}
			return true
		})
	}
	
	return flows
}

// analyzeGoAssignment analyzes variable assignments for taint propagation
func (dfa *DataFlowAnalyzer) analyzeGoAssignment(assignStmt *ast.AssignStmt, funcName string, variables map[string]*Variable, flows *[]TaintFlow) {
	if len(assignStmt.Lhs) == 0 || len(assignStmt.Rhs) == 0 {
		return
	}
	
	// Get the assigned variable
	var varName string
	if ident, ok := assignStmt.Lhs[0].(*ast.Ident); ok {
		varName = ident.Name
	} else {
		return
	}
	
	pos := dfa.parser.fileSet.Position(assignStmt.Pos())
	position := Position{Line: pos.Line, Column: pos.Column, Offset: pos.Offset}
	
	// Check if the right-hand side is a taint source
	rhsText := dfa.getGoNodeText(assignStmt.Rhs[0])
	if taintType := dfa.isTaintSource(rhsText, "go"); taintType != "" {
		// Mark variable as tainted
		variables[varName] = &Variable{
			Name:      varName,
			Tainted:   true,
			TaintType: taintType,
			Position:  position,
			Function:  funcName,
		}
	} else {
		// Check if RHS uses tainted variables
		taintedVars := dfa.findTaintedVariablesInExpression(assignStmt.Rhs[0], variables)
		if len(taintedVars) > 0 {
			// Propagate taint
			variables[varName] = &Variable{
				Name:      varName,
				Tainted:   true,
				TaintType: taintedVars[0].TaintType,
				Position:  position,
				Function:  funcName,
			}
		} else {
			// Variable is clean
			variables[varName] = &Variable{
				Name:     varName,
				Tainted:  false,
				Position: position,
				Function: funcName,
			}
		}
	}
}

// analyzeGoFunctionCall analyzes function calls for taint sinks
func (dfa *DataFlowAnalyzer) analyzeGoFunctionCall(callExpr *ast.CallExpr, funcName string, variables map[string]*Variable, flows *[]TaintFlow) {
	// Get function name
	var callName string
	switch fun := callExpr.Fun.(type) {
	case *ast.Ident:
		callName = fun.Name
	case *ast.SelectorExpr:
		if x, ok := fun.X.(*ast.Ident); ok {
			callName = x.Name + "." + fun.Sel.Name
		}
	default:
		return
	}
	
	pos := dfa.parser.fileSet.Position(callExpr.Pos())
	position := Position{Line: pos.Line, Column: pos.Column, Offset: pos.Offset}
	
	// Check if this is a taint sink
	if sinkType := dfa.isTaintSink(callName, "go"); sinkType != "" {
		// Check if any arguments are tainted
		for _, arg := range callExpr.Args {
			taintedVars := dfa.findTaintedVariablesInExpression(arg, variables)
			for _, taintedVar := range taintedVars {
				// Create a taint flow
				flow := TaintFlow{
					ID: fmt.Sprintf("flow_%d_%d", position.Line, position.Column),
					Source: FlowNode{
						Type:     "source",
						Name:     taintedVar.Name,
						Position: taintedVar.Position,
						Function: taintedVar.Function,
						Variable: taintedVar.Name,
					},
					Sink: FlowNode{
						Type:     "sink",
						Name:     callName,
						Position: position,
						Code:     dfa.getGoNodeText(callExpr),
						Function: funcName,
					},
					TaintType:   taintedVar.TaintType,
					Confidence:  0.8,
					Severity:    dfa.calculateSeverity(taintedVar.TaintType, sinkType),
					Description: fmt.Sprintf("Tainted data from %s flows to dangerous sink %s", taintedVar.Name, callName),
				}
				*flows = append(*flows, flow)
			}
		}
	}
	
	// Check if this is a sanitizer
	if dfa.isSanitizer(callName, "go") {
		// Mark arguments as potentially cleaned (simplified)
		for _, arg := range callExpr.Args {
			if ident, ok := arg.(*ast.Ident); ok {
				if variable, exists := variables[ident.Name]; exists && variable.Tainted {
					// Create a sanitized version (in a real implementation, this would be more sophisticated)
					variables[ident.Name+"_sanitized"] = &Variable{
						Name:     ident.Name + "_sanitized",
						Tainted:  false,
						Position: position,
						Function: funcName,
					}
				}
			}
		}
	}
}

// analyzeJSDataFlow analyzes data flow in JavaScript code
func (dfa *DataFlowAnalyzer) analyzeJSDataFlow(jsAST *JSASTNode, sourceCode string) ([]TaintFlow, error) {
	var flows []TaintFlow
	variables := make(map[string]*Variable)
	
	dfa.traverseJSForDataFlow(jsAST, variables, &flows, "global")
	
	return flows, nil
}

// traverseJSForDataFlow traverses JavaScript AST for data flow analysis
func (dfa *DataFlowAnalyzer) traverseJSForDataFlow(node *JSASTNode, variables map[string]*Variable, flows *[]TaintFlow, funcName string) {
	switch node.Type {
	case "VariableDeclaration", "AssignmentExpression":
		dfa.analyzeJSAssignment(node, funcName, variables, flows)
	case "CallExpression":
		dfa.analyzeJSFunctionCall(node, funcName, variables, flows)
	}
	
	// Recurse into children
	for _, child := range node.Children {
		dfa.traverseJSForDataFlow(child, variables, flows, funcName)
	}
}

// analyzeJSAssignment analyzes JavaScript assignments
func (dfa *DataFlowAnalyzer) analyzeJSAssignment(node *JSASTNode, funcName string, variables map[string]*Variable, flows *[]TaintFlow) {
	varName := node.Value
	
	// Check if assigned value is from a taint source
	var valueText string
	if len(node.Children) > 0 {
		valueText = node.Children[0].Value
	}
	
	if taintType := dfa.isTaintSource(valueText, "javascript"); taintType != "" {
		variables[varName] = &Variable{
			Name:      varName,
			Tainted:   true,
			TaintType: taintType,
			Position:  node.Position,
			Function:  funcName,
		}
	}
}

// analyzeJSFunctionCall analyzes JavaScript function calls
func (dfa *DataFlowAnalyzer) analyzeJSFunctionCall(node *JSASTNode, funcName string, variables map[string]*Variable, flows *[]TaintFlow) {
	callName := node.Value
	
	// Check if this is a taint sink
	if sinkType := dfa.isTaintSink(callName, "javascript"); sinkType != "" {
		// In a real implementation, we'd analyze the arguments more thoroughly
		// For now, create a simplified flow if we detect potential issues
		if strings.Contains(callName, "innerHTML") || strings.Contains(callName, "eval") {
			flow := TaintFlow{
				ID: fmt.Sprintf("js_flow_%d_%d", node.Position.Line, node.Position.Column),
				Source: FlowNode{
					Type:     "source",
					Name:     "user_input",
					Position: node.Position,
					Function: funcName,
				},
				Sink: FlowNode{
					Type:     "sink",
					Name:     callName,
					Position: node.Position,
					Code:     callName,
					Function: funcName,
				},
				TaintType:   "user_input",
				Confidence:  0.6,
				Severity:    "high",
				Description: fmt.Sprintf("Potential taint flow to dangerous sink %s", callName),
			}
			*flows = append(*flows, flow)
		}
	}
}

// Helper methods

func (dfa *DataFlowAnalyzer) findTaintedVariablesInExpression(expr ast.Expr, variables map[string]*Variable) []*Variable {
	var taintedVars []*Variable
	
	ast.Inspect(expr, func(node ast.Node) bool {
		if ident, ok := node.(*ast.Ident); ok {
			if variable, exists := variables[ident.Name]; exists && variable.Tainted {
				taintedVars = append(taintedVars, variable)
			}
		}
		return true
	})
	
	return taintedVars
}

func (dfa *DataFlowAnalyzer) isTaintSource(text, language string) string {
	for _, source := range dfa.taintSources {
		if source.Language == language || source.Language == "generic" {
			for _, pattern := range source.Patterns {
				if strings.Contains(text, pattern) {
					return source.TaintType
				}
			}
		}
	}
	return ""
}

func (dfa *DataFlowAnalyzer) isTaintSink(text, language string) string {
	for _, sink := range dfa.taintSinks {
		if sink.Language == language || sink.Language == "generic" {
			for _, pattern := range sink.Patterns {
				if strings.Contains(text, pattern) {
					return sink.SinkType
				}
			}
		}
	}
	return ""
}

func (dfa *DataFlowAnalyzer) isSanitizer(text, language string) bool {
	for _, sanitizer := range dfa.sanitizers {
		if sanitizer.Language == language || sanitizer.Language == "generic" {
			for _, pattern := range sanitizer.Patterns {
				if strings.Contains(text, pattern) {
					return true
				}
			}
		}
	}
	return false
}

func (dfa *DataFlowAnalyzer) calculateSeverity(taintType, sinkType string) string {
	// Define severity based on taint type and sink type combinations
	severityMatrix := map[string]map[string]string{
		"user_input": {
			"sql_query":    "critical",
			"command_exec": "critical",
			"file_write":   "high",
			"log_output":   "medium",
		},
		"file_input": {
			"command_exec": "high",
			"file_write":   "medium",
			"log_output":   "low",
		},
		"network_input": {
			"sql_query":    "high",
			"command_exec": "high",
			"file_write":   "medium",
		},
	}
	
	if sinkMap, exists := severityMatrix[taintType]; exists {
		if severity, exists := sinkMap[sinkType]; exists {
			return severity
		}
	}
	
	return "medium" // default severity
}

func (dfa *DataFlowAnalyzer) getGoNodeText(node ast.Node) string {
	// This would extract the actual text representation of a Go AST node
	// For now, return a placeholder
	return fmt.Sprintf("node_%T", node)
}

// Load built-in taint sources, sinks, and sanitizers

func (dfa *DataFlowAnalyzer) loadBuiltInSources() {
	dfa.taintSources = map[string]TaintSource{
		"http_request_go": {
			Name:        "HTTP Request Parameters",
			Description: "HTTP request parameters and body",
			Language:    "go",
			Patterns:    []string{"r.FormValue", "r.PostFormValue", "r.URL.Query", "r.Body"},
			TaintType:   "user_input",
		},
		"os_args_go": {
			Name:        "Command Line Arguments",
			Description: "Command line arguments",
			Language:    "go",
			Patterns:    []string{"os.Args", "flag.String", "flag.Int"},
			TaintType:   "user_input",
		},
		"file_read_go": {
			Name:        "File Input",
			Description: "Data read from files",
			Language:    "go",
			Patterns:    []string{"ioutil.ReadFile", "os.ReadFile", "bufio.Scanner"},
			TaintType:   "file_input",
		},
		"http_request_js": {
			Name:        "HTTP Request",
			Description: "HTTP request data in JavaScript",
			Language:    "javascript",
			Patterns:    []string{"req.body", "req.query", "req.params", "location.search"},
			TaintType:   "user_input",
		},
		"dom_input_js": {
			Name:        "DOM Input",
			Description: "User input from DOM elements",
			Language:    "javascript",
			Patterns:    []string{".value", ".innerHTML", "prompt(", "confirm("},
			TaintType:   "user_input",
		},
	}
}

func (dfa *DataFlowAnalyzer) loadBuiltInSinks() {
	dfa.taintSinks = map[string]TaintSink{
		"sql_query_go": {
			Name:        "SQL Query",
			Description: "SQL query execution",
			Language:    "go",
			Patterns:    []string{"db.Query", "db.Exec", "db.QueryRow"},
			SinkType:    "sql_query",
			Dangerous:   true,
		},
		"command_exec_go": {
			Name:        "Command Execution",
			Description: "System command execution",
			Language:    "go",
			Patterns:    []string{"exec.Command", "os.Exec", "syscall.Exec"},
			SinkType:    "command_exec",
			Dangerous:   true,
		},
		"file_write_go": {
			Name:        "File Write",
			Description: "Writing data to files",
			Language:    "go",
			Patterns:    []string{"ioutil.WriteFile", "os.WriteFile", "file.Write"},
			SinkType:    "file_write",
			Dangerous:   false,
		},
		"eval_js": {
			Name:        "Code Evaluation",
			Description: "Dynamic code evaluation",
			Language:    "javascript",
			Patterns:    []string{"eval(", "Function(", "setTimeout", "setInterval"},
			SinkType:    "code_eval",
			Dangerous:   true,
		},
		"dom_write_js": {
			Name:        "DOM Write",
			Description: "Writing to DOM elements",
			Language:    "javascript",
			Patterns:    []string{".innerHTML", ".outerHTML", "document.write"},
			SinkType:    "dom_write",
			Dangerous:   true,
		},
	}
}

func (dfa *DataFlowAnalyzer) loadBuiltInSanitizers() {
	dfa.sanitizers = map[string]Sanitizer{
		"html_escape_go": {
			Name:         "HTML Escape",
			Description:  "HTML escaping functions",
			Language:     "go",
			Patterns:     []string{"html.EscapeString", "template.HTMLEscapeString"},
			Effectiveness: "full",
		},
		"sql_prepare_go": {
			Name:         "SQL Prepared Statements",
			Description:  "SQL prepared statements",
			Language:     "go",
			Patterns:     []string{"db.Prepare", "stmt.Query", "stmt.Exec"},
			Effectiveness: "full",
		},
		"input_validation_go": {
			Name:         "Input Validation",
			Description:  "Input validation functions",
			Language:     "go",
			Patterns:     []string{"regexp.MatchString", "strconv.Atoi", "url.Parse"},
			Effectiveness: "partial",
		},
		"html_escape_js": {
			Name:         "HTML Escape",
			Description:  "HTML escaping in JavaScript",
			Language:     "javascript",
			Patterns:     []string{"escape(", "encodeURIComponent(", ".textContent"},
			Effectiveness: "full",
		},
	}
}

