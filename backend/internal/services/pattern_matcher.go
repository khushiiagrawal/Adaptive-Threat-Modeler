package services

import (
	"fmt"
	"go/ast"
	"regexp"
	"strings"
)

// PatternMatcher handles advanced pattern matching with metavariables
type PatternMatcher struct {
	parser *ASTParser
}

// PatternRule represents a pattern matching rule with metavariables
type PatternRule struct {
	ID          string                 `json:"id"`
	Pattern     string                 `json:"pattern"`
	Language    string                 `json:"language"`
	Type        string                 `json:"type"` // ast, regex, semantic
	Metavars    map[string]MetaVar     `json:"metavars"`
	Constraints []Constraint           `json:"constraints"`
	Message     string                 `json:"message"`
	Severity    string                 `json:"severity"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// MetaVar represents a metavariable in a pattern
type MetaVar struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"` // identifier, expression, literal, etc.
	Constraints []string `json:"constraints"`
	Regex       string   `json:"regex,omitempty"`
}

// Constraint represents a constraint on pattern matching
type Constraint struct {
	Type      string      `json:"type"` // equals, contains, regex, not_equals, etc.
	Variable  string      `json:"variable"`
	Value     interface{} `json:"value"`
	Operator  string      `json:"operator,omitempty"`
}

// Match represents a pattern match with variable bindings
type Match struct {
	Pattern     string                 `json:"pattern"`
	Position    Position               `json:"position"`
	Bindings    map[string]string      `json:"bindings"`
	Context     string                 `json:"context"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// NewPatternMatcher creates a new pattern matcher
func NewPatternMatcher() *PatternMatcher {
	return &PatternMatcher{
		parser: NewASTParser(),
	}
}

// MatchPattern matches a pattern against source code
func (pm *PatternMatcher) MatchPattern(rule PatternRule, sourceCode string, astNode interface{}) ([]Match, error) {
	switch rule.Type {
	case "ast":
		return pm.matchASTPattern(rule, sourceCode, astNode)
	case "regex":
		return pm.matchRegexPattern(rule, sourceCode)
	case "semantic":
		return pm.matchSemanticPattern(rule, sourceCode, astNode)
	default:
		return pm.matchRegexPattern(rule, sourceCode)
	}
}

// matchASTPattern performs AST-based pattern matching with metavariables
func (pm *PatternMatcher) matchASTPattern(rule PatternRule, sourceCode string, astNode interface{}) ([]Match, error) {
	var matches []Match
	
	switch rule.Language {
	case "go":
		if goAST, ok := astNode.(*ast.File); ok {
			matches = pm.matchGoASTPattern(rule, sourceCode, goAST)
		}
	case "javascript", "typescript":
		if jsAST, ok := astNode.(*JSASTNode); ok {
			matches = pm.matchJSASTPattern(rule, sourceCode, jsAST)
		}
	}
	
	// Apply constraints to filter matches
	filteredMatches := pm.applyConstraints(matches, rule.Constraints)
	
	return filteredMatches, nil
}

// matchGoASTPattern matches patterns against Go AST
func (pm *PatternMatcher) matchGoASTPattern(rule PatternRule, sourceCode string, goAST *ast.File) []Match {
	var matches []Match
	
	ast.Inspect(goAST, func(node ast.Node) bool {
		match := pm.matchGoNode(rule, node, sourceCode)
		if match != nil {
			matches = append(matches, *match)
		}
		return true
	})
	
	return matches
}

// matchGoNode matches a single Go AST node against a pattern
func (pm *PatternMatcher) matchGoNode(rule PatternRule, node ast.Node, sourceCode string) *Match {
	switch n := node.(type) {
	case *ast.CallExpr:
		return pm.matchGoCallExpr(rule, n, sourceCode)
	case *ast.AssignStmt:
		return pm.matchGoAssignStmt(rule, n, sourceCode)
	case *ast.FuncDecl:
		return pm.matchGoFuncDecl(rule, n, sourceCode)
	case *ast.IfStmt:
		return pm.matchGoIfStmt(rule, n, sourceCode)
	}
	return nil
}

// matchGoCallExpr matches function call expressions
func (pm *PatternMatcher) matchGoCallExpr(rule PatternRule, callExpr *ast.CallExpr, sourceCode string) *Match {
	// Example pattern: $FUNC($ARG1, $ARG2)
	// This would match any function call with two arguments
	
	if !strings.Contains(rule.Pattern, "$FUNC") {
		return nil
	}
	
	var funcName string
	switch fun := callExpr.Fun.(type) {
	case *ast.Ident:
		funcName = fun.Name
	case *ast.SelectorExpr:
		if x, ok := fun.X.(*ast.Ident); ok {
			funcName = x.Name + "." + fun.Sel.Name
		}
	default:
		return nil
	}
	
	// Create bindings for metavariables
	bindings := make(map[string]string)
	bindings["$FUNC"] = funcName
	
	// Bind arguments if pattern specifies them
	for i, arg := range callExpr.Args {
		argVar := fmt.Sprintf("$ARG%d", i+1)
		if strings.Contains(rule.Pattern, argVar) {
			argText := pm.getNodeText(arg, sourceCode)
			bindings[argVar] = argText
		}
	}
	
	// Check if pattern matches
	if pm.patternMatches(rule.Pattern, bindings) {
		pos := pm.parser.fileSet.Position(callExpr.Pos())
		return &Match{
			Pattern:  rule.Pattern,
			Position: Position{Line: pos.Line, Column: pos.Column, Offset: pos.Offset},
			Bindings: bindings,
			Context:  pm.getNodeText(callExpr, sourceCode),
		}
	}
	
	return nil
}

// matchGoAssignStmt matches assignment statements
func (pm *PatternMatcher) matchGoAssignStmt(rule PatternRule, assignStmt *ast.AssignStmt, sourceCode string) *Match {
	// Example pattern: $VAR := $VALUE
	if !strings.Contains(rule.Pattern, "$VAR") {
		return nil
	}
	
	if len(assignStmt.Lhs) == 0 || len(assignStmt.Rhs) == 0 {
		return nil
	}
	
	bindings := make(map[string]string)
	
	// Bind left-hand side variable
	if ident, ok := assignStmt.Lhs[0].(*ast.Ident); ok {
		bindings["$VAR"] = ident.Name
	}
	
	// Bind right-hand side value
	if strings.Contains(rule.Pattern, "$VALUE") {
		valueText := pm.getNodeText(assignStmt.Rhs[0], sourceCode)
		bindings["$VALUE"] = valueText
	}
	
	if pm.patternMatches(rule.Pattern, bindings) {
		pos := pm.parser.fileSet.Position(assignStmt.Pos())
		return &Match{
			Pattern:  rule.Pattern,
			Position: Position{Line: pos.Line, Column: pos.Column, Offset: pos.Offset},
			Bindings: bindings,
			Context:  pm.getNodeText(assignStmt, sourceCode),
		}
	}
	
	return nil
}

// matchGoFuncDecl matches function declarations
func (pm *PatternMatcher) matchGoFuncDecl(rule PatternRule, funcDecl *ast.FuncDecl, sourceCode string) *Match {
	if !strings.Contains(rule.Pattern, "$FUNC") {
		return nil
	}
	
	bindings := make(map[string]string)
	bindings["$FUNC"] = funcDecl.Name.Name
	
	// Bind parameters if pattern specifies them
	if funcDecl.Type.Params != nil {
		for i, param := range funcDecl.Type.Params.List {
			paramVar := fmt.Sprintf("$PARAM%d", i+1)
			if strings.Contains(rule.Pattern, paramVar) && len(param.Names) > 0 {
				bindings[paramVar] = param.Names[0].Name
			}
		}
	}
	
	if pm.patternMatches(rule.Pattern, bindings) {
		pos := pm.parser.fileSet.Position(funcDecl.Pos())
		return &Match{
			Pattern:  rule.Pattern,
			Position: Position{Line: pos.Line, Column: pos.Column, Offset: pos.Offset},
			Bindings: bindings,
			Context:  pm.getNodeText(funcDecl, sourceCode),
		}
	}
	
	return nil
}

// matchGoIfStmt matches if statements
func (pm *PatternMatcher) matchGoIfStmt(rule PatternRule, ifStmt *ast.IfStmt, sourceCode string) *Match {
	if !strings.Contains(rule.Pattern, "$COND") {
		return nil
	}
	
	bindings := make(map[string]string)
	bindings["$COND"] = pm.getNodeText(ifStmt.Cond, sourceCode)
	
	if pm.patternMatches(rule.Pattern, bindings) {
		pos := pm.parser.fileSet.Position(ifStmt.Pos())
		return &Match{
			Pattern:  rule.Pattern,
			Position: Position{Line: pos.Line, Column: pos.Column, Offset: pos.Offset},
			Bindings: bindings,
			Context:  pm.getNodeText(ifStmt, sourceCode),
		}
	}
	
	return nil
}

// matchJSASTPattern matches patterns against JavaScript AST
func (pm *PatternMatcher) matchJSASTPattern(rule PatternRule, sourceCode string, jsAST *JSASTNode) []Match {
	var matches []Match
	
	pm.traverseJSNode(jsAST, func(node *JSASTNode) bool {
		match := pm.matchJSNode(rule, node, sourceCode)
		if match != nil {
			matches = append(matches, *match)
		}
		return true
	})
	
	return matches
}

// matchJSNode matches a JavaScript AST node against a pattern
func (pm *PatternMatcher) matchJSNode(rule PatternRule, node *JSASTNode, sourceCode string) *Match {
	switch node.Type {
	case "CallExpression":
		return pm.matchJSCallExpr(rule, node, sourceCode)
	case "AssignmentExpression":
		return pm.matchJSAssignExpr(rule, node, sourceCode)
	case "FunctionDeclaration":
		return pm.matchJSFuncDecl(rule, node, sourceCode)
	}
	return nil
}

// matchJSCallExpr matches JavaScript function calls
func (pm *PatternMatcher) matchJSCallExpr(rule PatternRule, node *JSASTNode, sourceCode string) *Match {
	if !strings.Contains(rule.Pattern, "$FUNC") {
		return nil
	}
	
	bindings := make(map[string]string)
	bindings["$FUNC"] = node.Value
	
	if pm.patternMatches(rule.Pattern, bindings) {
		return &Match{
			Pattern:  rule.Pattern,
			Position: node.Position,
			Bindings: bindings,
			Context:  node.Value,
		}
	}
	
	return nil
}

// matchJSAssignExpr matches JavaScript assignments
func (pm *PatternMatcher) matchJSAssignExpr(rule PatternRule, node *JSASTNode, sourceCode string) *Match {
	if !strings.Contains(rule.Pattern, "$VAR") {
		return nil
	}
	
	bindings := make(map[string]string)
	bindings["$VAR"] = node.Value
	
	if len(node.Children) > 0 {
		bindings["$VALUE"] = node.Children[0].Value
	}
	
	if pm.patternMatches(rule.Pattern, bindings) {
		return &Match{
			Pattern:  rule.Pattern,
			Position: node.Position,
			Bindings: bindings,
			Context:  node.Value,
		}
	}
	
	return nil
}

// matchJSFuncDecl matches JavaScript function declarations
func (pm *PatternMatcher) matchJSFuncDecl(rule PatternRule, node *JSASTNode, sourceCode string) *Match {
	if !strings.Contains(rule.Pattern, "$FUNC") {
		return nil
	}
	
	bindings := make(map[string]string)
	bindings["$FUNC"] = node.Value
	
	if pm.patternMatches(rule.Pattern, bindings) {
		return &Match{
			Pattern:  rule.Pattern,
			Position: node.Position,
			Bindings: bindings,
			Context:  node.Value,
		}
	}
	
	return nil
}

// matchRegexPattern performs regex-based pattern matching
func (pm *PatternMatcher) matchRegexPattern(rule PatternRule, sourceCode string) ([]Match, error) {
	var matches []Match
	
	// Replace metavariables with regex capture groups
	regexPattern := pm.convertPatternToRegex(rule.Pattern, rule.Metavars)
	
	re, err := regexp.Compile(regexPattern)
	if err != nil {
		return nil, fmt.Errorf("invalid regex pattern: %w", err)
	}
	
	lines := strings.Split(sourceCode, "\n")
	
	for lineNum, line := range lines {
		matches = append(matches, pm.findRegexMatches(re, line, lineNum+1, rule)...)
	}
	
	return matches, nil
}

// matchSemanticPattern performs semantic analysis-based matching
func (pm *PatternMatcher) matchSemanticPattern(rule PatternRule, sourceCode string, astNode interface{}) ([]Match, error) {
	// This would implement more sophisticated semantic analysis
	// For now, fall back to AST pattern matching
	return pm.matchASTPattern(rule, sourceCode, astNode)
}

// Helper methods

func (pm *PatternMatcher) patternMatches(pattern string, bindings map[string]string) bool {
	// Replace metavariables in pattern with their bindings
	resolvedPattern := pattern
	for metavar, value := range bindings {
		resolvedPattern = strings.ReplaceAll(resolvedPattern, metavar, value)
	}
	
	// Check if the resolved pattern still contains unbound metavariables
	if strings.Contains(resolvedPattern, "$") {
		return false
	}
	
	return true
}

func (pm *PatternMatcher) convertPatternToRegex(pattern string, metavars map[string]MetaVar) string {
	regexPattern := regexp.QuoteMeta(pattern)
	
	// Replace metavariables with appropriate regex patterns
	for name, metavar := range metavars {
		var replacement string
		
		if metavar.Regex != "" {
			replacement = fmt.Sprintf("(%s)", metavar.Regex)
		} else {
			switch metavar.Type {
			case "identifier":
				replacement = `(\w+)`
			case "expression":
				replacement = `([^;,)]+)`
			case "literal":
				replacement = `("[^"]*"|'[^']*'|\d+)`
			case "string":
				replacement = `("[^"]*"|'[^']*')`
			case "number":
				replacement = `(\d+(?:\.\d+)?)`
			default:
				replacement = `([^;,)]+)`
			}
		}
		
		quotedName := regexp.QuoteMeta(name)
		regexPattern = regexp.MustCompile(quotedName).ReplaceAllString(regexPattern, replacement)
	}
	
	return regexPattern
}

func (pm *PatternMatcher) findRegexMatches(re *regexp.Regexp, line string, lineNum int, rule PatternRule) []Match {
	var matches []Match
	
	allMatches := re.FindAllStringSubmatch(line, -1)
	allIndices := re.FindAllStringSubmatchIndex(line, -1)
	
	for i, match := range allMatches {
		if len(match) > 0 {
			bindings := make(map[string]string)
			
			// Create bindings for captured groups
			groupIndex := 1
			for name := range rule.Metavars {
				if groupIndex < len(match) {
					bindings[name] = match[groupIndex]
					groupIndex++
				}
			}
			
			var column int
			if i < len(allIndices) && len(allIndices[i]) > 0 {
				column = allIndices[i][0] + 1
			}
			
			matches = append(matches, Match{
				Pattern:  rule.Pattern,
				Position: Position{Line: lineNum, Column: column},
				Bindings: bindings,
				Context:  line,
			})
		}
	}
	
	return matches
}

func (pm *PatternMatcher) applyConstraints(matches []Match, constraints []Constraint) []Match {
	var filteredMatches []Match
	
	for _, match := range matches {
		if pm.matchesConstraints(match, constraints) {
			filteredMatches = append(filteredMatches, match)
		}
	}
	
	return filteredMatches
}

func (pm *PatternMatcher) matchesConstraints(match Match, constraints []Constraint) bool {
	for _, constraint := range constraints {
		if !pm.evaluateConstraint(match, constraint) {
			return false
		}
	}
	return true
}

func (pm *PatternMatcher) evaluateConstraint(match Match, constraint Constraint) bool {
	value, exists := match.Bindings[constraint.Variable]
	if !exists {
		return false
	}
	
	switch constraint.Type {
	case "equals":
		return value == fmt.Sprintf("%v", constraint.Value)
	case "not_equals":
		return value != fmt.Sprintf("%v", constraint.Value)
	case "contains":
		return strings.Contains(value, fmt.Sprintf("%v", constraint.Value))
	case "not_contains":
		return !strings.Contains(value, fmt.Sprintf("%v", constraint.Value))
	case "regex":
		if re, err := regexp.Compile(fmt.Sprintf("%v", constraint.Value)); err == nil {
			return re.MatchString(value)
		}
		return false
	case "length_greater":
		if length, ok := constraint.Value.(float64); ok {
			return len(value) > int(length)
		}
		return false
	case "length_less":
		if length, ok := constraint.Value.(float64); ok {
			return len(value) < int(length)
		}
		return false
	}
	
	return true
}

func (pm *PatternMatcher) getNodeText(node interface{}, sourceCode string) string {
	// This would extract the actual text of an AST node from source code
	// Implementation depends on the AST type and would need proper position tracking
	return ""
}

func (pm *PatternMatcher) traverseJSNode(node *JSASTNode, visitor func(*JSASTNode) bool) {
	if !visitor(node) {
		return
	}
	
	for _, child := range node.Children {
		pm.traverseJSNode(child, visitor)
	}
}

// Example pattern rules for common vulnerability patterns

func (pm *PatternMatcher) GetBuiltInPatterns() []PatternRule {
	return []PatternRule{
		{
			ID:       "sql-injection-go",
			Pattern:  `$DB.Query($QUERY + $USER_INPUT)`,
			Language: "go",
			Type:     "ast",
			Metavars: map[string]MetaVar{
				"$DB":         {Name: "$DB", Type: "identifier"},
				"$QUERY":      {Name: "$QUERY", Type: "string"},
				"$USER_INPUT": {Name: "$USER_INPUT", Type: "expression"},
			},
			Constraints: []Constraint{
				{Type: "contains", Variable: "$DB", Value: "db"},
				{Type: "contains", Variable: "$QUERY", Value: "SELECT"},
			},
			Message:  "Potential SQL injection vulnerability",
			Severity: "high",
		},
		{
			ID:       "xss-js",
			Pattern:  `$ELEMENT.innerHTML = $USER_INPUT`,
			Language: "javascript",
			Type:     "ast",
			Metavars: map[string]MetaVar{
				"$ELEMENT":    {Name: "$ELEMENT", Type: "identifier"},
				"$USER_INPUT": {Name: "$USER_INPUT", Type: "expression"},
			},
			Message:  "Potential XSS vulnerability through innerHTML",
			Severity: "high",
		},
		{
			ID:       "hardcoded-secret",
			Pattern:  `$VAR := "$SECRET"`,
			Language: "go",
			Type:     "regex",
			Metavars: map[string]MetaVar{
				"$VAR":    {Name: "$VAR", Type: "identifier", Regex: `(?i)(password|secret|key|token|api_key)`},
				"$SECRET": {Name: "$SECRET", Type: "string"},
			},
			Constraints: []Constraint{
				{Type: "length_greater", Variable: "$SECRET", Value: 8},
				{Type: "not_contains", Variable: "$SECRET", Value: "example"},
			},
			Message:  "Hardcoded secret detected",
			Severity: "critical",
		},
	}
}

