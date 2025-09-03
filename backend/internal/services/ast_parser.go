package services

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
	"strings"
)

// ASTParser handles parsing source code into Abstract Syntax Trees
type ASTParser struct {
	fileSet *token.FileSet
}

// ASTNode represents a generic AST node interface
type ASTNode interface {
	GetType() string
	GetPosition() Position
	GetChildren() []ASTNode
}

// Position represents a position in source code
type Position struct {
	Line   int
	Column int
	Offset int
}

// GoASTNode wraps Go AST nodes
type GoASTNode struct {
	Node     ast.Node
	FileSet  *token.FileSet
	NodeType string
}

// JSASTNode represents JavaScript/TypeScript AST nodes (simplified)
type JSASTNode struct {
	Type     string
	Value    string
	Position Position
	Children []*JSASTNode
}

// NewASTParser creates a new AST parser instance
func NewASTParser() *ASTParser {
	return &ASTParser{
		fileSet: token.NewFileSet(),
	}
}

// ParseFile parses a source file and returns its AST
func (p *ASTParser) ParseFile(filePath, content string) (interface{}, error) {
	ext := strings.ToLower(filepath.Ext(filePath))
	
	switch ext {
	case ".go":
		return p.parseGoFile(filePath, content)
	case ".js", ".jsx", ".mjs":
		return p.parseJavaScriptFile(filePath, content)
	case ".ts", ".tsx":
		return p.parseTypeScriptFile(filePath, content)
	case ".py", ".pyw":
		return p.parsePythonFile(filePath, content)
	case ".tf", ".hcl":
		return p.parseHCLFile(filePath, content)
	case ".sh", ".bash":
		return p.parseShellFile(filePath, content)
	default:
		return nil, fmt.Errorf("unsupported file type: %s", ext)
	}
}

// parseGoFile parses a Go source file
func (p *ASTParser) parseGoFile(filePath, content string) (*ast.File, error) {
	file, err := parser.ParseFile(p.fileSet, filePath, content, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Go file: %w", err)
	}
	
	return file, nil
}

// parseJavaScriptFile parses a JavaScript file (simplified implementation)
func (p *ASTParser) parseJavaScriptFile(filePath, content string) (*JSASTNode, error) {
	// This is a simplified JavaScript parser
	// In a production system, you would use a proper JS parser like esprima or babel
	
	root := &JSASTNode{
		Type:     "Program",
		Position: Position{Line: 1, Column: 1, Offset: 0},
		Children: []*JSASTNode{},
	}
	
	// Simple tokenization and parsing
	lines := strings.Split(content, "\n")
	
	for lineNum, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		
		// Parse function declarations
		if funcNode := p.parseFunctionDeclaration(line, lineNum+1); funcNode != nil {
			root.Children = append(root.Children, funcNode)
		}
		
		// Parse variable declarations
		if varNode := p.parseVariableDeclaration(line, lineNum+1); varNode != nil {
			root.Children = append(root.Children, varNode)
		}
		
		// Parse function calls
		if callNode := p.parseFunctionCall(line, lineNum+1); callNode != nil {
			root.Children = append(root.Children, callNode)
		}
		
		// Parse assignments
		if assignNode := p.parseAssignment(line, lineNum+1); assignNode != nil {
			root.Children = append(root.Children, assignNode)
		}
	}
	
	return root, nil
}

// parseTypeScriptFile parses a TypeScript file
func (p *ASTParser) parseTypeScriptFile(filePath, content string) (*JSASTNode, error) {
	// For now, treat TypeScript similar to JavaScript
	// In production, you'd want a proper TypeScript parser
	return p.parseJavaScriptFile(filePath, content)
}

// JavaScript parsing helper methods

func (p *ASTParser) parseFunctionDeclaration(line string, lineNum int) *JSASTNode {
	// Match function declarations: function name() { ... }
	funcRegex := regexp.MustCompile(`function\s+(\w+)\s*\([^)]*\)\s*\{?`)
	matches := funcRegex.FindStringSubmatch(line)
	
	if len(matches) > 1 {
		return &JSASTNode{
			Type:  "FunctionDeclaration",
			Value: matches[1],
			Position: Position{
				Line:   lineNum,
				Column: strings.Index(line, "function") + 1,
				Offset: 0,
			},
			Children: []*JSASTNode{},
		}
	}
	
	// Match arrow functions: const name = () => { ... }
	arrowRegex := regexp.MustCompile(`const\s+(\w+)\s*=\s*\([^)]*\)\s*=>\s*\{?`)
	matches = arrowRegex.FindStringSubmatch(line)
	
	if len(matches) > 1 {
		return &JSASTNode{
			Type:  "ArrowFunctionExpression",
			Value: matches[1],
			Position: Position{
				Line:   lineNum,
				Column: strings.Index(line, "const") + 1,
				Offset: 0,
			},
			Children: []*JSASTNode{},
		}
	}
	
	return nil
}

func (p *ASTParser) parseVariableDeclaration(line string, lineNum int) *JSASTNode {
	// Match variable declarations: var/let/const name = value
	varRegex := regexp.MustCompile(`(var|let|const)\s+(\w+)\s*=\s*(.+)`)
	matches := varRegex.FindStringSubmatch(line)
	
	if len(matches) > 2 {
		return &JSASTNode{
			Type:  "VariableDeclaration",
			Value: matches[2], // variable name
			Position: Position{
				Line:   lineNum,
				Column: strings.Index(line, matches[1]) + 1,
				Offset: 0,
			},
			Children: []*JSASTNode{
				{
					Type:  "Literal",
					Value: matches[3], // variable value
					Position: Position{
						Line:   lineNum,
						Column: strings.Index(line, matches[3]) + 1,
						Offset: 0,
					},
				},
			},
		}
	}
	
	return nil
}

func (p *ASTParser) parseFunctionCall(line string, lineNum int) *JSASTNode {
	// Match function calls: functionName(args)
	callRegex := regexp.MustCompile(`(\w+(?:\.\w+)*)\s*\([^)]*\)`)
	matches := callRegex.FindStringSubmatch(line)
	
	if len(matches) > 1 {
		return &JSASTNode{
			Type:  "CallExpression",
			Value: matches[1],
			Position: Position{
				Line:   lineNum,
				Column: strings.Index(line, matches[1]) + 1,
				Offset: 0,
			},
			Children: []*JSASTNode{},
		}
	}
	
	return nil
}

func (p *ASTParser) parseAssignment(line string, lineNum int) *JSASTNode {
	// Match assignments: object.property = value
	assignRegex := regexp.MustCompile(`(\w+(?:\.\w+)*)\s*=\s*(.+)`)
	matches := assignRegex.FindStringSubmatch(line)
	
	if len(matches) > 2 && !strings.Contains(matches[0], "var") && 
		!strings.Contains(matches[0], "let") && !strings.Contains(matches[0], "const") {
		return &JSASTNode{
			Type:  "AssignmentExpression",
			Value: matches[1],
			Position: Position{
				Line:   lineNum,
				Column: strings.Index(line, matches[1]) + 1,
				Offset: 0,
			},
			Children: []*JSASTNode{
				{
					Type:  "Literal",
					Value: matches[2],
					Position: Position{
						Line:   lineNum,
						Column: strings.Index(line, matches[2]) + 1,
						Offset: 0,
					},
				},
			},
		}
	}
	
	return nil
}

// Go AST node methods
func (g *GoASTNode) GetType() string {
	return g.NodeType
}

func (g *GoASTNode) GetPosition() Position {
	pos := g.FileSet.Position(g.Node.Pos())
	return Position{
		Line:   pos.Line,
		Column: pos.Column,
		Offset: pos.Offset,
	}
}

func (g *GoASTNode) GetChildren() []ASTNode {
	// This would implement proper child node extraction for Go AST
	return []ASTNode{}
}

// JavaScript AST node methods
func (j *JSASTNode) GetType() string {
	return j.Type
}

func (j *JSASTNode) GetPosition() Position {
	return j.Position
}

func (j *JSASTNode) GetChildren() []ASTNode {
	children := make([]ASTNode, len(j.Children))
	for i, child := range j.Children {
		children[i] = child
	}
	return children
}

// Utility methods for AST traversal and analysis

// TraverseAST traverses an AST and applies a visitor function
func (p *ASTParser) TraverseAST(node interface{}, visitor func(interface{}) bool) {
	switch n := node.(type) {
	case *ast.File:
		ast.Inspect(n, func(node ast.Node) bool {
			return visitor(node)
		})
	case *JSASTNode:
		p.traverseJSAST(n, visitor)
	}
}

func (p *ASTParser) traverseJSAST(node *JSASTNode, visitor func(interface{}) bool) {
	if !visitor(node) {
		return
	}
	
	for _, child := range node.Children {
		p.traverseJSAST(child, visitor)
	}
}

// FindNodes finds all nodes of a specific type in an AST
func (p *ASTParser) FindNodes(rootNode interface{}, nodeType string) []interface{} {
	var nodes []interface{}
	
	p.TraverseAST(rootNode, func(node interface{}) bool {
		switch n := node.(type) {
		case *ast.CallExpr:
			if nodeType == "CallExpr" {
				nodes = append(nodes, n)
			}
		case *ast.FuncDecl:
			if nodeType == "FuncDecl" {
				nodes = append(nodes, n)
			}
		case *JSASTNode:
			if n.Type == nodeType {
				nodes = append(nodes, n)
			}
		}
		return true
	})
	
	return nodes
}

// ExtractFunctionCalls extracts all function calls from an AST
func (p *ASTParser) ExtractFunctionCalls(rootNode interface{}) []FunctionCall {
	var calls []FunctionCall
	
	p.TraverseAST(rootNode, func(node interface{}) bool {
		switch n := node.(type) {
		case *ast.CallExpr:
			if ident, ok := n.Fun.(*ast.Ident); ok {
				pos := p.fileSet.Position(n.Pos())
				calls = append(calls, FunctionCall{
					Name: ident.Name,
					Position: Position{
						Line:   pos.Line,
						Column: pos.Column,
						Offset: pos.Offset,
					},
					Arguments: len(n.Args),
				})
			}
		case *JSASTNode:
			if n.Type == "CallExpression" {
				calls = append(calls, FunctionCall{
					Name:      n.Value,
					Position:  n.Position,
					Arguments: 0, // Would need more sophisticated parsing
				})
			}
		}
		return true
	})
	
	return calls
}

// ExtractVariableAssignments extracts variable assignments from an AST
func (p *ASTParser) ExtractVariableAssignments(rootNode interface{}) []VariableAssignment {
	var assignments []VariableAssignment
	
	p.TraverseAST(rootNode, func(node interface{}) bool {
		switch n := node.(type) {
		case *ast.AssignStmt:
			if len(n.Lhs) > 0 && len(n.Rhs) > 0 {
				if ident, ok := n.Lhs[0].(*ast.Ident); ok {
					pos := p.fileSet.Position(n.Pos())
					assignments = append(assignments, VariableAssignment{
						Variable: ident.Name,
						Position: Position{
							Line:   pos.Line,
							Column: pos.Column,
							Offset: pos.Offset,
						},
					})
				}
			}
		case *JSASTNode:
			if n.Type == "AssignmentExpression" {
				assignments = append(assignments, VariableAssignment{
					Variable: n.Value,
					Position: n.Position,
				})
			}
		}
		return true
	})
	
	return assignments
}

// Helper structures
type FunctionCall struct {
	Name      string
	Position  Position
	Arguments int
}

type VariableAssignment struct {
	Variable string
	Position Position
}

// GetNodeText extracts the text representation of a node
func (p *ASTParser) GetNodeText(node interface{}, sourceCode string) string {
	switch n := node.(type) {
	case *ast.CallExpr:
		pos := p.fileSet.Position(n.Pos())
		end := p.fileSet.Position(n.End())
		
		lines := strings.Split(sourceCode, "\n")
		if pos.Line <= len(lines) {
			line := lines[pos.Line-1]
			if pos.Column <= len(line) && end.Column <= len(line) {
				return line[pos.Column-1 : end.Column-1]
			}
		}
	case *JSASTNode:
		// For JS nodes, we'd need to track the original text more carefully
		return n.Value
	}
	
	return ""
}

// IsInsecureFunction checks if a function call is potentially insecure
func (p *ASTParser) IsInsecureFunction(functionName string, language string) bool {
	insecureFunctions := map[string][]string{
		"go": {
			"exec.Command", "os.Exec", "syscall.Exec",
			"sql.Query", "sql.Exec", // when used with string concatenation
			"fmt.Printf", // when used with user input
		},
		"javascript": {
			"eval", "Function", "setTimeout", "setInterval",
			"document.write", "innerHTML", "outerHTML",
		},
		"typescript": {
			"eval", "Function", "setTimeout", "setInterval",
			"document.write", "innerHTML", "outerHTML",
		},
		"python": {
			"eval", "exec", "compile", "input", "__import__",
			"open", "file", "subprocess", "os.system", "pickle.loads",
		},
	}
	
	if functions, exists := insecureFunctions[language]; exists {
		for _, insecure := range functions {
			if strings.Contains(functionName, insecure) {
				return true
			}
		}
	}
	
	return false
}

// parsePythonFile parses a Python file (simplified parsing for security analysis)
func (p *ASTParser) parsePythonFile(filePath, content string) (map[string]interface{}, error) {
	// For Python files, we'll do a simplified text-based analysis
	// In a production system, you'd use a proper Python AST parser
	
	lines := strings.Split(content, "\n")
	result := map[string]interface{}{
		"type":      "python",
		"file":      filePath,
		"lines":     len(lines),
		"imports":   extractPythonImports(content),
		"functions": extractPythonFunctions(content),
		"content":   content,
	}
	
	return result, nil
}

// extractPythonImports extracts import statements from Python code
func extractPythonImports(content string) []string {
	var imports []string
	lines := strings.Split(content, "\n")
	
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "import ") || strings.HasPrefix(trimmed, "from ") {
			imports = append(imports, trimmed)
		}
	}
	
	return imports
}

// extractPythonFunctions extracts function definitions from Python code
func extractPythonFunctions(content string) []string {
	var functions []string
	lines := strings.Split(content, "\n")
	
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "def ") {
			// Extract function name
			if idx := strings.Index(trimmed, "("); idx > 4 {
				funcName := strings.TrimSpace(trimmed[4:idx])
				functions = append(functions, funcName)
			}
		}
	}
	
	return functions
}

// parseHCLFile parses an HCL/Terraform file (simplified parsing for security analysis)
func (p *ASTParser) parseHCLFile(filePath, content string) (map[string]interface{}, error) {
	lines := strings.Split(content, "\n")
	result := map[string]interface{}{
		"type":      "hcl",
		"file":      filePath,
		"lines":     len(lines),
		"resources": extractHCLResources(content),
		"variables": extractHCLVariables(content),
		"content":   content,
	}
	
	return result, nil
}

// parseShellFile parses a shell script file (simplified parsing for security analysis)
func (p *ASTParser) parseShellFile(filePath, content string) (map[string]interface{}, error) {
	lines := strings.Split(content, "\n")
	result := map[string]interface{}{
		"type":      "shell",
		"file":      filePath,
		"lines":     len(lines),
		"variables": extractShellVariables(content),
		"functions": extractShellFunctions(content),
		"content":   content,
	}
	
	return result, nil
}

// extractHCLResources extracts resource definitions from HCL code
func extractHCLResources(content string) []string {
	var resources []string
	lines := strings.Split(content, "\n")
	
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "resource ") {
			// Extract resource type and name
			parts := strings.Fields(trimmed)
			if len(parts) >= 3 {
				resourceType := strings.Trim(parts[1], "\"")
				resourceName := strings.Trim(parts[2], "\"")
				resources = append(resources, resourceType+"."+resourceName)
			}
		}
	}
	
	return resources
}

// extractHCLVariables extracts variable definitions from HCL code
func extractHCLVariables(content string) []string {
	var variables []string
	lines := strings.Split(content, "\n")
	
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "variable ") {
			// Extract variable name
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 {
				varName := strings.Trim(parts[1], "\"")
				variables = append(variables, varName)
			}
		}
	}
	
	return variables
}

// extractShellVariables extracts variable assignments from shell scripts
func extractShellVariables(content string) []string {
	var variables []string
	lines := strings.Split(content, "\n")
	
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "=") && !strings.HasPrefix(trimmed, "#") {
			// Extract variable name (before =)
			parts := strings.SplitN(trimmed, "=", 2)
			if len(parts) == 2 {
				varName := strings.TrimSpace(parts[0])
				// Basic validation for variable names
				if len(varName) > 0 && (varName[0] >= 'A' && varName[0] <= 'Z' || varName[0] >= 'a' && varName[0] <= 'z' || varName[0] == '_') {
					variables = append(variables, varName)
				}
			}
		}
	}
	
	return variables
}

// extractShellFunctions extracts function definitions from shell scripts
func extractShellFunctions(content string) []string {
	var functions []string
	lines := strings.Split(content, "\n")
	
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Look for function definitions: function_name() { or function function_name {
		if strings.Contains(trimmed, "()") && strings.Contains(trimmed, "{") {
			// Extract function name
			if idx := strings.Index(trimmed, "()"); idx > 0 {
				funcName := strings.TrimSpace(trimmed[:idx])
				functions = append(functions, funcName)
			}
		} else if strings.HasPrefix(trimmed, "function ") && strings.Contains(trimmed, "{") {
			// Extract function name from "function name {"
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 {
				funcName := parts[1]
				if strings.HasSuffix(funcName, "()") {
					funcName = funcName[:len(funcName)-2]
				}
				functions = append(functions, funcName)
			}
		}
	}
	
	return functions
}

