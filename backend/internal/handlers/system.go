package handlers

import (
	"runtime"
	
	"github.com/gofiber/fiber/v2"
)

// GetSystemInfo returns system information and capabilities
func GetSystemInfo(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"service":    "Adaptive Threat Modeler",
		"version":    "1.0.0",
		"go_version": runtime.Version(),
		"supported_languages": []string{
			"go", "javascript", "typescript", "python", "java", "php", "ruby", "csharp", "cpp",
		},
		"supported_frameworks": []string{
			"fiber", "gin", "echo", "react", "vue", "angular", "express", "fastapi", "django", "spring",
		},
		"analysis_features": []string{
			"static_analysis", "ast_parsing", "pattern_matching", "dataflow_analysis",
			"vulnerability_detection", "threat_modeling", "autofix_suggestions",
		},
	})
}

