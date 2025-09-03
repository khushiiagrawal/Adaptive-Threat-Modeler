package handlers

import (
	"github.com/gofiber/fiber/v2"
	
	"adaptive-threat-modeler/internal/services"
)

// DetectLanguages analyzes project files to detect programming languages
func DetectLanguages(c *fiber.Ctx) error {
	var req struct {
		ProjectPath string   `json:"project_path"`
		Files       []string `json:"files,omitempty"`
	}

	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error":   true,
			"message": "Invalid request body",
		})
	}

	detector := services.NewProjectDetector()
	languages, err := detector.DetectLanguages(req.ProjectPath, req.Files)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"error":   true,
			"message": "Failed to detect languages: " + err.Error(),
		})
	}

	return c.JSON(fiber.Map{
		"languages": languages,
	})
}

// DetectFrameworks analyzes project files to detect frameworks and libraries
func DetectFrameworks(c *fiber.Ctx) error {
	var req struct {
		ProjectPath string   `json:"project_path"`
		Languages   []string `json:"languages,omitempty"`
	}

	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error":   true,
			"message": "Invalid request body",
		})
	}

	detector := services.NewProjectDetector()
	frameworks, err := detector.DetectFrameworks(req.ProjectPath, req.Languages)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"error":   true,
			"message": "Failed to detect frameworks: " + err.Error(),
		})
	}

	return c.JSON(fiber.Map{
		"frameworks": frameworks,
	})
}

