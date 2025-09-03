package handlers

import (
	"github.com/gofiber/fiber/v2"
	
	"adaptive-threat-modeler/internal/services"
)

// GetAvailableRules returns all available security rules
func GetAvailableRules(c *fiber.Ctx) error {
	ruleEngine := services.NewRuleEngine()
	rules := ruleEngine.GetAllRules()

	return c.JSON(fiber.Map{
		"rules": rules,
		"count": len(rules),
	})
}

// GetRulesForLanguage returns security rules for a specific language
func GetRulesForLanguage(c *fiber.Ctx) error {
	language := c.Params("language")
	if language == "" {
		return c.Status(400).JSON(fiber.Map{
			"error":   true,
			"message": "Language parameter is required",
		})
	}

	ruleEngine := services.NewRuleEngine()
	rules := ruleEngine.GetRulesForLanguage(language)

	return c.JSON(fiber.Map{
		"language": language,
		"rules":    rules,
		"count":    len(rules),
	})
}

