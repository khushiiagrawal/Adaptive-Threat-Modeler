package api

import (
	"github.com/gofiber/fiber/v2"

	"adaptive-threat-modeler/internal/handlers"
)

// SetupRoutes configures all API routes
func SetupRoutes(app *fiber.App) {
	// Create API group
	api := app.Group("/api/v1")

	// Analysis endpoints
	api.Post("/analyze/github", handlers.AnalyzeGitHubRepo)
	api.Post("/analyze/upload", handlers.AnalyzeUpload)
	api.Post("/analyze/commit", handlers.AnalyzeGitCommit)
	api.Get("/analysis/:id", handlers.GetAnalysisResult)
	api.Get("/analysis/:id/status", handlers.GetAnalysisStatus)
	api.Get("/analysis/:id/logs", handlers.GetAnalysisLogs)

	// Project detection endpoints
	api.Post("/detect/languages", handlers.DetectLanguages)
	api.Post("/detect/frameworks", handlers.DetectFrameworks)

	// Rules endpoints
	api.Get("/rules", handlers.GetAvailableRules)
	api.Get("/rules/:language", handlers.GetRulesForLanguage)

	// Commit analysis endpoints
	api.Get("/commits/latest", handlers.GetLatestCommitAnalysis)
	api.Get("/commits/:hash", handlers.GetCommitAnalysisByHash)
	api.Get("/commits", handlers.GetAllCommitAnalyses)
	api.Post("/commits", handlers.StoreCommitAnalysis)

	// Health and info endpoints
	api.Get("/info", handlers.GetSystemInfo)
}
