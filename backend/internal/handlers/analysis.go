package handlers

import (
	"path/filepath"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"adaptive-threat-modeler/internal/models"
	"adaptive-threat-modeler/internal/services"
)

// AnalyzeGitHubRepo handles GitHub repository analysis requests
func AnalyzeGitHubRepo(c *fiber.Ctx) error {
	var req struct {
		RepoURL string `json:"repo_url" validate:"required,url"`
		Branch  string `json:"branch,omitempty"`
	}

	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error":   true,
			"message": "Invalid request body",
		})
	}

	// Validate GitHub URL
	if !isValidGitHubURL(req.RepoURL) {
		return c.Status(400).JSON(fiber.Map{
			"error":   true,
			"message": "Invalid GitHub repository URL",
		})
	}

	// Generate analysis ID
	analysisID := uuid.New().String()

	// Store initial processing status
	services.StoreAnalysisResult(analysisID, &models.AnalysisResult{
		ID:        analysisID,
		Timestamp: time.Now(),
		Status:    "processing",
		Summary: models.Summary{
			SecurityPosture: "analyzing",
		},
	})

	// Start analysis asynchronously
	go func() {
		analyzer := services.NewAnalyzer()
		result, err := analyzer.AnalyzeGitHubRepo(analysisID, req.RepoURL, req.Branch)
		if err != nil {
			// Store error result
			services.StoreAnalysisResult(analysisID, &models.AnalysisResult{
				ID:        analysisID,
				Timestamp: time.Now(),
				Status:    "failed",
				Summary: models.Summary{
					SecurityPosture: "unknown",
				},
			})
			return
		}
		services.StoreAnalysisResult(analysisID, result)
	}()

	return c.Status(202).JSON(fiber.Map{
		"analysis_id": analysisID,
		"status":      "processing",
		"message":     "Analysis started successfully",
	})
}

// AnalyzeUpload handles zip file upload analysis requests
func AnalyzeUpload(c *fiber.Ctx) error {
	// Parse multipart form
	file, err := c.FormFile("file")
	if err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error":   true,
			"message": "No file uploaded",
		})
	}

	// Validate file type and size
	if filepath.Ext(file.Filename) != ".zip" {
		return c.Status(400).JSON(fiber.Map{
			"error":   true,
			"message": "Only ZIP files are supported",
		})
	}

	if file.Size > 100*1024*1024 { // 100MB limit
		return c.Status(400).JSON(fiber.Map{
			"error":   true,
			"message": "File size exceeds 100MB limit",
		})
	}

	// Generate analysis ID
	analysisID := uuid.New().String()

	// Store initial processing status
	services.StoreAnalysisResult(analysisID, &models.AnalysisResult{
		ID:        analysisID,
		Timestamp: time.Now(),
		Status:    "processing",
		Summary: models.Summary{
			SecurityPosture: "analyzing",
		},
	})

	// Start analysis asynchronously
	go func() {
		analyzer := services.NewAnalyzer()
		result, err := analyzer.AnalyzeUpload(analysisID, file)
		if err != nil {
			// Store error result
			services.StoreAnalysisResult(analysisID, &models.AnalysisResult{
				ID:        analysisID,
				Timestamp: time.Now(),
				Status:    "failed",
				Summary: models.Summary{
					SecurityPosture: "unknown",
				},
			})
			return
		}
		services.StoreAnalysisResult(analysisID, result)
	}()

	return c.Status(202).JSON(fiber.Map{
		"analysis_id": analysisID,
		"status":      "processing",
		"message":     "Analysis started successfully",
		"filename":    file.Filename,
	})
}

// GetAnalysisResult retrieves the analysis result by ID
func GetAnalysisResult(c *fiber.Ctx) error {
	analysisID := c.Params("id")
	if analysisID == "" {
		return c.Status(400).JSON(fiber.Map{
			"error":   true,
			"message": "Analysis ID is required",
		})
	}

	result, exists := services.GetAnalysisResult(analysisID)
	if !exists {
		return c.Status(404).JSON(fiber.Map{
			"error":   true,
			"message": "Analysis not found",
		})
	}

	return c.JSON(result)
}

// GetAnalysisStatus retrieves the analysis status by ID
func GetAnalysisStatus(c *fiber.Ctx) error {
	analysisID := c.Params("id")
	if analysisID == "" {
		return c.Status(400).JSON(fiber.Map{
			"error":   true,
			"message": "Analysis ID is required",
		})
	}

	result, exists := services.GetAnalysisResult(analysisID)
	if !exists {
		return c.Status(404).JSON(fiber.Map{
			"error":   true,
			"message": "Analysis not found",
		})
	}

	return c.JSON(fiber.Map{
		"analysis_id": analysisID,
		"status":      result.Status,
		"progress":    getProgressPercentage(result.Status),
	})
}

// Helper functions
func isValidGitHubURL(url string) bool {
	// Basic GitHub URL validation
	return len(url) > 0 && (
		len(url) > 19 && url[:19] == "https://github.com/" ||
		len(url) > 15 && url[:15] == "github.com/")
}

func getProgressPercentage(status string) int {
	switch status {
	case "processing":
		return 50
	case "completed":
		return 100
	case "failed":
		return 0
	default:
		return 0
	}
}

// AnalyzeGitCommit handles git commit analysis requests
func AnalyzeGitCommit(c *fiber.Ctx) error {
	var req struct {
		RepoPath   string `json:"repo_path,omitempty"`
		CommitHash string `json:"commit_hash,omitempty"`
	}

	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error":   true,
			"message": "Invalid request body",
		})
	}

	// Determine repository path
	var repoPath string
	var err error
	
	if req.RepoPath != "" {
		repoPath = req.RepoPath
	} else {
		repoPath, err = services.GetCurrentRepoPath()
		if err != nil {
			return c.Status(400).JSON(fiber.Map{
				"error":   true,
				"message": "Could not find git repository: " + err.Error(),
			})
		}
	}

	// Create git service
	gitService := services.NewGitService(repoPath)

	var commitDiff *services.CommitDiff

	if req.CommitHash != "" {
		// Analyze specific commit
		commitDiff, err = gitService.GetCommitDiff(req.CommitHash)
	} else {
		// Analyze latest commit
		commitDiff, err = gitService.GetLatestCommitDiff()
	}

	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"error":   true,
			"message": "Failed to analyze commit: " + err.Error(),
		})
	}

	// Print to console (as requested)
	gitService.PrintCommitDiff(commitDiff)

	return c.JSON(fiber.Map{
		"error":   false,
		"message": "Commit analysis completed successfully",
		"data":    commitDiff,
	})
}

