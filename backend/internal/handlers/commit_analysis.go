package handlers

import (
	"strconv"

	"adaptive-threat-modeler/internal/models"
	"adaptive-threat-modeler/internal/services"

	"github.com/gofiber/fiber/v2"
)

var commitStorage *services.CommitStorageService

// InitializeCommitStorage initializes the commit storage service
func InitializeCommitStorage(storagePath string) {
	commitStorage = services.NewCommitStorageService(storagePath)
}

// GetLatestCommitAnalysis returns the most recent commit analysis data (simplified version)
func GetLatestCommitAnalysis(c *fiber.Ctx) error {
	if commitStorage == nil {
		return c.Status(500).JSON(fiber.Map{
			"error":   true,
			"message": "Commit storage not initialized",
		})
	}

	analysis, err := commitStorage.GetLatestCommitAnalysis()
	if err != nil {
		return c.Status(404).JSON(fiber.Map{
			"error":   true,
			"message": err.Error(),
		})
	}

	// Convert to simplified version without file diffs and full diff
	simplifiedData := &models.SimplifiedCommitData{
		ID:           analysis.ID,
		Timestamp:    analysis.Timestamp,
		CommitHash:   analysis.CommitHash,
		Author:       analysis.Author,
		Email:        analysis.Email,
		Message:      analysis.Message,
		Additions:    analysis.Additions,
		Deletions:    analysis.Deletions,
		FilesChanged: analysis.FilesChanged,
	}

	return c.JSON(fiber.Map{
		"success": true,
		"data":    simplifiedData,
	})
}

// GetCommitAnalysisByHash returns commit analysis data for a specific commit hash
func GetCommitAnalysisByHash(c *fiber.Ctx) error {
	if commitStorage == nil {
		return c.Status(500).JSON(fiber.Map{
			"error":   true,
			"message": "Commit storage not initialized",
		})
	}

	commitHash := c.Params("hash")
	if commitHash == "" {
		return c.Status(400).JSON(fiber.Map{
			"error":   true,
			"message": "Commit hash is required",
		})
	}

	analysis, err := commitStorage.GetCommitAnalysisByHash(commitHash)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{
			"error":   true,
			"message": err.Error(),
		})
	}

	return c.JSON(fiber.Map{
		"success": true,
		"data":    analysis,
	})
}

// GetAllCommitAnalyses returns all stored commit analyses
func GetAllCommitAnalyses(c *fiber.Ctx) error {
	if commitStorage == nil {
		return c.Status(500).JSON(fiber.Map{
			"error":   true,
			"message": "Commit storage not initialized",
		})
	}

	// Parse query parameters for pagination
	page := 1
	limit := 10

	if pageStr := c.Query("page"); pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
	}

	if limitStr := c.Query("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 100 {
			limit = l
		}
	}

	analyses, err := commitStorage.GetAllCommitAnalyses()
	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"error":   true,
			"message": err.Error(),
		})
	}

	// Simple pagination
	total := len(analyses)
	start := (page - 1) * limit
	end := start + limit

	var paginatedAnalyses []*models.CommitAnalysisData
	if start >= total {
		paginatedAnalyses = []*models.CommitAnalysisData{}
	} else {
		if end > total {
			end = total
		}
		paginatedAnalyses = analyses[start:end]
	}

	return c.JSON(fiber.Map{
		"success": true,
		"data": fiber.Map{
			"analyses": paginatedAnalyses,
			"pagination": fiber.Map{
				"page":        page,
				"limit":       limit,
				"total":       total,
				"total_pages": (total + limit - 1) / limit,
			},
		},
	})
}

// StoreCommitAnalysis stores new commit analysis data (used by git hook)
func StoreCommitAnalysis(c *fiber.Ctx) error {
	if commitStorage == nil {
		return c.Status(500).JSON(fiber.Map{
			"error":   true,
			"message": "Commit storage not initialized",
		})
	}

	var commitDiff services.CommitDiff
	if err := c.BodyParser(&commitDiff); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error":   true,
			"message": "Invalid request body",
		})
	}

	if err := commitStorage.StoreCommitAnalysis(&commitDiff); err != nil {
		return c.Status(500).JSON(fiber.Map{
			"error":   true,
			"message": err.Error(),
		})
	}

	return c.JSON(fiber.Map{
		"success": true,
		"message": "Commit analysis stored successfully",
	})
}
