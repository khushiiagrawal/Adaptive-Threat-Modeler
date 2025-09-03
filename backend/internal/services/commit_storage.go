package services

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"adaptive-threat-modeler/internal/models"
)

// CommitStorageService manages storage of commit analysis data
type CommitStorageService struct {
	storagePath string
	mutex       sync.RWMutex
}

// NewCommitStorageService creates a new commit storage service
func NewCommitStorageService(storagePath string) *CommitStorageService {
	// Ensure storage directory exists
	if err := os.MkdirAll(storagePath, 0755); err != nil {
		panic(fmt.Sprintf("Failed to create storage directory: %v", err))
	}

	return &CommitStorageService{
		storagePath: storagePath,
	}
}

// StoreCommitAnalysis stores commit analysis data to disk
func (c *CommitStorageService) StoreCommitAnalysis(commitDiff *CommitDiff) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Convert CommitDiff to CommitAnalysisData
	analysisData := &models.CommitAnalysisData{
		ID:           fmt.Sprintf("commit_%s_%d", commitDiff.CommitHash[:8], time.Now().Unix()),
		Timestamp:    time.Now(),
		CommitHash:   commitDiff.CommitHash,
		Author:       commitDiff.Author,
		Email:        commitDiff.Email,
		Message:      commitDiff.Message,
		FilesChanged: commitDiff.FilesChanged,
		Additions:    commitDiff.Additions,
		Deletions:    commitDiff.Deletions,
		FullDiff:     commitDiff.Diff,
	}

	// Convert FileDiff to models.FileDiff
	for _, fileDiff := range commitDiff.FileDiffs {
		analysisData.FileDiffs = append(analysisData.FileDiffs, models.FileDiff{
			FileName:    fileDiff.FileName,
			Status:      fileDiff.Status,
			Additions:   fileDiff.Additions,
			Deletions:   fileDiff.Deletions,
			OldFileName: fileDiff.OldFileName,
			Diff:        fileDiff.Diff,
		})
	}

	// Store as JSON file
	filename := fmt.Sprintf("commit_%s.json", commitDiff.CommitHash[:8])
	filePath := filepath.Join(c.storagePath, filename)

	data, err := json.MarshalIndent(analysisData, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal commit analysis data: %w", err)
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write commit analysis file: %w", err)
	}

	// Also store as latest.json for easy access
	latestPath := filepath.Join(c.storagePath, "latest.json")
	if err := os.WriteFile(latestPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write latest commit analysis file: %w", err)
	}

	return nil
}

// GetLatestCommitAnalysis retrieves the most recent commit analysis
func (c *CommitStorageService) GetLatestCommitAnalysis() (*models.CommitAnalysisData, error) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	latestPath := filepath.Join(c.storagePath, "latest.json")
	data, err := os.ReadFile(latestPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no commit analysis data found")
		}
		return nil, fmt.Errorf("failed to read latest commit analysis: %w", err)
	}

	var analysisData models.CommitAnalysisData
	if err := json.Unmarshal(data, &analysisData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal commit analysis data: %w", err)
	}

	return &analysisData, nil
}

// GetCommitAnalysisByHash retrieves commit analysis by commit hash
func (c *CommitStorageService) GetCommitAnalysisByHash(commitHash string) (*models.CommitAnalysisData, error) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	filename := fmt.Sprintf("commit_%s.json", commitHash[:8])
	filepath := filepath.Join(c.storagePath, filename)

	data, err := os.ReadFile(filepath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("commit analysis not found for hash: %s", commitHash[:8])
		}
		return nil, fmt.Errorf("failed to read commit analysis file: %w", err)
	}

	var analysisData models.CommitAnalysisData
	if err := json.Unmarshal(data, &analysisData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal commit analysis data: %w", err)
	}

	return &analysisData, nil
}

// GetAllCommitAnalyses retrieves all stored commit analyses
func (c *CommitStorageService) GetAllCommitAnalyses() ([]*models.CommitAnalysisData, error) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	files, err := filepath.Glob(filepath.Join(c.storagePath, "commit_*.json"))
	if err != nil {
		return nil, fmt.Errorf("failed to list commit analysis files: %w", err)
	}

	var analyses []*models.CommitAnalysisData
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			continue // Skip files that can't be read
		}

		var analysisData models.CommitAnalysisData
		if err := json.Unmarshal(data, &analysisData); err != nil {
			continue // Skip files that can't be unmarshaled
		}

		analyses = append(analyses, &analysisData)
	}

	return analyses, nil
}
