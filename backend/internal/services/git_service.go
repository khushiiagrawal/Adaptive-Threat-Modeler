package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
)

// GitService handles git operations and commit analysis
type GitService struct {
	repoPath string
}

// NewGitService creates a new git service instance
func NewGitService(repoPath string) *GitService {
	return &GitService{
		repoPath: repoPath,
	}
}

// FileDiff represents changes to a single file
type FileDiff struct {
	FileName    string `json:"file_name"`
	Status      string `json:"status"` // A (added), M (modified), D (deleted), R (renamed)
	Additions   int    `json:"additions"`
	Deletions   int    `json:"deletions"`
	OldFileName string `json:"old_file_name,omitempty"` // For renamed files
	Diff        string `json:"diff"`                    // The actual diff content for this file
}

// CommitDiff represents the difference information for a commit
type CommitDiff struct {
	CommitHash   string     `json:"commit_hash"`
	Author       string     `json:"author"`
	Email        string     `json:"email"`
	Message      string     `json:"message"`
	Timestamp    time.Time  `json:"timestamp"`
	FilesChanged []string   `json:"files_changed"`
	Additions    int        `json:"additions"`
	Deletions    int        `json:"deletions"`
	Diff         string     `json:"diff"`
	FileDiffs    []FileDiff `json:"file_diffs"` // Detailed per-file changes
}

// GetLatestCommitDiff gets the diff for the most recent commit
func (g *GitService) GetLatestCommitDiff() (*CommitDiff, error) {
	repo, err := git.PlainOpen(g.repoPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open repository: %w", err)
	}

	// Get the HEAD reference
	ref, err := repo.Head()
	if err != nil {
		return nil, fmt.Errorf("failed to get HEAD: %w", err)
	}

	// Get the commit object
	commit, err := repo.CommitObject(ref.Hash())
	if err != nil {
		return nil, fmt.Errorf("failed to get commit object: %w", err)
	}

	// Get the diff using git command (more reliable for diff output)
	diff, stats, err := g.getCommitDiffUsingGitCommand(commit.Hash.String())
	if err != nil {
		return nil, fmt.Errorf("failed to get commit diff: %w", err)
	}

	// Get changed files
	changedFiles, err := g.getChangedFiles(commit.Hash.String())
	if err != nil {
		return nil, fmt.Errorf("failed to get changed files: %w", err)
	}

	// Get detailed file diffs
	fileDiffs, err := g.getDetailedFileDiffs(commit.Hash.String())
	if err != nil {
		return nil, fmt.Errorf("failed to get detailed file diffs: %w", err)
	}

	commitDiff := &CommitDiff{
		CommitHash:   commit.Hash.String(),
		Author:       commit.Author.Name,
		Email:        commit.Author.Email,
		Message:      commit.Message,
		Timestamp:    commit.Author.When,
		FilesChanged: changedFiles,
		Additions:    stats.Additions,
		Deletions:    stats.Deletions,
		Diff:         diff,
		FileDiffs:    fileDiffs,
	}

	return commitDiff, nil
}

// GetCommitDiff gets the diff for a specific commit hash
func (g *GitService) GetCommitDiff(commitHash string) (*CommitDiff, error) {
	repo, err := git.PlainOpen(g.repoPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open repository: %w", err)
	}

	// Get the commit object
	hash := plumbing.NewHash(commitHash)
	commit, err := repo.CommitObject(hash)
	if err != nil {
		return nil, fmt.Errorf("failed to get commit object: %w", err)
	}

	// Get the diff using git command
	diff, stats, err := g.getCommitDiffUsingGitCommand(commitHash)
	if err != nil {
		return nil, fmt.Errorf("failed to get commit diff: %w", err)
	}

	// Get changed files
	changedFiles, err := g.getChangedFiles(commitHash)
	if err != nil {
		return nil, fmt.Errorf("failed to get changed files: %w", err)
	}

	// Get detailed file diffs
	fileDiffs, err := g.getDetailedFileDiffs(commitHash)
	if err != nil {
		return nil, fmt.Errorf("failed to get detailed file diffs: %w", err)
	}

	commitDiff := &CommitDiff{
		CommitHash:   commit.Hash.String(),
		Author:       commit.Author.Name,
		Email:        commit.Author.Email,
		Message:      commit.Message,
		Timestamp:    commit.Author.When,
		FilesChanged: changedFiles,
		Additions:    stats.Additions,
		Deletions:    stats.Deletions,
		Diff:         diff,
		FileDiffs:    fileDiffs,
	}

	return commitDiff, nil
}

// DiffStats represents diff statistics
type DiffStats struct {
	Additions int
	Deletions int
}

// getCommitDiffUsingGitCommand uses git command to get detailed diff
func (g *GitService) getCommitDiffUsingGitCommand(commitHash string) (string, *DiffStats, error) {
	// Change to repository directory
	originalDir, err := os.Getwd()
	if err != nil {
		return "", nil, err
	}
	defer os.Chdir(originalDir)

	if err := os.Chdir(g.repoPath); err != nil {
		return "", nil, fmt.Errorf("failed to change directory: %w", err)
	}

	// Get detailed diff with more context lines and better formatting
	cmd := exec.Command("git", "show",
		"--pretty=format:",
		"--unified=5",   // Show 5 lines of context around changes
		"--color=never", // Disable color for clean output
		"--full-index",  // Show full SHA-1 in diff header
		"--stat",        // Include file statistics
		commitHash)

	detailedDiff, err := cmd.Output()
	if err != nil {
		return "", nil, fmt.Errorf("failed to execute git show for detailed diff: %w", err)
	}

	// Get numeric stats separately for more reliable parsing
	cmd = exec.Command("git", "show", "--stat", "--pretty=format:", "--numstat", commitHash)
	statsOutput, err := cmd.Output()
	if err != nil {
		return "", nil, fmt.Errorf("failed to execute git show --stat: %w", err)
	}

	stats := g.parseGitStats(string(statsOutput))

	return string(detailedDiff), stats, nil
}

// getChangedFiles gets the list of changed files in a commit
func (g *GitService) getChangedFiles(commitHash string) ([]string, error) {
	originalDir, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	defer os.Chdir(originalDir)

	if err := os.Chdir(g.repoPath); err != nil {
		return nil, fmt.Errorf("failed to change directory: %w", err)
	}

	cmd := exec.Command("git", "show", "--pretty=format:", "--name-only", commitHash)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to execute git show --name-only: %w", err)
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	var files []string
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			files = append(files, strings.TrimSpace(line))
		}
	}

	return files, nil
}

// getDetailedFileDiffs gets detailed diff information for each file in a commit
func (g *GitService) getDetailedFileDiffs(commitHash string) ([]FileDiff, error) {
	originalDir, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	defer os.Chdir(originalDir)

	if err := os.Chdir(g.repoPath); err != nil {
		return nil, fmt.Errorf("failed to change directory: %w", err)
	}

	// Get file status information (added, modified, deleted, renamed)
	cmd := exec.Command("git", "show", "--name-status", "--pretty=format:", commitHash)
	statusOutput, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get file status: %w", err)
	}

	// Get numstat for each file (additions/deletions count)
	cmd = exec.Command("git", "show", "--numstat", "--pretty=format:", commitHash)
	numstatOutput, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get numstat: %w", err)
	}

	var fileDiffs []FileDiff
	statusLines := strings.Split(strings.TrimSpace(string(statusOutput)), "\n")
	numstatLines := strings.Split(strings.TrimSpace(string(numstatOutput)), "\n")

	// Create a map of filenames to numstat info
	numstatMap := make(map[string]struct{ additions, deletions int })
	for _, line := range numstatLines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) >= 3 {
			additions := parseInt(parts[0])
			deletions := parseInt(parts[1])
			filename := parts[2]
			numstatMap[filename] = struct{ additions, deletions int }{additions, deletions}
		}
	}

	// Process each file
	for _, line := range statusLines {
		if strings.TrimSpace(line) == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		status := parts[0]
		fileName := parts[1]
		var oldFileName string

		// Handle renamed files (R100 oldname newname)
		if strings.HasPrefix(status, "R") && len(parts) >= 3 {
			oldFileName = parts[1]
			fileName = parts[2]
		}

		// Get individual file diff
		fileDiffContent, err := g.getIndividualFileDiff(commitHash, fileName, oldFileName)
		if err != nil {
			log.Printf("Warning: Could not get diff for file %s: %v", fileName, err)
			fileDiffContent = fmt.Sprintf("Error getting diff: %v", err)
		}

		// Get stats for this file
		stats := numstatMap[fileName]
		if oldFileName != "" {
			// For renamed files, try both names
			if oldStats, exists := numstatMap[oldFileName]; exists {
				stats = oldStats
			}
		}

		fileDiff := FileDiff{
			FileName:    fileName,
			Status:      status,
			Additions:   stats.additions,
			Deletions:   stats.deletions,
			OldFileName: oldFileName,
			Diff:        fileDiffContent,
		}

		fileDiffs = append(fileDiffs, fileDiff)
	}

	return fileDiffs, nil
}

// getIndividualFileDiff gets the diff content for a specific file
func (g *GitService) getIndividualFileDiff(commitHash, fileName, oldFileName string) (string, error) {
	originalDir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	defer os.Chdir(originalDir)

	if err := os.Chdir(g.repoPath); err != nil {
		return "", fmt.Errorf("failed to change directory: %w", err)
	}

	// Get diff for specific file with context
	var cmd *exec.Cmd
	if oldFileName != "" {
		// For renamed files
		cmd = exec.Command("git", "show", "--pretty=format:", "--unified=5", commitHash, "--", oldFileName, fileName)
	} else {
		// For regular files
		cmd = exec.Command("git", "show", "--pretty=format:", "--unified=5", commitHash, "--", fileName)
	}

	output, err := cmd.Output()
	if err != nil {
		// If the specific file diff fails, try to extract it from the full diff
		return g.extractFileDiffFromFullDiff(commitHash, fileName)
	}

	return string(output), nil
}

// extractFileDiffFromFullDiff extracts a specific file's diff from the full commit diff
func (g *GitService) extractFileDiffFromFullDiff(commitHash, fileName string) (string, error) {
	originalDir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	defer os.Chdir(originalDir)

	if err := os.Chdir(g.repoPath); err != nil {
		return "", fmt.Errorf("failed to change directory: %w", err)
	}

	// Get the full diff
	cmd := exec.Command("git", "show", "--pretty=format:", "--unified=5", commitHash)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get full diff: %w", err)
	}

	fullDiff := string(output)

	// Find the section for this file
	lines := strings.Split(fullDiff, "\n")
	var fileDiffLines []string
	inTargetFile := false

	for _, line := range lines {
		// Look for diff header for our file
		if strings.HasPrefix(line, "diff --git") && strings.Contains(line, fileName) {
			inTargetFile = true
			fileDiffLines = append(fileDiffLines, line)
			continue
		}

		// If we're in our target file, collect lines
		if inTargetFile {
			// Stop when we hit the next file's diff header
			if strings.HasPrefix(line, "diff --git") && !strings.Contains(line, fileName) {
				break
			}
			fileDiffLines = append(fileDiffLines, line)
		}
	}

	if len(fileDiffLines) == 0 {
		return fmt.Sprintf("No diff found for file: %s", fileName), nil
	}

	return strings.Join(fileDiffLines, "\n"), nil
}

// parseGitStats parses git stats output to extract additions and deletions
func (g *GitService) parseGitStats(statsOutput string) *DiffStats {
	stats := &DiffStats{}
	lines := strings.Split(statsOutput, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Parse numstat format: "additions\tdeletions\tfilename"
		if strings.Contains(line, "\t") {
			parts := strings.Split(line, "\t")
			if len(parts) >= 2 {
				if additions := parseInt(parts[0]); additions > 0 {
					stats.Additions += additions
				}
				if deletions := parseInt(parts[1]); deletions > 0 {
					stats.Deletions += deletions
				}
			}
		} else if strings.Contains(line, "insertion") || strings.Contains(line, "deletion") {
			// Parse summary lines like: " 5 files changed, 123 insertions(+), 45 deletions(-)"
			parts := strings.Fields(line)
			for i, part := range parts {
				if strings.Contains(part, "insertion") && i > 0 {
					if num := parseInt(parts[i-1]); num > 0 {
						stats.Additions = num
					}
				}
				if strings.Contains(part, "deletion") && i > 0 {
					if num := parseInt(parts[i-1]); num > 0 {
						stats.Deletions = num
					}
				}
			}
		}
	}

	return stats
}

// parseInt safely parses an integer from string
func parseInt(s string) int {
	var result int
	for _, char := range s {
		if char >= '0' && char <= '9' {
			result = result*10 + int(char-'0')
		} else {
			break
		}
	}
	return result
}

// PrintCommitDiff prints the commit diff to console in a formatted way
func (g *GitService) PrintCommitDiff(commitDiff *CommitDiff) {
	fmt.Println(strings.Repeat("=", 80))
	fmt.Printf("🔄 COMMIT ANALYSIS\n")
	fmt.Println(strings.Repeat("=", 80))
	fmt.Printf("📝 Commit Hash: %s\n", commitDiff.CommitHash[:8])
	fmt.Printf("👤 Author: %s <%s>\n", commitDiff.Author, commitDiff.Email)
	fmt.Printf("⏰ Timestamp: %s\n", commitDiff.Timestamp.Format("2006-01-02 15:04:05"))
	fmt.Printf("💬 Message: %s\n", strings.TrimSpace(commitDiff.Message))
	fmt.Printf("📊 Changes: +%d additions, -%d deletions\n", commitDiff.Additions, commitDiff.Deletions)
	fmt.Printf("📁 Files Changed (%d):\n", len(commitDiff.FilesChanged))

	for _, file := range commitDiff.FilesChanged {
		fmt.Printf("   • %s\n", file)
	}

	// Show detailed file-by-file differences
	if len(commitDiff.FileDiffs) > 0 {
		fmt.Println("\n" + strings.Repeat("=", 80))
		fmt.Println("📋 DETAILED FILE CHANGES:")
		fmt.Println(strings.Repeat("=", 80))

		for i, fileDiff := range commitDiff.FileDiffs {
			fmt.Printf("\n📄 File %d: %s", i+1, fileDiff.FileName)

			// Show status
			switch fileDiff.Status {
			case "A":
				fmt.Printf(" (✅ ADDED)")
			case "M":
				fmt.Printf(" (📝 MODIFIED)")
			case "D":
				fmt.Printf(" (❌ DELETED)")
			default:
				if strings.HasPrefix(fileDiff.Status, "R") {
					fmt.Printf(" (🔄 RENAMED from %s)", fileDiff.OldFileName)
				} else {
					fmt.Printf(" (%s)", fileDiff.Status)
				}
			}

			fmt.Printf(" [+%d/-%d]\n", fileDiff.Additions, fileDiff.Deletions)
			fmt.Println(strings.Repeat("-", 80))

			// Show the actual diff content
			if strings.TrimSpace(fileDiff.Diff) != "" {
				fmt.Println(fileDiff.Diff)
			} else {
				fmt.Println("(No diff content available)")
			}

			if i < len(commitDiff.FileDiffs)-1 {
				fmt.Println("\n" + strings.Repeat("-", 40))
			}
		}

		fmt.Println("\n" + strings.Repeat("=", 80))
	} else {
		// Fallback to showing the full diff if no file diffs available
		fmt.Println("\n" + strings.Repeat("=", 80))
		fmt.Println("📋 DETAILED DIFF:")
		fmt.Println(strings.Repeat("=", 80))
		fmt.Println(commitDiff.Diff)
		fmt.Println(strings.Repeat("=", 80))
	}
}

// OnCommitHook is called when a commit is made (to be used with git hooks)
func (g *GitService) OnCommitHook() error {
	log.Println("🎯 Git commit detected! Analyzing changes...")

	commitDiff, err := g.GetLatestCommitDiff()
	if err != nil {
		log.Printf("❌ Error getting commit diff: %v", err)
		return err
	}

	// Print the diff to console
	g.PrintCommitDiff(commitDiff)

	// Optional: Log to file as well
	g.logCommitToFile(commitDiff)

	return nil
}

// OnCommitHookWithAPI is called when a commit is made and sends data to API
func (g *GitService) OnCommitHookWithAPI(apiURL string) error {
	log.Println("🎯 Git commit detected! Analyzing changes...")

	commitDiff, err := g.GetLatestCommitDiff()
	if err != nil {
		log.Printf("❌ Error getting commit diff: %v", err)
		return err
	}

	// Print the diff to console
	g.PrintCommitDiff(commitDiff)

	// Send to API
	if err := g.sendCommitToAPI(commitDiff, apiURL); err != nil {
		log.Printf("⚠️ Warning: Failed to send commit analysis to API: %v", err)
		// Don't fail the hook if API is unavailable
	}

	// Optional: Log to file as well
	g.logCommitToFile(commitDiff)

	return nil
}

// logCommitToFile logs commit information to a file
func (g *GitService) logCommitToFile(commitDiff *CommitDiff) {
	logFile := filepath.Join(g.repoPath, ".git", "commit-analysis.log")
	file, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Warning: Could not write to log file: %v", err)
		return
	}
	defer file.Close()

	logEntry := fmt.Sprintf("[%s] %s by %s - %d files changed (+%d/-%d)\n",
		commitDiff.Timestamp.Format("2006-01-02 15:04:05"),
		commitDiff.CommitHash[:8],
		commitDiff.Author,
		len(commitDiff.FilesChanged),
		commitDiff.Additions,
		commitDiff.Deletions,
	)

	file.WriteString(logEntry)
}

// sendCommitToAPI sends commit analysis data to the API
func (g *GitService) sendCommitToAPI(commitDiff *CommitDiff, apiURL string) error {
	// Prepare the JSON payload
	jsonData, err := json.Marshal(commitDiff)
	if err != nil {
		return fmt.Errorf("failed to marshal commit diff: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequest("POST", apiURL+"/api/v1/commits", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Send request
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API returned status code: %d", resp.StatusCode)
	}

	log.Println("✅ Commit analysis sent to API successfully")
	return nil
}

// GetCurrentRepoPath tries to find the git repository root
func GetCurrentRepoPath() (string, error) {
	// Start from current directory and walk up to find .git
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for {
		gitDir := filepath.Join(dir, ".git")
		if _, err := os.Stat(gitDir); err == nil {
			return dir, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached root directory
			break
		}
		dir = parent
	}

	return "", fmt.Errorf("not in a git repository")
}
