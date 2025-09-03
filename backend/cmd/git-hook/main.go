package main

import (
	"flag"
	"log"

	"adaptive-threat-modeler/internal/services"
)

func main() {
	var (
		repoPath   = flag.String("repo", "", "Path to git repository (default: current directory)")
		commitHash = flag.String("commit", "", "Specific commit hash to analyze (default: latest)")
		hookMode   = flag.Bool("hook", false, "Run in git hook mode")
		apiMode    = flag.Bool("api", false, "Send analysis to API instead of just console output")
		apiURL     = flag.String("api-url", "http://localhost:8080", "API base URL")
	)
	flag.Parse()

	// Determine repository path
	var gitRepoPath string
	var err error

	if *repoPath != "" {
		gitRepoPath = *repoPath
	} else {
		gitRepoPath, err = services.GetCurrentRepoPath()
		if err != nil {
			log.Fatalf("❌ Error finding git repository: %v", err)
		}
	}

	// Create git service
	gitService := services.NewGitService(gitRepoPath)

	if *hookMode {
		// Run in hook mode - analyze latest commit
		log.Println("🎯 Running git commit analysis hook...")
		if *apiMode {
			if err := gitService.OnCommitHookWithAPI(*apiURL); err != nil {
				log.Fatalf("❌ Hook execution failed: %v", err)
			}
		} else {
			if err := gitService.OnCommitHook(); err != nil {
				log.Fatalf("❌ Hook execution failed: %v", err)
			}
		}
	} else if *commitHash != "" {
		// Analyze specific commit
		log.Printf("🔍 Analyzing commit: %s", *commitHash)
		commitDiff, err := gitService.GetCommitDiff(*commitHash)
		if err != nil {
			log.Fatalf("❌ Error getting commit diff: %v", err)
		}
		gitService.PrintCommitDiff(commitDiff)
	} else {
		// Analyze latest commit
		log.Println("🔍 Analyzing latest commit...")
		commitDiff, err := gitService.GetLatestCommitDiff()
		if err != nil {
			log.Fatalf("❌ Error getting latest commit diff: %v", err)
		}
		gitService.PrintCommitDiff(commitDiff)
	}

	log.Println("✅ Analysis complete!")
}
