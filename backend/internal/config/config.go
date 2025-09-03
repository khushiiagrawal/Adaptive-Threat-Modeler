package config

import (
	"os"
)

type Config struct {
	Port          string
	TempDir       string
	MaxFileSize   int64
	AllowedOrigins []string
}

func Load() *Config {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8000"
	}

	tempDir := os.Getenv("TEMP_DIR")
	if tempDir == "" {
		tempDir = "/tmp"
	}

	return &Config{
		Port:        port,
		TempDir:     tempDir,
		MaxFileSize: 100 * 1024 * 1024, // 100MB
		AllowedOrigins: []string{
			"http://localhost:3000",
			"http://localhost:5173",
		},
	}
}

