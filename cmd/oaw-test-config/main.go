package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/openassetwatch/openassetwatch/internal/config"
	"github.com/openassetwatch/openassetwatch/internal/output"
)

func main() {
	var configPath string
	flag.StringVar(&configPath, "config", "", "path to an OAW JSON config")
	flag.Parse()

	if configPath == "" {
		fmt.Fprintln(os.Stderr, "--config is required")
		os.Exit(2)
	}

	cfg, err := config.LoadJSON(configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	if err := output.WriteJSON(os.Stdout, map[string]any{"status": "valid", "config": cfg}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
