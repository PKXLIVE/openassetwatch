package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/openassetwatch/openassetwatch/internal/collector"
	"github.com/openassetwatch/openassetwatch/internal/config"
	"github.com/openassetwatch/openassetwatch/internal/output"
	"github.com/openassetwatch/openassetwatch/pkg/version"
)

func main() {
	var configPath string
	var siteID string
	var showVersion bool

	flag.StringVar(&configPath, "config", "", "path to an OAW agent JSON config")
	flag.StringVar(&siteID, "site-id", "", "safe site identifier")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.Parse()

	if showVersion {
		fmt.Println(version.String())
		return
	}

	cfg := config.Default(config.ModeAgent)
	if configPath != "" {
		loaded, err := config.LoadJSON(configPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		cfg = loaded
	}
	cfg.Mode = config.ModeAgent
	if siteID != "" {
		cfg.SiteID = siteID
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	if err := output.WriteJSON(os.Stdout, collector.CollectLocalInventory(cfg.SiteID)); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
