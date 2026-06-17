package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/openassetwatch/openassetwatch/internal/collector"
	"github.com/openassetwatch/openassetwatch/internal/config"
	"github.com/openassetwatch/openassetwatch/internal/output"
	"github.com/openassetwatch/openassetwatch/pkg/version"
)

var collectLocalInventory = collector.CollectLocalInventory

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "collect" {
		return runCollect(args[1:], stdout, stderr)
	}

	var configPath string
	var siteID string
	var showVersion bool

	flags := flag.NewFlagSet("oaw-agent", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&configPath, "config", "", "path to an OAW agent JSON config")
	flags.StringVar(&siteID, "site-id", "", "safe site identifier")
	flags.BoolVar(&showVersion, "version", false, "print version and exit")
	if err := flags.Parse(args); err != nil {
		return 2
	}

	if showVersion {
		fmt.Fprintln(stdout, version.String())
		return 0
	}

	cfg, err := loadAgentConfig(configPath, siteID)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	if err := output.WriteJSON(stdout, collectLocalInventory(cfg.SiteID)); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func runCollect(args []string, stdout io.Writer, stderr io.Writer) int {
	var configPath string
	var outputPath string
	var once bool
	var siteID string

	flags := flag.NewFlagSet("oaw-agent collect", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.BoolVar(&once, "once", false, "run one passive local inventory collection")
	flags.StringVar(&configPath, "config", "", "path to an OAW agent JSON config")
	flags.StringVar(&outputPath, "output", "", "optional local file path for JSON output")
	flags.StringVar(&siteID, "site-id", "", "safe site identifier")
	if err := flags.Parse(args); err != nil {
		return 2
	}

	if !once {
		fmt.Fprintln(stderr, "oaw-agent collect requires --once")
		return 2
	}

	cfg, err := loadAgentConfig(configPath, siteID)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	writer := stdout
	var file *os.File
	if outputPath != "" {
		file, err = os.OpenFile(outputPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		defer file.Close()
		writer = file
	}

	if err := output.WriteJSON(writer, collectLocalInventory(cfg.SiteID)); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func loadAgentConfig(configPath string, siteID string) (config.Config, error) {
	cfg := config.Default(config.ModeAgent)
	if configPath != "" {
		loaded, err := config.LoadJSON(configPath)
		if err != nil {
			return config.Config{}, err
		}
		cfg = loaded
	}
	cfg.Mode = config.ModeAgent
	if siteID != "" {
		cfg.SiteID = siteID
	}
	if err := cfg.Validate(); err != nil {
		return config.Config{}, err
	}
	return cfg, nil
}
