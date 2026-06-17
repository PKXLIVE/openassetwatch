package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	agentidentity "github.com/openassetwatch/openassetwatch/internal/agent/identity"
	"github.com/openassetwatch/openassetwatch/internal/collector"
	"github.com/openassetwatch/openassetwatch/internal/config"
	"github.com/openassetwatch/openassetwatch/internal/output"
	"github.com/openassetwatch/openassetwatch/pkg/models"
	"github.com/openassetwatch/openassetwatch/pkg/version"
)

var collectLocalInventory = collector.CollectLocalInventory
var submitHTTPClient = func() *http.Client {
	return &http.Client{Timeout: 10 * time.Second}
}

const localInventorySubmitPath = "/api/v1/collections/local-inventory"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "collect" {
		return runCollect(args[1:], stdout, stderr)
	}
	if len(args) > 0 && args[0] == "submit" {
		return runSubmit(args[1:], stdout, stderr)
	}
	if len(args) > 0 && args[0] == "identity" {
		return runIdentity(args[1:], stdout, stderr)
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
	var identityPath string
	var outputPath string
	var once bool
	var siteID string

	flags := flag.NewFlagSet("oaw-agent collect", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.BoolVar(&once, "once", false, "run one passive local inventory collection")
	flags.StringVar(&configPath, "config", "", "path to an OAW agent JSON config")
	flags.StringVar(&identityPath, "identity-file", "", "optional non-secret local agent identity JSON file")
	flags.StringVar(&outputPath, "output", "", "optional local file path for JSON output")
	flags.StringVar(&siteID, "site-id", "", "safe site identifier")
	if err := flags.Parse(args); err != nil {
		return 2
	}

	if !once {
		fmt.Fprintln(stderr, "oaw-agent collect requires --once")
		return 2
	}

	cfg, identity, err := loadCollectConfig(configPath, siteID, identityPath)
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

	inventory := collectLocalInventory(cfg.SiteID)
	if identity != nil {
		applyCollectionIdentity(&inventory, *identity)
	}
	if err := output.WriteJSON(writer, inventory); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func runIdentity(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "init" {
		fmt.Fprintln(stderr, "oaw-agent identity requires init")
		return 2
	}
	return runIdentityInit(args[1:], stdout, stderr)
}

func runIdentityInit(args []string, stdout io.Writer, stderr io.Writer) int {
	var deploymentID string
	var outputPath string
	var siteID string
	var tenantID string

	flags := flag.NewFlagSet("oaw-agent identity init", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&deploymentID, "deployment-id", "", "optional deployment GUID from installer or enrollment input")
	flags.StringVar(&outputPath, "output", "", "local identity JSON output path")
	flags.StringVar(&siteID, "site-id", "", "required safe site identifier")
	flags.StringVar(&tenantID, "tenant-id", "", "optional tenant identifier")
	if err := flags.Parse(args); err != nil {
		return 2
	}

	if outputPath == "" {
		fmt.Fprintln(stderr, "oaw-agent identity init requires --output")
		return 2
	}

	if _, err := agentidentity.CreateFile(outputPath, agentidentity.CreateParams{
		SiteID:       siteID,
		DeploymentID: deploymentID,
		TenantID:     tenantID,
	}, time.Now().UTC()); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	fmt.Fprintln(stdout, "created local agent identity file")
	return 0
}

func runSubmit(args []string, stdout io.Writer, stderr io.Writer) int {
	var filePath string
	var serverURL string

	flags := flag.NewFlagSet("oaw-agent submit", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&filePath, "file", "", "local inventory JSON file to submit")
	flags.StringVar(&serverURL, "server-url", "", "explicit OpenAssetWatch backend URL")
	if err := flags.Parse(args); err != nil {
		return 2
	}

	if filePath == "" {
		fmt.Fprintln(stderr, "oaw-agent submit requires --file")
		return 2
	}
	if serverURL == "" {
		fmt.Fprintln(stderr, "oaw-agent submit requires --server-url")
		return 2
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Fprintln(stderr, "failed to read collection file")
		return 1
	}
	if !json.Valid(data) {
		fmt.Fprintln(stderr, "collection file must contain valid JSON")
		return 2
	}

	statusCode, err := submitLocalInventory(context.Background(), submitHTTPClient(), serverURL, data)
	if err != nil {
		fmt.Fprintf(stderr, "submit failed: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "submitted local inventory collection: HTTP %d\n", statusCode)
	return 0
}

func loadCollectConfig(configPath string, siteID string, identityPath string) (config.Config, *agentidentity.Identity, error) {
	cfg := config.Default(config.ModeAgent)
	if configPath != "" {
		loaded, err := config.LoadJSON(configPath)
		if err != nil {
			return config.Config{}, nil, err
		}
		cfg = loaded
	}
	cfg.Mode = config.ModeAgent

	cliSiteID := strings.TrimSpace(siteID)
	if identityPath == "" {
		if cliSiteID != "" {
			cfg.SiteID = cliSiteID
		}
		if err := cfg.Validate(); err != nil {
			return config.Config{}, nil, err
		}
		return cfg, nil, nil
	}

	if config.IsQuarantinedPath(identityPath) {
		return config.Config{}, nil, fmt.Errorf("refusing to load identity from quarantined path: %s", identityPath)
	}

	identity, err := agentidentity.ReadFile(identityPath)
	if err != nil {
		return config.Config{}, nil, err
	}
	identity.SiteID = strings.TrimSpace(identity.SiteID)
	identity.TenantID = strings.TrimSpace(identity.TenantID)
	identity.DeploymentID = strings.TrimSpace(identity.DeploymentID)
	identity.AgentID = strings.TrimSpace(identity.AgentID)

	if cliSiteID != "" && cliSiteID != identity.SiteID {
		return config.Config{}, nil, fmt.Errorf("site_id from --site-id conflicts with identity file site_id")
	}
	if cliSiteID == "" && cfg.SiteID != "" && cfg.SiteID != identity.SiteID {
		return config.Config{}, nil, fmt.Errorf("site_id from config conflicts with identity file site_id")
	}

	cfg.SiteID = identity.SiteID
	if err := cfg.Validate(); err != nil {
		return config.Config{}, nil, err
	}
	return cfg, &identity, nil
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

func applyCollectionIdentity(inventory *models.Inventory, identity agentidentity.Identity) {
	inventory.SiteID = identity.SiteID
	inventory.TenantID = identity.TenantID
	inventory.DeploymentID = identity.DeploymentID
	inventory.AgentID = identity.AgentID

	for index := range inventory.Assets {
		inventory.Assets[index].SiteID = identity.SiteID
	}
}

func submitLocalInventory(ctx context.Context, client *http.Client, serverURL string, body []byte) (int, error) {
	if client == nil {
		client = submitHTTPClient()
	}

	endpoint, err := localInventoryEndpointURL(serverURL)
	if err != nil {
		return 0, err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return 0, errors.New("failed to build submit request")
	}
	request.Header.Set("Content-Type", "application/json")

	response, err := client.Do(request)
	if err != nil {
		return 0, errors.New("request failed")
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))

	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return response.StatusCode, fmt.Errorf("backend returned HTTP status %d", response.StatusCode)
	}
	return response.StatusCode, nil
}

func localInventoryEndpointURL(serverURL string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(serverURL))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", errors.New("server-url must include http or https scheme and host")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", errors.New("server-url must use http or https")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("server-url must not include query or fragment")
	}

	parsed.Path = strings.TrimRight(parsed.Path, "/") + localInventorySubmitPath
	parsed.RawPath = ""
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}
