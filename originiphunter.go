package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/rix4uni/originiphunter/banner"
	"github.com/spf13/pflag"
	"gopkg.in/yaml.v3"
)

// Config represents the configuration structure
type Config struct {
	SecurityTrails []string `yaml:"securitytrails"`
	Shodan         []string `yaml:"shodan"`
	ViewDNS        []string `yaml:"viewdns"`
	Hunter         []string `yaml:"hunter"`
	Censys         []string `yaml:"censys"`
	Fofa           []string `yaml:"fofa"`
}

// DomainScanResult represents the result of scanning a domain
type DomainScanResult struct {
	URL           string
	StatusCode    int
	ContentLength int64
	Title         string
}

// JSONOutput represents the JSON output structure
type JSONOutput struct {
	Domain       string              `json:"domain"`
	OriginDomain *DomainScanResult   `json:"origin_domain,omitempty"`
	OriginIPs    []*DomainScanResult `json:"origin_ips"`
	OtherIPs     []*DomainScanResult `json:"other_ips"`
}

// FavInfoOutput represents the favinfo JSON output structure
type FavInfoOutput struct {
	MurmurHash int64  `json:"murmur_hash"`
	MD5Hash    string `json:"md5_hash"`
	SHA256Hash string `json:"sha256_hash"`
}

// OriginIpHunter represents the main hunting instance
type OriginIpHunter struct {
	config             *Config
	engines            []string
	configPath         string
	originResult       *DomainScanResult // Store the original domain scan result
	verbose            bool              // Show verbose output
	userAgent          string            // HTTP User-Agent header
	matchContentLength bool              // Match content length in Origin IPs Found
	matchStatusCode    bool              // Match status code in Origin IPs Found
	jsonOutput         bool              // Enable JSON output format
	parallel           bool              // Enable parallel engine execution
	concurrent         int               // Number of concurrent IP validations
}

func main() {
	var (
		engines            = pflag.StringSlice("engine", []string{}, "Specific search engines to use (comma-separated). Available: shodan,securitytrails,viewdns,hunter,censys,fofa")
		configPath         = pflag.String("config", "", "Custom config file path (default: ~/.config/originiphunter/config.yaml)")
		silent             = pflag.Bool("silent", false, "Silent mode.")
		version            = pflag.Bool("version", false, "Print the version of the tool and exit.")
		verbose            = pflag.Bool("verbose", false, "Show detailed information about the scanning process")
		userAgent          = pflag.StringP("useragent", "H", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36", "HTTP User-Agent header")
		contentLengthMatch = pflag.BoolP("content-length", "C", false, "Match content length in Origin IPs Found section")
		statusCodeMatch    = pflag.BoolP("status-code", "S", false, "Match status code in Origin IPs Found section")
		jsonOutput         = pflag.Bool("json", false, "Output results in JSON format")
		parallel           = pflag.BoolP("parallel", "p", false, "Run search engines in parallel for faster execution")
		concurrent         = pflag.Int("concurrent", 50, "Number of concurrent IP validations (default: 50)")
	)
	pflag.Parse()

	if *version {
		banner.PrintBanner()
		banner.PrintVersion()
		os.Exit(0)
	}

	if !*silent {
		banner.PrintBanner()
	}

	// Set default config path if not provided
	if *configPath == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			log.Fatalf("Failed to get home directory: %v", err)
		}
		*configPath = filepath.Join(homeDir, ".config", "originiphunter", "config.yaml")
	}

	// Load configuration
	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Create OriginIpHunter instance
	hunter := &OriginIpHunter{
		config:             cfg,
		engines:            *engines,
		configPath:         *configPath,
		verbose:            *verbose,
		userAgent:          *userAgent,
		matchContentLength: *contentLengthMatch,
		matchStatusCode:    *statusCodeMatch,
		jsonOutput:         *jsonOutput,
		parallel:           *parallel,
		concurrent:         *concurrent,
	}

	// Process input
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain == "" {
			continue
		}

		// Remove http:// or https:// prefix if present
		domain = strings.TrimPrefix(domain, "https://")
		domain = strings.TrimPrefix(domain, "http://")

		if !hunter.jsonOutput {
			fmt.Printf("Processing: %s\n", domain)
		}

		// Run httpx on the input domain to show current status
		hunter.scanDomainWithHttpx(domain)

		// Run the origin hunting process
		err := hunter.HuntOrigin(domain)
		if err != nil {
			log.Printf("Error processing domain %s: %v", domain, err)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("Error reading input: %v", err)
	}
}

// loadConfig loads configuration from YAML file
func loadConfig(configPath string) (*Config, error) {
	// Check if config file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// Create default config if it doesn't exist
		return createDefaultConfig(configPath)
	}

	// Read config file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &config, nil
}

// createDefaultConfig creates a default configuration file
func createDefaultConfig(configPath string) (*Config, error) {
	// Create directory if it doesn't exist
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create config directory: %w", err)
	}

	// Create default config
	config := &Config{
		SecurityTrails: []string{},
		Shodan:         []string{},
		ViewDNS:        []string{},
		Hunter:         []string{},
		Censys:         []string{},
		Fofa:           []string{},
	}

	// Write default config
	data, err := yaml.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal default config: %w", err)
	}

	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return nil, fmt.Errorf("failed to write default config: %w", err)
	}

	fmt.Printf("Created default config file at: %s\n", configPath)
	fmt.Println("Please add your API keys to the config file and run again.")

	return config, nil
}

// HuntOrigin is the main hunting function
func (h *OriginIpHunter) HuntOrigin(domain string) error {
	var allIPs []string

	// Extract favicon hashes for different services
	shodanFaviconHash, err := h.extractShodanFaviconHash(domain)
	if err != nil {
		if h.verbose {
			fmt.Printf("\033[33mWarning:\033[0m Could not extract Shodan favicon hash for %s: %v\n", domain, err)
		}
	} else if shodanFaviconHash != "" && h.verbose {
		fmt.Printf("\033[36mShodan favicon hash:\033[0m %s\n", shodanFaviconHash)
	}

	hunterFaviconHash, err := h.extractHunterFaviconHash(domain)
	if err != nil {
		if h.verbose {
			fmt.Printf("\033[33mWarning:\033[0m Could not extract Hunter favicon hash for %s: %v\n", domain, err)
		}
	} else if hunterFaviconHash != "" && h.verbose {
		fmt.Printf("\033[36mHunter favicon hash:\033[0m %s\n", hunterFaviconHash)
	}

	// Extract page title for title-based searches
	pageTitle, err := h.extractPageTitle(domain)
	if err != nil {
		if h.verbose {
			fmt.Printf("\033[33mWarning:\033[0m Could not extract page title for %s: %v\n", domain, err)
		}
	} else if pageTitle != "" && h.verbose {
		fmt.Printf("\033[36mPage title:\033[0m %s\n", pageTitle)
	}

	// Determine which engines to use
	enginesToUse := h.getEnginesToUse()

	// Run each engine
	if h.parallel {
		// Parallel execution using goroutines
		var wg sync.WaitGroup
		var mu sync.Mutex
		for _, engine := range enginesToUse {
			wg.Add(1)
			go func(eng string) {
				defer wg.Done()
				ips, err := h.runEngine(eng, domain, shodanFaviconHash, hunterFaviconHash, pageTitle)
				if err != nil {
					if h.verbose {
						fmt.Printf("\033[31mError with %s:\033[0m %v\n", eng, err)
					}
					return
				}
				mu.Lock()
				allIPs = append(allIPs, ips...)
				mu.Unlock()
			}(engine)
		}
		wg.Wait()
	} else {
		// Sequential execution
		for _, engine := range enginesToUse {
			ips, err := h.runEngine(engine, domain, shodanFaviconHash, hunterFaviconHash, pageTitle)
			if err != nil {
				if h.verbose {
					fmt.Printf("\033[31mError with %s:\033[0m %v\n", engine, err)
				}
				continue
			}
			allIPs = append(allIPs, ips...)
		}
	}

	// Remove duplicates and validate IPs
	if len(allIPs) > 0 {
		uniqueIPs := h.removeDuplicates(allIPs)
		if h.verbose {
			fmt.Printf("\n\033[92mTotal unique IPs:\033[0m %d\n", len(uniqueIPs))
		}
		return h.validateIPs(domain, allIPs)
	}

	return nil
}

// getEnginesToUse determines which engines to use based on configuration
func (h *OriginIpHunter) getEnginesToUse() []string {
	if len(h.engines) > 0 {
		return h.engines
	}

	// Use all available engines
	availableEngines := []string{}
	if len(h.config.SecurityTrails) > 0 {
		availableEngines = append(availableEngines, "securitytrails")
	}
	if len(h.config.Shodan) > 0 {
		availableEngines = append(availableEngines, "shodan")
	}
	if len(h.config.ViewDNS) > 0 {
		availableEngines = append(availableEngines, "viewdns")
	}
	if len(h.config.Hunter) > 0 {
		availableEngines = append(availableEngines, "hunter")
	}
	if len(h.config.Censys) > 0 {
		availableEngines = append(availableEngines, "censys")
	}
	if len(h.config.Fofa) > 0 {
		availableEngines = append(availableEngines, "fofa")
	}

	return availableEngines
}

// extractShodanFaviconHash extracts favicon hash for Shodan using JSON output
func (h *OriginIpHunter) extractShodanFaviconHash(domain string) (string, error) {
	// Use favinfo with --silent --json flags
	cmd := exec.Command("bash", "-c", fmt.Sprintf("echo \"%s\" | favinfo --silent --json", domain))
	output, err := cmd.Output()
	if err != nil {
		// Try alternative approach with direct favinfo
		cmd = exec.Command("favinfo", "--silent", "--json", domain)
		output, err = cmd.Output()
		if err != nil {
			return "", fmt.Errorf("favinfo command failed: %w", err)
		}
	}

	// Parse JSON output
	var favInfo FavInfoOutput
	if err := json.Unmarshal(output, &favInfo); err != nil {
		return "", fmt.Errorf("failed to parse favinfo JSON: %w", err)
	}

	// Extract murmur_hash and convert to string
	if favInfo.MurmurHash == 0 {
		return "", fmt.Errorf("no Shodan favicon hash (murmur_hash) found in output")
	}

	return fmt.Sprintf("%d", favInfo.MurmurHash), nil
}

// extractHunterFaviconHash extracts favicon hash for Hunter using JSON output
func (h *OriginIpHunter) extractHunterFaviconHash(domain string) (string, error) {
	// Use favinfo with --silent --json flags
	cmd := exec.Command("bash", "-c", fmt.Sprintf("echo \"%s\" | favinfo --silent --json", domain))
	output, err := cmd.Output()
	if err != nil {
		// Try alternative approach with direct favinfo
		cmd = exec.Command("favinfo", "--silent", "--json", domain)
		output, err = cmd.Output()
		if err != nil {
			return "", fmt.Errorf("favinfo command failed: %w", err)
		}
	}

	// Parse JSON output
	var favInfo FavInfoOutput
	if err := json.Unmarshal(output, &favInfo); err != nil {
		return "", fmt.Errorf("failed to parse favinfo JSON: %w", err)
	}

	// Extract md5_hash (Hunter.how uses MD5 format, not MurmurHash)
	if favInfo.MD5Hash == "" {
		return "", fmt.Errorf("no Hunter favicon hash (md5_hash) found in output")
	}

	return favInfo.MD5Hash, nil
}

// extractPageTitle extracts page title using Go HTTP client
func (h *OriginIpHunter) extractPageTitle(domain string) (string, error) {
	// Try both https and http (prefer https first)
	protocols := []string{"https", "http"}
	for _, protocol := range protocols {
		url := fmt.Sprintf("%s://%s", protocol, domain)
		result, err := h.scanSingleDomain(url)
		if err != nil {
			continue // Try next protocol
		}
		if result.Title != "" {
			return result.Title, nil
		}
	}
	return "", fmt.Errorf("could not extract page title")
}

// scanDomainWithHttpx scans the input domain to show current status
func (h *OriginIpHunter) scanDomainWithHttpx(domain string) {
	// Try both https and http (prefer https first)
	protocols := []string{"https", "http"}
	for _, protocol := range protocols {
		url := fmt.Sprintf("%s://%s", protocol, domain)
		result, err := h.scanSingleDomain(url)
		if err != nil {
			continue // Try next protocol
		}
		// Store the origin result for later comparison
		h.originResult = result
		// Print the scan result in httpx-like format with colors (unless JSON mode)
		if !h.jsonOutput {
			h.printColoredResult(result)
		}
		break // Exit after first successful scan
	}
}

// runEngine runs a specific search engine
func (h *OriginIpHunter) runEngine(engine, domain, shodanFaviconHash, hunterFaviconHash, pageTitle string) ([]string, error) {
	switch engine {
	case "securitytrails":
		return h.querySecurityTrails(domain)
	case "shodan":
		return h.queryShodan(domain, shodanFaviconHash, pageTitle)
	case "viewdns":
		return h.queryViewDNS(domain)
	case "hunter":
		return h.queryHunter(domain, hunterFaviconHash, pageTitle)
	case "censys":
		return h.queryCensys(domain)
	case "fofa":
		return h.queryFofa(domain)
	default:
		return nil, fmt.Errorf("unknown engine: %s", engine)
	}
}

// querySecurityTrails queries SecurityTrails API
func (h *OriginIpHunter) querySecurityTrails(domain string) ([]string, error) {
	if len(h.config.SecurityTrails) == 0 {
		return nil, fmt.Errorf("no SecurityTrails API keys configured")
	}

	// Select random API key
	apiKey := h.getRandomAPIKey(h.config.SecurityTrails)

	url := fmt.Sprintf("https://api.securitytrails.com/v1/history/%s/dns/a", domain)
	if h.verbose {
		fmt.Printf("\n\033[92mSearching SecurityTrails:\033[0m https://api.securitytrails.com/v1/history/%s/dns/a\n", domain)
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("apikey", apiKey)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Parse JSON response (simplified - in real implementation, use proper JSON parsing)
	ips := h.extractIPsFromJSON(string(body))

	if h.verbose {
		fmt.Printf("\033[92mSecurityTrails found %d IPs\033[0m\n", len(ips))
	}
	return ips, nil
}

// queryShodan queries Shodan API
func (h *OriginIpHunter) queryShodan(domain, faviconHash, pageTitle string) ([]string, error) {
	if len(h.config.Shodan) == 0 {
		return nil, fmt.Errorf("no Shodan API keys configured")
	}

	// Select random API key
	apiKey := h.getRandomAPIKey(h.config.Shodan)
	var allIPs []string

	// Run favicon hash search if available
	if faviconHash != "" {
		urlStr := fmt.Sprintf("https://api.shodan.io/shodan/host/search?key=%s&query=http.favicon.hash:\"%s\"", apiKey, faviconHash)
		if h.verbose {
			fmt.Printf("\n\033[92mSearching Shodan favicon:\033[0m https://api.shodan.io/shodan/host/search?key=YOUR_APIKEY&query=http.favicon.hash:\"%s\"\n", faviconHash)
		}

		resp, err := http.Get(urlStr)
		if err == nil {
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err == nil {
				ips := h.extractIPsFromShodanJSON(string(body))
				allIPs = append(allIPs, ips...)
				if h.verbose {
					fmt.Printf("\033[92mShodan favicon search found %d IPs\033[0m\n", len(ips))
				}
			}
		}
	}

	// Run title search if available
	if pageTitle != "" {
		// URL encode the query parameter
		query := fmt.Sprintf("http.title:\"%s\"", pageTitle)
		encodedQuery := url.QueryEscape(query)
		urlStr := fmt.Sprintf("https://api.shodan.io/shodan/host/search?key=%s&query=%s", apiKey, encodedQuery)
		if h.verbose {
			fmt.Printf("\033[92mSearching Shodan title:\033[0m https://api.shodan.io/shodan/host/search?key=YOUR_APIKEY&query=http.title:\"%s\"\n", pageTitle)
		}

		resp, err := http.Get(urlStr)
		if err == nil {
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err == nil {
				ips := h.extractIPsFromShodanJSON(string(body))
				allIPs = append(allIPs, ips...)
				if h.verbose {
					fmt.Printf("\033[92mShodan title search found %d IPs\033[0m\n", len(ips))
				}
			}
		}
	}

	// Always run SSL certificate search
	urlStr := fmt.Sprintf("https://api.shodan.io/shodan/host/search?key=%s&query=ssl:\"%s\"", apiKey, domain)
	if h.verbose {
		fmt.Printf("\033[92mSearching Shodan SSL:\033[0m https://api.shodan.io/shodan/host/search?key=YOUR_APIKEY&query=ssl:\"%s\"\n", domain)
	}

	resp, err := http.Get(urlStr)
	if err != nil {
		return allIPs, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return allIPs, err
	}

	// Parse JSON response (simplified)
	ips := h.extractIPsFromShodanJSON(string(body))
	allIPs = append(allIPs, ips...)
	if h.verbose {
		fmt.Printf("\033[92mShodan SSL search found %d IPs\033[0m\n", len(ips))
	}

	// Remove duplicates
	uniqueIPs := h.removeDuplicates(allIPs)
	if h.verbose {
		fmt.Printf("\033[92mShodan total unique IPs: %d\033[0m\n", len(uniqueIPs))
	}
	return uniqueIPs, nil
}

// queryViewDNS queries ViewDNS API
func (h *OriginIpHunter) queryViewDNS(domain string) ([]string, error) {
	if len(h.config.ViewDNS) == 0 {
		return nil, fmt.Errorf("no ViewDNS API keys configured")
	}

	// Select random API key
	apiKey := h.getRandomAPIKey(h.config.ViewDNS)

	url := fmt.Sprintf("https://api.viewdns.info/iphistory/?domain=%s&apikey=%s&output=json", domain, apiKey)
	if h.verbose {
		fmt.Printf("\n\033[92mSearching ViewDNS:\033[0m https://api.viewdns.info/iphistory/?domain=%s&apikey=YOUR_APIKEY&output=json\n", domain)
	}

	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Parse JSON response (simplified)
	ips := h.extractIPsFromJSON(string(body))

	if h.verbose {
		fmt.Printf("\033[92mViewDNS found %d IPs\033[0m\n", len(ips))
	}
	return ips, nil
}

// queryHunter queries Hunter API
func (h *OriginIpHunter) queryHunter(domain, faviconHash, pageTitle string) ([]string, error) {
	if len(h.config.Hunter) == 0 {
		return nil, fmt.Errorf("no Hunter API keys configured")
	}

	// Select random API key
	apiKey := h.getRandomAPIKey(h.config.Hunter)
	var allIPs []string

	// Calculate date range (last 31 days)
	endTime := time.Now().Format("2006-01-02")
	startTime := time.Now().AddDate(0, 0, -31).Format("2006-01-02")

	// Run favicon hash search if available
	if faviconHash != "" {
		hunterQuery := fmt.Sprintf("favicon_hash==\"%s\"", faviconHash)
		if h.verbose {
			fmt.Printf("\n\033[96mFor Browser - Hunter favicon:\033[0m %s\n", hunterQuery)
			fmt.Printf("\033[92mSearching Hunter favicon:\033[0m https://api.hunter.how/search?api-key=YOUR_APIKEY&query=%s&page=1&page_size=10&start_time=%s&end_time=%s\n",
				base64.StdEncoding.EncodeToString([]byte(hunterQuery)), startTime, endTime)
		}

		hunterQueryBase64 := base64.StdEncoding.EncodeToString([]byte(hunterQuery))
		url := fmt.Sprintf("https://api.hunter.how/search?api-key=%s&query=%s&page=1&page_size=10&start_time=%s&end_time=%s",
			apiKey, hunterQueryBase64, startTime, endTime)

		resp, err := http.Get(url)
		if err == nil {
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err == nil {
				ips := h.extractIPsFromHunterJSON(string(body))
				allIPs = append(allIPs, ips...)
				if h.verbose {
					fmt.Printf("\033[92mHunter favicon search found %d IPs\033[0m\n", len(ips))
				}
			}
		}
	}

	// Run title search if available
	if pageTitle != "" {
		hunterQuery := fmt.Sprintf("web.title=\"%s\"", pageTitle)
		if h.verbose {
			fmt.Printf("\033[96mFor Browser - Hunter title:\033[0m %s\n", hunterQuery)
			fmt.Printf("\033[92mSearching Hunter title:\033[0m https://api.hunter.how/search?api-key=YOUR_APIKEY&query=%s&page=1&page_size=10&start_time=%s&end_time=%s\n",
				base64.StdEncoding.EncodeToString([]byte(hunterQuery)), startTime, endTime)
		}

		hunterQueryBase64 := base64.StdEncoding.EncodeToString([]byte(hunterQuery))
		url := fmt.Sprintf("https://api.hunter.how/search?api-key=%s&query=%s&page=1&page_size=10&start_time=%s&end_time=%s",
			apiKey, hunterQueryBase64, startTime, endTime)

		resp, err := http.Get(url)
		if err == nil {
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err == nil {
				ips := h.extractIPsFromHunterJSON(string(body))
				allIPs = append(allIPs, ips...)
				if h.verbose {
					fmt.Printf("\033[92mHunter title search found %d IPs\033[0m\n", len(ips))
				}
			}
		}
	}

	// Always run certificate search
	hunterQuery := fmt.Sprintf("cert.subject=\"%s\"", domain)
	if h.verbose {
		fmt.Printf("\033[96mFor Browser - Hunter SSL:\033[0m %s\n", hunterQuery)
		fmt.Printf("\033[92mSearching Hunter SSL:\033[0m https://api.hunter.how/search?api-key=YOUR_APIKEY&query=%s&page=1&page_size=10&start_time=%s&end_time=%s\n",
			base64.StdEncoding.EncodeToString([]byte(hunterQuery)), startTime, endTime)
	}

	hunterQueryBase64 := base64.StdEncoding.EncodeToString([]byte(hunterQuery))
	url := fmt.Sprintf("https://api.hunter.how/search?api-key=%s&query=%s&page=1&page_size=10&start_time=%s&end_time=%s",
		apiKey, hunterQueryBase64, startTime, endTime)

	resp, err := http.Get(url)
	if err != nil {
		return allIPs, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return allIPs, err
	}

	// Parse JSON response (simplified)
	ips := h.extractIPsFromHunterJSON(string(body))
	allIPs = append(allIPs, ips...)
	if h.verbose {
		fmt.Printf("\033[92mHunter certificate search found %d IPs\033[0m\n", len(ips))
	}

	// Remove duplicates
	uniqueIPs := h.removeDuplicates(allIPs)
	if h.verbose {
		fmt.Printf("\033[92mHunter total unique IPs: %d\033[0m\n", len(uniqueIPs))
	}
	return uniqueIPs, nil
}

// queryCensys queries Censys API (placeholder)
func (h *OriginIpHunter) queryCensys(domain string) ([]string, error) {
	// Censys implementation would go here
	return nil, fmt.Errorf("Censys not implemented yet")
}

// queryFofa queries FOFA API (placeholder)
func (h *OriginIpHunter) queryFofa(domain string) ([]string, error) {
	// FOFA implementation would go here
	return nil, fmt.Errorf("FOFA not implemented yet")
}

// getRandomAPIKey selects a random API key from the list
func (h *OriginIpHunter) getRandomAPIKey(keys []string) string {
	if len(keys) == 0 {
		return ""
	}
	if len(keys) == 1 {
		return keys[0]
	}

	n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(keys))))
	return keys[n.Int64()]
}

// extractIPsFromJSON extracts IPs from generic JSON response
func (h *OriginIpHunter) extractIPsFromJSON(jsonStr string) []string {
	var ips []string
	lines := strings.Split(jsonStr, "\n")
	for _, line := range lines {
		if strings.Contains(line, "ip") && strings.Contains(line, "\"") {
			parts := strings.Split(line, "\"")
			for _, part := range parts {
				if h.isValidIP(part) {
					ips = append(ips, part)
				}
			}
		}
	}
	return ips
}

// extractIPsFromShodanJSON extracts IPs from Shodan JSON response
func (h *OriginIpHunter) extractIPsFromShodanJSON(jsonStr string) []string {
	var ips []string
	lines := strings.Split(jsonStr, "\n")
	for _, line := range lines {
		if strings.Contains(line, "ip_str") {
			parts := strings.Split(line, "\"")
			for _, part := range parts {
				if h.isValidIP(part) {
					ips = append(ips, part)
				}
			}
		}
	}
	return ips
}

// extractIPsFromHunterJSON extracts IPs from Hunter JSON response
func (h *OriginIpHunter) extractIPsFromHunterJSON(jsonStr string) []string {
	var ips []string
	lines := strings.Split(jsonStr, "\n")
	for _, line := range lines {
		if strings.Contains(line, "ip") && strings.Contains(line, ":") {
			parts := strings.Split(line, "\"")
			for _, part := range parts {
				if h.isValidIP(part) {
					ips = append(ips, part)
				}
			}
		}
	}
	return ips
}

// isValidIP performs basic IPv4 validation
func (h *OriginIpHunter) isValidIP(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if len(part) == 0 || len(part) > 3 {
			return false
		}
		for _, char := range part {
			if char < '0' || char > '9' {
				return false
			}
		}
		if len(part) > 1 && part[0] == '0' {
			return false
		}
	}
	return true
}

// validateIPs validates IPs using Go HTTP client
func (h *OriginIpHunter) validateIPs(domain string, ips []string) error {
	// Remove duplicates
	uniqueIPs := h.removeDuplicates(ips)

	var originIPs, otherIPs []*DomainScanResult
	var mu sync.Mutex

	// Use worker pool pattern for concurrent validation
	jobs := make(chan string, len(uniqueIPs))
	var wg sync.WaitGroup

	// Semaphore channel to limit concurrency
	semaphore := make(chan struct{}, h.concurrent)

	// Start workers
	for i := 0; i < h.concurrent; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				// Acquire semaphore
				semaphore <- struct{}{}

				// Try both https and http (prefer https first)
				protocols := []string{"https", "http"}
				scanned := false
				var result *DomainScanResult
				for _, protocol := range protocols {
					url := fmt.Sprintf("%s://%s", protocol, ip)
					scanResult, err := h.scanSingleDomain(url)
					if err != nil {
						continue // Try next protocol
					}
					result = scanResult
					scanned = true
					break // Exit after first successful scan
				}

				// Process result
				if scanned {
					// Check if this matches the origin
					if h.originResult != nil && h.isOriginMatch(result, h.originResult) {
						mu.Lock()
						originIPs = append(originIPs, result)
						mu.Unlock()
					} else {
						mu.Lock()
						otherIPs = append(otherIPs, result)
						mu.Unlock()
					}
				} else {
					// If both protocols failed, add to other IPs with error info
					failedResult := &DomainScanResult{
						URL:        fmt.Sprintf("http://%s", ip),
						StatusCode: 0,
					}
					mu.Lock()
					otherIPs = append(otherIPs, failedResult)
					mu.Unlock()
				}

				// Release semaphore
				<-semaphore
			}
		}()
	}

	// Send jobs
	for _, ip := range uniqueIPs {
		jobs <- ip
	}
	close(jobs)

	// Wait for all workers to complete
	wg.Wait()

	// Print results
	if h.jsonOutput {
		// JSON output format
		jsonOutput := JSONOutput{
			Domain:       domain,
			OriginDomain: h.originResult,
			OriginIPs:    originIPs,
			OtherIPs:     otherIPs,
		}
		jsonData, err := json.MarshalIndent(jsonOutput, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}
		fmt.Println(string(jsonData))
	} else {
		// Colored text output format
		if len(originIPs) > 0 {
			fmt.Println("\033[92m\nOrigin IPs Found:\033[0m")
			for _, result := range originIPs {
				h.printColoredResult(result)
			}
		}

		if len(otherIPs) > 0 {
			fmt.Println("\033[91m\nOther IPs:\033[0m")
			for _, result := range otherIPs {
				if result.StatusCode == 0 {
					// Print failed results in red
					fmt.Printf("\033[31m%s [Failed]\033[0m\n", result.URL)
				} else {
					h.printColoredResult(result)
				}
			}
		}
	}

	return nil
}

// isOriginMatch checks if a result matches the origin based on content length and title
func (h *OriginIpHunter) isOriginMatch(result, origin *DomainScanResult) bool {
	// Base requirement: title must match
	if result.Title == "" || result.Title != origin.Title {
		return false
	}

	// If content length matching is enabled, check for exact match
	if h.matchContentLength {
		if result.ContentLength != origin.ContentLength {
			return false
		}
	}

	// If status code matching is enabled, check for exact match
	if h.matchStatusCode {
		if result.StatusCode != origin.StatusCode {
			return false
		}
	}

	return true
}

// scanSingleDomain scans a single domain and returns results
func (h *OriginIpHunter) scanSingleDomain(url string) (*DomainScanResult, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", h.userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	contentLength := resp.ContentLength
	if contentLength == -1 {
		contentLength = int64(len(body))
	}

	// Extract title from HTML
	title := h.extractTitleFromHTML(string(body))

	result := &DomainScanResult{
		URL:           url,
		StatusCode:    resp.StatusCode,
		ContentLength: contentLength,
		Title:         title,
	}

	return result, nil
}

// getStatusCodeColor returns ANSI color code based on HTTP status code
func (h *OriginIpHunter) getStatusCodeColor(statusCode int) string {
	switch {
	case statusCode >= 200 && statusCode < 300:
		return "\033[32m" // Green for 2xx
	case statusCode >= 300 && statusCode < 400:
		return "\033[33m" // Yellow for 3xx
	case statusCode >= 400 && statusCode < 500:
		return "\033[31m" // Red for 4xx
	case statusCode >= 500:
		return "\033[31m" // Red for 5xx
	default:
		return "\033[0m" // Default/white
	}
}

// getProtocolColor returns ANSI color code based on protocol
func (h *OriginIpHunter) getProtocolColor(protocol string) string {
	// httpx uses cyan for both http and https
	return "\033[36m" // Cyan for both protocols
}

// printColoredResult prints a scan result with colors
func (h *OriginIpHunter) printColoredResult(result *DomainScanResult) {
	// Print URL without color
	fmt.Printf("%s", result.URL)

	// Print status code with appropriate color
	statusColor := h.getStatusCodeColor(result.StatusCode)
	fmt.Printf(" %s[%d]\033[0m", statusColor, result.StatusCode)

	// Print content length with pink/magenta color
	fmt.Printf(" \033[35m[%d]\033[0m", result.ContentLength)

	// Print title if available with cyan color (like httpx)
	urlColor := h.getProtocolColor("")
	if result.Title != "" {
		fmt.Printf(" %s[%s]\033[0m", urlColor, result.Title)
	}
	fmt.Println()
}

// extractTitleFromHTML extracts the page title from HTML content
func (h *OriginIpHunter) extractTitleFromHTML(html string) string {
	// Match <title> tag content
	titleRegex := regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`)
	matches := titleRegex.FindStringSubmatch(html)
	if len(matches) > 1 {
		title := strings.TrimSpace(matches[1])
		return title
	}
	return ""
}

// removeDuplicates removes duplicate strings from a slice
func (h *OriginIpHunter) removeDuplicates(ips []string) []string {
	keys := make(map[string]bool)
	var result []string

	for _, ip := range ips {
		if !keys[ip] {
			keys[ip] = true
			result = append(result, ip)
		}
	}

	return result
}
