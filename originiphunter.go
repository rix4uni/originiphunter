package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
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

// OriginHunter represents the main hunting instance
type OriginHunter struct {
	config       *Config
	engines      []string
	configPath   string
	originResult *DomainScanResult // Store the original domain scan result
	verbose      bool              // Show verbose output
	userAgent    string            // HTTP User-Agent header
}

func main() {
	var (
		engines    = pflag.StringSlice("engine", []string{}, "Specific search engines to use (comma-separated). Available: shodan,securitytrails,viewdns,hunter,censys,fofa")
		configPath = pflag.String("config", "", "Custom config file path (default: ~/.config/originhunter/config.yaml)")
		silent     = pflag.Bool("silent", false, "Silent mode.")
		version    = pflag.Bool("version", false, "Print the version of the tool and exit.")
		verbose    = pflag.Bool("verbose", false, "Show detailed information about the scanning process")
		userAgent  = pflag.StringP("useragent", "H", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36", "HTTP User-Agent header")
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
		*configPath = filepath.Join(homeDir, ".config", "originhunter", "config.yaml")
	}

	// Load configuration
	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Create OriginHunter instance
	hunter := &OriginHunter{
		config:     cfg,
		engines:    *engines,
		configPath: *configPath,
		verbose:    *verbose,
		userAgent:  *userAgent,
	}

	// Process input
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain == "" {
			continue
		}

		fmt.Printf("Processing: %s\n", domain)

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
func (h *OriginHunter) HuntOrigin(domain string) error {
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

	// Remove duplicates and validate IPs
	if len(allIPs) > 0 {
		uniqueIPs := h.removeDuplicates(allIPs)
		if h.verbose {
			fmt.Printf("\n\033[92mTotal unique IPs:\033[0m %d\n", len(uniqueIPs))
		}
		return h.validateIPs(allIPs)
	}

	return nil
}

// getEnginesToUse determines which engines to use based on configuration
func (h *OriginHunter) getEnginesToUse() []string {
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

// extractShodanFaviconHash extracts favicon hash for Shodan (occurrence 2)
func (h *OriginHunter) extractShodanFaviconHash(domain string) (string, error) {
	// Use bash command: echo "domain" | favinfo --silent | awk '{print $2}' | tr -d '[]'
	cmd := exec.Command("bash", "-c", fmt.Sprintf("echo \"%s\" | favinfo --silent | awk '{print $2}' | tr -d '[]'", domain))
	output, err := cmd.Output()
	if err != nil {
		// Try alternative approach with direct favinfo
		cmd = exec.Command("favinfo", "--silent", domain)
		output, err = cmd.Output()
		if err != nil {
			return "", fmt.Errorf("favinfo command failed: %w", err)
		}

		// Parse output manually - look for occurrence 2
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				hash := strings.Trim(fields[1], "[]")
				if hash != "" {
					return hash, nil
				}
			}
		}
		return "", fmt.Errorf("no Shodan favicon hash found in output")
	}

	hash := strings.TrimSpace(string(output))
	if hash == "" {
		return "", fmt.Errorf("no Shodan favicon hash found")
	}

	return hash, nil
}

// extractHunterFaviconHash extracts favicon hash for Hunter (occurrence 3)
func (h *OriginHunter) extractHunterFaviconHash(domain string) (string, error) {
	// Use bash command: echo "domain" | favinfo --silent | awk '{print $3}' | tr -d '[]'
	cmd := exec.Command("bash", "-c", fmt.Sprintf("echo \"%s\" | favinfo --silent | awk '{print $3}' | tr -d '[]'", domain))
	output, err := cmd.Output()
	if err != nil {
		// Try alternative approach with direct favinfo
		cmd = exec.Command("favinfo", "--silent", domain)
		output, err = cmd.Output()
		if err != nil {
			return "", fmt.Errorf("favinfo command failed: %w", err)
		}

		// Parse output manually - look for occurrence 3
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				hash := strings.Trim(fields[2], "[]")
				if hash != "" {
					return hash, nil
				}
			}
		}
		return "", fmt.Errorf("no Hunter favicon hash found in output")
	}

	hash := strings.TrimSpace(string(output))
	if hash == "" {
		return "", fmt.Errorf("no Hunter favicon hash found")
	}

	return hash, nil
}

// extractPageTitle extracts page title using Go HTTP client
func (h *OriginHunter) extractPageTitle(domain string) (string, error) {
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
func (h *OriginHunter) scanDomainWithHttpx(domain string) {
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
		// Print the scan result in httpx-like format with colors
		h.printColoredResult(result)
		break // Exit after first successful scan
	}
}

// runEngine runs a specific search engine
func (h *OriginHunter) runEngine(engine, domain, shodanFaviconHash, hunterFaviconHash, pageTitle string) ([]string, error) {
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
func (h *OriginHunter) querySecurityTrails(domain string) ([]string, error) {
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
func (h *OriginHunter) queryShodan(domain, faviconHash, pageTitle string) ([]string, error) {
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
func (h *OriginHunter) queryViewDNS(domain string) ([]string, error) {
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
func (h *OriginHunter) queryHunter(domain, faviconHash, pageTitle string) ([]string, error) {
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
func (h *OriginHunter) queryCensys(domain string) ([]string, error) {
	// Censys implementation would go here
	return nil, fmt.Errorf("Censys not implemented yet")
}

// queryFofa queries FOFA API (placeholder)
func (h *OriginHunter) queryFofa(domain string) ([]string, error) {
	// FOFA implementation would go here
	return nil, fmt.Errorf("FOFA not implemented yet")
}

// getRandomAPIKey selects a random API key from the list
func (h *OriginHunter) getRandomAPIKey(keys []string) string {
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
func (h *OriginHunter) extractIPsFromJSON(jsonStr string) []string {
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
func (h *OriginHunter) extractIPsFromShodanJSON(jsonStr string) []string {
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
func (h *OriginHunter) extractIPsFromHunterJSON(jsonStr string) []string {
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
func (h *OriginHunter) isValidIP(ip string) bool {
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
func (h *OriginHunter) validateIPs(ips []string) error {
	// Remove duplicates
	uniqueIPs := h.removeDuplicates(ips)

	var originIPs, otherIPs []*DomainScanResult

	// Scan each IP
	for _, ip := range uniqueIPs {
		// Try both https and http (prefer https first)
		protocols := []string{"https", "http"}
		scanned := false
		for _, protocol := range protocols {
			url := fmt.Sprintf("%s://%s", protocol, ip)
			result, err := h.scanSingleDomain(url)
			if err != nil {
				continue // Try next protocol
			}

			// Check if this matches the origin
			if h.originResult != nil && h.isOriginMatch(result, h.originResult) {
				originIPs = append(originIPs, result)
			} else {
				otherIPs = append(otherIPs, result)
			}
			scanned = true
			break // Exit after first successful scan
		}
		if !scanned {
			// If both protocols failed, add to other IPs with error info
			failedResult := &DomainScanResult{
				URL:        fmt.Sprintf("http://%s", ip),
				StatusCode: 0,
			}
			otherIPs = append(otherIPs, failedResult)
		}
	}

	// Print results
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

	return nil
}

// isOriginMatch checks if a result matches the origin based on content length and title
func (h *OriginHunter) isOriginMatch(result, origin *DomainScanResult) bool {
	// Match if title is the same (content length may vary slightly)
	if result.Title != "" && result.Title == origin.Title {
		return true
	}
	return false
}

// scanSingleDomain scans a single domain and returns results
func (h *OriginHunter) scanSingleDomain(url string) (*DomainScanResult, error) {
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
func (h *OriginHunter) getStatusCodeColor(statusCode int) string {
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
func (h *OriginHunter) getProtocolColor(protocol string) string {
	// httpx uses cyan for both http and https
	return "\033[36m" // Cyan for both protocols
}

// printColoredResult prints a scan result with colors
func (h *OriginHunter) printColoredResult(result *DomainScanResult) {
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
func (h *OriginHunter) extractTitleFromHTML(html string) string {
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
func (h *OriginHunter) removeDuplicates(ips []string) []string {
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
