## OriginipHunter

A powerful Go tool for finding origin IPs of domains by querying multiple security APIs and validating results with built-in HTTP client.

## Supported Search Engines
| Engine | Status | Methods |
|--------|--------|---------|
| **Shodan** | ✅ Active | Favicon hash, Title, SSL certificate |
| **Hunter** | ✅ Active | Favicon hash, Title, Certificate |
| **SecurityTrails** | ✅ Active | DNS history |
| **ViewDNS** | ✅ Active | IP history |
| **Censys** | 🚧 Coming Soon | - |
| **FOFA** | 🚧 Coming Soon | - |

## Installation
### Install via Go
```
go install github.com/rix4uni/originiphunter@latest
```

### Download Prebuilt Binaries
```
wget https://github.com/rix4uni/originiphunter/releases/download/v0.0.5/originiphunter-linux-amd64-0.0.5.tgz
tar -xvzf originiphunter-linux-amd64-0.0.5.tgz
rm -rf originiphunter-linux-amd64-0.0.5.tgz
mv originiphunter ~/go/bin/originiphunter
```

Or download the [latest release](https://github.com/rix4uni/originiphunter/releases) for your platform.

### Compile from Source
```
git clone --depth 1 https://github.com/rix4uni/originiphunter.git
cd originiphunter; go install
```

**Note**: You can add multiple `Free` API keys per service for load balancing and rate limit management.
### Get `Free` API Keys
- **SecurityTrails**: https://securitytrails.com/
- **Shodan**: https://www.shodan.io/
- **ViewDNS**: https://viewdns.info/
- **Hunter**: https://hunter.how/

## Configuration
### Default Config Location

The tool uses `~/.config/originiphunter/config.yaml` by default.

### Create Config File

1. Create config directory:
```bash
mkdir -p ~/.config/originiphunter
```

2. Create `config.yaml`:
```yaml
securitytrails:
  - YOUR_SECURITYTRAILS_API_KEY_1
  - YOUR_SECURITYTRAILS_API_KEY_2
shodan:
  - YOUR_SHODAN_API_KEY_1
  - YOUR_SHODAN_API_KEY_2
viewdns:
  - YOUR_VIEWDNS_API_KEY_1
  - YOUR_VIEWDNS_API_KEY_2
hunter:
  - YOUR_HUNTER_API_KEY_1
  - YOUR_HUNTER_API_KEY_2
censys: []
fofa: []
```

## Usage
```yaml
Usage of originiphunter:
      --config string         Custom config file path (default: ~/.config/originiphunter/config.yaml)
      --concurrent int        Number of concurrent IP validations (default: 50)
  -C, --content-length        Match content length in Origin IPs Found section
      --engine strings        Specific search engines to use (comma-separated). Available: shodan,securitytrails,viewdns,hunter,censys,fofa
  -H, --useragent string      HTTP User-Agent header (default: Mozilla/5.0 Chrome/141.0.0.0)
      --json                  Output results in JSON format
  -p, --parallel              Run search engines in parallel for faster execution
      --silent                Silent mode.
  -S, --status-code           Match status code in Origin IPs Found section
      --verbose               Show detailed information about the scanning process
      --version               Print the version of the tool and exit.
```

### Basic Usage
Process a single domain:
```yaml
echo "example.com" | originiphunter
```

Process multiple domains:
```yaml
cat domains.txt | originiphunter
```

### Command Line Options

| Flag | Shorthand | Description |
|------|-----------|-------------|
| `--engine` | - | Specify which search engines to use (comma-separated: shodan,securitytrails,viewdns,hunter,censys,fofa) |
| `--config` | - | Use a custom config file path |
| `--verbose` | - | Show detailed information about the scanning process |
| `--useragent` | `-H` | HTTP User-Agent header (default: Mozilla/5.0 Chrome/141.0.0.0) |
| `--silent` | - | Silent mode (no banner) |
| `--version` | - | Print version and exit |
| `--json` | - | Output results in JSON format |
| `--parallel` | `-p` | Run search engines in parallel for faster execution |
| `--concurrent` | - | Number of concurrent IP validations (default: 50) |
| `--content-length` | `-C` | Match content length in Origin IPs Found section |
| `--status-code` | `-S` | Match status code in Origin IPs Found section |

### Examples

```yaml
# Use all configured engines (default)
echo "example.com" | originiphunter

# Use specific engines only
echo "example.com" | originiphunter --engine shodan,hunter

# Enable verbose mode for detailed output
echo "example.com" | originiphunter --verbose

# Use custom config file
echo "example.com" | originiphunter --config /path/to/config.yaml

# Custom User-Agent
echo "example.com" | originiphunter -H "MyBot/1.0"

# Process multiple domains silently
cat domains.txt | originiphunter --silent

# Output results in JSON format
echo "example.com" | originiphunter --json

# Run search engines in parallel for faster execution
echo "example.com" | originiphunter --parallel

# Adjust concurrent IP validation limit
echo "example.com" | originiphunter --concurrent 100

# Match content length and status code in Origin IPs
echo "example.com" | originiphunter --content-length --status-code

# Combine multiple flags
echo "example.com" | originiphunter --parallel --json --concurrent 100 --silent

# Show version
originiphunter --version
```

## Features

### Performance Optimizations
- **Parallel Engine Execution**: Use `--parallel` flag to run multiple search engines concurrently, significantly speeding up the discovery process
- **Concurrent IP Validation**: By default, validates 50 IPs concurrently. Adjust with `--concurrent` flag to balance speed and resource usage

### Filtering Options
- **Content Length Matching**: Use `--content-length` flag to show only IPs that match the original domain's content length
- **Status Code Matching**: Use `--status-code` flag to show only IPs that match the original domain's status code
- Both flags work together with title matching (all criteria must match when both flags are set)

### Output Formats
- **Colored Text Output**: Default human-readable format with color-coded status codes
- **JSON Output**: Use `--json` flag for structured JSON output, perfect for automation and scripting

## Output
### Example Output

```yaml
                _         _         _         __                   __
  ____   _____ (_)____ _ (_)____   (_)____   / /_   __  __ ____   / /_ ___   _____
 / __ \ / ___// // __  // // __ \ / // __ \ / __ \ / / / // __ \ / __// _ \ / ___/
/ /_/ // /   / // /_/ // // / / // // /_/ // / / // /_/ // / / // /_ /  __// /
\____//_/   /_/ \__, //_//_/ /_//_// .___//_/ /_/ \__,_//_/ /_/ \__/ \___//_/
               /____/             /_/

                     Current originiphunter version v0.0.5

Processing: aiaqa.visa.com
https://aiaqa.visa.com [200] [12746] [Visa - Public Key Infrastructure]

Origin IPs Found:
http://198.241.171.81 [200] [12746] [Visa - Public Key Infrastructure]
http://198.241.169.249 [200] [12746] [Visa - Public Key Infrastructure]

Other IPs:
http://104.18.157.147 [403] [16]
http://104.18.158.147 [403] [16]
http://3.7.198.7 [301] [134] [301 Moved Permanently]
http://31.210.5.60 [Failed]
```

### Verbose Output Example
```yaml
Processing: aiaqa.visa.com
https://aiaqa.visa.com [200] [12746] [Visa - Public Key Infrastructure]
Shodan favicon hash: 708578229
Hunter favicon hash: f3418a443e7d841097c714d69ec4bcb8
Page title: Visa - Public Key Infrastructure

Searching Shodan favicon: https://api.shodan.io/shodan/host/search?key=YOUR_APIKEY&query=http.favicon.hash:"708578229"
Shodan favicon search found 2 IPs
Searching Shodan title: https://api.shodan.io/shodan/host/search?key=YOUR_APIKEY&query=http.title:"Visa - Public Key Infrastructure"
Shodan title search found 4 IPs
Searching Shodan SSL: https://api.shodan.io/shodan/host/search?key=YOUR_APIKEY&query=ssl:"aiaqa.visa.com"
Shodan SSL search found 32 IPs
Shodan total unique IPs: 17

For Browser - Hunter favicon: favicon_hash=="f3418a443e7d841097c714d69ec4bcb8"
Searching Hunter favicon: https://api.hunter.how/search?api-key=YOUR_APIKEY&query=ZmF2aWNvbl9oYXNoPT0iZjM0MThhNDQzZTdkODQxMDk3YzcxNGQ2OWVjNGJjYjgi...
Hunter favicon search found 10 IPs
Hunter total unique IPs: 4

Total unique IPs: 21

Origin IPs Found:
http://198.241.171.81 [200] [12746] [Visa - Public Key Infrastructure]
http://198.241.169.249 [200] [12746] [Visa - Public Key Infrastructure]

Other IPs:
http://104.18.157.147 [403] [16]
...
```

### JSON Output Example
```json
{
  "domain": "example.com",
  "origin_domain": {
    "URL": "https://example.com",
    "StatusCode": 200,
    "ContentLength": 12345,
    "Title": "Example Domain"
  },
  "origin_ips": [
    {
      "URL": "http://1.2.3.4",
      "StatusCode": 200,
      "ContentLength": 12345,
      "Title": "Example Domain"
    }
  ],
  "other_ips": [
    {
      "URL": "http://5.6.7.8",
      "StatusCode": 200,
      "ContentLength": 67890,
      "Title": "Other Site"
    }
  ]
}
```

### Filtering with Content Length and Status Code
```yaml
# Show only IPs matching both content length and status code
echo "example.com" | originiphunter --content-length --status-code

# Show only IPs matching content length (title matching still required)
echo "example.com" | originiphunter --content-length

# Show only IPs matching status code (title matching still required)
echo "example.com" | originiphunter --status-code
```
