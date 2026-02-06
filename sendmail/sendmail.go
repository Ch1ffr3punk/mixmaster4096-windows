package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/smtp"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/proxy"
	"github.com/awnumar/memguard"
)

// Config structure for configuration file
type Config struct {
	Sources       []string      // URLs of statistics files to download
	SMTPRelay     string        // SMTP server hostname
	SMTPPort      string        // SMTP server port
	ProxyPort     string        // SOCKS5 proxy port
	StatsInterval time.Duration // Interval for statistics downloads (e.g., 6h, 1d)
}

// EmailData contains email in secure buffer
type EmailData struct {
	Buffer *memguard.LockedBuffer // Secure buffer for email content
	Size   int                    // Size of email in bytes
}

// Global variables for proxy
var (
	proxyDialer proxy.Dialer // SOCKS5 proxy dialer for all connections
	proxyServer string       // Proxy server address (host:port)
)

func main() {
	// sendmail compatible flags
	tFlag := flag.Bool("t", false, "Read recipients from To: header")
	fFlag := flag.String("f", "", "Set envelope sender")
	vFlag := flag.Bool("v", false, "Verbose mode")
	helpFlag := flag.Bool("?", false, "Show help")

	// Custom flags
	smtpHost := flag.String("smtp", "", "SMTP server:port (overrides config)")
	proxyAddr := flag.String("proxy", "127.0.0.1:9050", "SOCKS5 proxy address")
	configFile := flag.String("config", "sendmail.cfg", "Configuration file")
	noStats := flag.Bool("nostats", false, "Skip downloading statistics")

	flag.Parse()

	if *helpFlag {
		printHelp()
		os.Exit(0)
	}

	if *vFlag {
		fmt.Fprintf(os.Stderr, "sendmail: Starting with config file: %s\n", *configFile)
	}

	// 1. Load configuration from file
	config, err := loadConfig(*configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sendmail: Error loading config: %v\n", err)
		os.Exit(1)
	}

	if *vFlag {
		fmt.Fprintf(os.Stderr, "sendmail: Loaded configuration\n")
		if len(config.Sources) > 0 {
			fmt.Fprintf(os.Stderr, "sendmail: Found %d sources\n", len(config.Sources))
		}
		if config.StatsInterval > 0 {
			fmt.Fprintf(os.Stderr, "sendmail: Stats download interval: %v\n", config.StatsInterval)
		}
	}

	// 2. Determine proxy address (command line overrides config)
	proxyServer = *proxyAddr
	if config.ProxyPort != "" {
		// Validate port number
		if port, err := strconv.Atoi(config.ProxyPort); err == nil && port > 0 && port <= 65535 {
			proxyServer = "127.0.0.1:" + config.ProxyPort
		}
	}

	// Create SOCKS5 dialer for ALL network connections
	var errDialer error
	proxyDialer, errDialer = proxy.SOCKS5("tcp", proxyServer, nil, proxy.Direct)
	if errDialer != nil {
		fmt.Fprintf(os.Stderr, "sendmail: Error creating proxy dialer: %v\n", errDialer)
		os.Exit(1)
	}

	if *vFlag {
		fmt.Fprintf(os.Stderr, "sendmail: Using proxy %s for ALL connections\n", proxyServer)
	}

	// 3. Download statistics files via proxy (if not disabled)
	if !*noStats {
		if *vFlag {
			fmt.Fprintf(os.Stderr, "sendmail: Downloading statistics files via proxy...\n")
		}
		successCount := downloadStatisticsViaProxy(config.Sources, config.StatsInterval, *vFlag)
		if successCount == 0 && len(config.Sources) > 0 {
			fmt.Fprintf(os.Stderr, "sendmail: Warning: No statistics files downloaded (may be due to interval)\n")
		} else if *vFlag {
			fmt.Fprintf(os.Stderr, "sendmail: Downloaded %d/%d files via proxy\n", successCount, len(config.Sources))
		}
	} else if *vFlag {
		fmt.Fprintf(os.Stderr, "sendmail: Skipping statistics download\n")
	}

	// 4. Read email from stdin into MemGuard buffer
	if *vFlag {
		fmt.Fprintf(os.Stderr, "sendmail: Reading email from stdin...\n")
	}

	// Check if stdin has data
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) != 0 {
		fmt.Fprintln(os.Stderr, "sendmail: Error: No data piped to stdin")
		fmt.Fprintln(os.Stderr, "sendmail: Usage: cat email.txt | sendmail recipient@example.com")
		os.Exit(1)
	}

	emailData, err := readEmailIntoBuffer(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sendmail: Error reading email: %v\n", err)
		os.Exit(1)
	}

	if *vFlag {
		fmt.Fprintf(os.Stderr, "sendmail: Email loaded into secure buffer (%d bytes)\n", emailData.Size)
	}
	defer emailData.Buffer.Destroy()

	// 5. Determine SMTP server (command line overrides config)
	smtpServer := *smtpHost
	if smtpServer == "" {
		if config.SMTPRelay != "" && config.SMTPPort != "" {
			smtpServer = config.SMTPRelay + ":" + config.SMTPPort
		} else {
			smtpServer = "mailrelay.archiade.net:2525" // Default fallback
		}
	}

	if *vFlag {
		fmt.Fprintf(os.Stderr, "sendmail: SMTP server %s\n", smtpServer)
	}

	// 6. Read email from buffer
	message := emailData.Buffer.Bytes()

	// Determine recipients
	var recipients []string
	if *tFlag {
		recipients = parseToHeader(message)
		if *vFlag && len(recipients) > 0 {
			fmt.Fprintf(os.Stderr, "sendmail: Parsed To: recipients: %v\n", recipients)
		}
	} else {
		recipients = flag.Args()
	}

	if len(recipients) == 0 {
		fmt.Fprintln(os.Stderr, "sendmail: No recipients specified")
		os.Exit(1)
	}

	// Determine sender
	sender := ""
	if *fFlag != "" {
		sender = *fFlag
	} else {
		sender = extractFromHeader(message)
		if sender == "" {
			sender = "anonymous@localhost"
		}
	}

	if *vFlag {
		fmt.Fprintf(os.Stderr, "sendmail: Sender: %s\n", sender)
		fmt.Fprintf(os.Stderr, "sendmail: Recipients: %v\n", recipients)
	}

	// Send via SMTP with timeout
	done := make(chan error, 1)
	go func() {
		done <- sendEmailViaProxy(smtpServer, sender, recipients, message, *vFlag)
	}()

	// Timeout after 120 seconds
	select {
	case err := <-done:
		if err != nil {
			fmt.Fprintf(os.Stderr, "sendmail: Error: %v\n", err)
			os.Exit(1)
		}
	case <-time.After(120 * time.Second):
		fmt.Fprintln(os.Stderr, "sendmail: Error: Timeout after 120 seconds")
		os.Exit(1)
	}

	if *vFlag {
		fmt.Fprintln(os.Stderr, "sendmail: Message sent successfully via proxy")
	}
}

// loadConfig loads and parses the configuration file
func loadConfig(filename string) (*Config, error) {
	// Try to read configuration file
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return createDefaultConfig(filename)
		}
		return nil, err
	}

	config := &Config{
		Sources:       []string{},
		StatsInterval: 0, // Default: always download
	}

	lines := strings.Split(string(data), "\n")
	currentSection := ""
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		
		// Section header
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		
		// Remove inline comments
		if idx := strings.Index(line, "#"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}
		if idx := strings.Index(line, ";"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}
		
		// Parse line based on current section
		switch currentSection {
		case "Sources":
			// Extract URL - handle both "key = value" and direct URL formats
			var url string
			if idx := strings.Index(line, "="); idx != -1 {
				// Format: "file1 = https://..."
				url = strings.TrimSpace(line[idx+1:])
			} else {
				// Format: direct URL
				url = strings.TrimSpace(line)
			}
			
			if url != "" {
				// Ensure URL has protocol
				if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
					url = "https://" + url
				}
				config.Sources = append(config.Sources, url)
			}
			
		case "SMTPRelay":
			var value string
			if idx := strings.Index(line, "="); idx != -1 {
				value = strings.TrimSpace(line[idx+1:])
			} else {
				value = strings.TrimSpace(line)
			}
			if value != "" {
				config.SMTPRelay = value
			}
			
		case "SMTPPort":
			var value string
			if idx := strings.Index(line, "="); idx != -1 {
				value = strings.TrimSpace(line[idx+1:])
			} else {
				value = strings.TrimSpace(line)
			}
			if value != "" {
				// Validate it's a proper port number
				if _, err := strconv.Atoi(value); err == nil {
					config.SMTPPort = value
				}
			}
			
		case "ProxyPort":
			var value string
			if idx := strings.Index(line, "="); idx != -1 {
				value = strings.TrimSpace(line[idx+1:])
			} else {
				value = strings.TrimSpace(line)
			}
			if value != "" {
				// Validate it's a proper port number
				if _, err := strconv.Atoi(value); err == nil {
					config.ProxyPort = value
				}
			}
			
		case "Stats Lifecycle":
			var value string
			if idx := strings.Index(line, "="); idx != -1 {
				value = strings.TrimSpace(line[idx+1:])
			} else {
				value = strings.TrimSpace(line)
			}
			if value != "" {
				// Parse interval like "6h", "30m", "1d"
				duration, err := parseDuration(value)
				if err == nil {
					config.StatsInterval = duration
				}
			}
		}
	}

	return config, nil
}

// createDefaultConfig creates a default configuration file
func createDefaultConfig(filename string) (*Config, error) {
	configContent := `# sendmail.cfg - Configuration file
# Simple format - just URLs and values

[Sources]
https://archiade.net/echolot/mlist.txt
https://archiade.net/echolot/rlist.txt
https://archiade.net/echolot/pubring.mix
https://archiade.net/echolot/pgp-all.asc

[SMTPRelay]
mailrelay.archiade.net

[SMTPPort]
2525

[ProxyPort]
9050

[Stats Lifecycle]
# Interval for statistics downloads (examples: 6h, 30m, 1d, 0=always)
# 0 = always download, 6h = every 6 hours, 1d = every day
# Format: Go duration format + 'd' for days, 'w' for weeks
Interval = 6h`

	if err := ioutil.WriteFile(filename, []byte(configContent), 0644); err != nil {
		return nil, err
	}

	fmt.Fprintf(os.Stderr, "sendmail: Created default config file: %s\n", filename)

	return &Config{
		Sources: []string{
			"https://archiade.net/echolot/mlist.txt",
			"https://archiade.net/echolot/rlist.txt",
			"https://archiade.net/echolot/pubring.mix",
			"https://archiade.net/echolot/pgp-all.asc",
		},
		SMTPRelay:     "mailrelay.archiade.net",
		SMTPPort:      "2525",
		ProxyPort:     "9050",
		StatsInterval: 6 * time.Hour, // Default: 6 hours
	}, nil
}

// parseDuration parses duration strings like "6h", "30m", "1d", "1w"
func parseDuration(s string) (time.Duration, error) {
	// Try standard Go duration parsing first
	if duration, err := time.ParseDuration(s); err == nil {
		return duration, nil
	}
	
	// Custom parsing for days and weeks
	s = strings.ToLower(strings.TrimSpace(s))
	
	// Parse days (e.g., "1d", "2d")
	if strings.HasSuffix(s, "d") {
		daysStr := strings.TrimSuffix(s, "d")
		days, err := strconv.Atoi(daysStr)
		if err != nil {
			return 0, fmt.Errorf("invalid days: %v", err)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	
	// Parse weeks (e.g., "1w", "2w")
	if strings.HasSuffix(s, "w") {
		weeksStr := strings.TrimSuffix(s, "w")
		weeks, err := strconv.Atoi(weeksStr)
		if err != nil {
			return 0, fmt.Errorf("invalid weeks: %v", err)
		}
		return time.Duration(weeks) * 7 * 24 * time.Hour, nil
	}
	
	return 0, fmt.Errorf("invalid duration format: %s", s)
}

// createHTTPClientWithProxy creates an HTTP client that uses the SOCKS5 proxy
func createHTTPClientWithProxy() *http.Client {
	// Create transport that uses our proxy dialer
	transport := &http.Transport{
		Dial:                proxyDialer.Dial,
		DialTLS:             nil, // Will be handled by Dial
		TLSHandshakeTimeout: 10 * time.Second,
		IdleConnTimeout:     30 * time.Second,
		MaxIdleConns:        10,
		Proxy: func(req *http.Request) (*url.URL, error) {
			// Return nil to use direct connection (via our dialer)
			return nil, nil
		},
	}

	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}
}

// shouldDownloadFile checks if a file needs to be downloaded based on its age and interval
func shouldDownloadFile(filename string, interval time.Duration) bool {
	// If interval is 0 or negative, always download
	if interval <= 0 {
		return true
	}
	
	// Get file information
	fileInfo, err := os.Stat(filename)
	if os.IsNotExist(err) {
		// File doesn't exist, need to download
		return true
	}
	if err != nil {
		// Other error, download to be safe
		return true
	}
	
	// Calculate time since last modification
	modTime := fileInfo.ModTime()
	timeSinceMod := time.Since(modTime)
	
	// Download if file is older than the interval
	return timeSinceMod >= interval
}

// downloadStatisticsViaProxy downloads statistics files via proxy and returns success count
func downloadStatisticsViaProxy(sources []string, interval time.Duration, verbose bool) int {
	successCount := 0
	
	// Create HTTP client that uses proxy
	client := createHTTPClientWithProxy()
	
	for _, url := range sources {
		if url == "" {
			continue
		}

		filename := extractFilename(url)
		
		// Check if file needs to be downloaded based on interval
		if !shouldDownloadFile(filename, interval) {
			if verbose {
				// Get file info for debug output
				if fileInfo, err := os.Stat(filename); err == nil {
					age := time.Since(fileInfo.ModTime())
					fmt.Fprintf(os.Stderr, "sendmail: Skipping %s (downloaded %v ago, interval: %v)\n", 
						filename, age.Round(time.Minute), interval)
				} else {
					fmt.Fprintf(os.Stderr, "sendmail: Skipping %s (not expired)\n", filename)
				}
			}
			continue
		}

		if verbose {
			fmt.Fprintf(os.Stderr, "sendmail: Downloading %s from %s via proxy...", filename, url)
		}

		resp, err := client.Get(url)
		if err != nil {
			if verbose {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
			}
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			if verbose {
				fmt.Fprintf(os.Stderr, "error: HTTP %d\n", resp.StatusCode)
			}
			continue
		}

		data, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			if verbose {
				fmt.Fprintf(os.Stderr, "error reading: %v\n", err)
			}
			continue
		}

		if err := ioutil.WriteFile(filename, data, 0644); err != nil {
			if verbose {
				fmt.Fprintf(os.Stderr, "error writing: %v\n", err)
			}
			continue
		}

		successCount++
		if verbose {
			// Get file info after writing
			if fileInfo, err := os.Stat(filename); err == nil {
				fmt.Fprintf(os.Stderr, "done (%d bytes, modified: %s)\n", 
					len(data), fileInfo.ModTime().Format("2006-01-02 15:04:05"))
			} else {
				fmt.Fprintf(os.Stderr, "done (%d bytes)\n", len(data))
			}
		}

		// Short pause between downloads to be nice to the server
		time.Sleep(200 * time.Millisecond)
	}
	return successCount
}

// extractFilename extracts filename from URL
func extractFilename(url string) string {
	// Remove protocol prefix
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "https://")
	
	// Get last part after /
	parts := strings.Split(url, "/")
	if len(parts) > 0 {
		filename := parts[len(parts)-1]
		// If filename is empty or suspiciously long, use a default
		if filename == "" || len(filename) > 100 {
			return "download.txt"
		}
		return filename
	}
	return "download.txt"
}

// readEmailIntoBuffer reads email into MemGuard secure buffer
func readEmailIntoBuffer(r io.Reader) (*EmailData, error) {
	data, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("no data read")
	}

	// Check size (approximately 30 KB)
	if len(data) > 35*1024 {
		fmt.Fprintf(os.Stderr, "sendmail: Warning: Email larger than expected (%d bytes)\n", len(data))
	}

	// Create secure buffer
	buffer := memguard.NewBuffer(len(data))
	copy(buffer.Bytes(), data)

	return &EmailData{
		Buffer: buffer,
		Size:   len(data),
	}, nil
}

// sendEmailViaProxy sends email via SMTP through proxy
func sendEmailViaProxy(smtpAddr, from string, to []string, message []byte, verbose bool) error {
	// Extract host and port from SMTP address
	host := smtpAddr
	port := "2525"
	if strings.Contains(smtpAddr, ":") {
		parts := strings.SplitN(smtpAddr, ":", 2)
		if len(parts) == 2 {
			host = parts[0]
			port = parts[1]
		}
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "sendmail: Connecting to %s:%s via proxy...\n", host, port)
	}

	// Connect via proxy (using the global proxyDialer)
	conn, err := proxyDialer.Dial("tcp", host+":"+port)
	if err != nil {
		return fmt.Errorf("proxy connection failed: %v", err)
	}
	defer conn.Close()

	// Create SMTP client
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return fmt.Errorf("SMTP client failed: %v", err)
	}

	// Send QUIT when done
	defer func() {
		client.Quit()
		if verbose {
			fmt.Fprintf(os.Stderr, "sendmail: Connection closed\n")
		}
	}()

	if verbose {
		fmt.Fprintln(os.Stderr, "sendmail: Connected")
	}

	// Try STARTTLS for non-port 25 connections
	if port != "25" {
		if verbose {
			fmt.Fprintln(os.Stderr, "sendmail: Attempting STARTTLS...")
		}

		tlsConfig := &tls.Config{
			InsecureSkipVerify: true, // Allow self-signed certificates
			ServerName:         host,
		}

		if err := client.StartTLS(tlsConfig); err != nil {
			if verbose {
				fmt.Fprintf(os.Stderr, "sendmail: STARTTLS failed: %v\n", err)
			}
			// Continue without TLS
		} else if verbose {
			fmt.Fprintln(os.Stderr, "sendmail: TLS established")
		}
	}

	// Set sender
	if verbose {
		fmt.Fprintf(os.Stderr, "sendmail: MAIL FROM: %s\n", from)
	}
	if err := client.Mail(from); err != nil {
		return fmt.Errorf("MAIL FROM failed: %v", err)
	}

	// Set recipients
	for _, rcpt := range to {
		if verbose {
			fmt.Fprintf(os.Stderr, "sendmail: RCPT TO: %s\n", rcpt)
		}
		if err := client.Rcpt(rcpt); err != nil {
			return fmt.Errorf("RCPT TO failed for %s: %v", rcpt, err)
		}
	}

	// Send message data
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("DATA failed: %v", err)
	}

	if verbose {
		fmt.Fprintln(os.Stderr, "sendmail: Sending message data...")
	}

	if _, err := w.Write(message); err != nil {
		return fmt.Errorf("writing message failed: %v", err)
	}

	if err := w.Close(); err != nil {
		return fmt.Errorf("closing data failed: %v", err)
	}

	if verbose {
		fmt.Fprintln(os.Stderr, "sendmail: Message data sent")
	}

	return nil
}

// parseToHeader extracts recipients from To: header in email
func parseToHeader(message []byte) []string {
	lines := strings.Split(string(message), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "to:") {
			return extractEmails(line[3:])
		}
		if line == "" {
			break // End of headers
		}
	}

	return []string{}
}

// extractEmails extracts email addresses from header string
func extractEmails(header string) []string {
	var emails []string
	remaining := header

	for {
		start := strings.Index(remaining, "<")
		if start == -1 {
			trimmed := strings.TrimSpace(remaining)
			if strings.Contains(trimmed, "@") && len(trimmed) > 3 {
				emails = append(emails, trimmed)
			}
			break
		}

		end := strings.Index(remaining[start:], ">")
		if end == -1 {
			break
		}

		email := remaining[start+1 : start+end]
		if strings.Contains(email, "@") {
			emails = append(emails, strings.TrimSpace(email))
		}

		remaining = remaining[start+end+1:]
	}

	return emails
}

// extractFromHeader extracts sender from From: header in email
func extractFromHeader(message []byte) string {
	lines := strings.Split(string(message), "\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "from:") {
			emails := extractEmails(line[5:])
			if len(emails) > 0 {
				return emails[0]
			}
			return strings.TrimSpace(line[5:])
		}
	}
	return ""
}

// printHelp displays usage information
func printHelp() {
	fmt.Println(`sendmail - sendmail replacement with secure email handling and Tor support

Usage: sendmail [options] [recipients...]

Email must be provided via stdin:
  cat email.txt | sendmail recipient@example.com
  sendmail recipient@example.com < email.txt

Options (sendmail compatible):
  -t            Read recipients from To: header
  -f <addr>     Set envelope sender address
  -v            Verbose output
  -?            Show this help

Configuration options:
  -config file  Configuration file (default: sendmail.cfg)
  -nostats      Skip downloading statistics files

Proxy/SMTP options:
  -smtp host:port  SMTP server (overrides config)
  -proxy addr:port SOCKS5 proxy (default: 127.0.0.1:9050)

Example sendmail.cfg:
  [Sources]
  https://archiade.net/echolot/mlist.txt
  https://archiade.net/echolot/rlist.txt
  https://archiade.net/echolot/pubring.mix
  https://archiade.net/echolot/pgp-all.asc
  
  [SMTPRelay]
  mailrelay.archiade.net
  
  [SMTPPort]
  2525
  
  [ProxyPort]
  9050
  
  [Stats Lifecycle]
  # Interval for statistics downloads
  # 0 = always download, 6h = every 6 hours, 1d = every day
  Interval = 6h

Features:
  - ALL connections go through SOCKS5 proxy (Tor compatible)
  - Secure email storage in memory
  - Intelligent statistics file downloads (checks file timestamps)
  - Configurable download intervals via [Stats Lifecycle] section
  - SMTP via proxy
  - STARTTLS support
  - sendmail command line compatible
  
Statistics Download Behavior:
  - First run: Always downloads all statistics files
  - Subsequent runs: Checks file modification time
  - Only downloads if file is older than configured interval
  - Files are saved locally and reused within the interval`)
}
