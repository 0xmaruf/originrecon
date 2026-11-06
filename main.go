package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
)

type Result struct {
	url        string
	match      bool
	distance   int
	bodyMatch  bool
	matchedStr string
	certCN     string
	certOrg    string
	certIssuer string
	certSANs   []string
}

func getHTTPClient(timeout time.Duration) *http.Client {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   timeout / 2,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   timeout / 2,
		ResponseHeaderTimeout: timeout / 2,
		ExpectContinueTimeout: 1 * time.Second,
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   50,
		IdleConnTimeout:       30 * time.Second,
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func fetchBody(client *http.Client, url string, maxRead int64) (string, *tls.ConnectionState, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()

	limit := maxRead
	if maxRead <= 0 {
		limit = 1 << 20
	}
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return "", nil, err
	}

	var tlsState *tls.ConnectionState
	if resp.TLS != nil {
		tlsState = resp.TLS
	}
	return string(bodyBytes), tlsState, nil
}

func getCertInfo(tlsState *tls.ConnectionState) (string, string, string, []string) {
	if tlsState == nil || len(tlsState.PeerCertificates) == 0 {
		return "", "", "", nil
	}
	cert := tlsState.PeerCertificates[0]
	cn := cert.Subject.CommonName
	org := ""
	if len(cert.Subject.Organization) > 0 {
		org = strings.Join(cert.Subject.Organization, ", ")
	}
	issuer := ""
	if cert.Issuer.CommonName != "" {
		issuer = cert.Issuer.CommonName
	}
	seen := map[string]bool{}
	sans := make([]string, 0, len(cert.DNSNames)+1)
	for _, san := range cert.DNSNames {
		san = strings.TrimSpace(san)
		if san == "" || seen[san] {
			continue
		}
		seen[san] = true
		sans = append(sans, san)
	}
	if cn != "" && !seen[cn] {
		sans = append([]string{cn}, sans...)
	}
	return cn, org, issuer, sans
}

func formatCertInfo(cn, org, issuer string, sans []string) string {
	if cn == "" && org == "" && issuer == "" && len(sans) == 0 {
		return ""
	}
	parts := []string{}
	if cn != "" {
		parts = append(parts, fmt.Sprintf("CN=%s", cn))
	}
	if len(sans) > 0 {
		parts = append(parts, fmt.Sprintf("SAN=%s", strings.Join(sans, ", ")))
	}
	if org != "" {
		parts = append(parts, fmt.Sprintf("O=%s", org))
	}
	if issuer != "" {
		parts = append(parts, fmt.Sprintf("ISSUER=%s", issuer))
	}
	return fmt.Sprintf(" [%s]", strings.Join(parts, " | "))
}

func sanitizeBodyForMatch(body string) string {
	lines := strings.Split(body, "\n")
	filtered := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		lower := strings.ToLower(trimmed)
		if strings.Contains(lower, "insecure request") || strings.Contains(lower, "certificate is invalid") || strings.Contains(lower, "self-signed certificate") || strings.Contains(lower, "tls warning") || strings.Contains(lower, "ssl warning") {
			continue
		}
		filtered = append(filtered, line)
	}
	return strings.Join(filtered, "\n")
}

func checkIP(ip string, ports []string, originalBody string, threshold int, matchRegex *regexp.Regexp, client *http.Client, results chan<- Result, wg *sync.WaitGroup) {
	defer wg.Done()
	schemes := []string{"https", "http"}
	for _, scheme := range schemes {
		for _, port := range ports {
			url := fmt.Sprintf("%s://%s:%s", scheme, ip, port)
			bodyLimit := int64(4096)
			if matchRegex != nil {
				bodyLimit = 1 << 20
			}
			body, tlsState, err := fetchBody(client, url, bodyLimit)
			if err != nil {
				continue
			}

			match := false
			distance := 0
			bodyMatch := false
			matchedStr := ""
			var certCN, certOrg, certIssuer string
			var certSANs []string

			if matchRegex != nil {
				body = sanitizeBodyForMatch(body)
				if matchRegex.MatchString(body) {
					bodyMatch = true
					matchedStr = matchRegex.String()
					match = true
				}
			} else {
				distance = len(body) - len(originalBody)
				if distance < 0 {
					distance = -distance
				}
				if distance <= threshold {
					match = true
				}
				certCN, certOrg, certIssuer, certSANs = getCertInfo(tlsState)
			}

			results <- Result{
				url:        url,
				match:      match,
				distance:   distance,
				bodyMatch:  bodyMatch,
				matchedStr: matchedStr,
				certCN:     certCN,
				certOrg:    certOrg,
				certIssuer: certIssuer,
				certSANs:   certSANs,
			}
		}
	}
}

func main() {
	targetURL := flag.String("h", "", "scheme://host[:port]/url of site, e.g. https://target.com")
	threshold := flag.Int("l", 5, "response-size threshold, higher means more lenient (default 5)")
	ports := flag.String("p", "80,443", "comma separated ports to scan for IP addresses given via stdin")
	threads := flag.Int("t", 128, "number of concurrent probes (default 128)")
	timeout := flag.Duration("timeout", 3*time.Second, "per-request timeout for each IP:port probe")
	matchString := flag.String("mr", "", "optional regex for body match; when set, cert metadata is ignored and only matching results are shown")
	showCert := flag.Bool("cert", false, "show CN/SAN/O/issuer beside matching results")
	debug := flag.Bool("debug", false, "print NOMATCH results for troubleshooting; default output stays quiet")
	flag.Parse()

	if *targetURL == "" {
		fmt.Println("Usage: originrecon -h https://target.com [-l 5] [-p 80,443] [-t 128] [-timeout 3s] [-mr 'regex'] [-cert]")
		os.Exit(1)
	}

	var re *regexp.Regexp
	if *matchString != "" {
		var err error
		re, err = regexp.Compile("(?i)" + *matchString)
		if err != nil {
			fmt.Printf("Error compiling regex %q: %v\n", *matchString, err)
			os.Exit(1)
		}
		fmt.Printf("%s[*] Match regex enabled: \"%s\"%s\n", colorYellow, *matchString, colorReset)
	}

	fmt.Printf("%s[*] Fetching original URL: %s%s\n", colorCyan, *targetURL, colorReset)
	client := getHTTPClient(*timeout)
	originalBody, _, err := fetchBody(client, *targetURL, 1<<20)
	if err != nil {
		fmt.Printf("Error getting original URL: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("%s[*] Got original response (%d bytes)%s\n", colorCyan, len(originalBody), colorReset)
	fmt.Println()

	portList := strings.Split(*ports, ",")
	results := make(chan Result, 100)
	var wg sync.WaitGroup
	sem := make(chan struct{}, *threads)

	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			ip := strings.TrimSpace(scanner.Text())
			if ip == "" {
				continue
			}
			sem <- struct{}{}
			wg.Add(1)
			go func(ip string) {
				defer func() { <-sem }()
				checkIP(ip, portList, originalBody, *threshold, re, client, results, &wg)
			}(ip)
		}
		if err := scanner.Err(); err != nil {
			fmt.Printf("Error reading stdin: %v\n", err)
		}
		wg.Wait()
		close(results)
	}()

	for result := range results {
		if re != nil {
			if !result.bodyMatch {
				if *debug {
					fmt.Printf("NOMATCH %s %d\n", result.url, result.distance)
				}
				continue
			}
			fmt.Printf("MATCH %s\n", result.url)
			continue
		}

		certInfo := ""
		if *showCert || re == nil {
			certInfo = formatCertInfo(result.certCN, result.certOrg, result.certIssuer, result.certSANs)
		}
		if certInfo == "" {
			fmt.Printf("%s %d\n", result.url, result.distance)
			continue
		}
		fmt.Printf("MATCH %s%s %d\n", result.url, certInfo, result.distance)
		if *debug {
			fmt.Printf("DEBUG %s %d\n", result.url, result.distance)
		}
	}
}
