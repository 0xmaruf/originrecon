package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/texttheater/golang-levenshtein/levenshtein"
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
	url          string
	match        bool
	distance     int
	bodyMatch    bool
	matchedStr   string
	certCN       string
	certOrg      string
}

func getHTTPClient() *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func fetchBody(url string) (string, *tls.ConnectionState, error) {
	client := getHTTPClient()
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", nil, err
	}

	var tlsState *tls.ConnectionState
	if resp.TLS != nil {
		tlsState = resp.TLS
	}

	return string(bodyBytes), tlsState, nil
}

func getCertInfo(tlsState *tls.ConnectionState) (string, string) {
	if tlsState == nil || len(tlsState.PeerCertificates) == 0 {
		return "", ""
	}
	cert := tlsState.PeerCertificates[0]
	cn := cert.Subject.CommonName
	org := ""
	if len(cert.Subject.Organization) > 0 {
		org = strings.Join(cert.Subject.Organization, ", ")
	}
	return cn, org
}

func checkIP(ip string, ports []string, originalBody string, levenshteinThreshold int, matchString string, results chan<- Result, wg *sync.WaitGroup) {
	defer wg.Done()
	schemes := []string{"https", "http"}
	for _, scheme := range schemes {
		for _, port := range ports {
			url := fmt.Sprintf("%s://%s:%s", scheme, ip, port)
			body, tlsState, err := fetchBody(url)
			if err != nil {
				continue
			}

			distance := levenshtein.DistanceForStrings(
				[]rune(originalBody),
				[]rune(body),
				levenshtein.DefaultOptions,
			)

			cn, org := getCertInfo(tlsState)

			// Check match string in body
			bodyMatch := false
			matchedStr := ""
			if matchString != "" && strings.Contains(body, matchString) {
				bodyMatch = true
				matchedStr = matchString
			}

			results <- Result{
				url:        url,
				match:      distance <= levenshteinThreshold,
				distance:   distance,
				bodyMatch:  bodyMatch,
				matchedStr: matchedStr,
				certCN:     cn,
				certOrg:    org,
			}
		}
	}
}

func formatCertInfo(cn, org string) string {
	if cn == "" && org == "" {
		return ""
	}
	parts := []string{}
	if cn != "" {
		parts = append(parts, fmt.Sprintf("CN=%s", cn))
	}
	if org != "" {
		parts = append(parts, fmt.Sprintf("O=%s", org))
	}
	return fmt.Sprintf(" [%s]", strings.Join(parts, " | "))
}

func main() {
	targetURL := flag.String("h", "", "scheme://host[:port]/url of site, e.g. https://0xmaruf.com:443/blog")
	levenshteinThreshold := flag.Int("l", 5, "levenshtein threshold, higher means more lenient (default 5)")
	ports := flag.String("p", "80,443", "comma separated ports to scan for IP addresses given via stdin")
	threads := flag.Int("t", 32, "number of threads (default 32)")
	matchString := flag.String("mr", "", "optional: if this string is found in response body, highlight the result (e.g. -mr 'Admin Panel')")
	flag.Parse()

	if *targetURL == "" {
		fmt.Println("Usage: originrecon -h https://target.com [-l 5] [-p 80,443] [-t 32] [-mr 'match string']")
		os.Exit(1)
	}

	fmt.Printf("%s[*] Fetching original URL: %s%s\n", colorCyan, *targetURL, colorReset)
	originalBody, _, err := fetchBody(*targetURL)
	if err != nil {
		fmt.Printf("Error getting original URL: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("%s[*] Got original response (%d bytes)%s\n", colorCyan, len(originalBody), colorReset)
	if *matchString != "" {
		fmt.Printf("%s[*] Match string enabled: \"%s\"%s\n", colorYellow, *matchString, colorReset)
	}
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
				checkIP(ip, portList, originalBody, *levenshteinThreshold, *matchString, results, &wg)
			}(ip)
		}
		wg.Wait()
		close(results)
	}()

	for result := range results {
		certInfo := formatCertInfo(result.certCN, result.certOrg)

		if result.bodyMatch {
			// Body match string found — always show in magenta/bold
			fmt.Printf("\033[35m%sBODY-MATCH\033[0m %s%s (distance:%d) matched: \"%s\"\n",
				colorBold, result.url, certInfo, result.distance, result.matchedStr)
		} else if result.match {
			fmt.Printf("%sMATCH%s %s%s %d\n",
				colorGreen, colorReset, result.url, certInfo, result.distance)
		} else {
			fmt.Printf("NOMATCH %s%s %d\n",
				result.url, certInfo, result.distance)
		}
	}
}
