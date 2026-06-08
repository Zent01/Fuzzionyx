package main

import (
	"bufio"       // buffered file reading for wordlists
	"flag"        // command-line argument parsing
	"fmt"         // formatted terminal output
	"io"          // io.ReadAll — reads HTTP response body to measure its byte size
	"net/http"    // HTTP client, requests, and responses
	"os"          // file system access and process exit
	"strconv"     // string ↔ int conversion for status codes and flags
	"strings"     // string manipulation (split, trim, contains, repeat)
	"sync"        // WaitGroup and Mutex for goroutine coordination
	"sync/atomic" // lock-free counters for progress tracking across goroutines
	"time"        // timeouts, durations, and the progress bar ticker
)

// =============================================================================
// ANSI COLOR CONSTANTS
// \033 is the ESC character that begins every ANSI escape sequence.
// All sequences end with 'm'. cReset must follow every colored string
// to prevent color from bleeding into subsequent output.
// =============================================================================

const (
	cReset     = "\033[0m"  // restore terminal default color and style
	cRed       = "\033[31m" // red   — 5xx server errors
	cGreen     = "\033[32m" // green — 2xx success, found count, completion markers
	cYellow    = "\033[33m" // yellow — 4xx client errors (403, 401, etc.)
	cCyan      = "\033[36m" // cyan  — 3xx redirects, section headers, accent color
	cBold      = "\033[1m"  // bold text weight
	cGray      = "\033[90m" // dark gray — borders, labels, secondary info
	cBlue      = "\033[34m" // blue — currently reserved for future use
	cClearLine = "\033[2K"  // erase the entire current terminal line

	// Box-drawing characters — used to build the results panel frame
	cBoxH  = "─" // horizontal line segment
	cBoxV  = "│" // vertical line segment
	cBoxTL = "┌" // top-left corner
	cBoxTR = "┐" // top-right corner
	cBoxBL = "└" // bottom-left corner
	cBoxBR = "┘" // bottom-right corner
	cBoxML = "├" // left-side T-junction (mid-left connector)
	cBoxMR = "┤" // right-side T-junction (mid-right connector)
)

// =============================================================================
// DATA STRUCTURES
// Result captures everything known about one discovered URL.
// queueItem is an entry in the BFS work queue.
// outputMsg is sent over the output channel so that a single goroutine
// owns all writes to stdout, preventing interleaved/garbled lines.
// =============================================================================

// Result holds the data collected for a single discovered URL.
type Result struct {
	URL        string        // the full URL that responded
	StatusCode int           // HTTP status code returned by the server
	Size       int64         // response body size in bytes
	Duration   time.Duration // round-trip time for the request
	Depth      int           // BFS recursion depth at which this URL was found
}

// queueItem is one entry in the BFS work queue.
type queueItem struct {
	baseURL string // base URL to fuzz at this level
	depth   int    // recursion depth of this scan level
}

// outputMsg carries a display event from a worker goroutine to outputWriter.
type outputMsg struct {
	msgType string // "header" | "result" | "bar" | "complete"
	line    string // formatted text to display
	depth   int    // depth level (used by the "header" type)
	base    string // base URL  (used by "header" and "complete" types)
}

// =============================================================================
// FUZZER — central struct
// Configuration fields are set once in main() and read-only during the scan.
// Runtime fields (visited, counters, channel) are mutated concurrently and
// are protected either by their own mutex or by atomic operations.
// =============================================================================

// Fuzzer owns all scan configuration and shared runtime state.
type Fuzzer struct {
	// ── configuration (read-only after initialisation) ──
	baseURL      string       // target base URL, e.g. "http://example.com/api"
	wordlist     string       // path to the primary wordlist file
	wordlist2    string       // path to an optional secondary wordlist
	maxDepth     int          // maximum BFS recursion depth (0 = no recursion)
	recurseCodes map[int]bool // status codes that trigger a recursive scan
	threads      int          // number of concurrent worker goroutines
	timeout      int          // per-request HTTP timeout in seconds
	filterCodes  map[int]bool // if non-empty, only show responses with these codes
	extensions   []string     // file extensions to append (e.g. ["php","asp"])
	headers      []string     // validated custom HTTP headers ("Key: Value")
	delay        int          // milliseconds to wait between requests (rate limit)
	followRedir  bool         // whether to follow HTTP redirects
	quiet        bool         // suppress the progress bar; show results only

	// ── output file handle (nil when -o was not provided) ──
	// NOTE: only outFile (*os.File) is used for I/O.
	// The path string is read directly from the flag and never stored in the struct.
	outFile *os.File

	// ── deduplication (protected by visitedMu) ──
	visited   map[string]struct{} // set of URLs already dispatched to avoid retesting
	visitedMu sync.Mutex          // guards the visited map

	// ── atomic progress counters ──
	totalReqs  int64 // total HTTP requests made so far
	foundCount int64 // total URLs that passed all filters
	startTime  time.Time

	// ── output pipeline ──
	outputChan chan outputMsg // workers send display events; outputWriter consumes them
	barLine    string        // most recently rendered progress-bar string
	barVisible bool          // true when the progress bar is currently on screen
}

// =============================================================================
// LOGO + BANNER
// printLogo() is the single source of truth for the ASCII art header.
// Both banner() and help() call it — the art is never duplicated.
// =============================================================================

// printLogo prints the ASCII art title, tagline, and divider.
// This is the only place the logo is defined; banner() and help() both call it.
func printLogo() {
	fmt.Print(cCyan + cBold + `
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   ███████╗██╗   ██╗███████╗███████╗██╗ ██████╗ ███╗   ██╗██╗   ██╗██╗  ██╗   ║                   
║   ██╔════╝██║   ██║╚══███╔╝╚══███╔╝██║██╔═══██╗████╗  ██║╚██╗ ██╔╝╚██╗██╔╝   ║
║   █████╗  ██║   ██║  ███╔╝   ███╔╝ ██║██║   ██║██╔██╗ ██║ ╚████╔╝  ╚███╔╝    ║
║   ██╔══╝  ██║   ██║ ███╔╝   ███╔╝  ██║██║   ██║██║╚██╗██║  ╚██╔╝   ██╔██╗    ║
║   ██║     ╚██████╔╝███████╗███████╗██║╚██████╔╝██║ ╚████║   ██║   ██╔╝ ██╗   ║
║   ╚═╝      ╚═════╝ ╚══════╝╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝   ║
║                                                                              ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝` + cReset)
	fmt.Println(cGray + "\n Web Directory Fuzzer — Fuzzionyx v0.9" + cReset)
	fmt.Println(cGray + "  ─────────────────────────────────────────" + cReset)
	fmt.Println()
}

// banner prints the logo; called on every normal run.
func banner() { printLogo() }

// help prints the full usage reference and exits.
func help() {
	printLogo() // reuse the shared logo — no duplication

	fmt.Printf("  %s%s▸ BASIC PARAMETERS%s\n", cBold, cCyan, cReset)
	fmt.Printf("    %s%-24s%s %s\n", cGreen, "-u", cReset, "Target URL (required) — e.g., http://example.com/api")
	fmt.Printf("    %s%-24s%s %s\n", cGreen, "-w", cReset, "Wordlist path (required)")
	fmt.Printf("    %s%-24s%s %s\n", cGreen, "-w2", cReset, "Second wordlist path (optional) — merges with -w")
	fmt.Printf("    %s%-24s%s %s\n", cGreen, "-o", cReset, "Output file (txt format) — saves results")
	fmt.Println()

	fmt.Printf("  %s%s▸ PERFORMANCE & SPEED%s\n", cBold, cCyan, cReset)
	fmt.Printf("    %s%-24s%s %s\n", cGreen, "-t", cReset, "Threads (default: 50) — parallel requests")
	fmt.Printf("    %s%-24s%s %s\n", cGreen, "-timeout", cReset, "HTTP timeout seconds (default: 5)")
	fmt.Printf("    %s%-24s%s %s\n", cGreen, "-d", cReset, "Delay between requests in ms (rate limiting)")
	fmt.Printf("    %s%-24s%s %s\n", cGreen, "-follow", cReset, "Follow redirects (default: false)")
	fmt.Println()

	fmt.Printf("  %s%s▸ RESULT FILTERING%s\n", cBold, cCyan, cReset)
	fmt.Printf("    %s%-24s%s %s\n", cGreen, "-mc", cReset, "Match codes — show only these (e.g., -mc 200,301)")
	fmt.Println()

	fmt.Printf("  %s%s▸ EXTENSIONS & RECURSION%s\n", cBold, cCyan, cReset)
	fmt.Printf("    %s%-24s%s %s\n", cGreen, "-e", cReset, "Extensions to include (e.g., -e php,asp,js)")
	fmt.Printf("    %s%-24s%s %s\n", cGreen, "-r", cReset, "Recursive depth — requires -rst")
	fmt.Printf("    %s%-24s%s %s\n", cGreen, "-rst", cReset, "Status codes that trigger recursion (e.g., 200,301)")
	fmt.Println()

	fmt.Printf("  %s%s▸ HTTP HEADERS & MISC%s\n", cBold, cCyan, cReset)
	fmt.Printf("    %s%-24s%s %s\n", cGreen, "-H", cReset, "Custom headers — e.g., -H \"Cookie: session=xxx\"")
	fmt.Printf("    %s%-24s%s %s\n", cGreen, "-q", cReset, "Quiet mode — only results, no progress bar")
	fmt.Println()

	fmt.Printf("  %s%s▸ USAGE EXAMPLES%s\n", cBold, cCyan, cReset)
	fmt.Printf("    %s# Basic usage%s\n", cGray, cReset)
	fmt.Printf("    fuzzionyx -u http://example.com -w wordlist.txt\n\n")
	fmt.Printf("    %s# With extensions and filters%s\n", cGray, cReset)
	fmt.Printf("    fuzzionyx -u http://example.com -w common.txt -e php,asp -mc 200,403\n\n")
	fmt.Printf("    %s# Recursive scanning%s\n", cGray, cReset)
	fmt.Printf("    fuzzionyx -u http://example.com -w dirs.txt -r 2 -rst 200,301\n\n")
	fmt.Printf("    %s# With rate limiting and custom headers%s\n", cGray, cReset)
	fmt.Printf("    fuzzionyx -u http://example.com -w api.txt -d 100 -H \"Authorization: Bearer token\"\n\n")
	fmt.Printf("    %s# Save results%s\n", cGray, cReset)
	fmt.Printf("    fuzzionyx -u http://example.com -w big.txt -o results.txt -q\n")
	fmt.Println()
}

// =============================================================================
// COLOR HELPERS
// statusColor maps an HTTP status code to the appropriate ANSI color,
// giving instant visual feedback about the class of each response.
// =============================================================================

// statusColor returns the ANSI color constant for a given HTTP status code.
func statusColor(code int) string {
	switch {
	case code >= 200 && code < 300:
		return cGreen  // success
	case code >= 300 && code < 400:
		return cCyan   // redirect
	case code >= 400 && code < 500:
		return cYellow // client error (403, 404, etc.)
	case code >= 500:
		return cRed    // server error
	default:
		return cGray   // unknown / informational
	}
}

// =============================================================================
// SIZE FORMATTER
// Converts a raw byte count to a human-readable string (B / KB / MB).
// Negative values indicate that the body could not be read.
// =============================================================================

// formatSize returns a compact, right-aligned size string for a byte count.
func formatSize(size int64) string {
	if size < 0 {
		return "   ?   " // body unreadable or unavailable
	}
	switch {
	case size < 1024:
		return fmt.Sprintf("%4d B ", size)
	case size < 1024*1024:
		return fmt.Sprintf("%4.1f KB", float64(size)/1024)
	default:
		return fmt.Sprintf("%4.1f MB", float64(size)/(1024*1024))
	}
}

// =============================================================================
// ANSI STRIP + TEXT FITTING
// ANSI escape sequences are invisible bytes that don't consume column width.
// stripANSI removes them so that len() gives the true visible character count.
// fitText then uses that count to right-pad or truncate to an exact width,
// keeping the box-drawing frame aligned regardless of color codes in the text.
// =============================================================================

// stripANSI removes all ANSI escape sequences from s and returns plain text.
func stripANSI(s string) string {
	var b strings.Builder
	inEsc := false
	for i := 0; i < len(s); i++ {
		if s[i] == '\033' { // ESC begins an escape sequence
			inEsc = true
			continue
		}
		if inEsc {
			if s[i] == 'm' { // 'm' terminates the CSI sequence
				inEsc = false
			}
			continue
		}
		b.WriteByte(s[i]) // keep only visible characters
	}
	return b.String()
}

// fitText pads or truncates text so its visible width equals exactly width columns.
// Colors are preserved; only the visible character count is constrained.
func fitText(text string, width int) string {
	clean := stripANSI(text)
	if len(clean) > width {
		return text[:width-1] + "…" // truncate and mark with ellipsis
	}
	return text + strings.Repeat(" ", width-len(clean)) // right-pad with spaces
}

// =============================================================================
// WORDLIST LOADING
// Reads a plain-text file line by line.  Empty lines and lines starting with
// '#' are treated as comments and skipped.  Leading slashes are stripped from
// each word so that callers can safely prepend a base URL with a single '/'.
// =============================================================================

// loadWordlist reads a wordlist file and returns all valid candidate words.
func loadWordlist(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open wordlist: %w", err)
	}
	defer f.Close()

	var words []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			words = append(words, strings.TrimLeft(line, "/"))
		}
	}
	return words, sc.Err()
}

// =============================================================================
// HOST CHECK
// Makes a single GET request to the target before scanning begins.
// Any HTTP response — even a 404 — confirms the host is reachable.
// Connection errors cause an early exit so the user gets immediate feedback.
// =============================================================================

// checkHost verifies that the target URL is reachable before scanning starts.
func checkHost(urlStr string, timeout int) error {
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse // don't follow redirects for the probe
		},
	}
	resp, err := client.Get(urlStr)
	if err != nil {
		return fmt.Errorf("cannot connect to host: %w", err)
	}
	defer resp.Body.Close()
	return nil // any HTTP response means the host exists
}

// =============================================================================
// HEADER PARSING
// parseHeaders validates that each custom header string has the required
// "Key: Value" format.  Malformed entries are silently dropped.
// This is called in main() before the Fuzzer is constructed so that only
// valid headers reach the HTTP client.
// =============================================================================

// parseHeaders filters a slice of raw header strings to those with a valid
// "Key: Value" format and returns the validated subset.
func parseHeaders(raw []string) []string {
	var out []string
	for _, h := range raw {
		// SplitN with n=2 keeps everything after the first colon as the value
		if parts := strings.SplitN(h, ":", 2); len(parts) == 2 {
			out = append(out, h)
		}
	}
	return out
}

// =============================================================================
// DEDUPLICATION
// markVisited records a URL as seen and reports whether it was already known.
// The visited map is shared across goroutines and protected by visitedMu.
// Using struct{} as the map value type allocates zero bytes per entry.
// =============================================================================

// markVisited adds url to the visited set and returns true if it was already there.
func (f *Fuzzer) markVisited(url string) bool {
	f.visitedMu.Lock()
	defer f.visitedMu.Unlock()
	if _, ok := f.visited[url]; ok {
		return true
	}
	f.visited[url] = struct{}{}
	return false
}

// =============================================================================
// HTTP CLIENT FACTORY
// Creates a new http.Client with connection pooling sized to the thread count.
// DisableCompression is intentional: we need the raw body size for accurate
// size-based filtering and display; compressed transfers would misreport it.
// =============================================================================

// newClient creates a configured HTTP client for use by worker goroutines.
func (f *Fuzzer) newClient() *http.Client {
	tr := &http.Transport{
		MaxIdleConns:        f.threads * 2,    // total idle keep-alive connections
		MaxIdleConnsPerHost: f.threads * 2,    // per-host idle connections
		IdleConnTimeout:     30 * time.Second, // reclaim idle connections after 30 s
		DisableCompression:  true,             // get raw body bytes for accurate size
	}
	client := &http.Client{
		Timeout:   time.Duration(f.timeout) * time.Second,
		Transport: tr,
	}
	if !f.followRedir {
		// Stop at the first response to capture the real status code
		client.CheckRedirect = func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	return client
}

// =============================================================================
// OUTPUT WRITER GOROUTINE
// A single goroutine owns all writes to stdout.  Worker goroutines send
// outputMsg values over outputChan instead of writing directly, which
// prevents interleaved / garbled lines when many goroutines finish at once.
//
// Message types:
//   "header"   — top of a new scan level (box top + title row)
//   "result"   — one discovered URL (a row inside the box)
//   "bar"      — progress bar update (overwrites the current line with \r)
//   "complete" — end of a scan level (box bottom + summary line)
// =============================================================================

// outputWriter reads from outputChan and renders all terminal output.
// It runs in its own goroutine and exits when the channel is closed.
func (f *Fuzzer) outputWriter() {
	const boxWidth = 75
	const innerWidth = boxWidth - 2 // usable width inside the vertical bars

	for msg := range f.outputChan {
		// In quiet mode the progress bar is suppressed entirely
		if f.quiet && msg.msgType == "bar" {
			continue
		}

		switch msg.msgType {

		case "header":
			// ── Print the top of the scan-level box ──────────────────────
			if f.quiet {
				fmt.Printf("  %s[→]%s %s\n", cCyan, cReset, msg.base)
				continue
			}
			if f.barVisible {
				fmt.Print("\r" + cClearLine + "\033[1A" + cClearLine)
				f.barVisible = false
			}

			// Build the centered header text, trimming the URL if needed
			header := buildHeader(msg.base, msg.depth, f.maxDepth, innerWidth)

			cleanLen := len(stripANSI(header))
			padding  := innerWidth - cleanLen
			if padding < 0 { padding = 0 }
			left  := padding / 2
			right := padding - left

			fmt.Println(cBoxTL + strings.Repeat(cBoxH, innerWidth) + cBoxTR)
			fmt.Println(cBoxV + strings.Repeat(" ", left) +
				cBold + cCyan + header + cReset +
				strings.Repeat(" ", right) + cBoxV)
			fmt.Println(cBoxML + strings.Repeat(cBoxH, innerWidth) + cBoxMR)

		case "result":
			// ── Print one result row inside the box ───────────────────────
			if f.quiet {
				fmt.Println(strings.TrimSpace(msg.line))
				continue
			}
			if f.barVisible {
				fmt.Print("\r" + cClearLine + "\033[1A" + cClearLine)
				f.barVisible = false
			}
			fmt.Println(cBoxV + fitText(" "+msg.line, innerWidth) + cBoxV)

		case "bar":
			// ── Overwrite the current line with a fresh progress bar ──────
			f.barLine = cBoxV + " " + fitText(msg.line, innerWidth) + cBoxV
			if !f.barVisible {
				fmt.Println(cBoxML + strings.Repeat(cBoxH, innerWidth) + cBoxMR)
				f.barVisible = true
			}
			fmt.Print("\r" + cClearLine + f.barLine)

		case "complete":
			// ── Print the bottom of the box and a completion marker ───────
			if f.quiet {
				fmt.Printf("  %s[✓]%s %s\n", cGreen, cReset, msg.base)
				continue
			}
			if f.barVisible {
				fmt.Print("\r" + cClearLine + "\033[1A" + cClearLine)
				f.barVisible = false
			}
			fmt.Println(cBoxBL + strings.Repeat(cBoxH, innerWidth) + cBoxBR)

			short := msg.base
			if len(short) > 60 {
				short = "…" + short[len(short)-59:]
			}
			fmt.Printf("  %s[✓]%s Completed: %s\n", cGreen, cReset, short)
			fmt.Println()
		}
	}
}

// buildHeader returns the centered header string for a scan-level box.
// It trims the base URL if the full string would overflow innerWidth.
func buildHeader(base string, depth, maxDepth, innerWidth int) string {
	format := func(b string) string {
		if maxDepth > 0 {
			return fmt.Sprintf(" Depth %d/%d — %s ", depth, maxDepth, b)
		}
		return fmt.Sprintf(" Scanning: %s ", b)
	}

	h := format(base)
	if len(stripANSI(h)) <= innerWidth {
		return h
	}

	// Trim the URL until the header fits
	maxBase := innerWidth - 20
	if maxBase < 10 { maxBase = 10 }
	if len(base) > maxBase {
		base = "…" + base[len(base)-maxBase+1:]
	}
	return format(base)
}

// =============================================================================
// WORDLIST GENERATION WITH EXTENSIONS
// Takes the raw word list and produces the final set of paths to test.
// When -e is given, every word without a dot gets one copy per extension.
// Words that already carry a dot but not an allowed extension are dropped.
// =============================================================================

// generateWordlist expands baseWords with the configured extensions and returns
// the final slice of paths to probe.
func (f *Fuzzer) generateWordlist(baseWords []string) []string {
	var kept []string

	for _, word := range baseWords {
		if len(f.extensions) > 0 {
			// Keep words that already carry an allowed extension, or bare words
			// (bare words will have extensions appended in the next step)
			hasAllowedExt := false
			for _, ext := range f.extensions {
				if strings.HasSuffix(word, "."+ext) {
					hasAllowedExt = true
					break
				}
			}
			if hasAllowedExt || !strings.Contains(word, ".") {
				kept = append(kept, word)
			}
		} else {
			kept = append(kept, word) // no extension filter active — keep everything
		}
	}

	// For each bare word (no dot), generate one variant per extension
	if len(f.extensions) > 0 {
		var expanded []string
		for _, word := range kept {
			if !strings.Contains(word, ".") {
				for _, ext := range f.extensions {
					expanded = append(expanded, word+"."+ext)
				}
			} else {
				expanded = append(expanded, word)
			}
		}
		return expanded
	}

	return kept
}

// =============================================================================
// PROGRESS BAR
// updateBar computes current statistics and sends a "bar" message to the
// output channel.  It is called every 100 ms by a dedicated ticker goroutine.
// All counter reads use atomic loads so no lock is needed.
// =============================================================================

// updateBar sends a formatted progress-bar line to the output channel.
func (f *Fuzzer) updateBar(done, total int64, base string, depth, maxDepth int) {
	elapsed := time.Since(f.startTime).Seconds()
	rps := 0.0
	if elapsed > 0 {
		rps = float64(atomic.LoadInt64(&f.totalReqs)) / elapsed
	}
	found := atomic.LoadInt64(&f.foundCount)

	pct := 0
	if total > 0 {
		pct = int(done * 100 / total)
	}

	const barW = 20
	filled := barW * done / max64(total, 1)
	bar := strings.Repeat("█", int(filled)) + strings.Repeat("░", barW-int(filled))

	f.outputChan <- outputMsg{
		msgType: "bar",
		line:    fmt.Sprintf(" [%s] %3d%%  ⚡%4.0f/s  ✓%d", bar, pct, rps, found),
	}
}

// max64 returns the larger of two int64 values.
// Used to avoid division-by-zero in the progress bar calculation.
func max64(a, b int64) int64 {
	if a > b { return a }
	return b
}

// =============================================================================
// STATUS CODE PARSER
// parseCodes converts a comma-separated string of integers (e.g. "200,301,403")
// into a map[int]bool for O(1) membership tests during filtering.
// =============================================================================

// parseCodes converts "200,301,403" into map[int]bool{200:true, 301:true, 403:true}.
func parseCodes(s string) map[int]bool {
	m := make(map[int]bool)
	for _, part := range strings.Split(s, ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(part)); err == nil {
			m[n] = true
		}
	}
	return m
}

// =============================================================================
// RUN — BFS SCAN ORCHESTRATOR
// Implements a Breadth-First Search over the URL space.
// The initial queue contains only the root URL at depth 0.
// After each level, URLs whose status code is in recurseCodes are added to
// the queue at depth+1, up to maxDepth.
//
// Concurrency model:
//   • One "jobs" channel distributes URL paths to worker goroutines.
//   • A semaphore-like approach via the WaitGroup ensures all workers finish
//     before the next BFS level begins.
//   • A dedicated ticker goroutine updates the progress bar every 100 ms.
//   • All stdout writes go through outputChan → outputWriter goroutine.
// =============================================================================

// Run executes the BFS fuzzing loop, processing one queue level at a time.
func (f *Fuzzer) Run(baseWords []string) {
	client := f.newClient()

	f.outputChan = make(chan outputMsg, 200)
	go f.outputWriter()

	// Seed the BFS queue with the root URL at depth 0
	queue := []queueItem{{baseURL: strings.TrimRight(f.baseURL, "/"), depth: 0}}

	for len(queue) > 0 {
		item  := queue[0]
		queue  = queue[1:]
		base  := strings.TrimRight(item.baseURL, "/")
		depth := item.depth

		words := f.generateWordlist(baseWords)

		f.outputChan <- outputMsg{msgType: "header", depth: depth, base: base}

		total := int64(len(words))
		var done int64

		type job struct{ url string }
		jobs := make(chan job, f.threads*4)

		var nextMu   sync.Mutex
		var nextDirs []string
		var wg       sync.WaitGroup

		// Feed all candidate URLs into the jobs channel, then close it so
		// workers know when to stop ranging over it.
		go func() {
			for _, w := range words {
				jobs <- job{url: base + "/" + w}
			}
			close(jobs)
		}()

		// Ticker goroutine: refreshes the progress bar every 100 ms
		stopBar := make(chan struct{})
		if !f.quiet {
			go func() {
				tick := time.NewTicker(100 * time.Millisecond)
				defer tick.Stop()
				for {
					select {
					case <-tick.C:
						f.updateBar(atomic.LoadInt64(&done), total, base, depth, f.maxDepth)
					case <-stopBar:
						return
					}
				}
			}()
		}

		// Optional rate-limiter: block each worker until the next tick fires
		var throttle <-chan time.Time
		if f.delay > 0 {
			ticker := time.NewTicker(time.Duration(f.delay) * time.Millisecond)
			defer ticker.Stop()
			throttle = ticker.C
		}

		// Launch worker goroutines — each drains the jobs channel independently
		for i := 0; i < f.threads; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()

				for j := range jobs {
					if f.delay > 0 {
						<-throttle // enforce rate limit before each request
					}

					// Skip URLs that have already been dispatched in a prior level
					if f.markVisited(j.url) {
						atomic.AddInt64(&done, 1)
						continue
					}

					atomic.AddInt64(&f.totalReqs, 1)

					req, err := http.NewRequest("GET", j.url, nil)
					if err != nil {
						atomic.AddInt64(&done, 1)
						continue
					}

					// Attach every validated custom header to the request
					for _, h := range f.headers {
						if parts := strings.SplitN(h, ":", 2); len(parts) == 2 {
							req.Header.Set(strings.TrimSpace(parts[0]),
								strings.TrimSpace(parts[1]))
						}
					}

					start := time.Now()
					resp, err := client.Do(req)
					dur := time.Since(start)
					atomic.AddInt64(&done, 1)

					if err != nil { continue }

					// Read the full body to measure its byte size for display
					body, _ := io.ReadAll(resp.Body)
					resp.Body.Close()

					code := resp.StatusCode
					size := int64(len(body))

					// Always skip 404 — it means the path does not exist
					if code == 404 { continue }

					// Apply status-code filter (-mc flag)
					if len(f.filterCodes) > 0 && !f.filterCodes[code] { continue }

					// Trim the URL for display if it would overflow the column
					urlPath := j.url
					if len(urlPath) > 50 {
						urlPath = "…" + urlPath[len(urlPath)-49:]
					}

					resultLine := fmt.Sprintf("%s[%d]%s %-50s %s %4dms",
						statusColor(code), code, cReset,
						urlPath, formatSize(size), dur.Milliseconds())

					f.outputChan <- outputMsg{msgType: "result", line: resultLine}

					// Write to the output file when -o was provided
					if f.outFile != nil {
						fmt.Fprintf(f.outFile, "[%d] %s  %s  %dms\n",
							code, j.url, formatSize(size), dur.Milliseconds())
					}

					atomic.AddInt64(&f.foundCount, 1)

					// Queue this URL for recursion if its code triggers it
					if f.maxDepth > 0 && depth < f.maxDepth && f.recurseCodes[code] {
						nextMu.Lock()
						nextDirs = append(nextDirs, j.url)
						nextMu.Unlock()
					}
				}
			}()
		}

		wg.Wait()        // wait for all workers to finish this BFS level
		close(stopBar)   // stop the progress ticker
		time.Sleep(200 * time.Millisecond)

		f.outputChan <- outputMsg{msgType: "complete", base: base}

		// Enqueue discovered directories for the next BFS depth
		if f.maxDepth > 0 && depth < f.maxDepth {
			for _, dir := range nextDirs {
				d := strings.TrimRight(dir, "/")
				// Use a sentinel suffix to dedup BFS queue entries without
				// blocking the real URL from being visited at its own depth
				if !f.markVisited(d + "/__bfs__") {
					queue = append(queue, queueItem{baseURL: d, depth: depth + 1})
				}
			}
		}
	}

	close(f.outputChan)           // signal outputWriter to drain and exit
	time.Sleep(200 * time.Millisecond)
}

// =============================================================================
// ENTRY POINT
// Parses all flags, validates required inputs, constructs the Fuzzer,
// runs the connectivity check, then starts the scan.
// =============================================================================

func main() {
	// ── Flag definitions ────────────────────────────────────────────────────
	u        := flag.String("u",       "",    "Target URL (required)")
	w        := flag.String("w",       "",    "Wordlist path (required)")
	w2       := flag.String("w2",      "",    "Second wordlist path (optional)")
	o        := flag.String("o",       "",    "Output file (txt format)")
	r        := flag.Int(   "r",       0,     "Recursive depth — requires -rst")
	rst      := flag.String("rst",     "",    "Status codes that trigger recursion (e.g., 200,301)")
	threads  := flag.Int(   "t",       50,    "Threads (default 50)")
	timeout  := flag.Int(   "timeout", 5,     "HTTP timeout in seconds")
	mc       := flag.String("mc",      "",    "Match codes — show only these (e.g., 200,301)")
	e        := flag.String("e",       "",    "Extensions to include (e.g., php,asp,js)")
	H        := flag.String("H",       "",    "Custom header (e.g., \"Cookie: session=xxx\")")
	d        := flag.Int(   "d",       0,     "Delay between requests in ms")
	follow   := flag.Bool(  "follow",  false, "Follow redirects")
	q        := flag.Bool(  "q",       false, "Quiet mode — results only, no progress bar")
	helpFlag := flag.Bool(  "h",       false, "Show help and exit")
	flag.Parse()

	if *helpFlag {
		help()
		os.Exit(0)
	}

	banner()

	// ── Required flag validation ─────────────────────────────────────────────
	if *u == "" {
		fmt.Println(cRed + "  [!] -u is required" + cReset)
		flag.Usage()
		os.Exit(1)
	}
	if *w == "" {
		fmt.Println(cRed + "  [!] -w is required" + cReset)
		flag.Usage()
		os.Exit(1)
	}

	// Recursion requires both -r (depth) and -rst (trigger codes) to be set
	if *r > 0 && *rst == "" {
		fmt.Println(cRed + "  [!] -rst is required when -r > 0" + cReset)
		os.Exit(1)
	}
	if *rst != "" && *r == 0 {
		fmt.Println(cRed + "  [!] -r is required when -rst is set" + cReset)
		os.Exit(1)
	}

	// ── Parse comma-separated list flags ────────────────────────────────────
	splitTrim := func(s string) []string {
		var out []string
		for _, p := range strings.Split(s, ",") {
			if t := strings.TrimSpace(p); t != "" {
				out = append(out, t)
			}
		}
		return out
	}

	extensions := splitTrim(*e)

	// ── Parse and validate custom headers ───────────────────────────────────
	// parseHeaders filters out any header that doesn't have "Key: Value" format.
	// This was previously defined but never called — now it is properly used.
	var rawHeaders []string
	if *H != "" {
		rawHeaders = append(rawHeaders, *H)
	}
	headers := parseHeaders(rawHeaders) // validate format before storing

	recurseCodes := parseCodes(*rst)
	filterCodes  := parseCodes(*mc)

	// ── Construct the Fuzzer ─────────────────────────────────────────────────
	fz := &Fuzzer{
		baseURL:      strings.TrimRight(*u, "/"),
		wordlist:     *w,
		wordlist2:    *w2,
		maxDepth:     *r,
		recurseCodes: recurseCodes,
		threads:      *threads,
		timeout:      *timeout,
		filterCodes:  filterCodes,
		extensions:   extensions,
		headers:      headers,
		delay:        *d,
		followRedir:  *follow,
		quiet:        *q,
		visited:      make(map[string]struct{}),
		startTime:    time.Now(),
	}

	// ── Host connectivity check ──────────────────────────────────────────────
	fmt.Printf("  %s[*]%s Checking host connectivity...\n", cCyan, cReset)
	if err := checkHost(*u, *timeout); err != nil {
		fmt.Printf(cRed+"  [!] Host unreachable: %v\n"+cReset, err)
		os.Exit(1)
	}
	fmt.Printf("  %s[✓]%s Host is reachable\n\n", cGreen, cReset)

	// ── Open output file if -o was provided ─────────────────────────────────
	// The file path (*o) is used directly here and is NOT stored in the struct;
	// only the open *os.File handle (fz.outFile) is needed during the scan.
	if *o != "" {
		f, err := os.Create(*o)
		if err != nil {
			fmt.Printf(cRed+"  [!] Cannot create output file: %v\n"+cReset, err)
			os.Exit(1)
		}
		defer f.Close()
		fz.outFile = f
	}

	// ── Configuration summary ────────────────────────────────────────────────
	rcodeStr := "off"
	if len(recurseCodes) > 0 {
		var parts []string
		for k := range recurseCodes { parts = append(parts, strconv.Itoa(k)) }
		rcodeStr = strings.Join(parts, ",")
	}
	mcStr := "all (except 404)"
	if len(filterCodes) > 0 {
		var parts []string
		for k := range filterCodes { parts = append(parts, strconv.Itoa(k)) }
		mcStr = strings.Join(parts, ",")
	}

	fmt.Printf("  %s%-16s%s %s\n", cBold, "Target:",    cReset, fz.baseURL)
	fmt.Printf("  %s%-16s%s %s\n", cBold, "Wordlist:",  cReset, fz.wordlist)
	if *w2 != "" {
		fmt.Printf("  %s%-16s%s %s\n", cBold, "Wordlist 2:", cReset, fz.wordlist2)
	}
	fmt.Printf("  %s%-16s%s %d\n",   cBold, "Threads:",   cReset, fz.threads)
	fmt.Printf("  %s%-16s%s %ds\n",  cBold, "Timeout:",   cReset, fz.timeout)
	fmt.Printf("  %s%-16s%s %s\n",   cBold, "Show codes:", cReset, mcStr)
	if len(extensions) > 0 {
		fmt.Printf("  %s%-16s%s %s\n", cBold, "Extensions:", cReset, strings.Join(extensions, ","))
	}
	if len(headers) > 0 {
		fmt.Printf("  %s%-16s%s %s\n", cBold, "Headers:", cReset, strings.Join(headers, "; "))
	}
	if *d > 0 {
		fmt.Printf("  %s%-16s%s %dms\n", cBold, "Delay:", cReset, *d)
	}
	if *follow {
		fmt.Printf("  %s%-16s%s yes\n", cBold, "Follow redir:", cReset)
	}
	if *r > 0 {
		fmt.Printf("  %s%-16s%s depth=%d  trigger on [%s]\n", cBold, "Recursive:", cReset, *r, rcodeStr)
	} else {
		fmt.Printf("  %s%-16s%s off\n", cBold, "Recursive:", cReset)
	}
	if *o != "" {
		fmt.Printf("  %s%-16s%s %s\n", cBold, "Output:", cReset, *o)
	}
	if *q {
		fmt.Printf("  %s%-16s%s yes\n", cBold, "Quiet mode:", cReset)
	}
	fmt.Println()

	// ── Load wordlist(s) ─────────────────────────────────────────────────────
	words, err := loadWordlist(fz.wordlist)
	if err != nil {
		fmt.Printf(cRed+"  [!] %v\n"+cReset, err)
		os.Exit(1)
	}
	if *w2 != "" {
		words2, err := loadWordlist(fz.wordlist2)
		if err != nil {
			fmt.Printf(cRed+"  [!] %v\n"+cReset, err)
			os.Exit(1)
		}
		words = append(words, words2...) // merge the two wordlists
	}

	fmt.Printf("  %s[+]%s Loaded %d words  |  threads: %d\n\n",
		cGreen, cReset, len(words), fz.threads)

	// ── Execute the scan ─────────────────────────────────────────────────────
	fz.startTime = time.Now()
	fz.Run(words)

	// ── Final statistics ─────────────────────────────────────────────────────
	elapsed := time.Since(fz.startTime)
	totalR  := atomic.LoadInt64(&fz.totalReqs)
	rps     := float64(totalR) / elapsed.Seconds()

	fmt.Println()
	fmt.Println(cGray + "  ─────────────────────────────────────────" + cReset)
	fmt.Printf("  %s[✓] Finished%s  found: %s%d%s  reqs: %s%d%s  avg: %s%.0f req/s%s  time: %s\n",
		cGreen+cBold, cReset,
		cGreen, atomic.LoadInt64(&fz.foundCount), cReset,
		cGray, totalR, cReset,
		cCyan, rps, cReset,
		elapsed.Round(time.Millisecond))
	if *o != "" {
		fmt.Printf("  %s[✓] Saved → %s%s\n", cGreen+cBold, cReset, *o)
	}
	fmt.Println()
}
