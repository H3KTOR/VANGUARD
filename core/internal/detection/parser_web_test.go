package detection

import "testing"

// TestWebLogParser_StandardCombinedFormat verifies the stock Nginx/Apache
// "combined" format (no Host header logged) still parses exactly as
// before Phase 3's Protocol/Host additions -- Host must be empty, not a
// zero-value substitute for "unknown"/"suspicious".
func TestWebLogParser_StandardCombinedFormat(t *testing.T) {
	p := NewWebLogParser()
	line := `185.220.101.5 - - [23/Aug/2026:14:02:11 +0000] "GET /wp-admin HTTP/1.1" 404 162 "-" "Mozilla/5.0"`
	ev, ok := p.Parse(line)
	if !ok {
		t.Fatalf("expected line to parse")
	}
	if ev.SourceIP != "185.220.101.5" {
		t.Errorf("SourceIP = %q", ev.SourceIP)
	}
	if ev.Method != "GET" || ev.Path != "/wp-admin" {
		t.Errorf("Method/Path = %q/%q", ev.Method, ev.Path)
	}
	if ev.Protocol != "HTTP/1.1" {
		t.Errorf("Protocol = %q, want HTTP/1.1", ev.Protocol)
	}
	if ev.StatusCode != 404 {
		t.Errorf("StatusCode = %d", ev.StatusCode)
	}
	if ev.UserAgent != "Mozilla/5.0" {
		t.Errorf("UserAgent = %q", ev.UserAgent)
	}
	if ev.Host != "" {
		t.Errorf("expected empty Host for the stock combined format (not observable), got %q", ev.Host)
	}
}

// TestWebLogParser_HostSuffixedFormat verifies the opt-in customized
// log_format that appends the Host header as a trailing quoted field is
// correctly parsed, WITHOUT requiring operators to change anything if
// they don't customize their nginx config (see TestWebLogParser_StandardCombinedFormat).
func TestWebLogParser_HostSuffixedFormat(t *testing.T) {
	p := NewWebLogParser()
	line := `185.220.101.5 - - [23/Aug/2026:14:02:11 +0000] "GET /cart HTTP/1.1" 200 512 "-" "Mozilla/5.0" "shop.example.com"`
	ev, ok := p.Parse(line)
	if !ok {
		t.Fatalf("expected line to parse")
	}
	if ev.Host != "shop.example.com" {
		t.Errorf("Host = %q, want shop.example.com", ev.Host)
	}
	if ev.SourceIP != "185.220.101.5" || ev.Path != "/cart" {
		t.Errorf("unexpected core fields: ip=%q path=%q", ev.SourceIP, ev.Path)
	}
}

// TestWebLogParser_MalformedRequestLineStillHandledGracefully verifies a
// line with an unusual/malformed request-target still parses (or is
// safely rejected) without panicking.
func TestWebLogParser_MalformedRequestLineStillHandledGracefully(t *testing.T) {
	p := NewWebLogParser()
	lines := []string{
		``,
		`not a valid log line at all`,
		`185.220.101.5 - - [23/Aug/2026:14:02:11 +0000] "GET" 400 0 "-" "-"`,
	}
	for _, line := range lines {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Parse panicked on %q: %v", line, r)
				}
			}()
			p.Parse(line)
		}()
	}
}
