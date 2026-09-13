package detection

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

// combinedLogRe matches the standard Nginx/Apache "combined" log format:
//
//	185.220.101.5 - - [23/Aug/2026:14:02:11 +0000] "GET /wp-admin HTTP/1.1" 404 162 "-" "Mozilla/5.0"
//
// Field order: remote_addr, ident, user, time, request-line, status, size,
// referer, user-agent, with one OPTIONAL trailing quoted field VANGUARD
// also understands: the Host header, for operators who have customized
// their log_format to append it (a common, realistic nginx customization,
// e.g. `log_format vhost '$remote_addr ... "$http_user_agent" "$host"';`).
// The stock "combined" format does NOT log Host at all -- when the
// trailing field is absent, Event.Host is simply left empty (see Feature 6:
// Host Header / Virtual Host Abuse's own doc comment for why an empty
// Host must never be treated as suspicious).
var combinedLogRe = regexp.MustCompile(
	`^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+(\S+)"\s+(\d{3})\s+\S+` +
		`(?:\s+"[^"]*"\s+"([^"]*)"(?:\s+"([^"]*)")?)?`)

// WebLogParser turns raw Nginx/Apache combined-format access log lines into
// Events. Stateless and safe for concurrent use.
type WebLogParser struct{}

// NewWebLogParser constructs a WebLogParser.
func NewWebLogParser() *WebLogParser { return &WebLogParser{} }

// Parse attempts to extract an Event from a single access log line.
// Returns (nil, false) for lines that don't match the combined log format
// (with or without the optional trailing Host field).
func (p *WebLogParser) Parse(line string) (*Event, bool) {
	m := combinedLogRe.FindStringSubmatch(line)
	if m == nil {
		return nil, false
	}
	status, err := strconv.Atoi(m[6])
	if err != nil {
		status = 0
	}
	ua := ""
	if len(m) > 7 {
		ua = m[7]
	}
	host := ""
	if len(m) > 8 {
		host = m[8]
	}
	return &Event{
		Kind:       EventHTTPRequest,
		SourceIP:   m[1],
		Timestamp:  parseApacheTime(m[2]),
		Method:     strings.ToUpper(m[3]),
		Path:       m[4],
		Protocol:   m[5],
		StatusCode: status,
		UserAgent:  ua,
		Host:       host,
		RawLine:    line,
	}, true
}

// parseApacheTime parses the Apache/Nginx log timestamp format, e.g.
// "23/Aug/2026:14:02:11 +0000". Falls back to time.Now() on parse failure
// so a malformed line is still counted, just with slightly imprecise
// ordering.
func parseApacheTime(s string) time.Time {
	t, err := time.Parse("02/Jan/2006:15:04:05 -0700", s)
	if err != nil {
		return time.Now()
	}
	return t
}
