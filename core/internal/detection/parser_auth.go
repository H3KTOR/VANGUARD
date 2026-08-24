package detection

import (
	"regexp"
	"time"
)

// Standard Linux syslog-format auth.log lines look like:
//
//	Aug 23 14:02:11 web01 sshd[12345]: Failed password for root from 185.220.101.5 port 51234 ssh2
//	Aug 23 14:02:15 web01 sshd[12345]: Failed password for invalid user admin from 185.220.101.5 port 51240 ssh2
//	Aug 23 14:02:40 web01 sshd[12345]: Accepted password for deploy from 185.220.101.5 port 51300 ssh2
//	Aug 23 14:02:40 web01 sshd[12345]: Accepted publickey for deploy from 10.0.0.5 port 51301 ssh2
//
// We deliberately match "Failed password" / "Accepted {password,publickey}"
// rather than trying to parse every sshd message type, since those are the
// only two outcomes the V1 detection rules need.
var (
	sshFailedRe = regexp.MustCompile(
		`^(\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+Failed password for (?:invalid user )?(\S+) from ([0-9a-fA-F:.]+) port (\d+)`)
	sshAcceptedRe = regexp.MustCompile(
		`^(\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+Accepted (?:password|publickey) for (\S+) from ([0-9a-fA-F:.]+) port (\d+)`)
)

// AuthLogParser turns raw /var/log/auth.log lines into Events. It is
// stateless and safe for concurrent use; the current year is assumed for
// timestamps since syslog format omits it (auth.log is line-buffered and
// tailed live, so this is always correct in practice; a log rotated across
// a year boundary would need external correction, which is out of scope
// for V1).
type AuthLogParser struct{}

// NewAuthLogParser constructs an AuthLogParser.
func NewAuthLogParser() *AuthLogParser { return &AuthLogParser{} }

// Parse attempts to extract an Event from a single auth.log line. Returns
// (nil, false) for lines that don't match a recognized pattern (the vast
// majority of auth.log traffic -- cron, sudo, session opens, etc -- which
// V1 does not need to act on).
func (p *AuthLogParser) Parse(line string) (*Event, bool) {
	if m := sshFailedRe.FindStringSubmatch(line); m != nil {
		return &Event{
			Kind:      EventSSHAuthFailure,
			SourceIP:  m[3],
			Username:  m[2],
			Timestamp: parseSyslogTime(m[1]),
			Port:      22,
			RawLine:   line,
		}, true
	}
	if m := sshAcceptedRe.FindStringSubmatch(line); m != nil {
		return &Event{
			Kind:      EventSSHAuthSuccess,
			SourceIP:  m[3],
			Username:  m[2],
			Timestamp: parseSyslogTime(m[1]),
			Port:      22,
			RawLine:   line,
		}, true
	}
	return nil, false
}

// parseSyslogTime parses the "Mon _2 15:04:05" syslog timestamp format,
// assuming the current year (syslog format has no year field). Falls back
// to time.Now() if parsing fails, so a malformed timestamp never causes an
// event to be dropped -- ordering may be slightly off but the event is
// still counted.
func parseSyslogTime(s string) time.Time {
	now := time.Now()
	t, err := time.Parse("Jan _2 15:04:05", s)
	if err != nil {
		return now
	}
	return time.Date(now.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, now.Location())
}
