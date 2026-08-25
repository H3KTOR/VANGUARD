// Package honeypot implements VANGUARD's Deception layer: lightweight TCP
// listeners bound to decoy ports that mimic real services (SSH, MySQL, an
// admin panel) just convincingly enough to draw a connection attempt from
// automated scanners and opportunistic attackers. Per spec, ANY connection
// to a decoy port is treated as malicious intent -- there is no legitimate
// reason for real traffic to ever reach these ports, so no threshold or
// heuristic is applied; every connection is reported to the detection
// Engine as an instant CRITICAL trigger.
//
// Listeners are intentionally minimal: they accept a connection, optionally
// write a single fake service banner (to bait a scanner into logging a
// fingerprint match, which the incident metadata captures), read whatever
// the client sends for forensic value, then close. VANGUARD never engages
// in a real protocol handshake and never executes anything the client
// sends.
package honeypot

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// Hit is reported for every connection a decoy listener accepts.
type Hit struct {
	SourceIP  string
	Port      int
	Service   string
	Timestamp time.Time
	Banner    string // banner VANGUARD sent to the client, if any
	Received  string // first line the client sent back, if any (truncated)
}

// HitHandler is invoked for every Hit. The detection Engine's
// IngestHoneypotHit method satisfies this signature via a small adapter in
// cmd/vanguard.
type HitHandler func(Hit)

// Decoy describes a single fake service listener.
type Decoy struct {
	Port    int
	Service string
	// Banner, if non-empty, is written to the client immediately after
	// accept (mimicking a real service's greeting, e.g. an SSH version
	// string) to encourage scanners to log a full fingerprint before
	// VANGUARD closes the connection.
	Banner string
}

// DefaultDecoys mirrors the examples from the spec: "fake ports (e.g. 2222
// for fake SSH, 33060 for fake MySQL)", plus a fake admin panel port for
// broader web-scanner coverage.
func DefaultDecoys() []Decoy {
	return []Decoy{
		{Port: 2222, Service: "fake-ssh", Banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n"},
		{Port: 33060, Service: "fake-mysql", Banner: "\x4a\x00\x00\x00\x0a8.0.34\x00"},
		{Port: 8081, Service: "fake-admin-panel", Banner: ""},
	}
}

// Server owns a set of decoy listeners and reports every accepted
// connection to Handler.
type Server struct {
	decoys  []Decoy
	handler HitHandler
	// readTimeout bounds how long we wait for the client to send anything
	// after connecting, so a slow/idle scanner never ties up a goroutine
	// indefinitely (keeping with the "0 idle RAM / minimal footprint"
	// design goal).
	readTimeout time.Duration
	// wg tracks every accept-loop and in-flight connection-handler
	// goroutine so Wait() can block until all of them have fully returned
	// after ctx is cancelled -- this lets the caller safely close the
	// database only once no honeypot goroutine can still write to it.
	wg sync.WaitGroup
}

// NewServer constructs a honeypot Server. handler is called once per
// accepted connection; it must be fast and non-blocking (it typically just
// forwards to detection.Engine.IngestHoneypotHit, which itself only does an
// in-memory dedupe check plus a SQLite insert).
func NewServer(decoys []Decoy, handler HitHandler) *Server {
	if handler == nil {
		handler = func(Hit) {}
	}
	return &Server{decoys: decoys, handler: handler, readTimeout: 3 * time.Second}
}

// Start binds every configured decoy port and serves until ctx is
// cancelled. Each decoy runs in its own goroutine. A port that fails to
// bind (e.g. already in use, or insufficient privilege for a port <1024)
// is logged as a warning and skipped rather than aborting the whole
// server -- one blocked decoy should never prevent VANGUARD's other
// defenses from starting.
func (s *Server) Start(ctx context.Context) {
	for _, d := range s.decoys {
		s.wg.Add(1)
		go s.serveDecoy(ctx, d)
	}
}

// Wait blocks until every decoy's accept loop and every in-flight
// connection handler goroutine has returned. Callers should cancel the
// context passed to Start and then call Wait before closing the database,
// so no honeypot goroutine can attempt a write after the DB handle is gone.
func (s *Server) Wait() {
	s.wg.Wait()
}

func (s *Server) serveDecoy(ctx context.Context, d Decoy) {
	defer s.wg.Done()

	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", fmt.Sprintf(":%d", d.Port))
	if err != nil {
		log.Printf("[honeypot] WARNING: could not bind decoy port %d (%s): %v -- this decoy is disabled", d.Port, d.Service, err)
		return
	}
	log.Printf("[honeypot] listening on :%d (%s)", d.Port, d.Service)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				log.Printf("[honeypot] accept error on decoy port %d: %v", d.Port, err)
				continue
			}
		}
		s.wg.Add(1)
		go s.handleConn(conn, d)
	}
}

func (s *Server) handleConn(conn net.Conn, d Decoy) {
	defer s.wg.Done()
	defer conn.Close()

	remoteHost, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		remoteHost = conn.RemoteAddr().String()
	}

	hit := Hit{
		SourceIP:  remoteHost,
		Port:      d.Port,
		Service:   d.Service,
		Timestamp: time.Now().UTC(),
	}

	if d.Banner != "" {
		_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.Write([]byte(d.Banner)); err == nil {
			hit.Banner = strings.TrimSpace(d.Banner)
		}
	}

	_ = conn.SetReadDeadline(time.Now().Add(s.readTimeout))
	reader := bufio.NewReader(conn)
	line, _ := reader.ReadString('\n')
	if len(line) > 200 {
		line = line[:200]
	}
	hit.Received = strings.TrimSpace(line)

	// Report immediately -- do not wait for more data. Per spec, ANY
	// connection is sufficient; VANGUARD is not trying to fully capture an
	// attacker's session, just prove intent and hand off to the Autopilot.
	s.handler(hit)
}
