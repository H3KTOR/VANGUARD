package honeypot

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestDecoyListenerReportsConnection(t *testing.T) {
	// Use an ephemeral high port unlikely to collide in CI/sandbox
	// environments (real deployments use the documented 2222/33060/8081).
	testPort := 32222

	hits := make(chan Hit, 1)
	srv := NewServer([]Decoy{{Port: testPort, Service: "test-decoy", Banner: "TEST-BANNER\r\n"}}, func(h Hit) {
		hits <- h
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv.Start(ctx)

	// Give the listener goroutine a moment to bind.
	time.Sleep(100 * time.Millisecond)

	conn, err := net.Dial("tcp", "127.0.0.1:32222")
	if err != nil {
		t.Fatalf("failed to connect to decoy listener: %v", err)
	}
	_, _ = conn.Write([]byte("hello decoy\n"))
	// Half-close and drain the banner before closing: an immediate full
	// Close() with the server's banner still unread makes some TCP stacks
	// (observed on Windows) answer with RST and discard the data the
	// server has not read yet. That is a property of this test client, not
	// of the honeypot.
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = io.Copy(io.Discard, conn)
	conn.Close()

	select {
	case hit := <-hits:
		if hit.Port != testPort {
			t.Errorf("expected port %d, got %d", testPort, hit.Port)
		}
		if hit.Service != "test-decoy" {
			t.Errorf("expected service test-decoy, got %s", hit.Service)
		}
		if hit.SourceIP == "" {
			t.Errorf("expected a non-empty source IP")
		}
		if hit.Received != "hello decoy" {
			t.Errorf("expected received data 'hello decoy', got %q", hit.Received)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for honeypot hit callback")
	}
}

func TestUnbindablePortIsSkippedNotFatal(t *testing.T) {
	// Port 1 is a privileged low port that should fail to bind without
	// root, exercising the "log a warning and continue" path without
	// crashing the test.
	hits := make(chan Hit, 1)
	srv := NewServer([]Decoy{{Port: 1, Service: "unbindable"}}, func(h Hit) { hits <- h })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv.Start(ctx)
	time.Sleep(100 * time.Millisecond)

	select {
	case <-hits:
		t.Fatalf("did not expect any hits from an unbindable port")
	default:
		// expected: no panic, no hit, just a skipped decoy
	}
}

// Saturation must bound goroutines AND still report the hit: a connection
// to a decoy is a security signal that may not be dropped.
func TestSaturationShedsWorkButStillReportsEveryHit(t *testing.T) {
	const port = 32299
	var mu sync.Mutex
	var hits []Hit
	srv := NewServer([]Decoy{{Port: port, Service: "sat", Banner: "B\r\n"}}, func(h Hit) {
		mu.Lock()
		hits = append(hits, h)
		mu.Unlock()
	})
	srv.sem = make(chan struct{}, 2) // tiny bound for the test
	srv.readTimeout = 1500 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	srv.Start(ctx)
	time.Sleep(150 * time.Millisecond)

	var conns []net.Conn
	for i := 0; i < 5; i++ {
		c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c) // hold open, send nothing
		time.Sleep(40 * time.Millisecond)
	}
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(hits)
		mu.Unlock()
		if n == 5 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	for _, c := range conns {
		c.Close()
	}
	mu.Lock()
	got := len(hits)
	mu.Unlock()
	st := srv.Stats()
	if got != 5 {
		t.Fatalf("every connection must be reported even under saturation, got %d/5", got)
	}
	if st.Accepted != 2 || st.Shed != 3 || st.BoundPorts != 1 {
		t.Fatalf("stats = %+v (want accepted=2 shed=3 bound=1)", st)
	}
	cancel()
	done := make(chan struct{})
	go func() { srv.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Wait must return after cancellation (no leaked handlers)")
	}
}

func TestBindFailureIsCounted(t *testing.T) {
	ln, err := net.Listen("tcp", ":32298")
	if err != nil {
		t.Skip("cannot reserve test port: ", err)
	}
	defer ln.Close()
	srv := NewServer([]Decoy{{Port: 32298, Service: "taken"}}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	srv.Start(ctx)
	time.Sleep(150 * time.Millisecond)
	cancel()
	srv.Wait()
	if st := srv.Stats(); st.BindFailures != 1 || st.BoundPorts != 0 {
		t.Fatalf("a decoy that could not bind must be visible: %+v", st)
	}
}
