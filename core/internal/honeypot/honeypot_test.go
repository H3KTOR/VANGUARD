package honeypot

import (
	"context"
	"net"
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
