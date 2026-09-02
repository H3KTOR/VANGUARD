package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewTelegramNotifierNilWhenUnconfigured(t *testing.T) {
	if n := NewTelegramNotifier("", ""); n != nil {
		t.Fatalf("expected nil notifier when both token and chat ID are empty")
	}
	if n := NewTelegramNotifier("token", ""); n != nil {
		t.Fatalf("expected nil notifier when chat ID is empty")
	}
	if n := NewTelegramNotifier("", "chat"); n != nil {
		t.Fatalf("expected nil notifier when token is empty")
	}
}

func TestNilNotifierMethodsAreSafeNoOps(t *testing.T) {
	var n *TelegramNotifier
	if n.Enabled() {
		t.Fatalf("nil notifier must report Enabled() == false")
	}
	// Must not panic.
	n.Notify(context.Background(), "should not send")
	n.NotifyBan(context.Background(), "1.2.3.4", "ssh_bruteforce", "HIGH", 75, time.Hour, "test")
	n.NotifyPanicMode(context.Background(), true, "test")
}

func TestNotifySendsExpectedPayload(t *testing.T) {
	var received atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body sendMessageRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("failed to decode request body: %v", err)
		}
		received.Store(body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	n := NewTelegramNotifier("test-token", "12345")
	n.apiBase = srv.URL + "/bot%s/sendMessage"

	n.Notify(context.Background(), "hello world")

	got, ok := received.Load().(sendMessageRequest)
	if !ok {
		t.Fatalf("server never received a request")
	}
	if got.ChatID != "12345" {
		t.Errorf("expected chat_id=12345, got %s", got.ChatID)
	}
	if got.Text != "hello world" {
		t.Errorf("expected text='hello world', got %q", got.Text)
	}
}

func TestNotifyBanFormatsExpectedFields(t *testing.T) {
	var received atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body sendMessageRequest
		_ = json.NewDecoder(r.Body).Decode(&body)
		received.Store(body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	n := NewTelegramNotifier("test-token", "12345")
	n.apiBase = srv.URL + "/bot%s/sendMessage"

	n.NotifyBan(context.Background(), "203.0.113.10", "ssh_bruteforce", "HIGH", 75, time.Hour, "Autopilot: brute force")

	got, ok := received.Load().(sendMessageRequest)
	if !ok {
		t.Fatalf("server never received a request")
	}
	for _, want := range []string{"203.0.113.10", "ssh_bruteforce", "HIGH", "75/100", "1h0m0s", "Autopilot: brute force"} {
		if !contains(got.Text, want) {
			t.Errorf("expected notification text to contain %q, got: %s", want, got.Text)
		}
	}
}

func TestNotifyPanicModeEnterAndExit(t *testing.T) {
	var received atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body sendMessageRequest
		_ = json.NewDecoder(r.Body).Decode(&body)
		received.Store(body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	n := NewTelegramNotifier("test-token", "12345")
	n.apiBase = srv.URL + "/bot%s/sendMessage"

	n.NotifyPanicMode(context.Background(), true, "drill")
	got, _ := received.Load().(sendMessageRequest)
	if !contains(got.Text, "ENTERED") {
		t.Errorf("expected ENTERED in text, got: %s", got.Text)
	}

	n.NotifyPanicMode(context.Background(), false, "manual exit")
	got, _ = received.Load().(sendMessageRequest)
	if !contains(got.Text, "EXITED") {
		t.Errorf("expected EXITED in text, got: %s", got.Text)
	}
}

func TestNotifyHandlesNonOKResponseWithoutPanicking(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"ok":false,"description":"bot was blocked"}`))
	}))
	defer srv.Close()

	n := NewTelegramNotifier("test-token", "12345")
	n.apiBase = srv.URL + "/bot%s/sendMessage"

	// Must not panic even on a non-200 response.
	n.Notify(context.Background(), "hello")
}

func TestNotifyHandlesUnreachableServerWithoutPanicking(t *testing.T) {
	n := NewTelegramNotifier("test-token", "12345")
	// Point at a closed server (connection refused).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	n.apiBase = srv.URL + "/bot%s/sendMessage"
	srv.Close()

	// Must not panic even when the network call fails outright.
	n.Notify(context.Background(), "hello")
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
