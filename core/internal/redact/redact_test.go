package redact

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestText_Secrets(t *testing.T) {
	cases := map[string]string{
		"password=hunter2":                                                       "hunter2",
		"login failed, Password: hunter2 for root":                               "hunter2",
		`{"token":"abc123def"}`:                                                  "abc123def",
		"Authorization: Bearer eyJhbGciOi.payload.sig":                           "eyJhbGciOi",
		"curl -H 'Cookie: sid=XYZ789'":                                           "XYZ789",
		"api_key=sk_live_123456":                                                 "sk_live_123456",
		"key AKIAABCDEFGHIJKLMNOP leaked":                                        "AKIAABCDEFGHIJKLMNOP",
		"-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----": "MIIEow",
		"-----BEGIN PRIVATE KEY-----\nMIIEvQ-no-end":                             "MIIEvQ",
	}
	for in, leak := range cases {
		out := Text(in)
		if strings.Contains(out, leak) {
			t.Errorf("secret %q survived in %q -> %q", leak, in, out)
		}
	}
}

func TestText_BenignUnchanged(t *testing.T) {
	for _, s := range []string{
		"Resolved: shared office proxy, not an attack",
		"Host 203.0.113.7 scanned ports 22,80,443",
		"the token bucket limiter was tuned", // word 'token' without = or : value
		"password policy reviewed",
	} {
		if got := Text(s); got != s {
			t.Errorf("benign text altered: %q -> %q", s, got)
		}
	}
}

func TestText_BoundedInput(t *testing.T) {
	out := Text(strings.Repeat("A", MaxText*3))
	if len(out) > MaxText+32 {
		t.Fatalf("unbounded: %d", len(out))
	}
}

func TestValue_NestedAndKeyBased(t *testing.T) {
	in := map[string]any{
		"resource": "/etc/app.conf",
		"auth":     map[string]any{"Password": "p1", "ok": "fine"},
		"list":     []any{map[string]any{"api_key": "k1"}, "token=zzz999 inside text"},
		"n":        42.0,
	}
	b, _ := json.Marshal(Value(in))
	s := string(b)
	for _, leak := range []string{"p1", `"k1"`, "zzz999"} {
		if strings.Contains(s, leak) {
			t.Errorf("leak %q in %s", leak, s)
		}
	}
	if !strings.Contains(s, "/etc/app.conf") || !strings.Contains(s, `"ok":"fine"`) || !strings.Contains(s, "42") {
		t.Errorf("benign fields damaged: %s", s)
	}
	// input must not be mutated
	if in["auth"].(map[string]any)["Password"] != "p1" {
		t.Error("Value mutated its input")
	}
}

func TestValue_DepthBounded(t *testing.T) {
	var v any = "leaf"
	for i := 0; i < 50; i++ {
		v = map[string]any{"x": v}
	}
	if !strings.Contains(string(mustJSON(Value(v))), "TRUNCATED") {
		t.Fatal("deep nesting must be cut off")
	}
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }
