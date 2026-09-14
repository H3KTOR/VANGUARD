package detection

import "testing"

func TestIsProtocolAnomalous_ValidRequest_NotAnomalous(t *testing.T) {
	ev := &Event{Method: "GET", Protocol: "HTTP/1.1", StatusCode: 200}
	if isProtocolAnomalous(ev) {
		t.Fatalf("expected a normal GET/HTTP/1.1/200 request to not be anomalous")
	}
}

func TestIsProtocolAnomalous_InvalidMethod_Anomalous(t *testing.T) {
	ev := &Event{Method: "FOOBAR", Protocol: "HTTP/1.1", StatusCode: 200}
	if !isProtocolAnomalous(ev) {
		t.Fatalf("expected an invalid method to be anomalous")
	}
}

func TestIsProtocolAnomalous_MalformedProtocolToken_Anomalous(t *testing.T) {
	ev := &Event{Method: "GET", Protocol: "GARBAGE", StatusCode: 200}
	if !isProtocolAnomalous(ev) {
		t.Fatalf("expected a malformed protocol token to be anomalous")
	}
}

func TestIsProtocolAnomalous_ProtocolAnomalyStatusCode_Anomalous(t *testing.T) {
	for _, status := range []int{400, 414, 431} {
		ev := &Event{Method: "GET", Protocol: "HTTP/1.1", StatusCode: status}
		if !isProtocolAnomalous(ev) {
			t.Errorf("expected status %d to be anomalous", status)
		}
	}
}

func TestIsProtocolAnomalous_OrdinaryApplicationStatusCode_NotAnomalous(t *testing.T) {
	for _, status := range []int{200, 301, 403, 404, 500} {
		ev := &Event{Method: "GET", Protocol: "HTTP/1.1", StatusCode: status}
		if isProtocolAnomalous(ev) {
			t.Errorf("did not expect ordinary application status %d to be flagged as a protocol anomaly", status)
		}
	}
}

func TestIsProtocolAnomalous_EmptyMethodOrProtocol_MissingFieldSafe(t *testing.T) {
	// Missing-field-data test: an Event with empty Method/Protocol (e.g.
	// from a parser that couldn't fully extract them) must not panic and
	// must not be treated as anomalous purely because the fields are
	// empty -- emptiness means "unknown", not "malformed".
	ev := &Event{StatusCode: 200}
	if isProtocolAnomalous(ev) {
		t.Fatalf("did not expect an Event with merely empty Method/Protocol fields to be flagged")
	}
}

func TestIsWellFormedProtocolToken(t *testing.T) {
	cases := map[string]bool{
		"HTTP/1.1": true, "HTTP/1.0": true, "HTTP/2": true, "HTTP/2.0": true,
		"HTTP/3": true, "": false, "GARBAGE": false, "ftp/1.1": false,
	}
	for tok, want := range cases {
		if got := isWellFormedProtocolToken(tok); got != want {
			t.Errorf("isWellFormedProtocolToken(%q) = %v, want %v", tok, got, want)
		}
	}
}
