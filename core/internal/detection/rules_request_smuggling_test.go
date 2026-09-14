package detection

import "testing"

func TestIsRequestSmugglingSymptomStatus(t *testing.T) {
	cases := map[int]bool{
		400: true, 408: true, 502: true, 503: true,
		200: false, 301: false, 403: false, 404: false, 414: false, 431: false, 500: false, 504: false,
	}
	for status, want := range cases {
		if got := isRequestSmugglingSymptomStatus(status); got != want {
			t.Errorf("isRequestSmugglingSymptomStatus(%d) = %v, want %v", status, got, want)
		}
	}
}
