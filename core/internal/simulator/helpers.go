package simulator

import (
	"fmt"
	"math/rand"
)

// randomPublicIP generates a plausible-looking public IPv4 address for
// synthetic attack attribution. It deliberately avoids RFC1918 private
// ranges (10.x, 172.16-31.x, 192.168.x) and the 127.x loopback range so
// simulated incidents are visually indistinguishable from real external
// attacker IPs in the dashboard, while never being a routable address the
// operator might mistake for something to actually investigate on the
// public internet (we bias toward TEST-NET ranges reserved by RFC 5737 for
// documentation/example use: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).
func randomPublicIP() string {
	testNets := [][2]int{
		{192, 0}, // paired with fixed .0.2.x below
	}
	_ = testNets // kept for readability; ranges expanded explicitly below

	switch rand.Intn(3) {
	case 0:
		return fmt.Sprintf("192.0.2.%d", 1+rand.Intn(253))
	case 1:
		return fmt.Sprintf("198.51.100.%d", 1+rand.Intn(253))
	default:
		return fmt.Sprintf("203.0.113.%d", 1+rand.Intn(253))
	}
}

// clampScore keeps a computed risk score within the documented 0-100 range.
func clampScore(score int) int {
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return score
}
