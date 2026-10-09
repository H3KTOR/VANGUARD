package investigate

import (
	"fmt"

	"vanguard/core/internal/database"
)

// Graph is a small, bounded, incident-centred relationship list. Every
// edge is backed by an explicit stored reference (Ref) and carries a
// documented meaning. There are NO time-proximity edges and NO edges
// between actors or hosts: VANGUARD stores no such identity relation.
type Graph struct {
	Nodes     []Node   `json:"nodes"`
	Edges     []Edge   `json:"edges"`
	Truncated bool     `json:"truncated"`
	Notes     []string `json:"notes"`
}

// Node is an incident, indicator or response rule.
type Node struct {
	ID    string `json:"id"` // "<type>:<id>"
	Type  string `json:"type"`
	Label string `json:"label"`
}

// Edge relates two nodes. Relation values and meanings:
//
//	matched            an observation recorded for the incident exactly
//	                   matched the indicator (direct match)
//	matched_context    the incident's source address is listed by the
//	                   indicator; another detector raised the incident
//	triggered_response a firewall rule was created for the incident
//	shares_indicator   both incidents recorded a match to the same
//	                   indicator -- it does NOT establish a common actor
type Edge struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Relation string `json:"relation"`
	Meaning  string `json:"meaning"`
	Ref      string `json:"ref"` // the stored record that justifies the edge
}

const (
	maxGraphNodes         = 50
	maxGraphIndicators    = 10
	maxOthersPerIndicator = 10
)

// BuildGraph returns the depth-1 relationship list for an incident.
func BuildGraph(db *database.DB, inc *database.Incident) (*Graph, error) {
	g := &Graph{Nodes: []Node{}, Edges: []Edge{}, Notes: []string{
		"Edges exist only where a stored record references both ends; nothing is inferred from timing.",
		"Correlated incidents (attack chains) do not store their constituent observations, so no edges to them can be shown.",
	}}
	seenNode := map[string]bool{}
	seenEdge := map[string]bool{}
	addNode := func(n Node) bool {
		if seenNode[n.ID] {
			return true
		}
		if len(g.Nodes) >= maxGraphNodes {
			g.Truncated = true
			return false
		}
		seenNode[n.ID] = true
		g.Nodes = append(g.Nodes, n)
		return true
	}
	addEdge := func(e Edge) {
		k := e.From + "|" + e.To + "|" + e.Relation
		if seenEdge[k] {
			return
		}
		seenEdge[k] = true
		g.Edges = append(g.Edges, e)
	}

	self := fmt.Sprintf("incident:%d", inc.ID)
	addNode(Node{ID: self, Type: "incident", Label: fmt.Sprintf("#%d %s", inc.ID, inc.Type)})

	// Indicators matched by this incident (one edge per indicator).
	var matches []database.IOCMatch
	if err := db.Where("incident_id = ?", inc.ID).Order("id ASC").Limit(200).Find(&matches).Error; err != nil {
		return nil, err
	}
	var iocIDs []uint
	for _, m := range matches {
		id := fmt.Sprintf("indicator:%d", m.IOCID)
		label := fmt.Sprintf("%s %s", m.IOCType, m.Context)
		if !addNode(Node{ID: id, Type: "indicator", Label: label}) {
			continue
		}
		rel, meaning := "matched", "an observation recorded for this incident exactly matched the indicator"
		if m.Kind == "enrichment" {
			rel, meaning = "matched_context", "the incident's source address is listed by the indicator; a different detector raised the incident"
		}
		if !seenEdge[self+"|"+id+"|"+rel] {
			iocIDs = append(iocIDs, m.IOCID)
		}
		addEdge(Edge{From: self, To: id, Relation: rel, Meaning: meaning, Ref: fmt.Sprintf("ioc_matches#%d", m.ID)})
	}

	// Response rules.
	rules, err := db.ListFirewallRulesForIncident(inc.ID, 50)
	if err != nil {
		return nil, err
	}
	for _, r := range rules {
		id := fmt.Sprintf("response:%d", r.ID)
		if !addNode(Node{ID: id, Type: "response_rule", Label: fmt.Sprintf("ban %s (%s)", r.IPAddress, r.Source)}) {
			continue
		}
		addEdge(Edge{From: self, To: id, Relation: "triggered_response", Meaning: "a firewall rule was created for this incident", Ref: fmt.Sprintf("firewall_rules#%d", r.ID)})
	}

	// Other incidents that matched the same indicators (bounded fan-out).
	if len(iocIDs) > maxGraphIndicators {
		iocIDs = iocIDs[:maxGraphIndicators]
		g.Truncated = true
	}
	for _, iid := range iocIDs {
		var others []database.IOCMatch
		if err := db.Where("ioc_id = ? AND incident_id <> ? AND incident_id <> 0", iid, inc.ID).
			Order("id DESC").Limit(maxOthersPerIndicator + 1).Find(&others).Error; err != nil {
			return nil, err
		}
		if len(others) > maxOthersPerIndicator {
			others = others[:maxOthersPerIndicator]
			g.Truncated = true // more incidents share this indicator than are listed
		}
		for _, o := range others {
			oid := fmt.Sprintf("incident:%d", o.IncidentID)
			if !addNode(Node{ID: oid, Type: "incident", Label: fmt.Sprintf("#%d", o.IncidentID)}) {
				continue
			}
			addEdge(Edge{From: self, To: oid, Relation: "shares_indicator",
				Meaning: "both incidents recorded a match to the same indicator; this does not establish the same actor",
				Ref:     fmt.Sprintf("ioc_matches#%d", o.ID)})
		}
	}
	return g, nil
}
