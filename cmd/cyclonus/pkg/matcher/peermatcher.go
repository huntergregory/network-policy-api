package matcher

import (
	"encoding/json"

	v1 "k8s.io/api/core/v1"
)

var (
	AllPeersPorts = &AllPeersMatcher{}
)

// Effect is the effect of one or more v1/v2 NetPol rules on a peer.
type Effect struct {
	PolicyKind
	// Priority is only used for ANP (there can only be one BANP).
	// If priority is equal for two rules, the order of the rules matters, and the first rule wins.
	Priority int
	Verdict
}

func NewV1Effect(isAllowed bool) Effect {
	if isAllowed {
		return Effect{NetworkPolicyV1, 0, Allow}
	}
	return Effect{NetworkPolicyV1, 0, Deny}
}

type Verdict string

// Verdicts for v1 NetPols are Allow or Deny.
// Verdicts for ANP are None, Allow, Deny, and Pass.
// Verdicts for BANP are None, Allow, and Deny.
const (
	// None is used for ANP/BANP to indicate that the peer did not match.
	// None can also mean that no
	None Verdict = "None"
	// Allow is used to indicate that the peer allowed the traffic.
	// Priorities become relevant for ANP.
	Allow Verdict = "Allow"
	// Deny is used for v1 NetPol when the Verdict is not Allow.
	// Deny is used for ANP/BANP to indicate that the peer explicitly denied the traffic.
	// Priorities become relevant for ANP.
	Deny Verdict = "Deny"
	// Pass is used for ANP to indicate that the peer passes the traffic down to v1 NetPol. Priorities are relevant.
	Pass Verdict = "Pass"
)

type PeerMatcher interface {
	Evaluate(peer *TrafficPeer, portInt int, portName string, protocol v1.Protocol) Effect
}

type AllPeersMatcher struct{}

func (a *AllPeersMatcher) Evaluate(peer *TrafficPeer, portInt int, portName string, protocol v1.Protocol) Effect {
	return Effect{NetworkPolicyV1, 0, Allow}
}

func (a *AllPeersMatcher) MarshalJSON() (b []byte, e error) {
	return json.Marshal(map[string]interface{}{
		"Type": "all peers",
	})
}

type PortsForAllPeersMatcher struct {
	Port PortMatcher
}

func (a *PortsForAllPeersMatcher) Evaluate(peer *TrafficPeer, portInt int, portName string, protocol v1.Protocol) Effect {
	return NewV1Effect(a.Port.Allows(portInt, portName, protocol))
}

func (a *PortsForAllPeersMatcher) MarshalJSON() (b []byte, e error) {
	return json.Marshal(map[string]interface{}{
		"Type": "all peers for port",
		"Port": a.Port,
	})
}
