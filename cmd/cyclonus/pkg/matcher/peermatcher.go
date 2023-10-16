package matcher

import (
	"encoding/json"

	v1 "k8s.io/api/core/v1"
)

var (
	AllPeersPorts = &AllPeersMatcher{}
)

type Effect struct {
	PolicyKind
	Priority int
	Verdict
}

var (
	NoEffect      = Effect{"", 0, None}
	AllowV1Effect = Effect{NetworkPolicyV1, 0, Allow}
)

func NewV1Effect(isAllowed bool) Effect {
	if isAllowed {
		return AllowV1Effect
	}
	return NoEffect
}

type Verdict string

const (
	// None is used to indicate that the peer did not match
	None Verdict = "None"
	// Allow is used to indicate that the peer allowed the traffic. Priorities become relevant for ANP/BANP
	Allow Verdict = "Allow"
	// Deny is used for ANP/BANP to indicate that the peer explicitly denied the traffic. Priorities are relevant.
	// Deny is not used in v1 NetPol.
	Deny Verdict = "Deny"
	// Pass is used for ANP to indicate that the peer passes the traffic down to v1 NetPol. Priorities are relevant.
	// Pass is not used in BANP or v1 NetPol.
	Pass Verdict = "Pass"
)

func (v Verdict) v1Bool() bool {
	return v == Allow
}

type PeerMatcher interface {
	Evaluate(peer *TrafficPeer, portInt int, portName string, protocol v1.Protocol) Effect
}

type AllPeersMatcher struct{}

func (a *AllPeersMatcher) Evaluate(peer *TrafficPeer, portInt int, portName string, protocol v1.Protocol) Effect {
	return AllowV1Effect
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
