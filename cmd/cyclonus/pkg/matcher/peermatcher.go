package matcher

import (
	"encoding/json"

	"github.com/pkg/errors"
	v1 "k8s.io/api/core/v1"
	"sigs.k8s.io/network-policy-api/apis/v1alpha1"
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

func AdminActionToVerdict(action v1alpha1.AdminNetworkPolicyRuleAction) Verdict {
	switch action {
	case v1alpha1.AdminNetworkPolicyRuleActionAllow:
		return Allow
	case v1alpha1.AdminNetworkPolicyRuleActionDeny:
		return Deny
	case v1alpha1.AdminNetworkPolicyRuleActionPass:
		return Pass
	default:
		panic(errors.Errorf("unsupported ANP action %s", action))
	}
}

func BasaelineAdminActionToVerdict(action v1alpha1.BaselineAdminNetworkPolicyRuleAction) Verdict {
	switch action {
	case v1alpha1.BaselineAdminNetworkPolicyRuleActionAllow:
		return Allow
	case v1alpha1.BaselineAdminNetworkPolicyRuleActionDeny:
		return Deny
	default:
		panic(errors.Errorf("unsupported ANP action %s", action))
	}
}

/*
PeerMatcher matches a peer against an ANP, BANP, or v1 NetPol rule.

These are the original PeerMatcher implementations made for v1 NetPol:
- AllPeersMatcher
- PortsForAllPeersMatcher
- IPPeerMatcher
- PodPeerMatcher

All of these (except AllPeersMatcher) use a PortMatcher.
If the traffic doesn't match the port matcher, then the matcher will Evaluate to a Verdict of None (or Deny for v1 NetPol).

For v2 NetPol, all the above PeerMatchers are irrelevant except for PodPeerMatcher.

TODO
*/
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
	return NewV1Effect(a.Port.Matches(portInt, portName, protocol))
}

func (a *PortsForAllPeersMatcher) MarshalJSON() (b []byte, e error) {
	return json.Marshal(map[string]interface{}{
		"Type": "all peers for port",
		"Port": a.Port,
	})
}
