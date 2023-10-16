package matcher

import (
	"fmt"

	"github.com/mattfenwick/cyclonus/pkg/kube"
	"github.com/pkg/errors"
	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/network-policy-api/apis/v1alpha1"
)

// string of the form "[policyKind] namespace/name"
type NetPolID string

type PolicyKind string

const (
	NetworkPolicyV1            PolicyKind = "NPv1"
	AdminNetworkPolicy         PolicyKind = "ANP"
	BaselineAdminNetworkPolicy PolicyKind = "BANP"
)

func netPolID(p interface{}) NetPolID {
	switch p := p.(type) {
	case *networkingv1.NetworkPolicy:
		return NetPolID(fmt.Sprintf("[%s] %s/%s", NetworkPolicyV1, p.Namespace, p.Name))
	case *v1alpha1.AdminNetworkPolicy:
		return NetPolID(fmt.Sprintf("[%s] %s/%s", AdminNetworkPolicy, p.Namespace, p.Name))
	case *v1alpha1.BaselineAdminNetworkPolicy:
		return NetPolID(fmt.Sprintf("[%s] %s/%s", BaselineAdminNetworkPolicy, p.Namespace, p.Name))
	default:
		panic(fmt.Sprintf("invalid policy type %T", p))
	}
}

// Target represents ingress or egress for one or more NetworkPolicies.
// It can represent either:
// a) one or more v1 NetPols sharing the same Namespace and Pod Selector
// b) one or more ANPs/BANPs sharing the same Namespace Selector and Pod Selector.
type Target struct {
	Namespace   string
	PodSelector metav1.LabelSelector
	Peers       []PeerMatcher
	SourceRules []NetPolID
	primaryKey  string
}

func (t *Target) String() string {
	return t.GetPrimaryKey()
}

func (t *Target) IsMatch(namespace string, podLabels map[string]string) bool {
	return t.Namespace == namespace && kube.IsLabelsMatchLabelSelector(podLabels, t.PodSelector)
}

func (t *Target) Allows(peer *TrafficPeer, portInt int, portName string, protocol v1.Protocol) bool {
	for _, peerMatcher := range t.Peers {
		if peerMatcher.Allows(peer, portInt, portName, protocol) {
			return true
		}
	}
	return false
}

// Combine creates a new Target combining the egress and ingress rules
// of the two original targets.  Neither input is modified.
// The Primary Keys of the two targets must match.
func (t *Target) Combine(other *Target) *Target {
	myPk := t.GetPrimaryKey()
	otherPk := other.GetPrimaryKey()
	if myPk != otherPk {
		panic(errors.Errorf("cannot combine targets: primary keys differ -- '%s' vs '%s'", myPk, otherPk))
	}

	return &Target{
		Namespace:   t.Namespace,
		PodSelector: t.PodSelector,
		Peers:       append(t.Peers, other.Peers...),
		SourceRules: append(t.SourceRules, other.SourceRules...),
	}
}

// FIXME
// GetPrimaryKey returns a deterministic combination of PodSelector and namespace
func (t *Target) GetPrimaryKey() string {
	if t.primaryKey == "" {
		t.primaryKey = fmt.Sprintf(`{"Namespace": "%s", "PodSelector": %s}`, t.Namespace, kube.SerializeLabelSelector(t.PodSelector))
	}
	return t.primaryKey
}

// CombineTargetsIgnoringPrimaryKey creates a new target from the given namespace and pod selector,
// and combines all the edges and source rules from the original targets into the new target.
func CombineTargetsIgnoringPrimaryKey(namespace string, podSelector metav1.LabelSelector, targets []*Target) *Target {
	if len(targets) == 0 {
		return nil
	}
	target := &Target{
		Namespace:   namespace,
		PodSelector: podSelector,
		Peers:       targets[0].Peers,
		SourceRules: targets[0].SourceRules,
	}
	for _, t := range targets[1:] {
		target.Peers = append(target.Peers, t.Peers...)
		target.SourceRules = append(target.SourceRules, t.SourceRules...)
	}
	return target
}

func (t *Target) Simplify() {
	t.Peers = Simplify(t.Peers)
}
