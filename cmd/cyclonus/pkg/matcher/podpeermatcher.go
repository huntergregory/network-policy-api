package matcher

import (
	"encoding/json"
	"fmt"

	"github.com/mattfenwick/cyclonus/pkg/kube"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PodPeerMatcher matches a Peer in Pod to Pod traffic against an ANP, BANP, or v1 NetPol rule.
// It accounts for Namespace, Pod, and Port/Protocol.
type PodPeerMatcher struct {
	Namespace NamespaceMatcher
	Pod       PodMatcher
	Port      PortMatcher
	// v2Kind is used for ANP/BANP.
	// v1 NetPol should not use this field.
	v2Kind PolicyKind
	// v2Verdict is used for ANP/BANP.
	// v1 NetPol should not use this field.
	v2Verdict Verdict
	// v2Priority is used for ANP.
	// v1 NetPol and BANP should not use this field.
	v2Priority int
}

// NewPodPeerMatcherANP creates a new PodPeerMatcher for an ANP rule.
func NewPodPeerMatcherANP(ns NamespaceMatcher, pod PodMatcher, port PortMatcher, v Verdict, priority int) *PodPeerMatcher {
	return &PodPeerMatcher{
		Namespace:  ns,
		Pod:        pod,
		Port:       port,
		v2Kind:     AdminNetworkPolicy,
		v2Verdict:  v,
		v2Priority: priority,
	}
}

// NewPodPeerMatcherANP creates a new PodPeerMatcher for a BANP rule.
func NewPodPeerMatcherBANP(ns NamespaceMatcher, pod PodMatcher, port PortMatcher, v Verdict) *PodPeerMatcher {
	return &PodPeerMatcher{
		Namespace: ns,
		Pod:       pod,
		Port:      port,
		v2Kind:    BaselineAdminNetworkPolicy,
		v2Verdict: v,
	}
}

func (ppm *PodPeerMatcher) PrimaryKey() string {
	return ppm.Namespace.PrimaryKey() + "---" + ppm.Pod.PrimaryKey()
}

func (ppm *PodPeerMatcher) Evaluate(peer *TrafficPeer, portInt int, portName string, protocol v1.Protocol) Effect {
	isMatch := !peer.IsExternal() && ppm.Namespace.Allows(peer.Internal.Namespace, peer.Internal.NamespaceLabels) &&
		ppm.Pod.Allows(peer.Internal.PodLabels) &&
		ppm.Port.Matches(portInt, portName, protocol)

	if ppm.v2Verdict != "" && ppm.v2Kind != "" {
		// ANP or BANP rule
		e := Effect{
			PolicyKind: ppm.v2Kind,
			Priority:   ppm.v2Priority,
			Verdict:    None,
		}

		if isMatch {
			e.Verdict = ppm.v2Verdict
		}

		return e
	}

	// v1 NetPol rule
	return NewV1Effect(isMatch)
}

// PodMatcher possibilities:
// 1. PodSelector:
//   - empty/nil
//   - not empty
// 2. NamespaceSelector
//   - nil
//   - empty
//   - not empty
//
// Combined:
// 1. all pods in policy namespace
//   - empty/nil PodSelector
//   - nil NamespaceSelector
//
// 2. all pods in all namespaces
//   - empty/nil PodSelector
//   - empty NamespaceSelector
//
// 3. all pods in matching namespaces
//   - empty/nil PodSelector
//   - not empty NamespaceSelector
//
// 4. matching pods in policy namespace
//   - not empty PodSelector
//   - nil NamespaceSelector
//
// 5. matching pods in all namespaces
//   - not empty PodSelector
//   - empty NamespaceSelector
//
// 6. matching pods in matching namespaces
//   - not empty PodSelector
//   - not empty NamespaceSelector
//
// 7. everything
//   - don't have anything at all -- i.e. empty []NetworkPolicyPeer
//

type PodMatcher interface {
	Allows(podLabels map[string]string) bool
	PrimaryKey() string
}

type AllPodMatcher struct{}

func (p *AllPodMatcher) Allows(podLabels map[string]string) bool {
	return true
}

func (p *AllPodMatcher) MarshalJSON() (b []byte, e error) {
	return json.Marshal(map[string]interface{}{
		"Type": "all pods",
	})
}

func (p *AllPodMatcher) PrimaryKey() string {
	return `{"type": "all-pods"}`
}

type LabelSelectorPodMatcher struct {
	Selector metav1.LabelSelector
}

func (p *LabelSelectorPodMatcher) Allows(podLabels map[string]string) bool {
	return kube.IsLabelsMatchLabelSelector(podLabels, p.Selector)
}

func (p *LabelSelectorPodMatcher) MarshalJSON() (b []byte, e error) {
	return json.Marshal(map[string]interface{}{
		"Type":     "matching pods by label",
		"Selector": p.Selector,
	})
}

func (p *LabelSelectorPodMatcher) PrimaryKey() string {
	return fmt.Sprintf(`{"type": "label-selector", "selector": "%s"}`, kube.SerializeLabelSelector(p.Selector))
}

// namespaces

type NamespaceMatcher interface {
	Allows(namespace string, namespaceLabels map[string]string) bool
	PrimaryKey() string
}

type ExactNamespaceMatcher struct {
	Namespace string
}

func (p *ExactNamespaceMatcher) Allows(namespace string, namespaceLabels map[string]string) bool {
	return p.Namespace == namespace
}

func (p *ExactNamespaceMatcher) MarshalJSON() (b []byte, e error) {
	return json.Marshal(map[string]interface{}{
		"Type":      "specific namespace",
		"Namespace": p.Namespace,
	})
}

func (p *ExactNamespaceMatcher) PrimaryKey() string {
	return fmt.Sprintf(`{"type": "exact-namespace", "namespace": "%s"}`, p.Namespace)
}

type LabelSelectorNamespaceMatcher struct {
	Selector metav1.LabelSelector
}

func (p *LabelSelectorNamespaceMatcher) Allows(namespace string, namespaceLabels map[string]string) bool {
	return kube.IsLabelsMatchLabelSelector(namespaceLabels, p.Selector)
}

func (p *LabelSelectorNamespaceMatcher) MarshalJSON() (b []byte, e error) {
	return json.Marshal(map[string]interface{}{
		"Type":     "matching namespace by label",
		"Selector": p.Selector,
	})
}

func (p *LabelSelectorNamespaceMatcher) PrimaryKey() string {
	return fmt.Sprintf(`{"type": "label-selector", "selector": "%s"}`, kube.SerializeLabelSelector(p.Selector))
}

type AllNamespaceMatcher struct{}

func (a *AllNamespaceMatcher) Allows(namespace string, namespaceLabels map[string]string) bool {
	return true
}

func (a *AllNamespaceMatcher) MarshalJSON() (b []byte, e error) {
	return json.Marshal(map[string]interface{}{
		"Type": "all namespaces",
	})
}

func (a *AllNamespaceMatcher) PrimaryKey() string {
	return `{"type": "all-namespaces"}`
}
