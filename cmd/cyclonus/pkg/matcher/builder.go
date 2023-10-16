package matcher

import (
	"fmt"

	"github.com/mattfenwick/cyclonus/pkg/kube"
	"github.com/pkg/errors"
	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/network-policy-api/apis/v1alpha1"
)

func BuildNetworkPolicies(simplify bool, netpols []*networkingv1.NetworkPolicy) *Policy {
	return BuildV2NetworkPolicies(simplify, netpols, nil, nil)
}

func BuildV2NetworkPolicies(simplify bool, netpols []*networkingv1.NetworkPolicy, ANPs []*v1alpha1.AdminNetworkPolicy, BANPs []*v1alpha1.BaselineAdminNetworkPolicy) *Policy {
	np := NewPolicy()
	for _, policy := range netpols {
		ingress, egress := BuildTarget(policy)
		if ingress != nil {
			np.AddTarget(true, ingress)
		}
		if egress != nil {
			np.AddTarget(false, egress)
		}
	}

	for _, anp := range ANPs {
		// TODO
		fmt.Printf("TODO: build ANP %s\n", anp.Name)
	}

	for _, banp := range BANPs {
		// TODO
		fmt.Printf("TODO: build ANP %s\n", banp.Name)

	}

	if simplify {
		np.Simplify()
	}
	return np
}

func getPolicyNamespace(policy *networkingv1.NetworkPolicy) string {
	if policy.Namespace == "" {
		return v1.NamespaceDefault
	}
	return policy.Namespace
}

func BuildTargetAdmin(netpol *v1alpha1.AdminNetworkPolicy) (*Target, *Target) {
	return nil, nil
}

func BuildTargetBaselineAdmin(netpol *v1alpha1.BaselineAdminNetworkPolicy) (*Target, *Target) {
	return nil, nil
}

func BuildTarget(netpol *networkingv1.NetworkPolicy) (*Target, *Target) {
	var ingress *Target
	var egress *Target
	if len(netpol.Spec.PolicyTypes) == 0 {
		panic(errors.Errorf("invalid network policy: need at least 1 type"))
	}
	policyNamespace := getPolicyNamespace(netpol)
	for _, pType := range netpol.Spec.PolicyTypes {
		switch pType {
		case networkingv1.PolicyTypeIngress:
			ingress = &Target{
				Namespace:   policyNamespace,
				PodSelector: netpol.Spec.PodSelector,
				SourceRules: []NetPolID{netPolID(netpol)},
				Peers:       BuildIngressMatcher(policyNamespace, netpol.Spec.Ingress),
			}
		case networkingv1.PolicyTypeEgress:
			egress = &Target{
				Namespace:   policyNamespace,
				PodSelector: netpol.Spec.PodSelector,
				SourceRules: []NetPolID{netPolID(netpol)},
				Peers:       BuildEgressMatcher(policyNamespace, netpol.Spec.Egress),
			}
		}
	}
	return ingress, egress
}

func BuildIngressMatcher(policyNamespace string, ingresses []networkingv1.NetworkPolicyIngressRule) []PeerMatcher {
	var matchers []PeerMatcher
	for _, ingress := range ingresses {
		matchers = append(matchers, BuildPeerMatcher(policyNamespace, ingress.Ports, ingress.From)...)
	}
	return matchers
}

func BuildEgressMatcher(policyNamespace string, egresses []networkingv1.NetworkPolicyEgressRule) []PeerMatcher {
	var matchers []PeerMatcher
	for _, egress := range egresses {
		matchers = append(matchers, BuildPeerMatcher(policyNamespace, egress.Ports, egress.To)...)
	}
	return matchers
}

func BuildPeerMatcher(policyNamespace string, npPorts []networkingv1.NetworkPolicyPort, peers []networkingv1.NetworkPolicyPeer) []PeerMatcher {
	if len(npPorts) == 0 && len(peers) == 0 {
		return []PeerMatcher{AllPeersPorts}
	}
	// 1. build port matcher
	port := BuildPortMatcher(npPorts)
	// 2. build Peers
	if len(peers) == 0 {
		return []PeerMatcher{&PortsForAllPeersMatcher{Port: port}}
	}

	var matchers []PeerMatcher
	for _, from := range peers {
		ip, ns, pod := BuildIPBlockNamespacePodMatcher(policyNamespace, from)
		// invalid netpol guards
		if ip == nil && ns == nil && pod == nil {
			panic(errors.Errorf("invalid NetworkPolicyPeer: all of IPBlock, NamespaceSelector, and PodSelector are nil"))
		}
		if ip != nil && (ns != nil || pod != nil) {
			panic(errors.Errorf("invalid NetworkPolicyPeer: if NamespaceSelector or PodSelector is non-nil, IPBlock must be nil"))
		}
		// process a valid netpol
		if ip != nil {
			ip.Port = port
			matchers = append(matchers, ip)
		} else {
			matchers = append(matchers, &PodPeerMatcher{
				Namespace: ns,
				Pod:       pod,
				Port:      port,
			})
		}
	}
	return matchers
}

func BuildIPBlockNamespacePodMatcher(policyNamespace string, peer networkingv1.NetworkPolicyPeer) (*IPPeerMatcher, NamespaceMatcher, PodMatcher) {
	if peer.IPBlock != nil {
		return &IPPeerMatcher{
			IPBlock: peer.IPBlock,
			Port:    nil, // remember to set this elsewhere!
		}, nil, nil
	}

	podSel := peer.PodSelector
	var podMatcher PodMatcher
	if podSel == nil || kube.IsLabelSelectorEmpty(*podSel) {
		podMatcher = &AllPodMatcher{}
	} else {
		podMatcher = &LabelSelectorPodMatcher{Selector: *podSel}
	}

	nsSel := peer.NamespaceSelector
	var nsMatcher NamespaceMatcher
	if nsSel == nil {
		nsMatcher = &ExactNamespaceMatcher{Namespace: policyNamespace}
	} else if kube.IsLabelSelectorEmpty(*nsSel) {
		nsMatcher = &AllNamespaceMatcher{}
	} else {
		nsMatcher = &LabelSelectorNamespaceMatcher{Selector: *nsSel}
	}

	return nil, nsMatcher, podMatcher
}

func BuildPortMatcher(npPorts []networkingv1.NetworkPolicyPort) PortMatcher {
	if len(npPorts) == 0 {
		return &AllPortMatcher{}
	} else {
		matcher := &SpecificPortMatcher{}
		for _, p := range npPorts {
			singlePort, portRange := BuildSinglePortMatcher(p)
			if singlePort != nil {
				matcher.Ports = append(matcher.Ports, singlePort)
			} else {
				matcher.PortRanges = append(matcher.PortRanges, portRange)
			}
		}
		return matcher
	}
}

func BuildSinglePortMatcher(npPort networkingv1.NetworkPolicyPort) (*PortProtocolMatcher, *PortRangeMatcher) {
	protocol := v1.ProtocolTCP
	if npPort.Protocol != nil {
		protocol = *npPort.Protocol
	}
	if npPort.EndPort == nil {
		return &PortProtocolMatcher{
			Port:     npPort.Port,
			Protocol: protocol,
		}, nil
	}
	// we have a port range: make sure it's valid
	if npPort.Port == nil {
		panic(errors.Errorf("invalid port range: start port is nil"))
	}
	if npPort.Port.Type == intstr.String {
		panic(errors.Errorf("invalid port range: start port is string"))
	}
	if *npPort.EndPort < npPort.Port.IntVal {
		panic(errors.Errorf("invalid port range: end port < start port"))
	}
	return nil, &PortRangeMatcher{
		From:     int(npPort.Port.IntVal),
		To:       int(*npPort.EndPort),
		Protocol: protocol,
	}
}
