package matcher

import (
	"github.com/mattfenwick/collections/pkg/slice"
	"github.com/pkg/errors"
	"golang.org/x/exp/maps"
)

func Simplify(matchers []PeerMatcher) []PeerMatcher {
	if len(matchers) == 0 {
		return nil
	}

	result := make([]PeerMatcher, 0)
	for _, m := range matchers {
		if matcherV2, ok := m.(*PeerMatcherV2); ok {
			result = append(result, matcherV2)
		}
	}

	result = append(result, SimplifyV1(matchers)...)
	return result
}

// SimplifyV1 simplifies all v1 PeerMatchers, potentially resulting in less PeerMatchers.
func SimplifyV1(matchers []PeerMatcher) []PeerMatcher {
	v1Matchers := make([]PeerMatcher, 0)
	for _, m := range matchers {
		if _, ok := m.(*PeerMatcherV2); !ok {
			v1Matchers = append(v1Matchers, m)
		}
	}

	matchesAll := false
	var portsForAllPeersMatchers []*PortsForAllPeersMatcher
	var ips []*IPPeerMatcher
	var pods []*PodPeerMatcher
	for _, matcher := range v1Matchers {
		switch a := matcher.(type) {
		case *AllPeersMatcher:
			matchesAll = true
		case *PortsForAllPeersMatcher:
			portsForAllPeersMatchers = append(portsForAllPeersMatchers, a)
		case *IPPeerMatcher:
			ips = append(ips, a)
		case *PodPeerMatcher:
			pods = append(pods, a)
		default:
			panic(errors.Errorf("invalid matcher type %T", matcher))
		}
	}
	portsForAllPeersMatcher := simplifyPortsForAllPeers(portsForAllPeersMatchers)
	ips = simplifyIPMatchers(ips)
	pods = simplifyPodMatchers(pods)
	if portsForAllPeersMatcher != nil {
		ips, pods = simplifyIPsAndPodsIntoAlls(portsForAllPeersMatcher, ips, pods)
	}
	return GenerateSimplifiedMatchers(matchesAll, portsForAllPeersMatcher, ips, pods)
}

func simplifyPortsForAllPeers(matchers []*PortsForAllPeersMatcher) *PortsForAllPeersMatcher {
	if len(matchers) == 0 {
		return nil
	}
	port := matchers[0].Port
	for _, a := range matchers[1:] {
		port = CombinePortMatchers(port, a.Port)
	}
	return &PortsForAllPeersMatcher{Port: port}
}

func simplifyPodMatchers(pms []*PodPeerMatcher) []*PodPeerMatcher {
	key := func(ppm *PodPeerMatcher) string { return ppm.PrimaryKey() }
	combine := func(ppms []*PodPeerMatcher) *PodPeerMatcher { return slice.Foldl(CombinePodPeerMatchers, nil, ppms) }
	groupedSimplified := slice.Map(combine, maps.Values(slice.GroupOn(key, pms)))
	//grouped := map[string]*PodPeerMatcher{}
	//for _, pm := range pms {
	//	key := pm.PrimaryKey()
	//	if _, ok := grouped[key]; !ok {
	//		grouped[key] = pm
	//	} else {
	//		grouped[key] = CombinePodPeerMatchers(grouped[key], pm)
	//	}
	//}
	return slice.SortOn(key, groupedSimplified)
}

func simplifyIPMatchers(ims []*IPPeerMatcher) []*IPPeerMatcher {
	grouped := map[string]*IPPeerMatcher{}
	for _, im := range ims {
		key := im.PrimaryKey()
		if _, ok := grouped[key]; !ok {
			grouped[key] = im
		} else {
			grouped[key] = CombineIPPeerMatchers(grouped[key], im)
		}
	}
	return slice.SortOn(func(i *IPPeerMatcher) string { return i.PrimaryKey() }, maps.Values(grouped))
}

func simplifyIPsAndPodsIntoAlls(all *PortsForAllPeersMatcher, ips []*IPPeerMatcher, pods []*PodPeerMatcher) ([]*IPPeerMatcher, []*PodPeerMatcher) {
	var newIps []*IPPeerMatcher
	for _, ip := range ips {
		isEmpty, remainingPorts := SubtractPortMatchers(ip.Port, all.Port)
		if isEmpty {
			// nothing to do
		} else {
			newIps = append(newIps, &IPPeerMatcher{
				IPBlock: ip.IPBlock,
				Port:    remainingPorts,
			})
		}
	}
	var newPods []*PodPeerMatcher
	for _, pod := range pods {
		isEmpty, remainingPorts := SubtractPortMatchers(pod.Port, all.Port)
		if isEmpty {
			// nothing to do
		} else {
			newPods = append(newPods, &PodPeerMatcher{
				Namespace: pod.Namespace,
				Pod:       pod.Pod,
				Port:      remainingPorts,
			})
		}
	}
	return newIps, newPods
}

func GenerateSimplifiedMatchers(matchesAll bool, portsForAllPeersMatcher *PortsForAllPeersMatcher, ips []*IPPeerMatcher, pods []*PodPeerMatcher) []PeerMatcher {
	if matchesAll {
		return []PeerMatcher{AllPeersPorts}
	}
	var matchers []PeerMatcher
	if portsForAllPeersMatcher != nil {
		matchers = append(matchers, portsForAllPeersMatcher)
	}
	for _, ip := range ips {
		matchers = append(matchers, ip)
	}
	for _, pod := range pods {
		matchers = append(matchers, pod)
	}
	return matchers
}

func CombinePortMatchers(a PortMatcher, b PortMatcher) PortMatcher {
	switch l := a.(type) {
	case *AllPortMatcher:
		return a
	case *SpecificPortMatcher:
		switch r := b.(type) {
		case *AllPortMatcher:
			return b
		case *SpecificPortMatcher:
			return l.Combine(r)
		default:
			panic(errors.Errorf("invalid Port type %T", b))
		}
	default:
		panic(errors.Errorf("invalid Port type %T", a))
	}
}

// SubtractPortMatchers finds ports that are in `a` but not in `b`.
// The boolean return value is true if the return value is empty.
// TODO this doesn't handle "all but" cases correctly.
func SubtractPortMatchers(a PortMatcher, b PortMatcher) (bool, PortMatcher) {
	switch l := a.(type) {
	case *AllPortMatcher:
		switch b.(type) {
		case *AllPortMatcher:
			return true, nil
		case *SpecificPortMatcher:
			return false, a
		default:
			panic(errors.Errorf("invalid Port type %T", b))
		}
	case *SpecificPortMatcher:
		switch r := b.(type) {
		case *AllPortMatcher:
			return true, nil
		case *SpecificPortMatcher:
			return l.Subtract(r)
		default:
			panic(errors.Errorf("invalid Port type %T", b))
		}
	default:
		panic(errors.Errorf("invalid Port type %T", a))
	}
}

func CombinePodPeerMatchers(a *PodPeerMatcher, b *PodPeerMatcher) *PodPeerMatcher {
	if a == nil {
		return b
	}
	if a.PrimaryKey() != b.PrimaryKey() {
		panic(errors.Errorf("cannot combine PodPeerMatchers of different pks: %s vs. %s", a.PrimaryKey(), b.PrimaryKey()))
	}
	return &PodPeerMatcher{
		Namespace: a.Namespace,
		Pod:       a.Pod,
		Port:      CombinePortMatchers(a.Port, b.Port),
	}
}

func CombineIPPeerMatchers(a *IPPeerMatcher, b *IPPeerMatcher) *IPPeerMatcher {
	if a.PrimaryKey() != b.PrimaryKey() {
		panic(errors.Errorf("unable to combine IPPeerMatcher values with different primary keys: %s vs %s", a.PrimaryKey(), b.PrimaryKey()))
	}
	return &IPPeerMatcher{
		IPBlock: a.IPBlock,
		Port:    CombinePortMatchers(a.Port, b.Port),
	}
}
