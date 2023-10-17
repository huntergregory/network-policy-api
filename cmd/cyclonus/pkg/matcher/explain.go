package matcher

import (
	"fmt"
	"strings"

	"github.com/mattfenwick/collections/pkg/slice"
	"github.com/mattfenwick/cyclonus/pkg/kube"
	"github.com/mattfenwick/cyclonus/pkg/utils"
	"github.com/olekukonko/tablewriter"
	"github.com/pkg/errors"
)

type SliceBuilder struct {
	Prefix   []string
	Elements [][]string
}

func (s *SliceBuilder) Append(items ...string) {
	s.Elements = append(s.Elements, append(s.Prefix, items...))
}

func (p *Policy) ExplainTable() string {
	tableString := &strings.Builder{}
	table := tablewriter.NewWriter(tableString)
	table.SetAutoWrapText(false)
	table.SetRowLine(true)
	table.SetAutoMergeCells(true)
	table.SetHeader([]string{"Type", "Target", "Source rules", "Peer", "Port/Protocol"})

	builder := &SliceBuilder{}
	ingresses, egresses := p.SortedTargets()
	builder.TargetsTableLines(ingresses, true)
	builder.Elements = append(builder.Elements, []string{"", "", "", "", ""})
	builder.TargetsTableLines(egresses, false)

	table.AppendBulk(builder.Elements)

	table.Render()
	return tableString.String()
}

func (s *SliceBuilder) TargetsTableLines(targets []*Target, isIngress bool) {
	var ruleType string
	if isIngress {
		ruleType = "Ingress"
	} else {
		ruleType = "Egress"
	}
	for _, target := range targets {
		sourceRules := slice.Sort(target.SourceRules)
		sourceRulesStrings := make([]string, len(sourceRules), 0)
		for _, rule := range sourceRules {
			sourceRulesStrings = append(sourceRulesStrings, string(rule))
		}
		rules := strings.Join(sourceRulesStrings, "\n")
		s.Prefix = []string{ruleType, target.TargetString(), rules}

		if len(target.Peers) == 0 {
			s.Append("no pods, no ips", "no ports, no protocols")
		} else {
			for _, peer := range slice.SortOn(func(p PeerMatcher) string { return utils.DumpJSON(p) }, target.Peers) {
				switch a := peer.(type) {
				case *AllPeersMatcher:
					s.Append("all pods, all ips", "all ports, all protocols")
				case *PortsForAllPeersMatcher:
					pps := PortMatcherTableLines(a.Port)
					s.Append("all pods, all ips", strings.Join(pps, "\n"))
				case *IPPeerMatcher:
					s.IPPeerMatcherTableLines(a)
				case *PodPeerMatcher:
					s.PodPeerMatcherTableLines(a)
				default:
					panic(errors.Errorf("invalid PeerMatcher type %T", a))
				}
			}
		}
	}
}

func (s *SliceBuilder) IPPeerMatcherTableLines(ip *IPPeerMatcher) {
	peer := ip.IPBlock.CIDR + "\n" + fmt.Sprintf("except %+v", ip.IPBlock.Except)
	pps := PortMatcherTableLines(ip.Port)
	s.Append(peer, strings.Join(pps, "\n"))
}

func (s *SliceBuilder) PodPeerMatcherTableLines(nsPodMatcher *PodPeerMatcher) {
	var namespaces string
	switch ns := nsPodMatcher.Namespace.(type) {
	case *AllNamespaceMatcher:
		namespaces = "all"
	case *LabelSelectorNamespaceMatcher:
		namespaces = kube.LabelSelectorTableLines(ns.Selector)
	case *ExactNamespaceMatcher:
		namespaces = ns.Namespace
	default:
		panic(errors.Errorf("invalid NamespaceMatcher type %T", ns))
	}
	var pods string
	switch p := nsPodMatcher.Pod.(type) {
	case *AllPodMatcher:
		pods = "all"
	case *LabelSelectorPodMatcher:
		pods = kube.LabelSelectorTableLines(p.Selector)
	default:
		panic(errors.Errorf("invalid PodMatcher type %T", p))
	}
	s.Append("namespace: "+namespaces+"\n"+"pods: "+pods, strings.Join(PortMatcherTableLines(nsPodMatcher.Port), "\n"))
}

func PortMatcherTableLines(pm PortMatcher) []string {
	switch port := pm.(type) {
	case *AllPortMatcher:
		return []string{"all ports, all protocols"}
	case *SpecificPortMatcher:
		var lines []string
		for _, portProtocol := range port.Ports {
			if portProtocol.Port == nil {
				lines = append(lines, "all ports on protocol "+string(portProtocol.Protocol))
			} else if portProtocol.Port.StrVal != "" {
				lines = append(lines, fmt.Sprintf("namedport '%s'", portProtocol.Port.StrVal))
			} else {
				lines = append(lines, fmt.Sprintf("port %d on protocol %s", portProtocol.Port.IntVal, portProtocol.Protocol))
			}
		}
		for _, portRange := range port.PortRanges {
			lines = append(lines, fmt.Sprintf("ports [%d, %d] on protocol %s", portRange.From, portRange.To, portRange.Protocol))
		}
		return lines
	default:
		panic(errors.Errorf("invalid PortMatcher type %T", port))
	}
}
