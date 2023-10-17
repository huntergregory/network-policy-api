package connectivity

import (
	"fmt"

	"github.com/mattfenwick/cyclonus/pkg/connectivity/probe"
	"github.com/mattfenwick/cyclonus/pkg/generator"
	"github.com/mattfenwick/cyclonus/pkg/kube"
	"github.com/mattfenwick/cyclonus/pkg/matcher"
	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"sigs.k8s.io/network-policy-api/apis/v1alpha1"
)

// NOTE: this file is temporary to test ANP/BANP expected connectivity

func test(netpols []*networkingv1.NetworkPolicy, anps []*v1alpha1.AdminNetworkPolicy, banp *v1alpha1.BaselineAdminNetworkPolicy) {
	parsedPolicy := matcher.BuildV1AndV2NetPols(false, netpols, anps, banp)
	jobBuilder := &probe.JobBuilder{TimeoutSeconds: 3}
	simRunner := probe.NewSimulatedRunner(parsedPolicy, jobBuilder)

	kubernetes := kube.NewMockKubernetes(1.0)
	resources, err := probe.NewDefaultResources(kubernetes, []string{"x", "y"}, []string{"a", "b"}, []int{80}, []v1.Protocol{v1.ProtocolTCP}, []string{}, 5, false)
	if err != nil {
		panic(err)
	}
	// resources.CreateResourcesInKube(kubernetes)
	stepResult := &StepResult{
		SimulatedProbe: simRunner.RunProbeForConfig(generator.ProbeAllAvailable, resources),
		Policy:         parsedPolicy,
		KubePolicies:   netpols,
		ANPs:           anps,
		BANP:           banp,
	}

	fmt.Printf("Expected ingress:\n%s\n", stepResult.SimulatedProbe.RenderIngress())
	// fmt.Printf("Expected egress:\n%s\n", stepResult.SimulatedProbe.RenderEgress())
	// fmt.Printf("Expected combined:\n%s\n", stepResult.SimulatedProbe.RenderTable())
}
