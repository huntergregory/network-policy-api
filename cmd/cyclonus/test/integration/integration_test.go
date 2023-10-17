package connectivity

import (
	"testing"

	"github.com/mattfenwick/cyclonus/pkg/connectivity/probe"
	"github.com/mattfenwick/cyclonus/pkg/generator"
	"github.com/mattfenwick/cyclonus/pkg/kube"
	"github.com/mattfenwick/cyclonus/pkg/matcher"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/network-policy-api/apis/v1alpha1"

	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
)

var (
	tcp = v1.ProtocolTCP
	udp = v1.ProtocolUDP
)

type connectivityTest struct {
	name string
	args args
	// exactly one of expectedDrops or expectedAllows should be set
	// if expectedDrops is non-nil, the default will be allow
	// if expectedAllows is non-nil, the default will be deny
	expectedDrops  *directedFlows
	expectedAllows *directedFlows
}

type args struct {
	resources *probe.Resources
	netpols   []*networkingv1.NetworkPolicy
	anps      []*v1alpha1.AdminNetworkPolicy
	banp      *v1alpha1.BaselineAdminNetworkPolicy
}

type directedFlows struct {
	ingress []flow
	egress  []flow
	both    []flow
}

type flow struct {
	from, to string
	port     int
	proto    v1.Protocol
}

func TestNetPolV1Connectivity(t *testing.T) {
	tests := []connectivityTest{
		{
			name: "pod selector",
			args: args{
				resources: getResources(t, []string{"x", "y", "z"}, []string{"a", "b", "c"}, []int{80, 81}, []v1.Protocol{v1.ProtocolTCP, v1.ProtocolUDP}),
				netpols: []*networkingv1.NetworkPolicy{
					{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "x",
							Name:      "base",
						},
						Spec: networkingv1.NetworkPolicySpec{
							PodSelector: metav1.LabelSelector{
								MatchLabels: map[string]string{"pod": "a"},
							},
							Ingress: []networkingv1.NetworkPolicyIngressRule{
								{
									Ports: []networkingv1.NetworkPolicyPort{
										{
											Protocol: &tcp,
											Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 53},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// TODO
		})
	}
}

func TestBANPConnectivity(t *testing.T) {
	tests := []connectivityTest{
		{
			name: "ingress anp same labels port range",
			expectedDrops: &directedFlows{
				ingress: []flow{
					{"x/a", "x/a", 80, v1.ProtocolTCP},
					{"x/a", "x/a", 81, v1.ProtocolTCP},
					{"x/b", "x/a", 80, v1.ProtocolTCP},
					{"x/b", "x/a", 81, v1.ProtocolTCP},
					{"x/c", "x/a", 80, v1.ProtocolTCP},
					{"x/c", "x/a", 81, v1.ProtocolTCP},
				},
			},
			args: args{
				resources: getResources(t, []string{"x", "y", "z"}, []string{"a", "b", "c"}, []int{80, 81}, []v1.Protocol{v1.ProtocolTCP, v1.ProtocolUDP}),
				anps: []*v1alpha1.AdminNetworkPolicy{
					{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "x",
							Name:      "base",
						},
						Spec: v1alpha1.AdminNetworkPolicySpec{
							Priority: 100,
							Subject: v1alpha1.AdminNetworkPolicySubject{
								Pods: &v1alpha1.NamespacedPodSubject{
									NamespaceSelector: metav1.LabelSelector{
										MatchLabels: map[string]string{"ns": "x"},
									},
									PodSelector: metav1.LabelSelector{
										MatchLabels: map[string]string{"pod": "a"},
									},
								},
							},
							Ingress: []v1alpha1.AdminNetworkPolicyIngressRule{
								{
									Action: v1alpha1.AdminNetworkPolicyRuleActionDeny,
									Ports: &([]v1alpha1.AdminNetworkPolicyPort{
										{
											PortRange: &v1alpha1.PortRange{
												Protocol: v1.ProtocolTCP,
												Start:    80,
												End:      81,
											},
										},
									}),
									From: []v1alpha1.AdminNetworkPolicyPeer{
										{
											Pods: &v1alpha1.NamespacedPodPeer{
												Namespaces: v1alpha1.NamespacedPeer{
													SameLabels: []string{"ns"},
												},
												PodSelector: metav1.LabelSelector{},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "ingress anp same labels port range",
			expectedDrops: &directedFlows{
				ingress: []flow{
					{"x/a", "x/a", 80, v1.ProtocolTCP},
					{"x/a", "x/a", 81, v1.ProtocolTCP},
					{"x/a", "x/b", 80, v1.ProtocolTCP},
					{"x/a", "x/b", 81, v1.ProtocolTCP},
					{"x/a", "x/c", 80, v1.ProtocolTCP},
					{"x/a", "x/c", 81, v1.ProtocolTCP},
				},
			},
			args: args{
				resources: getResources(t, []string{"x", "y", "z"}, []string{"a", "b", "c"}, []int{80, 81}, []v1.Protocol{v1.ProtocolTCP, v1.ProtocolUDP}),
				anps: []*v1alpha1.AdminNetworkPolicy{
					{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "x",
							Name:      "base",
						},
						Spec: v1alpha1.AdminNetworkPolicySpec{
							Priority: 100,
							Subject: v1alpha1.AdminNetworkPolicySubject{
								Pods: &v1alpha1.NamespacedPodSubject{
									NamespaceSelector: metav1.LabelSelector{
										MatchLabels: map[string]string{"ns": "x"},
									},
									PodSelector: metav1.LabelSelector{
										MatchLabels: map[string]string{"pod": "a"},
									},
								},
							},
							Egress: []v1alpha1.AdminNetworkPolicyEgressRule{
								{
									Action: v1alpha1.AdminNetworkPolicyRuleActionDeny,
									Ports: &([]v1alpha1.AdminNetworkPolicyPort{
										{
											PortRange: &v1alpha1.PortRange{
												Protocol: v1.ProtocolTCP,
												Start:    80,
												End:      81,
											},
										},
									}),
									To: []v1alpha1.AdminNetworkPolicyPeer{
										{
											Pods: &v1alpha1.NamespacedPodPeer{
												Namespaces: v1alpha1.NamespacedPeer{
													SameLabels: []string{"ns"},
												},
												PodSelector: metav1.LabelSelector{},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			require.True(t, (tt.expectedAllows == nil && tt.expectedDrops != nil) || (tt.expectedAllows != nil && tt.expectedDrops == nil), "exactly one of expectedAllows or expectedDrops")
			var table *probe.Table
			var df *directedFlows
			var newConnectivity probe.Connectivity
			if tt.expectedAllows != nil {
				table = probe.NewTableDefaultDeny(tt.args.resources)
				df = tt.expectedAllows
				newConnectivity = probe.ConnectivityAllowed
			} else {
				table = probe.NewTableDefaultAllow(tt.args.resources)
				df = tt.expectedDrops
				newConnectivity = probe.ConnectivityBlocked
			}

			for _, job := range df.ingress {
				table.SetIngress(newConnectivity, job.from, job.to, job.port, job.proto)
			}

			for _, job := range df.egress {
				table.SetEgress(newConnectivity, job.from, job.to, job.port, job.proto)
			}

			for _, job := range df.both {
				table.SetIngress(newConnectivity, job.from, job.to, job.port, job.proto)
				table.SetEgress(newConnectivity, job.from, job.to, job.port, job.proto)
			}

			parsedPolicy := matcher.BuildV1AndV2NetPols(false, tt.args.netpols, tt.args.anps, tt.args.banp)
			jobBuilder := &probe.JobBuilder{TimeoutSeconds: 3}
			simRunner := probe.NewSimulatedRunner(parsedPolicy, jobBuilder)
			simTable := simRunner.RunProbeForConfig(generator.ProbeAllAvailable, tt.args.resources)

			expected := table.RenderIngress()
			actual := simTable.RenderIngress()
			t.Logf("expected:\n%s\n", expected)
			t.Logf("actual:\n%s\n", actual)
			require.Equal(t, expected, actual)
		})
	}
}

func getResources(t *testing.T, namespaces, podNames []string, ports []int, protocols []v1.Protocol) *probe.Resources {
	kubernetes := kube.NewMockKubernetes(1.0)
	resources, err := probe.NewDefaultResources(kubernetes, namespaces, podNames, ports, protocols, []string{}, 5, false)
	require.Nil(t, err, "failed to create resources")
	return resources
}

// {
// 	Action: v1alpha1.AdminNetworkPolicyRuleActionAllow,
// 	Ports: &([]v1alpha1.AdminNetworkPolicyPort{
// 		{
// 			PortRange: &v1alpha1.PortRange{
// 				Protocol: v1.ProtocolTCP,
// 				Start:    80,
// 				End:      81,
// 			},
// 		},
// 	}),
// 	From: []v1alpha1.AdminNetworkPolicyPeer{
// 		{
// 			Pods: &v1alpha1.NamespacedPodPeer{
// 				Namespaces: v1alpha1.NamespacedPeer{
// 					SameLabels: []string{"ns"},
// 				},
// 				PodSelector: metav1.LabelSelector{
// 					MatchLabels: map[string]string{"pod": "b"},
// 				},
// 			},
// 		},
// 	},
// },
