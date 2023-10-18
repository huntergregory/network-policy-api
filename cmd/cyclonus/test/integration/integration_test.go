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
	// if expectedDrops is non-nil, the default connectivity will be allow
	// if expectedAllows is non-nil, the default connectivity will be deny
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
			name: "ingress port allowed",
			expectedDrops: &directedFlows{
				ingress: []flow{
					{"x/a", "x/a", 80, v1.ProtocolTCP},
					{"x/a", "x/a", 81, v1.ProtocolTCP},
					{"x/a", "x/a", 81, v1.ProtocolUDP},
					{"x/b", "x/a", 80, v1.ProtocolTCP},
					{"x/b", "x/a", 81, v1.ProtocolTCP},
					{"x/b", "x/a", 81, v1.ProtocolUDP},
					{"y/a", "x/a", 80, v1.ProtocolTCP},
					{"y/a", "x/a", 81, v1.ProtocolTCP},
					{"y/a", "x/a", 81, v1.ProtocolUDP},
					{"y/b", "x/a", 80, v1.ProtocolTCP},
					{"y/b", "x/a", 81, v1.ProtocolTCP},
					{"y/b", "x/a", 81, v1.ProtocolUDP},
				},
			},
			args: args{
				resources: getResources(t, []string{"x", "y"}, []string{"a", "b"}, []int{80, 81}, []v1.Protocol{v1.ProtocolTCP, v1.ProtocolUDP}),
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
											Protocol: &udp,
											Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 80},
										},
									},
								},
							},
							PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
						},
					},
				},
			},
		},
	}

	runConnectivityTests(t, tests...)
}

func TestANPConnectivity(t *testing.T) {
	tests := []connectivityTest{
		{
			name: "egress port number protocol unspecified",
			expectedDrops: &directedFlows{
				egress: []flow{
					{"x/a", "x/b", 80, v1.ProtocolTCP},
				},
			},
			args: args{
				resources: getResources(t, []string{"x"}, []string{"a", "b"}, []int{80, 81}, []v1.Protocol{v1.ProtocolTCP}),
				anps: []*v1alpha1.AdminNetworkPolicy{
					{
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
									To: []v1alpha1.AdminNetworkPolicyPeer{
										{
											Pods: &v1alpha1.NamespacedPodPeer{
												Namespaces: v1alpha1.NamespacedPeer{
													NamespaceSelector: &metav1.LabelSelector{
														MatchLabels: map[string]string{"ns": "x"},
													},
												},
												PodSelector: metav1.LabelSelector{
													MatchLabels: map[string]string{"pod": "b"},
												},
											},
										},
									},
									Ports: &([]v1alpha1.AdminNetworkPolicyPort{
										{
											PortNumber: &v1alpha1.Port{
												Port: 80,
											},
										},
									}),
								},
							},
						},
					},
				},
			},
		},
		{
			name: "ingress port number protocol unspecified",
			expectedDrops: &directedFlows{
				ingress: []flow{
					{"x/b", "x/a", 80, v1.ProtocolTCP},
				},
			},
			args: args{
				resources: getResources(t, []string{"x", "y"}, []string{"a", "b"}, []int{80, 81}, []v1.Protocol{v1.ProtocolTCP, v1.ProtocolUDP}),
				anps: []*v1alpha1.AdminNetworkPolicy{
					{
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
									From: []v1alpha1.AdminNetworkPolicyPeer{
										{
											Pods: &v1alpha1.NamespacedPodPeer{
												Namespaces: v1alpha1.NamespacedPeer{
													NamespaceSelector: &metav1.LabelSelector{
														MatchLabels: map[string]string{"ns": "x"},
													},
												},
												PodSelector: metav1.LabelSelector{
													MatchLabels: map[string]string{"pod": "b"},
												},
											},
										},
									},
									Ports: &([]v1alpha1.AdminNetworkPolicyPort{
										{
											PortNumber: &v1alpha1.Port{
												Port: 80,
											},
										},
									}),
								},
							},
						},
					},
				},
			},
		},
		{
			name: "ingress same labels port range",
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
	}

	runConnectivityTests(t, tests[0])
}

func runConnectivityTests(t *testing.T, tests ...connectivityTest) {
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			require.NotNil(t, tt.args.resources, "resources must be set")
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
			t.Logf("expected ingress:\n%s\n", expected)
			t.Logf("actual ingress:\n%s\n", actual)
			require.Equal(t, expected, actual)

			expected = table.RenderEgress()
			actual = simTable.RenderEgress()
			t.Logf("expected egress:\n%s\n", expected)
			t.Logf("actual egress:\n%s\n", actual)
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
