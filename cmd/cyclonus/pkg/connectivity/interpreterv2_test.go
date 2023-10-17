package connectivity

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/network-policy-api/apis/v1alpha1"

	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
)

func TestBANP(t *testing.T) {
	var netpols []*networkingv1.NetworkPolicy
	var anps []*v1alpha1.AdminNetworkPolicy
	var banp *v1alpha1.BaselineAdminNetworkPolicy

	// netpols = append(netpols, &networkingv1.NetworkPolicy{
	// 	ObjectMeta: metav1.ObjectMeta{
	// 		Namespace: "x",
	// 		Name:      "base",
	// 	},
	// 	Spec: networkingv1.NetworkPolicySpec{
	// 		PodSelector: metav1.LabelSelector{
	// 			MatchLabels: map[string]string{"pod": "a"},
	// 		},
	// 		Ingress: []networkingv1.NetworkPolicyIngressRule{
	// 			{
	// 				From: []networkingv1.NetworkPolicyPeer{
	// 					{
	// 						PodSelector: &metav1.LabelSelector{
	// 							MatchLabels: map[string]string{"pod": "b"},
	// 						},
	// 					},
	// 				},
	// 			},
	// 		},
	// 		PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
	// 	},
	// })

	ports := []v1alpha1.AdminNetworkPolicyPort{
		{
			PortRange: &v1alpha1.PortRange{
				Protocol: v1.ProtocolTCP,
				Start:    80,
				End:      81,
			},
		},
	}

	// FIXME half of it works when == priority
	anps = append(anps, &v1alpha1.AdminNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "x",
			Name:      "base2",
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
					Action: v1alpha1.AdminNetworkPolicyRuleActionAllow,
					Ports:  &ports,
					From: []v1alpha1.AdminNetworkPolicyPeer{
						{
							Pods: &v1alpha1.NamespacedPodPeer{
								Namespaces: v1alpha1.NamespacedPeer{
									SameLabels: []string{"ns"},
								},
								PodSelector: metav1.LabelSelector{
									MatchLabels: map[string]string{"pod": "b"},
								},
							},
						},
					},
				},
				{
					Action: v1alpha1.AdminNetworkPolicyRuleActionDeny,
					Ports:  &ports,
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
	})

	// anps = append(anps, &v1alpha1.AdminNetworkPolicy{
	// 	ObjectMeta: metav1.ObjectMeta{
	// 		Namespace: "x",
	// 		Name:      "base1",
	// 	},
	// 	Spec: v1alpha1.AdminNetworkPolicySpec{
	// 		Priority: 99,
	// 		Subject: v1alpha1.AdminNetworkPolicySubject{
	// 			Pods: &v1alpha1.NamespacedPodSubject{
	// 				NamespaceSelector: metav1.LabelSelector{
	// 					// MatchLabels: map[string]string{"ns": "x"},
	// 				},
	// 				PodSelector: metav1.LabelSelector{
	// 					MatchLabels: map[string]string{"pod": "a"},
	// 				},
	// 			},
	// 		},
	// 		Ingress: []v1alpha1.AdminNetworkPolicyIngressRule{
	// 			{
	// 				Action: v1alpha1.AdminNetworkPolicyRuleActionDeny,
	// 				Ports:  &ports,
	// 				From: []v1alpha1.AdminNetworkPolicyPeer{
	// 					{
	// 						Pods: &v1alpha1.NamespacedPodPeer{
	// 							Namespaces: v1alpha1.NamespacedPeer{
	// 								SameLabels: []string{"ns"},
	// 							},
	// 							PodSelector: metav1.LabelSelector{},
	// 						},
	// 					},
	// 				},
	// 			},
	// 			// {
	// 			// 	Action: v1alpha1.AdminNetworkPolicyRuleActionDeny,
	// 			// 	Ports:  &ports,
	// 			// 	From: []v1alpha1.AdminNetworkPolicyPeer{
	// 			// 		{
	// 			// 			Pods: &v1alpha1.NamespacedPodPeer{
	// 			// 				Namespaces: v1alpha1.NamespacedPeer{
	// 			// 					SameLabels: []string{"ns"},
	// 			// 				},
	// 			// 				PodSelector: metav1.LabelSelector{
	// 			// 					MatchLabels: map[string]string{"pod": "b"},
	// 			// 				},
	// 			// 			},
	// 			// 		},
	// 			// 	},
	// 			// },
	// 		},
	// 	},
	// })

	test(netpols, anps, banp)
}
