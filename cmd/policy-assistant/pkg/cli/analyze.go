package cli

import (
	"fmt"
	"strings"

	"github.com/mattfenwick/cyclonus/examples"
	"github.com/mattfenwick/cyclonus/pkg/kube/netpol"
	"github.com/olekukonko/tablewriter"
	"sigs.k8s.io/network-policy-api/apis/v1alpha1"

	"github.com/mattfenwick/collections/pkg/json"
	"github.com/mattfenwick/cyclonus/pkg/connectivity/probe"
	"github.com/mattfenwick/cyclonus/pkg/generator"

	"github.com/mattfenwick/cyclonus/pkg/kube"
	"github.com/mattfenwick/cyclonus/pkg/matcher"
	"github.com/mattfenwick/cyclonus/pkg/utils"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// ParseMode        = "parse"
	ExplainMode = "explain"
	// QueryTrafficMode = "query-traffic"
	// QueryTargetMode  = "query-target"
	ProbeMode              = "probe"
	VerdictWalkthroughMode = "verdict"
)

var AllModes = []string{
	// ParseMode,
	ExplainMode,
	// QueryTrafficMode,
	// QueryTargetMode,
	ProbeMode,
	VerdictWalkthroughMode,
}

type AnalyzeArgs struct {
	AllNamespaces      bool
	Namespaces         []string
	UseExamplePolicies bool
	PolicyPath         string
	Context            string
	SimplifyPolicies   bool

	Modes []string

	// traffic
	TrafficPath string

	// targets
	TargetPodPath string

	// synthetic probe
	ProbePath string
}

func SetupAnalyzeCommand() *cobra.Command {
	args := &AnalyzeArgs{}

	command := &cobra.Command{
		Use:   "analyze",
		Short: "analyze network policies",
		Args:  cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, as []string) {
			RunAnalyzeCommand(args)
		},
	}

	command.Flags().BoolVar(&args.UseExamplePolicies, "use-example-policies", false, "if true, reads example policies")
	command.Flags().BoolVarP(&args.AllNamespaces, "all-namespaces", "A", false, "reads kube resources from all namespaces; same as kubectl's '--all-namespaces'/'-A' flag")
	command.Flags().StringSliceVarP(&args.Namespaces, "namespace", "n", []string{}, "namespaces to read kube resources from; similar to kubectl's '--namespace'/'-n' flag, except that multiple namespaces may be passed in and is empty if not set explicitly (instead of 'default' as in kubectl)")
	command.Flags().StringVar(&args.PolicyPath, "policy-path", "", "may be a file or a directory; if set, will attempt to read policies from the path")
	command.Flags().StringVar(&args.Context, "context", "", "selects kube context to read policies from; only reads from kube if one or more namespaces or all namespaces are specified")
	command.Flags().BoolVar(&args.SimplifyPolicies, "simplify-policies", false, "if true, reduce policies to simpler form while preserving semantics")

	command.Flags().StringSliceVar(&args.Modes, "mode", []string{ExplainMode}, "analysis modes to run; allowed values are "+strings.Join(AllModes, ","))

	command.Flags().StringVar(&args.TargetPodPath, "target-pod-path", "", "path to json target pod file -- json array of dicts")
	command.Flags().StringVar(&args.TrafficPath, "traffic-path", "", "path to json traffic file, containing of a list of traffic objects")
	command.Flags().StringVar(&args.ProbePath, "probe-path", "", "path to json model file for synthetic probe")

	return command
}

func RunAnalyzeCommand(args *AnalyzeArgs) {
	// 1. read policies from kube
	var kubePolicies []*networkingv1.NetworkPolicy
	var kubeANPs []*v1alpha1.AdminNetworkPolicy
	var kubeBANP *v1alpha1.BaselineAdminNetworkPolicy
	var kubePods []v1.Pod
	var kubeNamespaces []v1.Namespace
	if args.AllNamespaces || len(args.Namespaces) > 0 {
		kubeClient, err := kube.NewKubernetesForContext(args.Context)
		utils.DoOrDie(err)

		namespaces := args.Namespaces
		if args.AllNamespaces {
			nsList, err := kubeClient.GetAllNamespaces()
			utils.DoOrDie(err)
			kubeNamespaces = nsList.Items
			namespaces = []string{v1.NamespaceAll}
		}
		kubePolicies, err = kube.ReadNetworkPoliciesFromKube(kubeClient, namespaces)
		if err != nil {
			logrus.Errorf("unable to read network policies from kube, ns '%s': %+v", namespaces, err)
		}
		kubePods, err = kube.GetPodsInNamespaces(kubeClient, namespaces)
		if err != nil {
			logrus.Errorf("unable to read pods from kube, ns '%s': %+v", namespaces, err)
		}
	}

	// 2. read policies from file
	if args.PolicyPath != "" {
		policiesFromPath, err := kube.ReadNetworkPoliciesFromPath(args.PolicyPath + "/npv1")
		utils.DoOrDie(err)
		kubePolicies = append(kubePolicies, policiesFromPath...)

		kubeANPs, err = kube.ReadANPs(args.PolicyPath + "/anp")
		utils.DoOrDie(err)

		kubeBANP, err = kube.ReadBANP(args.PolicyPath + "/banp")
		utils.DoOrDie(err)
	}

	// 3. read example policies
	if args.UseExamplePolicies {
		kubePolicies = append(kubePolicies, netpol.AllExamples...)

		kubeANPs = examples.CoreGressRulesCombinedANB
		kubeBANP = examples.CoreGressRulesCombinedBANB
	}

	logrus.Debugf("parsed policies:\n%s", json.MustMarshalToString(kubePolicies))
	policies := matcher.BuildV1AndV2NetPols(args.SimplifyPolicies, kubePolicies, kubeANPs, kubeBANP)

	for _, mode := range args.Modes {
		switch mode {
		// case ParseMode:
		// 	fmt.Println("parsed policies:")
		// 	ParsePolicies(kubePolicies)
		case ExplainMode:
			fmt.Println("explained policies:")
			ExplainPolicies(policies)
		// case QueryTargetMode:
		// 	pods := make([]*QueryTargetPod, len(kubePods))
		// 	for i, p := range kubePods {
		// 		pods[i] = &QueryTargetPod{
		// 			Namespace: p.Namespace,
		// 			Labels:    p.Labels,
		// 		}
		// 	}
		// 	fmt.Println("query target:")
		// 	QueryTargets(policies, args.TargetPodPath, pods)
		// case QueryTrafficMode:
		// 	fmt.Println("query traffic:")
		// 	QueryTraffic(policies, args.TrafficPath)
		case ProbeMode:
			fmt.Println("simulated connectivity:")
			ProbeSyntheticConnectivity(policies, args.ProbePath, kubePods, kubeNamespaces)
		case VerdictWalkthroughMode:
			fmt.Println("verdict walkthrough:")
			VerdictWalkthrough(policies)
		default:
			panic(errors.Errorf("unrecognized mode %s", mode))
		}
	}
}

func ParsePolicies(kubePolicies []*networkingv1.NetworkPolicy) {
	fmt.Println(kube.NetworkPoliciesToTable(kubePolicies))
}

func ExplainPolicies(explainedPolicies *matcher.Policy) {
	fmt.Printf("%s\n", explainedPolicies.ExplainTable())
}

// QueryTargetPod matches targets; targets exist in only a single namespace and can't be matched by namespace
//
//	label, therefore we match by exact namespace and by pod labels.
type QueryTargetPod struct {
	Namespace string
	Labels    map[string]string
}

func QueryTargets(explainedPolicies *matcher.Policy, podPath string, pods []*QueryTargetPod) {
	if podPath != "" {
		podsFromFile, err := json.ParseFile[[]*QueryTargetPod](podPath)
		utils.DoOrDie(err)
		pods = append(pods, *podsFromFile...)
	}

	for _, pod := range pods {
		fmt.Printf("pod in ns %s with labels %+v:\n\n", pod.Namespace, pod.Labels)

		targets, combinedRules := QueryTargetHelper(explainedPolicies, pod)

		fmt.Printf("Matching targets:\n%s\n", targets.ExplainTable())
		fmt.Printf("Combined rules:\n%s\n\n\n", combinedRules.ExplainTable())
	}
}

func QueryTargetHelper(policies *matcher.Policy, pod *QueryTargetPod) (*matcher.Policy, *matcher.Policy) {
	podInfo := &matcher.InternalPeer{
		Namespace: pod.Namespace,
		PodLabels: pod.Labels,
	}
	ingressTargets := policies.TargetsApplyingToPod(true, podInfo)
	combinedIngressTarget := matcher.CombineTargetsIgnoringPrimaryKey(pod.Namespace, metav1.LabelSelector{MatchLabels: pod.Labels}, ingressTargets)

	egressTargets := policies.TargetsApplyingToPod(false, podInfo)
	combinedEgressTarget := matcher.CombineTargetsIgnoringPrimaryKey(pod.Namespace, metav1.LabelSelector{MatchLabels: pod.Labels}, egressTargets)

	var combinedIngresses []*matcher.Target
	if combinedIngressTarget != nil {
		combinedIngresses = []*matcher.Target{combinedIngressTarget}
	}
	var combinedEgresses []*matcher.Target
	if combinedEgressTarget != nil {
		combinedEgresses = []*matcher.Target{combinedEgressTarget}
	}

	return matcher.NewPolicyWithTargets(ingressTargets, egressTargets), matcher.NewPolicyWithTargets(combinedIngresses, combinedEgresses)
}

func QueryTraffic(explainedPolicies *matcher.Policy, trafficPath string) {
	if trafficPath == "" {
		logrus.Fatalf("%+v", errors.Errorf("path to traffic file required for QueryTraffic command"))
	}
	allTraffics, err := json.ParseFile[[]*matcher.Traffic](trafficPath)
	utils.DoOrDie(err)

	for _, traffic := range *allTraffics {
		fmt.Printf("Traffic:\n%s\n", traffic.Table())

		result := explainedPolicies.IsTrafficAllowed(traffic)
		fmt.Printf("Is traffic allowed?\n%s\n\n\n", result.Table())
	}
}

type SyntheticProbeConnectivityConfig struct {
	Resources *probe.Resources
	Probes    []*generator.PortProtocol
}

func ProbeSyntheticConnectivity(explainedPolicies *matcher.Policy, modelPath string, kubePods []v1.Pod, kubeNamespaces []v1.Namespace) {
	if modelPath != "" {
		config, err := json.ParseFile[SyntheticProbeConnectivityConfig](modelPath)
		utils.DoOrDie(err)

		jobBuilder := &probe.JobBuilder{TimeoutSeconds: 10}

		// FIXME JSON-defined resources not working?
		if len(config.Probes) == 0 {
			gen := generator.ProbeAllAvailable
			simRunner := probe.NewSimulatedRunner(explainedPolicies, jobBuilder)

			probeResult := simRunner.RunProbeForConfig(gen, config.Resources)

			logrus.Info("probing all available ports")
			fmt.Printf("Ingress:\n%s\n", probeResult.RenderIngress())
			fmt.Printf("Egress:\n%s\n", probeResult.RenderEgress())
			fmt.Printf("Combined:\n%s\n\n\n", probeResult.RenderTable())

			return
		}

		// run probes
		for _, probeConfig := range config.Probes {
			gen := generator.NewProbeConfig(probeConfig.Port, probeConfig.Protocol, generator.ProbeModeServiceName)
			simRunner := probe.NewSimulatedRunner(explainedPolicies, jobBuilder)
			probeResult := simRunner.RunProbeForConfig(gen, config.Resources)

			logrus.Infof("probe on port %s, protocol %s", probeConfig.Port.String(), probeConfig.Protocol)
			fmt.Printf("Ingress:\n%s\n", probeResult.RenderIngress())
			fmt.Printf("Egress:\n%s\n", probeResult.RenderEgress())
			fmt.Printf("Combined:\n%s\n\n\n", probeResult.RenderTable())
		}

		return
	}

	// resources := &probe.Resources{
	// 	Namespaces: map[string]map[string]string{},
	// 	Pods:       []*probe.Pod{},
	// }

	// nsMap := map[string]v1.Namespace{}
	// for _, ns := range kubeNamespaces {
	// 	nsMap[ns.Name] = ns
	// 	resources.Namespaces[ns.Name] = ns.Labels
	// }

	// for _, pod := range kubePods {
	// 	var containers []*probe.Container
	// 	for _, cont := range pod.Spec.Containers {
	// 		if len(cont.Ports) == 0 {
	// 			logrus.Warnf("skipping container %s/%s/%s, no ports available", pod.Namespace, pod.Name, cont.Name)
	// 			continue
	// 		}
	// 		port := cont.Ports[0]
	// 		containers = append(containers, &probe.Container{
	// 			Name:     cont.Name,
	// 			Port:     int(port.ContainerPort),
	// 			Protocol: port.Protocol,
	// 			PortName: port.Name,
	// 		})
	// 	}
	// 	if len(containers) == 0 {
	// 		logrus.Warnf("skipping pod %s/%s, no containers available", pod.Namespace, pod.Name)
	// 		continue
	// 	}
	// 	resources.Pods = append(resources.Pods, &probe.Pod{
	// 		Namespace:  pod.Namespace,
	// 		Name:       pod.Name,
	// 		Labels:     pod.Labels,
	// 		IP:         pod.Status.PodIP,
	// 		Containers: containers,
	// 	})
	// }

	// FIXME: use actual cluster pods
	kubernetes := kube.NewMockKubernetes(1.0)
	resources, err := probe.NewDefaultResources(kubernetes, []string{"demo"}, []string{"a", "b"}, []int{80, 81}, []v1.Protocol{v1.ProtocolTCP}, []string{}, 5, false, "registry.k8s.io")
	utils.DoOrDie(err)

	simRunner := probe.NewSimulatedRunner(explainedPolicies, &probe.JobBuilder{TimeoutSeconds: 10})
	simulatedProbe := simRunner.RunProbeForConfig(generator.ProbeAllAvailable, resources)
	// fmt.Printf("Ingress:\n%s\n", simulatedProbe.RenderIngress())
	// fmt.Printf("Egress:\n%s\n", simulatedProbe.RenderEgress())
	fmt.Printf("%s\n", simulatedProbe.RenderTable())
}

func VerdictWalkthrough(policies *matcher.Policy) {
	tableString := &strings.Builder{}
	table := tablewriter.NewWriter(tableString)
	table.SetAutoWrapText(false)
	table.SetRowLine(true)
	table.SetAutoMergeCells(true)

	table.SetHeader([]string{"Traffic", "Verdict", "Ingress Walkthrough", "Egress Walkthrough"})

	// FIXME: use pod resources from CLI arguments or JSON
	podA := &matcher.TrafficPeer{
		Internal: &matcher.InternalPeer{
			PodLabels:       map[string]string{"pod": "a"},
			NamespaceLabels: map[string]string{"kubernetes.io/metadata.name": "demo"},
			Namespace:       "demo",
		},
		IP: "10.0.0.4",
	}
	podB := &matcher.TrafficPeer{
		Internal: &matcher.InternalPeer{
			PodLabels:       map[string]string{"pod": "b"},
			NamespaceLabels: map[string]string{"kubernetes.io/metadata.name": "demo"},
			Namespace:       "demo",
		},
		IP: "10.0.0.5",
	}
	allTraffic := []*matcher.Traffic{
		{
			Source:       podA,
			Destination:  podB,
			ResolvedPort: 80,
			Protocol:     v1.ProtocolTCP,
		},
		{
			Source:       podA,
			Destination:  podB,
			ResolvedPort: 81,
			Protocol:     v1.ProtocolTCP,
		},
		{
			Source:       podB,
			Destination:  podA,
			ResolvedPort: 80,
			Protocol:     v1.ProtocolTCP,
		},
		{
			Source:       podB,
			Destination:  podA,
			ResolvedPort: 81,
			Protocol:     v1.ProtocolTCP,
		},
	}

	trafficStrings := []string{
		"demo/a -> demo/b:80 (TCP)",
		"demo/a -> demo/b:81 (TCP)",
		"demo/b -> demo/a:80 (TCP)",
		"demo/b -> demo/a:81 (TCP)",
	}

	for i, traffic := range allTraffic {
		trafficResult := policies.IsTrafficAllowed(traffic)
		ingressFlow := trafficResult.Ingress.Flow()
		egressFlow := trafficResult.Egress.Flow()
		if ingressFlow == "" {
			ingressFlow = "no policies targeting ingress"
		}
		if egressFlow == "" {
			egressFlow = "no policies targeting egress"
		}
		table.Append([]string{trafficStrings[i], trafficResult.Verdict(), ingressFlow, egressFlow})
	}

	table.Render()
	fmt.Println(tableString.String())
}
