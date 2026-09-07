package main

import (
	"encoding/json"
	"strings"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	policyapi "github.com/cilium/cilium/pkg/policy/api"
	lib "github.com/fristonio/kfuzz/lib"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type PolicyTest struct {
	LocalEndpoints  []*K8sEndpoint  `fuzz:"labelScope=local_endpoints,node=kind-worker,sliceSize=4-8,sliceAddCount=1,sliceAddChance=0.05,sliceDeleteCount=1,sliceDeleteChance=0.05,sliceUpdateCount=1-2,sliceUpdateChance=0.1"`
	RemoteEndpoints []*K8sEndpoint  `fuzz:"labelScope=remote_endpoints,sliceSize=4-8,sliceAddCount=1-3,sliceAddChance=0.1,sliceDeleteCount=1-2,sliceDeleteChance=0.1,sliceUpdateCount=1-3,sliceUpdateChance=0.25"`
	CIDRGroups      []*K8sCIDRGroup `fuzz:"labelScope=cidr_groups,sliceSize=16-64,sliceAddCount=4-8,sliceAddChance=0.25,sliceDeleteCount=4-8,sliceDeleteChance=0.25,sliceUpdateCount=2-8,sliceUpdateChance=0.1"`

	Policies []*K8sPolicy `fuzz:"sliceSize=16-32,sliceAddCount=2-8,sliceAddChance=0.25,sliceDeleteCount=1-8,sliceDeleteChance=0.25,sliceUpdateCount=2-8,sliceUpdateChance=0.25"`
}

type EndpointConfig struct {
	Node         string `json:"node"`
	NodeSelector string `json:"nodeSelector"`
}

func (c *EndpointConfig) Parse(config lib.RawConfig) error {
	return json.Unmarshal(config, c)
}

type Endpoint struct {
	config *EndpointConfig

	Replicas int `fuzz:"range=1-1"`
}

func (e *Endpoint) SetConfig(cfg *EndpointConfig) {
	e.config = cfg
}

func (e *Endpoint) Namespaced() bool { return true }

func (e *Endpoint) Object(meta *lib.ResourceMetadata) lib.K8sObject {
	replicas := max(int32(e.Replicas), 1)

	podSpec := corev1.PodSpec{
		Containers: []corev1.Container{
			{
				Name:            "app",
				Image:           "registry.k8s.io/pause:3.10",
				ImagePullPolicy: corev1.PullIfNotPresent,
			},
		},
		// Always tolerate kfuzz/block taint on the nodes.
		Tolerations: []corev1.Toleration{
			{
				Key:    "kfuzz.cilium.io/block",
				Value:  "true",
				Effect: "NoSchedule",
			},
		},
	}
	switch {
	case e.config.Node != "":
		// Node pins the pod directly via nodeName, bypassing the scheduler
		// entirely - takes precedence since it's the more specific request.
		podSpec.NodeName = e.config.Node
	case e.config.NodeSelector != "":
		if key, value, ok := strings.Cut(e.config.NodeSelector, "="); ok {
			podSpec.NodeSelector = map[string]string{key: value}
		}
	}

	return &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: meta.Labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: meta.Labels},
				Spec:       podSpec,
			},
		},
	}
}

type K8sEndpoint = lib.Resource[*Endpoint]

type CIDRGroup struct {
	CIDRs []*lib.CIDR `fuzz:"sliceSize=2-4"`
}

func (c *CIDRGroup) Namespaced() bool { return false }

func (c *CIDRGroup) Object(_ *lib.ResourceMetadata) lib.K8sObject {
	externalCIDRs := make([]policyapi.CIDR, 0, len(c.CIDRs))
	for _, cidr := range c.CIDRs {
		externalCIDRs = append(externalCIDRs, policyapi.CIDR(*cidr))
	}
	return &ciliumv2.CiliumCIDRGroup{
		TypeMeta: metav1.TypeMeta{APIVersion: "cilium.io/v2", Kind: "CiliumCIDRGroup"},
		Spec:     ciliumv2.CiliumCIDRGroupSpec{ExternalCIDRs: externalCIDRs},
	}
}

type K8sCIDRGroup = lib.Resource[*CIDRGroup]

type Policy struct {
	Subjects []*lib.LabelSelector `fuzz:"labelScope=local_endpoints,sliceSize=1-4"`
	Rules    []*PolicyRule        `fuzz:"sliceSize=2-16"`
}

func (p *Policy) Namespaced() bool { return true }

func (p *Policy) Object(_ *lib.ResourceMetadata) lib.K8sObject {
	var endpointSelector policyapi.EndpointSelector
	for _, subj := range p.Subjects {
		if ml := subj.MatchLabels(); len(ml) > 0 {
			endpointSelector = policyapi.NewESFromMatchRequirements(ml, nil)
			break
		}
	}

	spec := &policyapi.Rule{EndpointSelector: endpointSelector}
	for _, rule := range p.Rules {
		if rule.Ingress {
			spec.Ingress = append(spec.Ingress, rule.toIngressRule())
		} else {
			spec.Egress = append(spec.Egress, rule.toEgressRule())
		}
	}

	return &ciliumv2.CiliumNetworkPolicy{
		TypeMeta: metav1.TypeMeta{APIVersion: "cilium.io/v2", Kind: "CiliumNetworkPolicy"},
		Spec:     spec,
	}
}

type PolicyRule struct {
	Ingress bool `fuzz:"trueChance=0.5"`

	L3 lib.OneOf[PolicyL3]
	L4 PolicyL4
	L7 PolicyL7
}

func (rule *PolicyRule) toIngressRule() policyapi.IngressRule {
	ir := policyapi.IngressRule{ToPorts: rule.toPortRules()}
	l3 := rule.L3.Get()
	for _, sel := range l3.Endpoints {
		if ml := sel.MatchLabels(); len(ml) > 0 {
			ir.FromEndpoints = append(ir.FromEndpoints, policyapi.NewESFromMatchRequirements(ml, nil))
		}
	}
	for _, sel := range l3.CIDRGroups {
		if ml := sel.MatchLabels(); len(ml) > 0 {
			ir.FromEndpoints = append(ir.FromEndpoints, policyapi.NewESFromMatchRequirements(ml, nil))
		}
	}
	return ir
}

func (rule *PolicyRule) toEgressRule() policyapi.EgressRule {
	er := policyapi.EgressRule{ToPorts: rule.toPortRules()}
	l3 := rule.L3.Get()
	for _, sel := range l3.Endpoints {
		if ml := sel.MatchLabels(); len(ml) > 0 {
			er.ToEndpoints = append(er.ToEndpoints, policyapi.NewESFromMatchRequirements(ml, nil))
		}
	}
	for _, sel := range l3.CIDRGroups {
		if ml := sel.MatchLabels(); len(ml) > 0 {
			er.ToEndpoints = append(er.ToEndpoints, policyapi.NewESFromMatchRequirements(ml, nil))
		}
	}
	return er
}

func (rule *PolicyRule) toPortRules() policyapi.PortRules {
	if len(rule.L4.Ports) == 0 {
		return nil
	}
	ports := make([]policyapi.PortProtocol, 0, len(rule.L4.Ports))
	for _, pp := range rule.L4.Ports {
		ports = append(ports, pp.toPortProtocol())
	}
	pr := policyapi.PortRule{Ports: ports}
	// L7 HTTP rules are only valid for a single TCP port.
	if len(ports) == 1 && ports[0].Protocol == policyapi.ProtoTCP && len(rule.L7.HTTPRules) > 0 {
		httpRules := make(policyapi.PortRulesHTTP, 0, len(rule.L7.HTTPRules))
		for _, hr := range rule.L7.HTTPRules {
			httpRules = append(httpRules, policyapi.PortRuleHTTP{
				Method: string(hr.Method),
				Path:   string(hr.Path),
			})
		}
		pr.Rules = &policyapi.L7Rules{HTTP: httpRules}
	}
	return policyapi.PortRules{pr}
}

type PolicyL3 struct {
	CIDRGroups []*lib.LabelSelector `fuzz:"labelScope=cidr_groups,sliceSize=2-8,weight=0.75"`
	Endpoints  []*lib.LabelSelector `fuzz:"labelScope=remote_endpoints,sliceSize=2-4,weight=0.25"`
}

type PortProtocol struct {
	Port     lib.Port     `fuzz:"range=20000-30000"`
	Protocol lib.Protocol `fuzz:"oneOf=TCP;UDP"`
}

type PolicyL4 struct {
	Ports []*PortProtocol `fuzz:"sliceSize=2-8"`
}

type HTTPRule struct {
	Method lib.HttpMethod `fuzz:"oneof=GET;POST;PUT;DELETE"`
	Path   lib.HttpPath
}

type PolicyL7 struct {
	HTTPRules []*HTTPRule `fuzz:"sliceSize=2-8"`
}

func (pp PortProtocol) toPortProtocol() policyapi.PortProtocol {
	return policyapi.PortProtocol{
		Port:     string(pp.Port),
		Protocol: policyapi.L4Proto(pp.Protocol),
	}
}

type K8sPolicy = lib.Resource[*Policy]
