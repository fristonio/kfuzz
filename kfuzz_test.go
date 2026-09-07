package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"testing"

	clik8s "github.com/cilium/cilium/cilium-cli/k8s"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	lib "github.com/fristonio/kfuzz/lib"
	appsv1 "k8s.io/api/apps/v1"
)

// recordingClient records every Apply/Delete it receives as a string, so two
// runs can be compared for exact equality.
type recordingClient struct {
	ns  string
	ops []string
}

func (r *recordingClient) Namespace() string { return r.ns }

func (r *recordingClient) Apply(_, obj clik8s.Object) {
	r.ops = append(r.ops, "APPLY "+describeObj(obj))
}

func (r *recordingClient) Delete(obj clik8s.Object) {
	r.ops = append(r.ops, "DELETE "+describeObj(obj))
}

func (r *recordingClient) Execute(_ context.Context) {}

func describeObj(obj clik8s.Object) string {
	data, err := json.Marshal(obj)
	if err != nil {
		return fmt.Sprintf("<marshal error: %v>", err)
	}
	return string(data)
}

// TestFuzzDeterministic checks that running the fuzzer twice with the same
// seed produces the exact same sequence of resource operations.
func TestFuzzDeterministic(t *testing.T) {
	const seed = 42
	const ticks = 5

	run := func() []string {
		client := &recordingClient{ns: "kfuzz-test"}
		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		ctx := lib.NewFuzzContext(seed, logger, client)

		f, _, err := lib.InitializeFuzzer[PolicyTest](ctx, lib.RawConfig("{}"))
		if err != nil {
			t.Fatalf("failed to initialize fuzzer: %v", err)
		}

		for range ticks {
			f.Fuzz()
		}
		f.Close()

		return client.ops
	}

	first := run()
	second := run()

	if len(first) != len(second) {
		t.Fatalf("operation count differs between same-seed runs: %d vs %d", len(first), len(second))
	}

	for i := range first {
		if first[i] != second[i] {
			t.Fatalf("operation %d differs between same-seed runs:\nrun1: %s\nrun2: %s", i, first[i], second[i])
		}
	}
}

// selectorTrackingClient keeps the latest applied state per object (by kind
// and name), like a real cluster would, so policy selectors can be checked
// against the resources that currently exist.
type selectorTrackingClient struct {
	ns string

	deployments map[string]*appsv1.Deployment
	cidrGroups  map[string]*ciliumv2.CiliumCIDRGroup
	policies    map[string]*ciliumv2.CiliumNetworkPolicy
}

func newSelectorTrackingClient(ns string) *selectorTrackingClient {
	return &selectorTrackingClient{
		ns:          ns,
		deployments: map[string]*appsv1.Deployment{},
		cidrGroups:  map[string]*ciliumv2.CiliumCIDRGroup{},
		policies:    map[string]*ciliumv2.CiliumNetworkPolicy{},
	}
}

func (c *selectorTrackingClient) Namespace() string { return c.ns }

func (c *selectorTrackingClient) Apply(_, obj clik8s.Object) {
	switch o := obj.(type) {
	case *appsv1.Deployment:
		c.deployments[o.GetName()] = o
	case *ciliumv2.CiliumCIDRGroup:
		c.cidrGroups[o.GetName()] = o
	case *ciliumv2.CiliumNetworkPolicy:
		c.policies[o.GetName()] = o
	}
}

func (c *selectorTrackingClient) Delete(obj clik8s.Object) {
	switch o := obj.(type) {
	case *appsv1.Deployment:
		delete(c.deployments, o.GetName())
	case *ciliumv2.CiliumCIDRGroup:
		delete(c.cidrGroups, o.GetName())
	case *ciliumv2.CiliumNetworkPolicy:
		delete(c.policies, o.GetName())
	}
}

func (c *selectorTrackingClient) Execute(_ context.Context) {}

// labelSelectorMatchesAny reports whether matchLabels is a subset of at
// least one of the candidate label maps - i.e. the selector would actually
// select something that exists.
func labelSelectorMatchesAny(matchLabels map[string]string, candidates ...map[string]string) bool {
	if len(matchLabels) == 0 {
		return false
	}
	for _, cand := range candidates {
		match := true
		for k, v := range matchLabels {
			if cand[k] != v {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// TestPolicyLabelSelectorsMatchRealResources runs the fuzzer against the
// scenario config in scratch/config.json (entirely through a dry, in-memory
// client - no real cluster involved) and checks that the label selectors
// attached to generated CiliumNetworkPolicy objects (both the endpoint
// subject selector and every L3 FromEndpoints/ToEndpoints selector) actually
// resolve to labels carried by some currently-live endpoint/CIDR group,
// rather than to a value nothing in the cluster has.
func TestPolicyLabelSelectorsMatchRealResources(t *testing.T) {
	config, err := os.ReadFile("scratch/config.json")
	if err != nil {
		t.Fatalf("failed to read scratch config: %v", err)
	}

	client := newSelectorTrackingClient("kfuzz-test")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx := lib.NewFuzzContext(7, logger, client)

	f, _, err := lib.InitializeFuzzer[PolicyTest](ctx, lib.RawConfig(config))
	if err != nil {
		t.Fatalf("failed to initialize fuzzer: %v", err)
	}

	const ticks = 15
	for range ticks {
		f.Fuzz()
	}
	// Deliberately not calling f.Close(): that would tear down (delete) every
	// generated resource, leaving nothing live to check selectors against.

	if len(client.policies) == 0 {
		t.Fatal("no policies were generated, nothing to verify")
	}

	var localOrRemote []map[string]string
	for _, d := range client.deployments {
		localOrRemote = append(localOrRemote, d.GetLabels())
	}
	var remoteOrCIDR []map[string]string
	remoteOrCIDR = append(remoteOrCIDR, localOrRemote...)
	for _, g := range client.cidrGroups {
		remoteOrCIDR = append(remoteOrCIDR, g.GetLabels())
	}

	var subjectTotal, subjectMatched, l3Total, l3Matched int
	for name, p := range client.policies {
		if ml := p.Spec.EndpointSelector.MatchLabels; len(ml) > 0 {
			subjectTotal++
			if labelSelectorMatchesAny(ml, localOrRemote...) {
				subjectMatched++
			} else {
				t.Logf("policy %s: subject selector %v matches no live endpoint", name, ml)
			}
		}

		for _, ing := range p.Spec.Ingress {
			for _, fe := range ing.FromEndpoints {
				if len(fe.MatchLabels) == 0 {
					continue
				}
				l3Total++
				if labelSelectorMatchesAny(fe.MatchLabels, remoteOrCIDR...) {
					l3Matched++
				} else {
					t.Logf("policy %s: ingress FromEndpoints selector %v matches no live endpoint/CIDR group", name, fe.MatchLabels)
				}
			}
		}
		for _, eg := range p.Spec.Egress {
			for _, te := range eg.ToEndpoints {
				if len(te.MatchLabels) == 0 {
					continue
				}
				l3Total++
				if labelSelectorMatchesAny(te.MatchLabels, remoteOrCIDR...) {
					l3Matched++
				} else {
					t.Logf("policy %s: egress ToEndpoints selector %v matches no live endpoint/CIDR group", name, te.MatchLabels)
				}
			}
		}
	}

	if subjectTotal == 0 || l3Total == 0 {
		t.Fatalf("not enough selectors generated to verify: subjects=%d l3=%d", subjectTotal, l3Total)
	}

	// A small residual of misses is expected: a selector snapshots a label
	// value once and (by design, see LabelSelector.Close) never
	// reallocates when the endpoint it pointed at is later deleted/updated.
	// The overwhelming majority should still resolve; anything far below
	// this indicates selectors are allocating values disconnected from any
	// real resource (see LabelPool.PickReference/NewReference).
	const minMatchRatio = 0.95

	subjectRatio := float64(subjectMatched) / float64(subjectTotal)
	l3Ratio := float64(l3Matched) / float64(l3Total)

	t.Logf("subject selectors matched: %d/%d (%.1f%%)", subjectMatched, subjectTotal, subjectRatio*100)
	t.Logf("L3 selectors matched: %d/%d (%.1f%%)", l3Matched, l3Total, l3Ratio*100)

	if subjectRatio < minMatchRatio {
		t.Errorf("policy subject selectors mostly don't match any live endpoint: %d/%d (%.1f%%) < %.0f%%",
			subjectMatched, subjectTotal, subjectRatio*100, minMatchRatio*100)
	}
	if l3Ratio < minMatchRatio {
		t.Errorf("policy L3 selectors mostly don't match any live endpoint/CIDR group: %d/%d (%.1f%%) < %.0f%%",
			l3Matched, l3Total, l3Ratio*100, minMatchRatio*100)
	}
}
