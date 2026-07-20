package lib

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"os"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	clik8s "github.com/cilium/cilium/cilium-cli/k8s"
	"github.com/google/go-cmp/cmp"
	"github.com/spf13/pflag"
	"golang.org/x/time/rate"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const (
	TestNamespace string = "kfuzz"
)

// K8sClient applies and deletes Kubernetes resources. Apply and Delete
// merely enqueue work and return immediately; Execute dispatches everything
// queued so far to the backend, paced by a TuningSet.
type K8sClient interface {
	// Apply applies obj to the cluster. prev is the last applied version of
	// the object, or nil for a first-time create.
	Apply(prev, obj clik8s.Object)
	Delete(obj clik8s.Object)

	// Execute dispatches all currently queued operations to the backend,
	// paced by the configured tuning set, blocking until they've all been
	// processed or ctx is canceled.
	Execute(ctx context.Context)
}

// ClientConfig selects the K8sClient backend and the tuning set used to pace
// operations against the cluster.
type ClientConfig struct {
	DryRun bool

	ClientTuningSet string

	ClientQPS       float64
	ClientBurstSize int
	ClientStepDelay time.Duration
}

func (c ClientConfig) Flags(fs *pflag.FlagSet) {
	fs.Bool("dry-run", false, "Log Kubernetes operations to ./kfuzz-dry-run.log instead of applying them to a real cluster")
	fs.String("client-tuning-set", "qps", "Load pattern used to pace Kubernetes API calls: qps, randomized, or stepped")
	fs.Float64("client-qps", 32, "Target average queries-per-second, for the qps and randomized tuning sets")
	fs.Int("client-burst-size", 16, "Number of operations dispatched back-to-back before pausing, for the stepped/qps tuning set")
	fs.Duration("client-step-delay", time.Second, "Pause between bursts, for the stepped tuning set")
}

// NewK8sClient constructs a K8sClient according to cfg.
func NewK8sClient(cfg ClientConfig) (K8sClient, error) {
	tuningSet, err := newTuningSet(cfg)
	if err != nil {
		return nil, err
	}

	var backend k8sBackend
	if cfg.DryRun {
		backend, err = newDryRunBackend()
	} else {
		backend, err = clik8s.NewClient("", "", "", "", nil)
	}
	if err != nil {
		return nil, fmt.Errorf("creating k8s backend: %w", err)
	}

	return newClient(backend, tuningSet), nil
}

// NewDryRunClient returns a K8sClient that never touches a real cluster,
// useful for tests and tooling that need a K8sClient but perform no actual
// cluster operations.
func NewDryRunClient() (K8sClient, error) {
	return NewK8sClient(ClientConfig{DryRun: true, ClientTuningSet: "none"})
}

// k8sBackend performs the Apply/Delete calls that a client dispatches. The
// real cluster client and the dry-run mock both implement it, so client
// needs only a single implementation of K8sClient.
type k8sBackend interface {
	ApplyGeneric(ctx context.Context, obj clik8s.Object) (*unstructured.Unstructured, error)
	DeleteGeneric(ctx context.Context, obj clik8s.Object) error
}

// dryRunBackend logs a compact record of every operation to a log file in
// the current directory instead of touching a real cluster.
type dryRunBackend struct {
	log *slog.Logger
}

func newDryRunBackend() (*dryRunBackend, error) {
	f, err := os.Create("kfuzz-dry-run.log")
	if err != nil {
		return nil, fmt.Errorf("creating dry-run log file: %w", err)
	}
	return &dryRunBackend{log: slog.New(slog.NewTextHandler(f, nil))}, nil
}

func (b *dryRunBackend) ApplyGeneric(_ context.Context, obj clik8s.Object) (*unstructured.Unstructured, error) {
	gvk := obj.GetObjectKind().GroupVersionKind()
	b.log.Info("APPLY", "kind", gvk.Kind, "namespace", obj.GetNamespace(), "name", obj.GetName())
	return nil, nil
}

func (b *dryRunBackend) DeleteGeneric(_ context.Context, obj clik8s.Object) error {
	gvk := obj.GetObjectKind().GroupVersionKind()
	b.log.Info("DELETE", "kind", gvk.Kind, "namespace", obj.GetNamespace(), "name", obj.GetName())
	return nil
}

// action distinguishes Apply from Delete in the queue.
type action int

const (
	actionApply action = iota
	actionDelete
)

// resourceAction is an item in the client's work queue.
type resourceAction struct {
	action action
	prev   clik8s.Object // nil on first create; previous version for updates
	obj    clik8s.Object
}

// client is the sole K8sClient implementation. Apply/Delete just append to
// queue; Execute drains it and dispatches to backend, paced by tuningSet.
type client struct {
	backend   k8sBackend
	tuningSet TuningSet

	tick  atomic.Int64
	mu    sync.Mutex
	queue []resourceAction
}

func newClient(backend k8sBackend, tuningSet TuningSet) *client {
	return &client{backend: backend, tuningSet: tuningSet, tick: atomic.Int64{}}
}

func (c *client) enqueue(ra resourceAction) {
	c.mu.Lock()
	c.queue = append(c.queue, ra)
	c.mu.Unlock()
}

func (c *client) Apply(prev, obj clik8s.Object) {
	c.enqueue(resourceAction{action: actionApply, prev: prev, obj: obj})
}

func (c *client) Delete(obj clik8s.Object) {
	c.enqueue(resourceAction{action: actionDelete, obj: obj})
}

// Execute dispatches every operation queued so far to backend, paced by
// tuningSet, blocking until they've all been processed or ctx is canceled.
// It finishes by logging, per resource kind, how many creates/updates/
// deletes were actually performed.
func (c *client) Execute(ctx context.Context) {
	c.mu.Lock()
	queue := c.queue
	c.queue = nil
	c.tick.Add(1)
	c.mu.Unlock()

	counts := opCounts{}
	for _, ra := range queue {
		if err := c.tuningSet.Wait(ctx); err != nil {
			break
		}
		if kind, op, ok := c.process(ctx, ra); ok {
			counts.record(kind, op)
		}
	}
	counts.log(c.tick.Load())
}

// process executes a single resourceAction against backend, skipping applies
// that would be no-ops. It returns the resource kind and the operation that
// was (or would have been) performed, and whether it actually went through.
func (c *client) process(ctx context.Context, ra resourceAction) (kind, op string, ok bool) {
	gvk := ra.obj.GetObjectKind().GroupVersionKind()
	kind = gvk.Kind
	log := slog.With("kind", kind, "namespace", ra.obj.GetNamespace(), "name", ra.obj.GetName())

	switch ra.action {
	case actionApply:
		op = "CREATE"
		if ra.prev != nil {
			if cmp.Equal(ra.prev, ra.obj, cmpIgnoreUnexported) {
				return kind, op, false
			}
			op = "UPDATE"
		}
		if _, err := c.backend.ApplyGeneric(ctx, ra.obj); err != nil {
			log.Error("Apply failed", "op", op, "err", err)
			return kind, op, false
		}
		log.Debug("Applied resource", "op", op)
	case actionDelete:
		op = "DELETE"
		if err := c.backend.DeleteGeneric(ctx, ra.obj); err != nil {
			log.Error("Delete failed", "err", err)
			return kind, op, false
		}
		log.Debug("Deleted resource")
	}
	return kind, op, true
}

// opCounts aggregates, per resource kind, how many of each operation were
// performed during a single Execute call.
type opCounts map[string]map[string]int

func (c opCounts) record(kind, op string) {
	m := c[kind]
	if m == nil {
		m = make(map[string]int)
		c[kind] = m
	}
	m[op]++
}

func (c opCounts) log(tick int64) {
	for kind, ops := range c {
		args := make([]any, 0, len(ops)*2+4)

		args = append(args, "tick", tick, "kind", kind)
		for op, n := range ops {
			args = append(args, op, n)
		}
		slog.Info("K8s operations", args...)
	}
}

// TuningSet paces dispatch of queued Kubernetes operations, mirroring the
// tuning set concept from clusterloader2's load-testing framework:
// https://github.com/kubernetes/perf-tests/tree/master/clusterloader2/pkg/tuningset
type TuningSet interface {
	// Wait blocks until the next operation may be dispatched, or ctx is
	// canceled.
	Wait(ctx context.Context) error
}

func newTuningSet(cfg ClientConfig) (TuningSet, error) {
	switch cfg.ClientTuningSet {
	case "qps":
		return newQPSTuningSet(cfg.ClientQPS, cfg.ClientBurstSize), nil
	case "randomized":
		return newRandomizedTuningSet(cfg.ClientQPS), nil
	case "stepped":
		return newSteppedTuningSet(cfg.ClientBurstSize, cfg.ClientStepDelay), nil
	case "none":
		return &noWait{}, nil
	default:
		return nil, fmt.Errorf("unknown tuning set %q", cfg.ClientTuningSet)
	}
}

type noWait struct{}

func (n *noWait) Wait(_ context.Context) error {
	return nil
}

// qpsTuningSet paces operations at a fixed rate, matching clusterloader2's
// RateLimit tuning set.
type qpsTuningSet struct {
	limiter *rate.Limiter
}

func newQPSTuningSet(qps float64, burst int) *qpsTuningSet {
	return &qpsTuningSet{limiter: rate.NewLimiter(rate.Limit(qps), burst)}
}

func (t *qpsTuningSet) Wait(ctx context.Context) error {
	return t.limiter.Wait(ctx)
}

// randomizedTuningSet paces operations at a target average rate, with the
// interval between operations uniformly randomized in [0, 2/qps), matching
// clusterloader2's RandomizedLoad.
type randomizedTuningSet struct {
	avgInterval time.Duration
}

func newRandomizedTuningSet(qps float64) *randomizedTuningSet {
	return &randomizedTuningSet{avgInterval: time.Duration(float64(time.Second) / qps)}
}

func (t *randomizedTuningSet) Wait(ctx context.Context) error {
	d := time.Duration(rand.Int64N(int64(2 * t.avgInterval)))
	select {
	case <-time.After(d):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// steppedTuningSet dispatches burstSize operations back-to-back, then
// pauses for stepDelay, matching clusterloader2's SteppedLoad.
type steppedTuningSet struct {
	burstSize int
	stepDelay time.Duration

	mu    sync.Mutex
	count int
}

func newSteppedTuningSet(burstSize int, stepDelay time.Duration) *steppedTuningSet {
	if burstSize < 1 {
		burstSize = 1
	}
	return &steppedTuningSet{burstSize: burstSize, stepDelay: stepDelay}
}

func (t *steppedTuningSet) Wait(ctx context.Context) error {
	t.mu.Lock()
	t.count++
	pause := t.count%t.burstSize == 0
	t.mu.Unlock()

	if !pause {
		return nil
	}
	select {
	case <-time.After(t.stepDelay):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// cmpIgnoreUnexported is applied to every diff to avoid panics on unexported fields.
var cmpIgnoreUnexported = cmp.FilterPath(func(p cmp.Path) bool {
	sf, ok := p.Index(-1).(cmp.StructField)
	if !ok {
		return false
	}
	r, _ := utf8.DecodeRuneInString(sf.Name())
	return !unicode.IsUpper(r)
}, cmp.Ignore())
