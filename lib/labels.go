package lib

import (
	"encoding/json"
	"fmt"
	"strconv"

	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

const labelValueLength = 20

func randomLabelValue(ctx *FuzzContext) string {
	buf := make([]byte, labelValueLength)
	for i := range buf {
		buf[i] = charsetAlphanum[ctx.rand.IntN(len(charsetAlphanum))]
	}
	return string(buf)
}

var (
	LabelBucketsSize     = []int{2, 4, 8, 16, 32, 64, 128}
	NoMatchLabelSelector = slim_metav1.LabelSelector{
		MatchLabels: map[string]string{
			"cilium.io/no-match-selector": "true",
		},
	}
)

const (
	labelScopeKey     = "cilium.labels/scope"
	uniqueLabelKey    = "cilium.labels/unique"
	staticLabelPrefix = "cilium.labels/static-"
	bucketLabelPrefix = "cilium.labels/bucket-"
)

type LabelSelectorConfig struct {
	LabelScope       string `json:"labelScope"`
	ReallocateChance Chance `json:"reallocateChance"`
}

func (c *LabelSelectorConfig) Parse(raw RawConfig) error {
	c.ReallocateChance = 0
	return json.Unmarshal(raw, c)
}

// LabelSelector wraps a Kubernetes label selector derived from a LabelManager.
// It implements FuzzNodeInitializer: on Init it looks up (or creates) the
// LabelManager for the configured scope and allocates a selector from it.
// Selectors are placeholders only, so unlike labels there is no deallocation
// on Close.
type LabelSelector struct {
	config LabelSelectorConfig

	labelManager *LabelManager

	ctx *FuzzContext
	sel *slim_metav1.LabelSelector
}

func (ls *LabelSelector) Kind() FuzzNodeKind {
	return FuzzNodeCustom
}

func (ls *LabelSelector) Init(f Fuzzer, meta FuzzMeta) error {
	if err := ls.config.Parse(meta.Config); err != nil {
		return fmt.Errorf("failed to parse label selector config: %w", err)
	}

	key := labelManagerKey(ls.config.LabelScope)
	lm, ok := GetContextValue[*LabelManager](f.Context(), key)
	if !ok {
		lm = NewLabelManager(ls.config.LabelScope)
		SetContextValue(f.Context(), key, lm)
	}

	ls.ctx = f.Context()
	ls.labelManager = lm

	return nil
}

func (ls *LabelSelector) Fuzz() {
	if ls.sel == nil || ls.config.ReallocateChance.Next(ls.ctx) {
		bucketSize := LabelBucketsSize[ls.ctx.Rand().IntN(len(LabelBucketsSize))]
		ls.sel = ls.labelManager.AllocateLabelSelector(ls.ctx, bucketSize)
	}
}

func (ls *LabelSelector) Close() {}

func (ls *LabelSelector) Config() RawConfig {
	data, err := json.Marshal(ls.config)
	if err != nil {
		return RawConfig("{}")
	}
	return data
}

func (ls *LabelSelector) MatchLabels() map[string]string {
	if ls.sel != nil {
		return ls.sel.MatchLabels
	}
	return nil
}

type LabelPool struct {
	// Max number of allocated labels that can reference this pool.
	bucketSize int

	// values holds every label value ever allocated into this pool, in
	// allocation order. Iterating it (rather than the refs map) to find a
	// reusable value keeps NewReference's pick deterministic given the same
	// seed - map range order is randomized by Go on every iteration.
	values []string
	// refs is the active reference count for each value in values.
	refs map[string]int
}

// Iterates through the available pools, find a pool or create a new one where
// reference count is less than bucketSize and return the corresponding pool value.
func (p *LabelPool) NewReference(ctx *FuzzContext) string {
	for _, value := range p.values {
		if p.refs[value] < p.bucketSize {
			p.refs[value]++
			return value
		}
	}

	value := randomLabelValue(ctx)
	p.values = append(p.values, value)
	p.refs[value] = 1
	return value
}

// Decrement the reference count in pool map for the provided label value.
func (p *LabelPool) Dereference(value string) {
	if refs, ok := p.refs[value]; ok && refs > 0 {
		p.refs[value] = refs - 1
	}
}

// PickReference returns a value from the pool that's currently held by at
// least one real consumer (i.e. allocated via NewReference and not yet fully
// dereferenced), without itself taking a reference. Selectors only need to
// match an in-use value, not occupy one of the bucket's limited slots -
// unlike NewReference, this never mints a new value, so it returns false if
// no consumer has allocated into this pool yet.
func (p *LabelPool) PickReference(ctx *FuzzContext) (string, bool) {
	var candidates []string
	for _, value := range p.values {
		if p.refs[value] > 0 {
			candidates = append(candidates, value)
		}
	}
	if len(candidates) == 0 {
		return "", false
	}
	return candidates[ctx.rand.IntN(len(candidates))], true
}

type LabelManager struct {
	scope string

	// staticLabels are merged into every allocated label map and every selector.
	staticLabels map[string]string

	// When allocating labels each pool has to provide a reference so selector
	// can appropriately select.
	pools []LabelPool
}

func NewLabelManager(scope string) *LabelManager {
	lm := &LabelManager{
		scope:        scope,
		staticLabels: map[string]string{},
		pools:        make([]LabelPool, 0, len(LabelBucketsSize)),
	}

	for _, size := range LabelBucketsSize {
		lm.pools = append(lm.pools, LabelPool{
			bucketSize: size,
			refs:       map[string]int{},
		})
	}

	return lm
}

// Allocate labels for a k8s resource.
// * Always has a unique label: unique.cilium-test = <unique value>
// * Always contains a set of static labels = map[string]string{}
// * Labels from each bucket size.
//
// Usually called during the init of a k8s resource.
//
// Labels format:
// Static: cilium.labels/static-<key> = <value>
// Unique: cilium.labels/unique = <unique-value>
// Bucket: cilium.labels/bucket-<bucket-size> = <bucket-pool-value>
func (l *LabelManager) AllocateLabels(ctx *FuzzContext) map[string]string {
	lbls := make(map[string]string, len(l.staticLabels)+1+len(l.pools))

	for k, v := range l.staticLabels {
		lbls[staticLabelPrefix+k] = v
	}

	lbls[labelScopeKey] = l.scope
	lbls[uniqueLabelKey] = randomLabelValue(ctx)

	for i := range l.pools {
		key := bucketLabelPrefix + strconv.Itoa(l.pools[i].bucketSize)
		lbls[key] = l.pools[i].NewReference(ctx)
	}

	return lbls
}

// Deallocate the labels allocated in a previous call cleaning up all references
// in the pool. Usually called when a k8s resource is Closed.
func (l *LabelManager) DeallocateLabels(lbls map[string]string) {
	for i := range l.pools {
		key := bucketLabelPrefix + strconv.Itoa(l.pools[i].bucketSize)
		if value, ok := lbls[key]; ok {
			l.pools[i].Dereference(value)
		}
	}
}

func (l *LabelManager) ReallocateLabels(ctx *FuzzContext, lbls map[string]string) map[string]string {
	l.DeallocateLabels(lbls)
	return l.AllocateLabels(ctx)
}

// Allocate label selector from the pool of provided bucket size and logs the current
// allocated label reference size for the allocated selector.
func (l *LabelManager) AllocateLabelSelector(ctx *FuzzContext, size int) *slim_metav1.LabelSelector {
	for i := range l.pools {
		if l.pools[i].bucketSize != size {
			continue
		}

		value, ok := l.pools[i].PickReference(ctx)
		if !ok {
			return NoMatchLabelSelector.DeepCopy()
		}
		key := bucketLabelPrefix + strconv.Itoa(size)

		matchLabels := make(map[string]string, len(l.staticLabels)+1)
		for k, v := range l.staticLabels {
			matchLabels[staticLabelPrefix+k] = v
		}

		matchLabels[key] = value
		return &slim_metav1.LabelSelector{MatchLabels: matchLabels}
	}

	return NoMatchLabelSelector.DeepCopy()
}
