package lib

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"strconv"

	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

var (
	LabelBucketsSize = []int{2, 4, 8, 16, 32, 64, 128}
)

const (
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
		lm = NewLabelManager()
		SetContextValue(f.Context(), key, lm)
	}

	ls.ctx = f.Context()
	ls.labelManager = lm

	return nil
}

func (ls *LabelSelector) Fuzz() {
	if ls.sel == nil || ls.config.ReallocateChance.Next(ls.ctx) {
		bucketSize := LabelBucketsSize[ls.ctx.Rand().IntN(len(LabelBucketsSize))]
		ls.sel = ls.labelManager.AllocateLabelSelector(bucketSize)
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

	// pool is the label values available for this bucket size.
	// Map value corresponds to the active number of references the label value has.
	// Label values are randomly allocated string.
	pool map[string]int
}

// Iterates through the available pools, find a pool or create a new one where
// reference count is less than bucketSize and return the corresponding pool value.
func (p *LabelPool) NewReference() string {
	for value, refs := range p.pool {
		if refs < p.bucketSize {
			p.pool[value] = refs + 1
			return value
		}
	}

	value := rand.Text()
	p.pool[value] = 1
	return value
}

// Decrement the reference count in pool map for the provided label value.
func (p *LabelPool) Dereference(value string) {
	if refs, ok := p.pool[value]; ok && refs > 0 {
		p.pool[value] = refs - 1
	}
}

type LabelManager struct {
	// staticLabels are merged into every allocated label map and every selector.
	staticLabels map[string]string

	// When allocating labels each pool has to provide a reference so selector
	// can appropriately select.
	pools []LabelPool
}

func NewLabelManager() *LabelManager {
	lm := &LabelManager{
		staticLabels: map[string]string{},
		pools:        make([]LabelPool, 0, len(LabelBucketsSize)),
	}

	for _, size := range LabelBucketsSize {
		lm.pools = append(lm.pools, LabelPool{
			bucketSize: size,
			pool:       map[string]int{},
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
func (l *LabelManager) AllocateLabels() map[string]string {
	lbls := make(map[string]string, len(l.staticLabels)+1+len(l.pools))

	for k, v := range l.staticLabels {
		lbls[staticLabelPrefix+k] = v
	}

	lbls[uniqueLabelKey] = rand.Text()

	for i := range l.pools {
		key := bucketLabelPrefix + strconv.Itoa(l.pools[i].bucketSize)
		lbls[key] = l.pools[i].NewReference()
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

func (l *LabelManager) ReallocateLabels(lbls map[string]string) map[string]string {
	l.DeallocateLabels(lbls)
	return l.AllocateLabels()
}

// Allocate label selector from the pool of provided bucket size and logs the current
// allocated label reference size for the allocated selector.
func (l *LabelManager) AllocateLabelSelector(size int) *slim_metav1.LabelSelector {
	for i := range l.pools {
		if l.pools[i].bucketSize != size {
			continue
		}

		value := l.pools[i].NewReference()
		key := bucketLabelPrefix + strconv.Itoa(size)

		matchLabels := make(map[string]string, len(l.staticLabels)+1)
		for k, v := range l.staticLabels {
			matchLabels[staticLabelPrefix+k] = v
		}

		matchLabels[key] = value
		return &slim_metav1.LabelSelector{MatchLabels: matchLabels}
	}

	return nil
}
