package lib

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

type FuzzHandler[T any, TConfig Config] func(ctx *FuzzContext, config TConfig, obj *T)

func FuzzString(ctx *FuzzContext, config *StringConfig, out *string) {
	length := config.Length.Next(ctx)

	charset := charsetAlpha
	switch config.Charset {
	case "alpha":
		charset = charsetAlpha
	case "alphanum":
		charset = charsetAlphanum
	case "num":
		charset = charsetNum
	}

	buf := make([]byte, length)
	for i := range buf {
		buf[i] = charset[ctx.rand.IntN(len(charset))]
	}
	s := string(buf)

	if config.Lowercase {
		s = strings.ToLower(s)
	}

	*out = s
}

func FuzzBool(ctx *FuzzContext, config *BoolConfig, out *bool) {
	*out = config.TrueChance.Next(ctx)
}

// Numeric is the type constraint for all integer and floating-point kinds.
type Numeric interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64 |
		~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uintptr |
		~float32 | ~float64
}

func FuzzNumeric[T Numeric](ctx *FuzzContext, config *NumericConfig[T], out *T) {
	*out = config.Range.Next(ctx)
}

type CIDR string

func FuzzCIDR(ctx *FuzzContext, config *EmptyConfig, out *CIDR) {
	oc1 := ctx.rand.IntN(256)
	oc2 := ctx.rand.IntN(256)
	oc3 := ctx.rand.IntN(256)
	prefix := 28 + ctx.rand.IntN(5) // /28 to /32

	*out = CIDR(fmt.Sprintf("100.%d.%d.%d/%d", oc1, oc2, oc3, prefix))
}

type Port string

func FuzzPort(ctx *FuzzContext, config *PortConfig, out *Port) {
	*out = Port(strconv.Itoa(config.Range.Next(ctx)))
}

type Protocol string

func FuzzProtocol(ctx *FuzzContext, config *ProtocolConfig, out *Protocol) {
	*out = Protocol(config.OneOf[ctx.rand.IntN(len(config.OneOf))])
}

type HttpMethod string

func FuzzHttpMethod(ctx *FuzzContext, config *HttpMethodConfig, out *HttpMethod) {
	*out = HttpMethod(config.OneOf[ctx.rand.IntN(len(config.OneOf))])
}

type HttpPath string

func FuzzHttpPath(ctx *FuzzContext, config *HttpPathConfig, out *HttpPath) {
	charset := charsetAlphanum
	switch config.Charset {
	case "alpha":
		charset = charsetAlpha
	case "num":
		charset = charsetNum
	}

	segments := make([]string, config.Segments.Next(ctx))
	for i := range segments {
		buf := make([]byte, config.Length.Next(ctx))
		for j := range buf {
			buf[j] = charset[ctx.rand.IntN(len(charset))]
		}
		segments[i] = string(buf)
	}

	*out = HttpPath("/" + strings.Join(segments, "/"))
}

type OneOf[T any] struct {
	pickedIndex int

	pickedField reflect.StructField
	pickedValue reflect.Value

	obj T

	fuzzNode FuzzNode

	// eligibleIndexes/weights correspond 1:1, holding the struct field
	// index and resolved OneOf weight for every field considered during
	// the weighted pick in Init (not just the one that was picked).
	// Preserved so Config() can reproduce the same pick given the same
	// seed.
	eligibleIndexes []int
	weights         []float64
}

func (o *OneOf[T]) Kind() FuzzNodeKind {
	return FuzzNodeCustom
}

func (o *OneOf[T]) Init(f Fuzzer, meta FuzzMeta) error {
	objType := reflect.TypeFor[T]()
	if objType.Kind() != reflect.Struct {
		return fmt.Errorf("inner type for OneOf should be struct got %s", objType.Kind())
	}

	structConfig := StructConfig{}
	if err := json.Unmarshal(meta.Config, &structConfig); err != nil {
		return fmt.Errorf("failed to unmarshal struct config: %w", err)
	}

	o.obj = New[T]()
	v := reflect.ValueOf(&o.obj).Elem()
	t := v.Type()

	var (
		indexes []int
		weights []float64
	)

	for i := range t.NumField() {
		fieldType := t.Field(i)
		fieldKind := fieldType.Type.Kind()

		// Only pointer and slice fields are eligible: both zero-value to nil,
		// so every field not picked simply stays unallocated/empty.
		if !fieldType.IsExported() || !IsFuzzableKind(fieldKind) ||
			fieldType.Tag.Get("fuzz") == "-" ||
			(fieldKind != reflect.Pointer && fieldKind != reflect.Slice) {
			continue
		}

		fieldConfig, err := MergeStructFieldConfig(fieldType.Tag.Get("fuzz"), structConfig[fieldType.Name])
		if err != nil {
			return fmt.Errorf("failed to derive struct field %s config: %w", fieldType.Name, err)
		}

		weightConfig := OneOfConfig{}
		if err := weightConfig.Parse(fieldConfig); err != nil {
			return fmt.Errorf("failed to parse OneOf weight for field %s: %w", fieldType.Name, err)
		}

		indexes = append(indexes, i)
		weights = append(weights, float64(weightConfig.Weight))
	}

	if len(indexes) < 2 {
		return fmt.Errorf("need more than 2 valid fields for OneOf got %d", len(indexes))
	}

	o.eligibleIndexes = indexes
	o.weights = weights

	o.pickedIndex = WeightedPick(f.Context(), indexes, weights)
	o.pickedField = t.Field(o.pickedIndex)
	o.pickedValue = v.Field(o.pickedIndex)

	fieldName := o.pickedField.Name

	fieldConfig, err := MergeStructFieldConfig(o.pickedField.Tag.Get("fuzz"), structConfig[fieldName])
	if err != nil {
		return fmt.Errorf("failed to derive struct field %s config: %w", fieldName, err)
	}

	fuzzNode, err := f.Parse(o.pickedValue, FuzzMeta{
		Scope:  meta.Scope.Next(fieldName),
		Config: fieldConfig,
	})
	if err != nil || fuzzNode == nil {
		return fmt.Errorf("failed to parse struct field %s: %w", fieldName, err)
	}

	o.fuzzNode = fuzzNode
	return nil
}

func (o *OneOf[T]) Fuzz() {
	o.fuzzNode.Fuzz()
}

func (o *OneOf[T]) Close() {
	o.fuzzNode.Close()
}

func (o *OneOf[T]) Get() *T {
	return &o.obj
}

// Config returns a StructConfig-shaped JSON object over every field
// eligible for the weighted pick: each gets its resolved "weight", and the
// picked field additionally gets its nested (fully-resolved) config merged
// in. Non-picked fields' internal structure was never built, so only their
// weight - which is sufficient to reproduce the same pick given the same
// seed - is preserved.
func (o *OneOf[T]) Config() RawConfig {
	t := reflect.TypeOf(o.obj)

	cfg := StructConfig{}
	for i, fieldIndex := range o.eligibleIndexes {
		weightCfg, err := json.Marshal(OneOfConfig{Weight: Float64(o.weights[i])})
		if err != nil {
			continue
		}

		fieldName := t.Field(fieldIndex).Name
		if fieldIndex == o.pickedIndex {
			cfg[fieldName] = MergeConfigs(weightCfg, o.fuzzNode.Config())
		} else {
			cfg[fieldName] = weightCfg
		}
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		return RawConfig("{}")
	}
	return data
}

// Set behaves like the built-in slice fuzzer (grow/shrink/update/shuffle
// governed by the same SliceConfig knobs) but, unlike a []*T struct field
// parsed by ParseSliceFuzzer, T is not required to be a pointer type. Set
// owns its elements' storage itself: each object is independently
// heap-allocated (via new(T)) rather than living in a single contiguous
// backing array. Growing, shrinking, updating, and shuffling therefore only
// ever move *T pointers (and FuzzNode interface values) around - never the
// underlying T memory a nested FuzzNode's reflect.Value might be bound to -
// so object identity/fuzz state can never be corrupted by Set's own
// bookkeeping, regardless of T's kind.
type Set[T any] struct {
	f   Fuzzer
	ctx *FuzzContext

	meta   FuzzMeta
	config *SliceConfig

	// objects and elements correspond 1:1: objects[i] is the value
	// elements[i] is fuzzing. Both are independently heap-allocated per
	// element, so reordering/removing entries is always just a move of
	// their (pointer, FuzzNode) pair - see the type doc comment.
	objects  []*T
	elements []FuzzNode

	// elemTemplate is a throwaway FuzzNode parsed once during Init purely
	// to introspect the per-element config shape for Config(). It's never
	// Fuzzed/Closed.
	elemTemplate FuzzNode
}

func (s *Set[T]) Kind() FuzzNodeKind {
	return FuzzNodeCustom
}

func (s *Set[T]) Init(f Fuzzer, meta FuzzMeta) error {
	cfg := SliceConfig{}
	if err := cfg.Parse(meta.Config); err != nil {
		return fmt.Errorf("failed to parse set config: %w", err)
	}

	// Validate the element config up front (and keep the resulting node
	// around to describe the element config shape in Config()) rather
	// than only discovering a bad config the first time an element is
	// created, which may happen arbitrarily later.
	probeObj := New[T]()
	probeNode, err := f.Parse(reflect.ValueOf(&probeObj).Elem(), meta)
	if err != nil || probeNode == nil {
		return fmt.Errorf("failed to validate set element config: %w", err)
	}

	s.f = f
	s.ctx = f.Context()
	s.meta = meta
	s.config = &cfg
	s.elemTemplate = probeNode

	s.objects = make([]*T, 0, cfg.SliceSize.Max)
	s.elements = make([]FuzzNode, 0, cfg.SliceSize.Max)

	return nil
}

func (s *Set[T]) Fuzz() {
	init := (len(s.objects) == 0)
	if !init {
		// Shuffle objects/elements together as (pointer, FuzzNode) pairs -
		// unlike sliceFuzzer's shuffle (which swaps bytes in place within a
		// shared backing array), this only ever moves pointers, so there's
		// no risk of corrupting either side's fuzz state.
		s.ctx.rand.Shuffle(len(s.objects), func(i, j int) {
			s.objects[i], s.objects[j] = s.objects[j], s.objects[i]
			s.elements[i], s.elements[j] = s.elements[j], s.elements[i]
		})

		if s.config.SliceDeleteChance.Next(s.ctx) {
			// Never delete below the configured minimum size.
			maxDelete := len(s.objects) - s.config.SliceSize.Min
			if maxDelete > 0 {
				toDelete := min(s.config.SliceDeleteCount.Next(s.ctx), maxDelete)
				// Delete elements from end of the set.
				newLen := len(s.objects) - toDelete
				for _, node := range s.elements[newLen:] {
					node.Close()
				}
				s.objects = s.objects[:newLen]
				s.elements = s.elements[:newLen]
			}
		}

		if s.config.SliceUpdateChance.Next(s.ctx) {
			toUpdate := min(s.config.SliceUpdateCount.Next(s.ctx), len(s.objects))
			// Update/Fuzz existing elements in the set.
			for _, node := range s.elements[:toUpdate] {
				node.Fuzz()
			}
		}
	}

	toCreate := 0
	if init {
		toCreate = s.config.SliceSize.Next(s.ctx)
	} else if s.config.SliceAddChance.Next(s.ctx) {
		toCreate = min(s.config.SliceAddCount.Next(s.ctx), (s.config.SliceSize.Max - len(s.objects)))
	}

	// Create new elements in the set.
	for range toCreate {
		obj := New[T]()

		node, err := s.f.Parse(reflect.ValueOf(&obj).Elem(), s.meta)
		if err != nil || node == nil {
			panic(fmt.Sprintf("failed to parse new set element: %s", err))
		}
		node.Fuzz()

		s.objects = append(s.objects, &obj)
		s.elements = append(s.elements, node)
	}
}

func (s *Set[T]) Close() {
	for _, node := range s.elements {
		node.Close()
	}
}

// Objects returns the set's current elements.
func (s *Set[T]) Objects() []*T {
	return s.objects
}

// Config merges this set's own SliceConfig with its element template's
// config, since both are read from the exact same raw meta.Config JSON
// object (see Init) - mirroring sliceFuzzer.Config.
func (s *Set[T]) Config() RawConfig {
	setCfg, err := json.Marshal(s.config)
	if err != nil {
		setCfg = RawConfig("{}")
	}

	var elemCfg RawConfig
	if s.elemTemplate != nil {
		elemCfg = s.elemTemplate.Config()
	}

	return MergeConfigs(setCfg, elemCfg)
}

var _ FuzzNodeInitializer = &Set[int]{}
