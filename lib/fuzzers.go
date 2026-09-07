package lib

import (
	"encoding/json"
	"fmt"
	"reflect"
)

func (f *fuzzer) ParseCustomFuzzer(value reflect.Value, meta FuzzMeta) (FuzzNode, error) {
	if !value.CanInterface() {
		return nil, nil
	}

	if value.Type().Implements(fuzzNodeInitializerType) {
		if err := EnsurePointerValue(&value); err != nil {
			return nil, err
		}

		fn, ok := value.Interface().(FuzzNodeInitializer)
		if !ok {
			return nil, nil
		}
		if err := fn.Init(f, meta); err != nil {
			return nil, fmt.Errorf("failed to initialize fuzz node: %w", err)
		}
		return fn, nil
	}

	if value.CanAddr() {
		return f.ParseCustomFuzzer(value.Addr(), meta)
	}

	return nil, nil
}

type valueFuzzerConfig struct {
	FuzzChanceConfig `json:",inline"`
	Config           any
}

type valueFuzzer struct {
	ctx *FuzzContext

	config     valueFuzzerConfig
	fuzzInvoke func()

	fuzzedOnce bool
}

func (v *valueFuzzer) Kind() FuzzNodeKind {
	return FuzzNodeValue
}

func (v *valueFuzzer) Fuzz() {
	// FuzzChance 0 indicates that the value is to be fuzzed just once initially
	// and then virtually remains unchanged.
	if !v.fuzzedOnce || v.config.FuzzChance.Next(v.ctx) {
		v.fuzzInvoke()
		v.fuzzedOnce = true
	}
}

func (v *valueFuzzer) Close() {}

func (v *valueFuzzer) Config() RawConfig {
	data, err := json.Marshal(v.config)
	if err != nil {
		return RawConfig("{}")
	}
	return data
}

var _ FuzzNode = &valueFuzzer{}

func (f *fuzzer) ParseValueFuzzer(value reflect.Value, meta FuzzMeta) (FuzzNode, error) {
	handler, ok := f.handlers[value.Type()]
	if ok {
		if err := EnsurePointerValue(&value); err != nil {
			return nil, err
		}

		fuzzChance := FuzzChanceConfig{}
		if err := fuzzChance.Parse(meta.Config); err != nil {
			return nil, fmt.Errorf("failed to parse value fuzz chance config")
		}

		var valueConfig struct {
			Config RawConfig `json:"Config"`
		}
		if err := json.Unmarshal(meta.Config, &valueConfig); err != nil {
			return nil, fmt.Errorf("failed to unmarshal value config override: %w", err)
		}

		cfg := reflect.New(handler.configType.Elem()).Interface().(Config)
		if err := cfg.Parse(MergeConfigs(meta.Config, valueConfig.Config)); err != nil {
			return nil, fmt.Errorf("failed to parse config: %w", err)
		}

		return &valueFuzzer{
			ctx: f.ctx,
			config: valueFuzzerConfig{
				FuzzChanceConfig: fuzzChance,
				Config:           cfg,
			},
			fuzzInvoke: func() {
				handler.value.Call([]reflect.Value{
					reflect.ValueOf(f.ctx),
					reflect.ValueOf(cfg),
					value,
				})
			},
		}, nil
	}

	if value.CanAddr() {
		return f.ParseValueFuzzer(value.Addr(), meta)
	}

	return nil, nil
}

// structField pairs a field's name with its FuzzNode, preserving the struct's
// declaration order - see structFuzzer's fields doc comment.
type structField struct {
	name string
	node FuzzNode
}

type structFuzzer struct {
	config *StructConfig

	// fields is ordered by struct field declaration (see ParseStructFuzzer),
	// not keyed by name, so Fuzz/Close always visit fields in the same order
	// given the same type - unlike a map, whose range order Go randomizes on
	// every iteration. Fields consume a data-dependent number of draws from
	// the fuzzer's single shared *rand.Rand, so a random visit order would
	// make the whole tree's output depend on iteration order rather than
	// just the seed.
	fields []structField
}

func (f *structFuzzer) Kind() FuzzNodeKind {
	return FuzzNodeStruct
}

func (f *structFuzzer) Fuzz() {
	for _, field := range f.fields {
		field.node.Fuzz()
	}
}

func (f *structFuzzer) Close() {
	for _, field := range f.fields {
		field.node.Close()
	}
}

// Config returns a StructConfig-shaped JSON object mapping each field name
// to that field's own fully-resolved (nested) config.
func (f *structFuzzer) Config() RawConfig {
	cfg := StructConfig{}
	for _, field := range f.fields {
		cfg[field.name] = field.node.Config()
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		return RawConfig("{}")
	}
	return data
}

var _ FuzzNode = &structFuzzer{}

func (f *fuzzer) ParseStructFuzzer(v reflect.Value, meta FuzzMeta) (FuzzNode, error) {
	fuzzConfig := StructConfig{}
	if err := json.Unmarshal(meta.Config, &fuzzConfig); err != nil {
		return nil, fmt.Errorf("failed to unmarshal struct config: %w", err)
	}

	node := &structFuzzer{
		config: &fuzzConfig,
	}

	t := v.Type()
	for i := range t.NumField() {
		field := v.Field(i)
		fieldType := t.Field(i)
		if !fieldType.IsExported() || !IsFuzzableKind(field.Kind()) {
			continue
		}

		fieldName := fieldType.Name
		fieldTag := fieldType.Tag.Get("fuzz")
		if fieldTag == "-" {
			continue
		}

		fieldConfig, err := MergeStructFieldConfig(fieldTag, fuzzConfig[fieldName])
		if err != nil {
			return nil, fmt.Errorf("failed to derive struct field %s config: %w", fieldName, err)
		}

		fieldNode, err := f.Parse(field, FuzzMeta{
			Scope:  meta.Scope.Next(fieldName),
			Config: fieldConfig,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to parse struct field %s: %w", fieldName, err)
		}

		if fieldNode != nil {
			node.fields = append(node.fields, structField{name: fieldName, node: fieldNode})
		}
	}

	return node, nil
}

type sliceFuzzer struct {
	f   *fuzzer
	ctx *FuzzContext

	elemType reflect.Type

	value reflect.Value
	meta  FuzzMeta

	config *SliceConfig

	// elements corresponds 1:1 to the fuzzers for slice its managing in value.
	// whenever a new element is created for the slice this also needs to
	// update with the fuzzer corresponding to the value.
	// Use fuzzer.Parse() to get the FuzzNode.
	elements []FuzzNode

	// elemTemplate is a throwaway FuzzNode parsed once (from the same
	// meta as elements) purely to introspect the per-element config
	// shape. It's never Fuzzed/Closed - only used by Config().
	elemTemplate FuzzNode
}

func (f *sliceFuzzer) Kind() FuzzNodeKind {
	return FuzzNodeSlice
}

func (f *sliceFuzzer) Fuzz() {
	init := (f.value.Len() == 0)
	if !init {
		// Shuffle the slice before performing any operations. Only the
		// backing array's contents are swapped - f.elements is left
		// untouched. Each FuzzNode in f.elements holds a pointer bound
		// directly to a fixed backing-array address (obtained via
		// .Addr()/.Index()), so it already tracks "whatever occupies that
		// slot" correctly.
		f.ctx.rand.Shuffle(f.value.Len(), reflect.Swapper(f.value.Interface()))

		if f.config.SliceDeleteChance.Next(f.ctx) {
			// Never delete below the configured minimum size.
			maxDelete := f.value.Len() - f.config.SliceSize.Min
			if maxDelete > 0 {
				toDelete := min(f.config.SliceDeleteCount.Next(f.ctx), maxDelete)
				// Delete elements from end of the slice.
				newLen := f.value.Len() - toDelete
				for _, node := range f.elements[newLen:] {
					node.Close()
				}
				f.elements = f.elements[:newLen]
				f.value.Set(f.value.Slice(0, newLen))
			}
		}

		if f.config.SliceUpdateChance.Next(f.ctx) {
			toUpdate := min(f.config.SliceUpdateCount.Next(f.ctx), f.value.Len())
			// Update/Fuzz existing element in the slice.
			for _, node := range f.elements[:toUpdate] {
				node.Fuzz()
			}
		}
	}

	toCreate := 0
	if init {
		toCreate = f.config.SliceSize.Next(f.ctx)
	} else if f.config.SliceAddChance.Next(f.ctx) {
		toCreate = min(f.config.SliceAddCount.Next(f.ctx), (f.config.SliceSize.Max - f.value.Len()))
	}

	// Create new elements in the slice.
	for range toCreate {
		idx := f.value.Len()
		f.value.Set(reflect.Append(f.value, reflect.New(f.elemType).Elem()))

		node, err := f.f.Parse(f.value.Index(idx), f.meta)
		if err != nil || node == nil {
			panic(fmt.Sprintf("failed to parse new slice element: %s", err))
		}
		node.Fuzz()

		f.elements = append(f.elements, node)
	}
}

func (f *sliceFuzzer) Close() {
	for _, node := range f.elements {
		node.Close()
	}
}

// Config merges this slice's own SliceConfig with its element template's
// config, since both are read from the exact same raw meta.Config JSON
// object (see ParseSliceFuzzer).
func (f *sliceFuzzer) Config() RawConfig {
	sliceCfg, err := json.Marshal(f.config)
	if err != nil {
		sliceCfg = RawConfig("{}")
	}

	var elemCfg RawConfig
	if f.elemTemplate != nil {
		elemCfg = f.elemTemplate.Config()
	}

	return MergeConfigs(sliceCfg, elemCfg)
}

func (f *fuzzer) ParseSliceFuzzer(value reflect.Value, meta FuzzMeta) (FuzzNode, error) {
	cfg := SliceConfig{}
	if err := cfg.Parse(meta.Config); err != nil {
		return nil, fmt.Errorf("failed to parse slice config: %w", err)
	}

	elemType := value.Type().Elem()

	// Only pointer element types are allowed. sliceFuzzer physically shuffles
	// the backing array and deletes/updates elements in place; a pointer
	// element's pointee lives on independently heap-allocated memory (see
	// ensurePointerValue), so only the pointer value itself is ever moved by
	// a shuffle/swap - never the fuzz state beneath it. Any non-pointer
	// element that itself holds address-derived state (e.g. a nested slice
	// or OneOf) would otherwise be silently corrupted.
	if elemType.Kind() != reflect.Pointer {
		return nil, fmt.Errorf(
			"slice element type %s must be a pointer type (e.g. []*%s); non-pointer slice elements are not supported since this slice's own shuffle/delete/update can corrupt their fuzz state",
			elemType, elemType.Name())
	}

	// Validate the element config up front by parsing a throwaway element
	// of the slice's element type. Without this, a bad element config
	// (e.g. an unparsable tag/override) would only surface as a panic deep
	// inside sliceFuzzer.Fuzz() the first time a new element is created,
	// which may happen arbitrarily later (e.g. once SliceAddChance first
	// triggers), rather than being reported here as an error.
	probe := reflect.New(elemType)
	probeNode, err := f.Parse(probe.Elem(), meta)
	if err != nil || probeNode == nil {
		return nil, fmt.Errorf("failed to validate slice element config: %w", err)
	}

	// Preallocate capacity to the largest size this slice can ever reach
	// (per SliceSize / the add-count capping in sliceFuzzer.Fuzz). Growing
	// the slice one element at a time via reflect.Append would otherwise
	// risk reallocating the backing array, which silently orphans the
	// reflect.Value held by every already-created element's FuzzNode -
	// further Fuzz() calls on those nodes would then write into memory no
	// longer referenced by the actual slice.
	slice := reflect.MakeSlice(value.Type(), 0, cfg.SliceSize.Max)
	value.Set(slice)

	sf := &sliceFuzzer{
		f:   f,
		ctx: f.ctx,

		elemType: elemType,

		value: value,
		meta:  meta,

		elements: make([]FuzzNode, 0, cfg.SliceSize.Max),

		config:       &cfg,
		elemTemplate: probeNode,
	}

	return sf, nil
}
