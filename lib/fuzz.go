package lib

import (
	"fmt"
	"reflect"
)

// Package-level type sentinels used for signature validation.
var (
	fuzzContextPtrType      = reflect.TypeFor[*FuzzContext]()
	fuzzConfigType          = reflect.TypeFor[Config]()
	fuzzNodeInitializerType = reflect.TypeFor[FuzzNodeInitializer]()
)

type FuzzNodeKind int

const (
	FuzzNodeValue FuzzNodeKind = iota
	FuzzNodeStruct
	FuzzNodeSlice
	FuzzNodeCustom
)

// String returns a human-readable label for k.
func (k FuzzNodeKind) String() string {
	switch k {
	case FuzzNodeValue:
		return "Value"
	case FuzzNodeStruct:
		return "Struct"
	case FuzzNodeSlice:
		return "Slice"
	case FuzzNodeCustom:
		return "Custom"
	default:
		return "Unknown"
	}
}

type FuzzNodes []FuzzNode

type FuzzNode interface {
	Kind() FuzzNodeKind

	// Config returns the fully-resolved configuration this node is acting
	// on, as a JSON object. Feeding it back into the same node's Parse
	// path reproduces an equivalent node/tree.
	Config() RawConfig

	Fuzz()
	Close()
}

type FuzzNodeInitializer interface {
	Init(f Fuzzer, meta FuzzMeta) error
	FuzzNode
}

type fuzzHandler struct {
	configType reflect.Type
	value      reflect.Value
}

func IsFuzzableKind(kind reflect.Kind) bool {
	switch kind {
	case reflect.UnsafePointer, reflect.Uintptr, reflect.Map, reflect.Interface, reflect.Func, reflect.Chan, reflect.Array:
		return false
	default:
		return true
	}
}

type Fuzzer interface {
	Context() *FuzzContext

	Fuzz()
	Close()

	// Config returns the fully-resolved configuration the fuzzer is
	// acting on, as a JSON object. Feeding it back into InitializeFuzzer
	// reproduces an equivalent tree.
	Config() RawConfig

	Parse(reflect.Value, FuzzMeta) (FuzzNode, error)
}

type fuzzer struct {
	ctx *FuzzContext

	obj  any
	root FuzzNode

	handlers map[reflect.Type]fuzzHandler // key: *T; value: func(*FuzzContext, *TConfig, *T)
}

var _ Fuzzer = &fuzzer{}

func (f *fuzzer) Fuzz() {
	f.root.Fuzz()
}

func (f *fuzzer) Close() {
	f.root.Close()
}

func (f *fuzzer) Context() *FuzzContext {
	return f.ctx
}

func (f *fuzzer) Config() RawConfig {
	return f.root.Config()
}

func InitializeFuzzer[T any](ctx *FuzzContext, config RawConfig) (*fuzzer, *T, error) {
	if len(config) == 0 {
		config = RawConfig(`{}`)
	}

	obj := New[T]()
	f := &fuzzer{
		ctx:      ctx,
		handlers: make(map[reflect.Type]fuzzHandler),
		obj:      obj,
	}

	f.mustRegister(
		// Native types
		FuzzString,
		FuzzBool,
		FuzzNumeric[int],
		FuzzNumeric[int8],
		FuzzNumeric[int16],
		FuzzNumeric[int32],
		FuzzNumeric[int64],
		FuzzNumeric[uint],
		FuzzNumeric[uint8],
		FuzzNumeric[uint16],
		FuzzNumeric[uint32],
		FuzzNumeric[uint64],
		FuzzNumeric[float32],
		FuzzNumeric[float64],

		// Custom types
		FuzzCIDR,
		FuzzPort,
		FuzzProtocol,
		FuzzHttpPath,
		FuzzHttpMethod,
	)

	objValue := reflect.ValueOf(&obj).Elem()
	fuzzTree, err := f.Parse(objValue, FuzzMeta{
		Scope:  "",
		Config: config,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse type(%s): %w", objValue.Type(), err)
	}

	f.root = fuzzTree
	return f, &obj, nil
}

func (f *fuzzer) mustRegister(handlers ...any) {
	for _, h := range handlers {
		hv := reflect.ValueOf(h)
		if err := f.validateHandler(hv.Type()); err != nil {
			panic(fmt.Sprintf("Invalid handler %T: %s", h, err))
		}
		// Key by the exact pointer type in the third parameter (*T).
		f.handlers[hv.Type().In(2)] = fuzzHandler{
			configType: hv.Type().In(1),
			value:      hv,
		}
	}
}

func (f *fuzzer) validateHandler(ht reflect.Type) error {
	if ht.Kind() != reflect.Func {
		return fmt.Errorf("expected func, got %s", ht.Kind())
	}
	if ht.NumIn() != 3 {
		return fmt.Errorf("must have exactly 3 parameters, got %d", ht.NumIn())
	}
	if ht.In(0) != fuzzContextPtrType {
		return fmt.Errorf("first parameter must be *FuzzContext, got %s", ht.In(0))
	}
	if !ht.In(1).Implements(fuzzConfigType) || ht.In(1).Kind() != reflect.Pointer {
		return fmt.Errorf("second parameter must implment Config interface, got %s", ht.In(1))
	}
	if ht.In(2).Kind() != reflect.Pointer {
		return fmt.Errorf("third parameter must be a pointer (*T), got %s", ht.In(2))
	}
	return nil
}

func (f *fuzzer) Parse(v reflect.Value, meta FuzzMeta) (FuzzNode, error) {
	if !IsFuzzableKind(v.Kind()) {
		return nil, nil
	}

	// If the value is a pointer type, early skip if we know it will be nil.
	if v.Kind() == reflect.Pointer {
		cfg := PointerConfig{
			NilChance: 0,
		}
		if err := cfg.Parse(meta.Config); err != nil {
			return nil, fmt.Errorf("cannot parse pointer config: %w", err)
		}

		if cfg.NilChance.Next(f.ctx) {
			return nil, nil
		}
	}

	fuzzNode, err := f.ParseCustomFuzzer(v, meta)
	if err != nil {
		return nil, err
	} else if fuzzNode != nil {
		return fuzzNode, nil
	}

	fuzzNode, err = f.ParseValueFuzzer(v, meta)
	if err != nil {
		return nil, err
	} else if fuzzNode != nil {
		return fuzzNode, nil
	}

	switch v.Kind() {
	case reflect.Pointer:
		// Traverse pointer indirection allocating nil pointers(we already validated that its not going to be nil).
		if v.IsNil() {
			if !v.CanSet() {
				return nil, fmt.Errorf("cannot set pointer value")
			}
			v.Set(reflect.New(v.Type().Elem()))
		}
		v = v.Elem()
		return f.Parse(v, meta)
	case reflect.Struct:
		return f.ParseStructFuzzer(v, meta)
	case reflect.Slice:
		return f.ParseSliceFuzzer(v, meta)
	}

	return nil, nil
}
