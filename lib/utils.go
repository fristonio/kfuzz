package lib

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

const (
	charsetLower = "abcdefghijklmnopqrstuvwxyz"
	charsetUpper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

	charsetAlpha    = charsetLower + charsetUpper
	charsetNum      = "0123456789"
	charsetAlphanum = charsetAlpha + charsetNum
)

// New creates and initializes a new object of type T.
// If T is a pointer, the underlying value is allocated so it isn't nil.
func New[T any]() T {
	var zero T
	typ := reflect.TypeFor[T]()

	// if T is a pointer type allocate the underlying struct.
	if typ.Kind() == reflect.Pointer {
		return reflect.New(typ.Elem()).Interface().(T)
	}

	// If T is a value type, return its zero value.
	return zero
}

func EnsurePointerValue(value *reflect.Value) error {
	if value.Kind() == reflect.Pointer && value.IsNil() {
		if !value.CanSet() {
			return errors.New("cannot set pointer field value")
		}
		value.Set(reflect.New(value.Type().Elem()))
	}
	return nil
}

func MergeStructFieldConfig(tag string, override RawConfig) (RawConfig, error) {
	config := map[string]any{}

	for token := range strings.SplitSeq(tag, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}

		key, val, _ := strings.Cut(token, "=")
		config[strings.TrimSpace(key)] = strings.TrimSpace(val)
	}

	if override != nil {
		overrideConfig := StructConfig{}
		if err := json.Unmarshal(override, &overrideConfig); err != nil {
			return nil, fmt.Errorf("failed to unmarshal override config: %w", err)
		}

		for k, v := range overrideConfig {
			config[k] = v
		}
	}

	return json.Marshal(config)
}

// ParseNumericString parses a single numeric string into T.
func ParseNumericString[T Numeric](s string) (T, bool) {
	var zero T
	t := reflect.TypeFor[T]()
	v := reflect.New(t).Elem()
	switch t.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n, err := strconv.ParseInt(strings.TrimSpace(s), 10, t.Bits())
		if err != nil {
			return zero, false
		}
		v.SetInt(n)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		n, err := strconv.ParseUint(strings.TrimSpace(s), 10, t.Bits())
		if err != nil {
			return zero, false
		}
		v.SetUint(n)
	case reflect.Float32, reflect.Float64:
		n, err := strconv.ParseFloat(strings.TrimSpace(s), t.Bits())
		if err != nil {
			return zero, false
		}
		v.SetFloat(n)
	default:
		return zero, false
	}
	return v.Interface().(T), true
}

// MergeConfigs merges any number of JSON-object configs into one, unioning
// their top-level keys (later configs win on collision). Used to recombine
// a container node's own settings with a child's resolved config when both
// are read from the very same raw meta.Config JSON object - e.g. a slice's
// SliceConfig and its element's config, or Resource's ResourceConfig,
// wrapped-object config, and object-level TConfig.
func MergeConfigs(configs ...RawConfig) RawConfig {
	merged := map[string]json.RawMessage{}
	for _, c := range configs {
		if len(c) == 0 {
			continue
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal(c, &m); err != nil {
			continue
		}
		for k, v := range m {
			merged[k] = v
		}
	}

	data, err := json.Marshal(merged)
	if err != nil {
		return RawConfig("{}")
	}
	return data
}

// WeightedPick selects one candidate from candidates using a single weighted
// random draw proportional to weights.
func WeightedPick[T any](ctx *FuzzContext, candidates []T, weights []float64) T {
	var total float64
	for _, w := range weights {
		total += w
	}
	r := ctx.rand.Float64() * total
	var cum float64
	for i, w := range weights {
		cum += w
		if r < cum {
			return candidates[i]
		}
	}
	return candidates[len(candidates)-1]
}
