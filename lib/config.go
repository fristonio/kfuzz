package lib

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

type Config interface {
	Parse(RawConfig) error
}

type EmptyConfig struct{}

func (c *EmptyConfig) Parse(_ RawConfig) error { return nil }

type NumRange[T Numeric] struct {
	Min T
	Max T
}

func NewNumRange[T Numeric](min, max T) NumRange[T] {
	var r NumRange[T]
	r.Min = min
	r.Max = max
	return r
}

func (r *NumRange[T]) UnmarshalJSON(data []byte) error {
	var val string
	if err := json.Unmarshal(data, &val); err != nil {
		return err
	}

	sep := strings.LastIndex(val, "-")
	if sep > 0 {
		if min, minOk := ParseNumericString[T](val[:sep]); minOk {
			if max, maxOk := ParseNumericString[T](val[sep+1:]); maxOk {
				r.Min, r.Max = min, max
				return nil
			}
		}
	}
	if v, ok := ParseNumericString[T](val); ok {
		r.Min, r.Max = v, v
		return nil
	}

	return fmt.Errorf("failed to parse num range %s", val)
}

func (s *NumRange[T]) MarshalJSON() ([]byte, error) {
	return json.Marshal(fmt.Sprintf("%v-%v", s.Min, s.Max))
}

func (s NumRange[T]) Next(f *FuzzContext) T {
	if s.Max <= s.Min {
		return s.Min
	}
	// Reflect is used once to resolve the kind; all arithmetic and rand calls
	// then operate in the native type for that branch.
	switch reflect.TypeFor[T]().Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return T(int64(s.Min) + f.rand.Int64N(int64(s.Max)-int64(s.Min)))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return T(uint64(s.Min) + f.rand.Uint64N(uint64(s.Max)-uint64(s.Min)))
	case reflect.Float32, reflect.Float64:
		return T(float64(s.Min) + f.rand.Float64()*(float64(s.Max)-float64(s.Min)))
	case reflect.Uintptr:
		return T(uintptr(s.Min) + uintptr(f.rand.Uint64N(uint64(uintptr(s.Max))-uint64(uintptr(s.Min)))))
	}
	return s.Min
}

type Chance float64

func (c *Chance) UnmarshalJSON(data []byte) (err error) {
	var chance float64

	defer func() {
		if err != nil {
			return
		}
		if chance < 0.0 || chance > 1.0 {
			err = fmt.Errorf("invalid value %f for chance, should be in range [0, 1]", chance)
			return
		}
		*c = Chance(chance)
	}()

	if err = json.Unmarshal(data, &chance); err == nil {
		return nil
	}

	var val string
	if err = json.Unmarshal(data, &val); err != nil {
		return
	}

	chance, err = strconv.ParseFloat(val, 64)
	return
}

func (c *Chance) Next(ctx *FuzzContext) bool {
	return ctx.rand.Float64() < float64(*c)
}

type Enum []string

func (e *Enum) UnmarshalJSON(data []byte) error {
	enums := []string{}
	if err := json.Unmarshal(data, &enums); err == nil {
		*e = Enum(enums)
		return nil
	}

	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	*e = strings.Split(s, ";")
	return nil
}

// Bool is a boolean value that can be unmarshaled from either a JSON
// boolean or a JSON string ("true"/"false"). The latter is required to
// support struct field tags: MergeStructFieldConfig always merges tag
// key=val tokens as strings before marshaling them back to JSON, so a plain
// bool field could never be set via a tag otherwise.
type Bool bool

func (b *Bool) UnmarshalJSON(data []byte) error {
	var v bool
	if err := json.Unmarshal(data, &v); err == nil {
		*b = Bool(v)
		return nil
	}

	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	parsed, err := strconv.ParseBool(s)
	if err != nil {
		return err
	}
	*b = Bool(parsed)
	return nil
}

func UnmarshalNumber[T Numeric](data []byte, n *T) error {
	var num T
	if err := json.Unmarshal(data, &num); err == nil {
		*n = num
		return nil
	}

	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	num, ok := ParseNumericString[T](s)
	if !ok {
		return errors.New("failed to parse numeric value from string")
	}

	*n = num
	return nil
}

type Float64 float64

func (f *Float64) UnmarshalJSON(data []byte) error {
	return UnmarshalNumber[float64](data, (*float64)(f))
}

type PointerConfig struct {
	NilChance Chance `json:"nilChance"`
}

func (c *PointerConfig) Parse(raw RawConfig) error {
	c.NilChance = 0
	return json.Unmarshal(raw, c)
}

type StringConfig struct {
	Length    NumRange[int] `json:"length"`
	Charset   string        `json:"charset"`
	Lowercase Bool          `json:"lowercase"`
}

func (s *StringConfig) Parse(raw RawConfig) error {
	s.Length = NewNumRange(8, 16)
	s.Charset = "alpha"
	s.Lowercase = true

	return json.Unmarshal(raw, s)
}

type BoolConfig struct {
	TrueChance Chance `json:"trueChance"`
}

func (c *BoolConfig) Parse(raw RawConfig) error {
	c.TrueChance = 0
	return json.Unmarshal(raw, c)
}

type NumericConfig[T Numeric] struct {
	Range NumRange[T] `json:"range"`
}

func (c *NumericConfig[T]) Parse(raw RawConfig) error {
	c.Range = NewNumRange[T](4, 16)
	return json.Unmarshal(raw, c)
}

type SliceConfig struct {
	SliceSize NumRange[int] `json:"sliceSize"`

	SliceAddChance Chance        `json:"sliceAddChance"`
	SliceAddCount  NumRange[int] `json:"sliceAddCount"`

	SliceDeleteChance Chance        `json:"sliceDeleteChance"`
	SliceDeleteCount  NumRange[int] `json:"sliceDeleteCount"`

	SliceUpdateChance Chance        `json:"sliceUpdateChance"`
	SliceUpdateCount  NumRange[int] `json:"sliceUpdateCount"`
}

func (s *SliceConfig) Parse(raw RawConfig) error {
	s.SliceSize = NewNumRange(2, 16)

	s.SliceAddChance = 0.5
	s.SliceAddCount = NewNumRange(2, 4)

	s.SliceDeleteChance = 0.5
	s.SliceDeleteCount = NewNumRange(2, 4)

	s.SliceUpdateChance = 0.5
	s.SliceUpdateCount = NewNumRange(2, 4)

	return json.Unmarshal(raw, s)
}

type OneOfConfig struct {
	Weight Float64 `json:"weight"`
}

func (o *OneOfConfig) Parse(raw RawConfig) error {
	o.Weight = 1.0
	return json.Unmarshal(raw, o)
}

type PortConfig struct {
	Range NumRange[int] `json:"range"`
}

func (c *PortConfig) Parse(raw RawConfig) error {
	c.Range = NewNumRange(1024, 65535)
	return json.Unmarshal(raw, c)
}

type ProtocolConfig struct {
	OneOf Enum `json:"oneOf"`
}

func (c *ProtocolConfig) Parse(raw RawConfig) error {
	c.OneOf = Enum{"TCP", "UDP"}
	return json.Unmarshal(raw, c)
}

type HttpMethodConfig struct {
	OneOf Enum `json:"oneOf"`
}

func (c *HttpMethodConfig) Parse(raw RawConfig) error {
	c.OneOf = Enum{"GET", "POST", "PUT", "DELETE"}
	return json.Unmarshal(raw, c)
}

type HttpPathConfig struct {
	Segments NumRange[int] `json:"segments"`
	Length   NumRange[int] `json:"length"`
	Charset  string        `json:"charset"`
}

func (c *HttpPathConfig) Parse(raw RawConfig) error {
	c.Segments = NewNumRange(1, 3)
	c.Length = NewNumRange(3, 8)
	c.Charset = "alphanum"

	return json.Unmarshal(raw, c)
}
