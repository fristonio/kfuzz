package lib

import (
	"log/slog"
	"math/rand/v2"
)

type FuzzContext struct {
	rand.Source

	rand   *rand.Rand
	logger *slog.Logger
	client K8sClient

	valueStore map[any]any
}

func NewFuzzContext(seed uint64, logger *slog.Logger, client K8sClient) *FuzzContext {
	src := rand.NewPCG(seed, seed)
	return &FuzzContext{
		Source: src,
		rand:   rand.New(src),
		logger: logger,
		client: client,
	}
}

func (ctx *FuzzContext) Rand() *rand.Rand {
	return ctx.rand
}

func (ctx *FuzzContext) Client() K8sClient {
	return ctx.client
}

// SetValue stores val in ctx under key. Struct keys are compared by value;
// use unexported sentinel struct types for cheap, collision-free keys.
func SetContextValue[T any](ctx *FuzzContext, key any, val T) {
	if ctx.valueStore == nil {
		ctx.valueStore = make(map[any]any)
	}
	ctx.valueStore[key] = val
}

// GetValue retrieves the value stored under key and type-asserts it to T.
// Returns the zero value and false when the key is absent or type mismatch.
func GetContextValue[T any](ctx *FuzzContext, key any) (T, bool) {
	var zero T
	if ctx.valueStore == nil {
		return zero, false
	}
	v, ok := ctx.valueStore[key]
	if !ok {
		return zero, false
	}
	t, ok := v.(T)
	return t, ok
}
