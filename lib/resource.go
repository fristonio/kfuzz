package lib

import (
	"encoding/json"
	"fmt"
	"reflect"

	clik8s "github.com/cilium/cilium/cilium-cli/k8s"
)

var configInterfaceType = reflect.TypeFor[Config]()

type K8sObject = clik8s.Object

type K8sResource interface {
	Object(meta *ResourceMetadata) K8sObject
	Namespaced() bool
}

type ResourceMetadata struct {
	Name   string
	Labels map[string]string
}

type ResourceConfig struct {
	LabelScope       string `json:"labelScope"`
	MetaUpdateChance Chance `json:"metaUpdateChance"`
}

func (r *ResourceConfig) Parse(raw RawConfig) error {
	r.LabelScope = ""
	r.MetaUpdateChance = 0

	return json.Unmarshal(raw, r)
}

// labelManagerKey namespaces LabelScope values in the fuzz context's value
// store, so they can't collide with unrelated context keys.
type labelManagerKey string

type Resource[T K8sResource] struct {
	fuzzer Fuzzer

	resourceConfig ResourceConfig
	config         any

	fuzzNode FuzzNode

	labelManager *LabelManager

	obj     T
	objMeta ResourceMetadata

	last K8sObject
}

func (r *Resource[T]) Kind() FuzzNodeKind {
	return FuzzNodeCustom
}

func (r *Resource[T]) Init(f Fuzzer, meta FuzzMeta) error {
	r.fuzzer = f

	config := ResourceConfig{}
	if err := config.Parse(meta.Config); err != nil {
		return fmt.Errorf("failed to unmarshal resource config: %w", err)
	}
	r.resourceConfig = config

	FuzzString(f.Context(), &StringConfig{
		Length:    NewNumRange(8, 16),
		Charset:   "alpha",
		Lowercase: true,
	}, &r.objMeta.Name)

	// When a label scope is configured, get-or-create the LabelManager for
	// that scope (shared across every Resource using the same scope) and
	// allocate this object's label set from it.
	if config.LabelScope != "" {
		key := labelManagerKey(config.LabelScope)
		lm, ok := GetContextValue[*LabelManager](f.Context(), key)
		if !ok {
			lm = NewLabelManager(config.LabelScope)
			SetContextValue(f.Context(), key, lm)
		}

		r.labelManager = lm
		r.objMeta.Labels = lm.AllocateLabels(f.Context())
	}

	// Similar to OneOf, construct the underlying resource object and build
	// its fuzz node tree.
	r.obj = New[T]()
	v := reflect.ValueOf(&r.obj).Elem()

	fuzzNode, err := f.Parse(v, meta)
	if err != nil || fuzzNode == nil {
		return fmt.Errorf("failed to parse resource object: %w", err)
	}
	r.fuzzNode = fuzzNode

	if err := r.initObjConfig(meta.Config); err != nil {
		return err
	}

	return nil
}

// initObjConfig checks whether T (or *T) has a method SetConfig(*TConfig)
// where TConfig implements Config. If so, it constructs a TConfig,
// parses it from rawConfig, and calls SetConfig with the result.
func (r *Resource[T]) initObjConfig(rawConfig RawConfig) error {
	method := reflect.ValueOf(r.obj).MethodByName("SetConfig")
	if !method.IsValid() {
		return nil
	}

	mt := method.Type()
	if mt.NumIn() != 1 || mt.In(0).Kind() != reflect.Pointer || !mt.In(0).Implements(configInterfaceType) {
		return fmt.Errorf("SetConfig must take a single pointer argument implementing Config, got %s", mt)
	}

	cfgPtr := reflect.New(mt.In(0).Elem())
	cfg, ok := cfgPtr.Interface().(Config)
	if !ok {
		return fmt.Errorf("SetConfig argument type %s does not implement Config", mt.In(0))
	}
	if err := cfg.Parse(rawConfig); err != nil {
		return fmt.Errorf("failed to parse resource object config: %w", err)
	}

	method.Call([]reflect.Value{cfgPtr})
	r.config = cfg
	return nil
}

func (r *Resource[T]) Fuzz() {
	if r.last != nil && r.resourceConfig.MetaUpdateChance.Next(r.fuzzer.Context()) {
		r.objMeta.Labels = r.labelManager.ReallocateLabels(r.fuzzer.Context(), r.objMeta.Labels)
		return
	}

	r.fuzzNode.Fuzz()
	r.apply()
}

func (r *Resource[T]) Close() {
	r.fuzzNode.Close()

	if r.last != nil {
		r.fuzzer.Context().Client().Delete(r.last)
		r.last = nil
	}

	if r.labelManager != nil && r.objMeta.Labels != nil {
		r.labelManager.DeallocateLabels(r.objMeta.Labels)
		r.objMeta.Labels = nil
	}
}

func (r *Resource[T]) Get() *T {
	return &r.obj
}

// Config merges this resource's own ResourceConfig, its wrapped object's
// fully-resolved config, and (if T implements SetConfig) the object-level
// TConfig - all three read from the exact same raw meta.Config JSON object
// in Init.
func (r *Resource[T]) Config() RawConfig {
	resourceCfg, err := json.Marshal(r.resourceConfig)
	if err != nil {
		resourceCfg = RawConfig("{}")
	}

	configs := []RawConfig{resourceCfg, r.fuzzNode.Config()}
	if r.config != nil {
		if objCfg, err := json.Marshal(r.config); err == nil {
			configs = append(configs, objCfg)
		}
	}

	return MergeConfigs(configs...)
}

// apply stamps metadata onto the K8s object and sends it to the client.
func (r *Resource[T]) apply() {
	obj := r.obj.Object(&r.objMeta)
	if obj == nil {
		return
	}

	obj.SetName(r.objMeta.Name)
	if r.obj.Namespaced() {
		ns := r.fuzzer.Context().client.Namespace()
		obj.SetNamespace(ns)
	}
	if r.objMeta.Labels != nil {
		obj.SetLabels(r.objMeta.Labels)
	}

	r.fuzzer.Context().Client().Apply(r.last, obj)
	r.last = obj
}
