package lib

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"reflect"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/spf13/pflag"
)

type HarnessConfig struct {
	ConfigFile   string
	TickInterval time.Duration
	Seed         uint64
	SkipCleanup  bool
}

func (c HarnessConfig) Flags(fs *pflag.FlagSet) {
	fs.StringP("config-file", "c", "", "Config file path with overrides for the harness")
	fs.DurationP("tick-interval", "t", 5*time.Second, "Interval between fuzz iteration tick")
	fs.Uint64P("seed", "s", 42, "Seed to use for creating fuzz random source")
	fs.Bool("skip-cleanup", false, "Option to specify if the resources should be cleaned up after the harness run is complete/stopped")
}

type Harness[T any] struct {
	obj    *T
	fuzzer *fuzzer

	ctx *FuzzContext

	logger *slog.Logger
	config HarnessConfig
	client K8sClient

	trigger job.Trigger
	runner  job.Group
}

func NewHarness[T any](logger *slog.Logger, lc cell.Lifecycle, jg job.Group, cfg HarnessConfig, client K8sClient) *Harness[T] {
	h := &Harness[T]{
		logger: logger,
		config: cfg,
		client: client,

		trigger: job.NewTrigger(),
		runner:  jg,
	}

	lc.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
			return h.Start(ctx)
		},
		OnStop: func(ctx cell.HookContext) error {
			return h.Stop(ctx)
		},
	})

	return h
}

func (h *Harness[T]) Start(ctx context.Context) error {
	h.logger.Info("Starting test harness")

	objKind := reflect.TypeFor[T]().Kind()
	if objKind != reflect.Struct {
		return fmt.Errorf("cannot run harness on non struct type %s", objKind)
	}

	h.ctx = NewFuzzContext(h.config.Seed, h.logger, h.client)

	testConfig := RawConfig("{}")
	if h.config.ConfigFile != "" {
		data, err := os.ReadFile(h.config.ConfigFile)
		if err != nil {
			return fmt.Errorf("failed to read config file: %w", err)
		}

		testConfig = RawConfig(data)
		h.logger.Info("Test config parsed", "config-path", h.config.ConfigFile)
	}

	fuzzer, fuzzObj, err := InitializeFuzzer[T](h.ctx, testConfig)
	if err != nil {
		return err
	}

	h.fuzzer = fuzzer
	h.obj = fuzzObj

	h.logger.Info("Fuzzer initialized, creating initial set of resources", "type", reflect.TypeFor[T]().String())
	h.runner.Add(job.Timer("fuzz-tick", h.Run, h.config.TickInterval, job.WithTrigger(h.trigger)))
	h.trigger.Trigger()

	return nil
}

func (h *Harness[T]) Stop(ctx context.Context) error {
	if h.config.SkipCleanup {
		h.logger.Info("Skipping cleanup, fuzzer not closed")
		return nil
	}

	h.logger.Info("Closing fuzzer and cleaning up the resources")
	h.fuzzer.Close()
	h.client.Execute(ctx)
	return nil
}

func (h *Harness[T]) Run(ctx context.Context) error {
	h.fuzzer.Fuzz()
	h.client.Execute(ctx)
	return nil
}
