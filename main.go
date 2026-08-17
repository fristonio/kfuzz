package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/spf13/cobra"

	lib "github.com/fristonio/kfuzz/lib"
)

var hiveApp = hive.NewWithOptions(
	hive.Options{
		StartTimeout: time.Second * 30,
		StopTimeout:  time.Second * 300,
	},

	job.Cell,
	cell.SimpleHealthCell,

	cell.Module(
		"kfuzz",
		"Fuzzes Cilium resources against a Kubernetes cluster",

		cell.Config(lib.HarnessConfig{}),
		cell.Config(lib.ClientConfig{}),

		cell.Provide(job.Registry.NewGroup),

		cell.Provide(lib.NewK8sClient),
		cell.Invoke(lib.NewHarness[PolicyTest]),
	),
)

var rootCmd = &cobra.Command{
	Use: "kfuzz",
	RunE: func(_ *cobra.Command, _ []string) error {
		return hiveApp.Run(slog.Default())
	},
}

var logConfigCmd = &cobra.Command{
	Use:   "log-config",
	Short: "Print the fully-resolved configuration structure for test type",
	RunE: func(cmd *cobra.Command, _ []string) error {
		configFile, err := cmd.Flags().GetString("config-file")
		if err != nil {
			return err
		}

		config := lib.RawConfig("{}")
		if configFile != "" {
			data, err := os.ReadFile(configFile)
			if err != nil {
				return fmt.Errorf("failed to read config file: %w", err)
			}
			config = lib.RawConfig(data)
		}

		client, err := lib.NewDryRunClient()
		if err != nil {
			return fmt.Errorf("failed to create k8s client: %w", err)
		}

		ctx := lib.NewFuzzContext(0, slog.Default(), client)
		f, _, err := lib.InitializeFuzzer[PolicyTest](ctx, config)
		if err != nil {
			return fmt.Errorf("failed to initialize fuzzer: %w", err)
		}

		data, err := json.MarshalIndent(json.RawMessage(f.Config()), "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal config: %w", err)
		}
		fmt.Println(string(data))

		return nil
	},
}

func init() {
	logConfigCmd.Flags().StringP("config-file", "c", "", "Config file path with overrides for the fuzzer")
}

func main() {
	hiveApp.RegisterFlags(rootCmd.Flags())
	rootCmd.AddCommand(hiveApp.Command())
	rootCmd.AddCommand(logConfigCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
