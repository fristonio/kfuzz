# kfuzz

`kfuzz` is an experimental kubernetes resource fuzzing tool focused on
simulating churn for Cilium running in a cluster.

## Usage

Build the binary:

```sh
make help
make build
```

Run against the cluster selected with current Kubernetes configuration:

```sh
./bin/kfuzz --config-file hack/config.json --run-duration 5m
```

The fuzz seed, tick interval, API request pacing, namespace, and resource
generation settings are configurable through command-line flags and the JSON
configuration file. Run `kfuzz --help` to see the available options.

Run make target `docker-buildx-push` to build and push cross platform image.
