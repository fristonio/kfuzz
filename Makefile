SHELL := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c

ROOT_DIR := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

IMAGE_REGISTRY ?=
IMAGE_NAME ?= fristonio/kfuzz
IMAGE_TAG ?= latest
IMAGE_PLATFORM ?= linux/amd64,linux/arm64

##@ Build and Run

build: ## Build the project
	go build -ldflags="-w -s" -o bin/kfuzz .

run: ## Run the project
	go run ./...

##@ Development

test: ## Run the tests
	go test ./...

gofmt: ## Run gofmt for the project
	go fmt ./...

##@ Artifacts
docker-build: ## Build docker image.
	docker build -f hack/Dockerfile -t $(IMAGE_NAME):$(IMAGE_TAG)

docker-push: ## Push the Docker image
	docker tag $(IMAGE_NAME):$(IMAGE_TAG) $(IMAGE_REGISTRY)$(IMAGE_NAME):$(IMAGE_TAG)
	docker push $(IMAGE_REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)

docker-buildx-push: ## Build platform specific docker image(requires buildx) and push to registry.
	# https://docs.docker.com/build/building/multi-platform/
	docker buildx build --push --platform $(IMAGE_PLATFORM) -f hack/Dockerfile -t $(IMAGE_REGISTRY)$(IMAGE_NAME):$(IMAGE_TAG) .

##@ Helpers

.PHONY: help
help: ## Display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)
