#
# Copyright (c) 2018 Infoblox Inc. All Rights Reserved.
#
PROJECT_ROOT            := github.com/Infoblox-CTO/cdc.grpc-in
BUILD_PATH              := bin
SERVER_DOCKERFILE       := $(CURDIR)/Dockerfile
TAG_LATEST              := latest

# configuration for dockerfiles
DOCKERFILE_TEST_PATH    := $(CURDIR)/test
SERVER_TEST_DOCKERFILE  := $(DOCKERFILE_TEST_PATH)/Dockerfile

# configuration for image names
GIT_TAG                 ?= $(shell git describe --dirty=-unsupported --always --tags)
GIT_SHA                 ?= $(shell git log --format="%H" -n 1)
IMAGE_VERSION           ?= $(GIT_TAG)
IMAGE_REGISTRY          ?= infobloxcto

SERVER_IMAGE            := $(IMAGE_REGISTRY)/cdc.grpc-in
SERVER_TEST_IMAGE       := $(IMAGE_REGISTRY)/cdc.grpc-in-test

# configuration for building on host machine
GO_CACHE                := -pkgdir $(BUILD_PATH)/go-cache
GO_BUILD_FLAGS          ?= $(GO_CACHE) -i -v
GO_TEST_FLAGS           ?= -v -cover
GO_PACKAGES             := $(shell go list ./... | grep -v vendor)
GO_TEST_PKG             := $(shell go list ./... | grep -v vendor)

.PHONY: all
all: vendor test build

.PHONY: fmt
fmt:
	@go fmt $(GO_PACKAGES)

.PHONY: test
test:
	@go test -p 1 $(GO_TEST_FLAGS) $(GO_PACKAGES)

# Build container image
.PHONY: build
build:
	@docker build --build-arg GIT_TAG=$(GIT_TAG) --build-arg GIT_SHA=$(GIT_SHA) --build-arg GITHUB_PAT=$(GitHub_PAT) -f $(SERVER_DOCKERFILE) -t $(SERVER_IMAGE):$(IMAGE_VERSION) .
	@docker tag $(SERVER_IMAGE):$(IMAGE_VERSION) $(SERVER_IMAGE):$(TAG_LATEST)
	@docker image prune -f --filter label=stage=server-intermediate

# push container image
.PHONY: push
push:
	@docker push $(SERVER_IMAGE):$(IMAGE_VERSION)

# push latest container image
.PHONY: push-latest
push-latest:
	@docker push $(SERVER_IMAGE):$(TAG_LATEST)

.PHONY: clean
clean:
	@docker rmi -f $(SERVER_IMAGE):$(IMAGE_VERSION)  || true
	@docker rmi -f $(SERVER_IMAGE):$(TAG_LATEST)  || true

.PHONY: test-build
test-build:
	@echo "Not Implemented"
	#@docker build -f $(SERVER_TEST_DOCKERFILE) -t $(SERVER_TEST_IMAGE):$(TAG_LATEST) .

# testing
#.PHONY: test
#test:
#	@echo "Not Implemented"
	#@docker run -v $(shell pwd):/tmp/p4 --rm=true $(SERVER_TEST_IMAGE):$(TAG_LATEST)

.PHONY: test-clean
test-clean:
	docker rmi -f $(SERVER_TEST_IMAGE):$(TAG_LATEST) || true

.PHONY: clean-test-data
clean-test-data:
	rm -rf $(CURDIR)/pkg/test/data/parser/generated-files || true
	rm -rf $(CURDIR)/pkg/test/data/cdc_metrics || true

vendor:
	@dep ensure -vendor-only

vendor-update:
	@dep ensure