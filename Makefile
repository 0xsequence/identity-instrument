CONFIG           ?= $(TOP)/etc/nitro.conf
ENV              ?= prod

TOP              := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
SHELL            = bash -o pipefail
TEST_FLAGS       ?= -v

define run
	@go run github.com/goware/rerun/cmd/rerun -watch ./ -ignore bin tests -run \
		'GOGC=off go build -o ./bin/$(1) ./cmd/$(1)/main.go && CONFIG=$(CONFIG) ./bin/$(1)'
endef

run:
	$(call run,identity)

run-ingress-proxy:
	$(call run,ingress-proxy)

run-builder-mock:
	$(call run,builder-mock)

up:
	docker-compose up --build

define build
	CGO_ENABLED=0 \
	GOARCH=amd64 \
	GOOS=linux \
	go build -v \
		-trimpath \
		-buildvcs=false \
		-ldflags='-X "github.com/0xsequence/identity-instrument.VERSION=$(VERSION)" -s -w -buildid=' \
		-o ./bin/$(1) \
		./cmd/$(1)
endef

build: build-identity build-ingress-proxy

build-identity:
	$(call build,identity)

build-ingress-proxy:
	$(call build,ingress-proxy)

generate:
	go generate -x ./...

.PHONY: proto
proto:
	go generate -x ./proto

clean:
	@rm -rf ./bin/*
	@go clean -cache -testcache

test: test-clean
	GOGC=off go test $(TEST_FLAGS) -run=$(TEST) ./...
	GOGC=off cd tests && go test $(TEST_FLAGS) -run=$(TEST) ./...

test-clean:
	GOGC=off go clean -testcache

eif: clean ensure-version
	@mkdir -p bin
	@docker build --quiet --platform linux/amd64 --build-arg VERSION=$(VERSION) --build-arg ENV_ARG=$(ENV) -t identity-instrument-builder .
	@docker run --platform linux/amd64 -v $(TOP)/bin:/out identity-instrument-builder identity.$(VERSION)

ensure-version:
	@test -n "$(VERSION)" || (echo "Oops! you forgot to pass the VERSION env variable, try: make VERSION=vX.X.X eif" && exit 1)

.PHONY: vendor
vendor:
	go mod tidy && go mod vendor

