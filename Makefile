# Obtain an absolute path to the directory of the Makefile.
# Assume the Makefile is in the root of the repository.
REPODIR := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

BPF_INCLUDE += -I${REPODIR}/internal/headers
TESTS_BIN_DIR = test/bin
FILE_OPEN_PROG_BIN = ${TESTS_BIN_DIR}/file_open
BASE_IMAGE = keyval/odiglet-base:v1.10

GOLANGCI_LINT_VERSION := v2.7.2
GOLANGCI_LINT_PACKAGE := github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

ALL_GO_MOD_DIRS := $(shell find . -type f -name 'go.mod' -exec dirname {} \; | sort)

.PHONY: golangci-lint golangci-lint-fix
golangci-lint-fix: ARGS=--fix
golangci-lint-fix: golangci-lint
golangci-lint: go-mod-tidy generate $(ALL_GO_MOD_DIRS:%=golangci-lint/%)
golangci-lint/%: DIR=$*
golangci-lint/%:
	@echo 'golangci-lint $(if $(ARGS),$(ARGS) ,)$(DIR)' \
		&& cd $(DIR) \
		&& go run $(GOLANGCI_LINT_PACKAGE) run --allow-serial-runners --timeout=2m0s $(ARGS)


$(TESTS_BIN_DIR):
	mkdir -p $(TESTS_BIN_DIR)

.PHONY: go-mod-tidy
go-mod-tidy: $(ALL_GO_MOD_DIRS:%=go-mod-tidy/%)
go-mod-tidy/%: DIR=$*
go-mod-tidy/%:
	@cd $(DIR) && go mod tidy -compat=1.20

.PHONY: generate
generate: export CFLAGS := $(BPF_INCLUDE)
generate: go-mod-tidy
generate:
	go generate ./...

.PHONY: docker-generate
docker-generate:
	docker run --rm -v $(shell pwd):/app $(BASE_IMAGE) /bin/sh -c "cd ../app && make generate"

$(FILE_OPEN_PROG_BIN): test/c_processes/file_open.c | $(TESTS_BIN_DIR)
	gcc test/c_processes/file_open.c -o $(FILE_OPEN_PROG_BIN)

.PHONY: docker-test-debian docker-test-alpine
docker-test:
	docker run --rm \
		--privileged \
		--pid=host \
		-v $(shell pwd):/app \
		-v /sys/kernel/debug:/sys/kernel/debug \
		-v /sys/kernel/tracing:/sys/kernel/tracing \
		-w /app \
		$(BASE_IMAGE) \
		/bin/sh -c "make test"

docker-test-debian:
	docker run --rm \
		--privileged \
		--pid=host \
		-v $(shell pwd):/app \
		-v /sys/kernel/debug:/sys/kernel/debug \
		-v /sys/kernel/tracing:/sys/kernel/tracing \
		-w /app \
		golang:1.25 bash -c '\
			apt-get update && \
			apt-get install -y gcc llvm clang && \
			make test'

docker-test-alpine:
	docker run --rm \
		--privileged \
		--pid=host \
		-v $(shell pwd):/app \
		-v /sys/kernel/debug:/sys/kernel/debug \
		-v /sys/kernel/tracing:/sys/kernel/tracing \
		-w /app \
		golang:1.25-alpine sh -c '\
			apk add --no-cache make gcc musl-dev llvm clang bash && \
			make test'

.PHONY: test
test: generate $(FILE_OPEN_PROG_BIN)
	go test -v ./...

.PHONY: build
build: generate
	go build -o runtime-detector ./cmd/...

.PHONY: check-clean-work-tree
check-clean-work-tree:
	if [ -n "$$(git status --porcelain)" ]; then \
		git status; \
		git --no-pager diff; \
		echo 'Working tree is not clean, did you forget to run "make precommit", "make generate" or "make offsets"?'; \
		exit 1; \
	fi