# Obtain an absolute path to the directory of the Makefile.
# Assume the Makefile is in the root of the repository.
REPODIR := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

BPF_INCLUDE += -I${REPODIR}/internal/headers
TOOLS_MOD_DIR := ./internal/tools
TOOLS = $(CURDIR)/.tools

$(TOOLS):
	@mkdir -p $@
$(TOOLS)/%: | $(TOOLS)
	cd $(TOOLS_MOD_DIR) && \
	go build  -buildvcs=false -o $@ $(PACKAGE)

GOLANGCI_LINT = $(TOOLS)/golangci-lint
$(TOOLS)/golangci-lint: PACKAGE=github.com/golangci/golangci-lint/v2/cmd/golangci-lint

ALL_GO_MOD_DIRS := $(shell find . -type f -name 'go.mod' ! -path './internal/tools/*' -exec dirname {} \; | sort)

.PHONY: golangci-lint golangci-lint-fix
golangci-lint-fix: ARGS=--fix
golangci-lint-fix: golangci-lint
golangci-lint: go-mod-tidy generate $(ALL_GO_MOD_DIRS:%=golangci-lint/%)
golangci-lint/%: DIR=$*
golangci-lint/%: | $(GOLANGCI_LINT)
	@echo 'golangci-lint $(if $(ARGS),$(ARGS) ,)$(DIR)' \
		&& cd $(DIR) \
		&& $(GOLANGCI_LINT) run --allow-serial-runners --timeout=2m0s $(ARGS)

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
	docker run --rm -v $(shell pwd):/app keyval/odiglet-base:v1.8 /bin/sh -c "cd ../app && make generate"

.PHONY: docker-test
docker-test:
	docker run --rm \
		--privileged \
		--pid=host \
		-v $(shell pwd):/app \
		-v /sys/kernel/debug:/sys/kernel/debug \
		-v /sys/kernel/tracing:/sys/kernel/tracing \
		keyval/odiglet-base:v1.8 \
		/bin/sh -c "cd ../app && make test"

.PHONY: test
test: generate
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