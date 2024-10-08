# Obtain an absolute path to the directory of the Makefile.
# Assume the Makefile is in the root of the repository.
REPODIR := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

BPF_INCLUDE += -I${REPODIR}/internal/headers

ALL_GO_MOD_DIRS := $(shell find . -type f -name 'go.mod' ! -path './LICENSES/*' -exec dirname {} \; | sort)

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
	docker run --rm -v $(shell pwd):/app keyval/odiglet-base:v1.5 /bin/sh -c "cd ../app && make generate"

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