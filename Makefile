mkfile_path := $(abspath $(lastword $(MAKEFILE_LIST)))
ROOT_DIR := $(dir $(mkfile_path))
CORE_DIR := $(ROOT_DIR)core
FRONTEND_DIR := $(CORE_DIR)/frontend
TOOLKIT_DIR := $(ROOT_DIR)toolkit
BIN := $(CORE_DIR)/vanguard

VERSION ?= $(shell git -C $(ROOT_DIR) describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: build build-frontend build-go run-simulate-ssh test vet fmt clean toolkit-install check-deploy release

## build: Build the React dashboard, then compile the VANGUARD core binary (stripped, for size) with it embedded.
build: build-frontend build-go

## build-frontend: Install (if needed) and build the Vite/React dashboard into core/cmd/vanguard/dist.
build-frontend:
	cd $(FRONTEND_DIR) && [ -d node_modules ] || npm install
	cd $(FRONTEND_DIR) && npm run build

## build-go: Compile the VANGUARD core binary only (assumes core/cmd/vanguard/dist is already up to date).
build-go:
	cd $(CORE_DIR) && go build -trimpath -ldflags="-s -w -X main.version=$(VERSION)" -o vanguard ./cmd/vanguard

## toolkit-install: Install Python toolkit dependencies.
toolkit-install:
	cd $(TOOLKIT_DIR) && pip3 install -r requirements.txt

## run-simulate-ssh: Quick smoke test of the ssh-bruteforce simulator (dry-run).
run-simulate-ssh: build
	$(BIN) simulate ssh-bruteforce -dry-run

## test: Run the Go test suite.
test:
	cd $(CORE_DIR) && go test ./...

## vet: Run go vet across the core module.
vet:
	cd $(CORE_DIR) && go vet ./...

## fmt: Format all Go source files.
fmt:
	cd $(CORE_DIR) && gofmt -w .

## check-deploy: Syntax-check the deployment scripts (bash -n). Does not prove they work on a real host.
check-deploy:
	for f in deploy/*.sh; do bash -n $$f || exit 1; done

## release: Build unsigned local release artifacts into dist/ (needs the dashboard built; see deploy/release.sh).
release: build-frontend
	bash deploy/release.sh --version $(VERSION)

## clean: Remove build artifacts and local dev databases.
clean:
	rm -f $(BIN) $(CORE_DIR)/*.db $(CORE_DIR)/*.db-wal $(CORE_DIR)/*.db-shm $(CORE_DIR)/*.db-journal
	find $(CORE_DIR)/cmd/vanguard/dist -mindepth 1 ! -name '.gitkeep' -exec rm -rf {} +
