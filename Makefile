mkfile_path := $(abspath $(lastword $(MAKEFILE_LIST)))
ROOT_DIR := $(dir $(mkfile_path))
CORE_DIR := $(ROOT_DIR)core
FRONTEND_DIR := $(CORE_DIR)/frontend
TOOLKIT_DIR := $(ROOT_DIR)toolkit
BIN := $(CORE_DIR)/vanguard

.PHONY: build build-frontend build-go run-simulate-ssh test vet fmt clean toolkit-install

## build: Build the React dashboard, then compile the VANGUARD core binary (stripped, for size) with it embedded.
build: build-frontend build-go

## build-frontend: Install (if needed) and build the Vite/React dashboard into core/cmd/vanguard/dist.
build-frontend:
	cd $(FRONTEND_DIR) && [ -d node_modules ] || npm install
	cd $(FRONTEND_DIR) && npm run build

## build-go: Compile the VANGUARD core binary only (assumes core/cmd/vanguard/dist is already up to date).
build-go:
	cd $(CORE_DIR) && go build -ldflags="-s -w" -o vanguard ./cmd/vanguard

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

## clean: Remove build artifacts and local dev databases.
clean:
	rm -f $(BIN) $(CORE_DIR)/*.db $(CORE_DIR)/*.db-wal $(CORE_DIR)/*.db-shm $(CORE_DIR)/*.db-journal
	find $(CORE_DIR)/cmd/vanguard/dist -mindepth 1 ! -name '.gitkeep' -exec rm -rf {} +
