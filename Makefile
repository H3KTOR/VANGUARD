mkfile_path := $(abspath $(lastword $(MAKEFILE_LIST)))
ROOT_DIR := $(dir $(mkfile_path))
CORE_DIR := $(ROOT_DIR)core
BIN := $(CORE_DIR)/vanguard

.PHONY: build run-simulate-ssh test vet fmt clean

## build: Compile the VANGUARD core binary (stripped, for size).
build:
	cd $(CORE_DIR) && go build -ldflags="-s -w" -o vanguard ./cmd/vanguard

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
