# ADR 0006 feasibility suite - build + gate suite.
#
# `make`            build host + all adapters, then run the 11-gate suite
# `make build`      build the host binary and the Rust-based adapters
# `make test`       run the executable 11-gate suite (manages fake servers)
# `make clean`      remove ALL generated suite output (clean reproducibility
#                   boundary: bindings, wasm, certs, target dirs, temp state)
#
# The TinyGo adapter (adapters/go-adapter/adapter_go.wasm) is generated from
# source during the build (see adapters/go-adapter/Makefile), so it does not
# rely on a prebuilt committed artifact (Gate 3).

SHELL := /bin/bash
POC   := $(CURDIR)
HOST_BIN := host/target/debug/permsync-adr0006-host
RUST_ADAPTERS := rust-adapter bad-adapter missing-import-adapter egress-adapter \
                 wasi-adapter process-adapter runaway-mem-adapter runaway-cpu-adapter
# The TinyGo adapter is generated from source (adapters/go-adapter/wit-build, see
# its Makefile for recorded toolchain versions + build command), so it is built
# here like any other adapter rather than relying on a prebuilt artifact (Gate 3).
GO_ADAPTER    := go-adapter

GATE_SCRIPT := tests/gates.py

.PHONY: all build adapters test certs clean

all: build test

build: $(HOST_BIN) adapters

# Ephemeral test CA + server certs are generated (never committed) and the host
# verifies the fake servers' TLS against the generated CA (Gate 6).
certs:
	./tooling/gen_certs.sh

$(HOST_BIN):
	cd host && cargo build

adapters:
	@for a in $(RUST_ADAPTERS); do \
		echo "== building adapter $$a =="; \
		$(MAKE) -C adapters/$$a wasm || exit 1; \
	done
	@echo "== building adapter $(GO_ADAPTER) =="
	$(MAKE) -C adapters/$(GO_ADAPTER) wasm || exit 1

test: build certs
	@echo "== running 11-gate suite =="
	python3 $(GATE_SCRIPT)

clean:
	cd host && cargo clean
	rm -rf generated tests/_tmp_cfg.json
	@for a in $(RUST_ADAPTERS) $(GO_ADAPTER); do \
		rm -rf adapters/$$a/target; \
	done
	@for a in $(RUST_ADAPTERS); do \
		rm -f adapters/$$a/src/bindings.rs; \
	done
	$(MAKE) -C adapters/$(GO_ADAPTER) clean
