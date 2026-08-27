# Reproducible TinyGo (Go) Target Adapter build for ADR 0006 Gate 3.
#
# The non-Rust guest is built here from source each time so it never relies on a
# committed prebuilt `adapter_go.wasm` artifact (Gate 3: language independence).
# `wit-build/` is the flattened WIT resolver layout (see build-world.wit) that
# TinyGo needs to link the `adapter-build` world (permissionsync contract +
# wasi:cli/command). `wit-build/permissions.wit` is regenerated from the single
# canonical ../../wit/permissions.wit (one source of truth, no per-crate copy).
#
# Recorded toolchain versions:
#   tinygo 0.37.0  (go 1.24.4, LLVM 19.1.2)
#   wit-bindgen-go v0.7.0
#   wasm-tools 1.258.0
#
# Requirements on PATH at build time: tinygo, wit-bindgen-go (for bindgen regen
# only), wasm-tools, go.

.PHONY: wasm bindgen clean

wasm: adapter_go.wasm

adapter_go.wasm: main.go go.mod wit-build
	cp ../../wit/permissions.wit wit-build/permissions.wit
	wit-bindgen-go generate --world adapter-build ./wit-build
	tinygo build \
		-target=wasip2 \
		-wit-package=./wit-build \
		-wit-world=adapter-build \
		-o adapter_go.wasm \
		.

# Regenerate the bindings (only needed when the WIT contract changes).
bindgen:
	cp ../../wit/permissions.wit wit-build/permissions.wit
	wit-bindgen-go generate --world adapter-build ./wit-build

clean:
	rm -f adapter_go.wasm
	rm -rf permissionsync wasi
	rm -f wit-build/permissions.wit
