SHELL := /usr/bin/env bash

CARGO_ENV ?= CARGO_PROFILE_DEV_DEBUG=0 CARGO_BUILD_JOBS=1
DB ?= infra/map.db
BIND ?= 127.0.0.1:8765

.PHONY: help fmt check build buld test ui loc clean

help:
	@printf 'cloudmapper Make targets\n\n'
	@printf '  make build       Build the cloudmapper CLI\n'
	@printf '  make test        Run unit tests\n'
	@printf '  make check       Run fmt, check, tests, and build\n'
	@printf '  make fmt         Check Rust formatting\n'
	@printf '  make ui          Serve the local Cytoscape UI\n'
	@printf '  make loc         Count lines in source files\n'
	@printf '  make clean       Remove Cargo build output\n\n'
	@printf 'Options:\n'
	@printf '  DB=%s\n' '$(DB)'
	@printf '  BIND=%s\n' '$(BIND)'

fmt:
	$(CARGO_ENV) cargo fmt --check

check: fmt
	$(CARGO_ENV) cargo check
	$(CARGO_ENV) cargo test
	$(CARGO_ENV) cargo build

build:
	$(CARGO_ENV) cargo build

buld: build

test:
	$(CARGO_ENV) cargo test

ui:
	$(CARGO_ENV) cargo run -- ui --db "$(DB)" --bind "$(BIND)"

loc:
	@git ls-files -z -- \
		Makefile \
		Cargo.toml \
		'src/*.rs' \
		'src/ui_assets/*.html' \
		'src/ui_assets/*.css' \
		'src/ui_assets/*.js' \
		| xargs -0 wc -l

clean:
	cargo clean
