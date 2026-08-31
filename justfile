default:
    @just --list

# everything CI checks
ci: fmt-check lint test

build:
    cargo build

release:
    cargo build --release

fmt:
    cargo fmt

fmt-check:
    cargo fmt --check

lint:
    cargo clippy

test:
    cargo test

# STUN test, needs internet and a reachable RFC 5780 server
test-network:
    cargo test --features network-test

clean:
    cargo clean
