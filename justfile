# Clippy over the whole workspace, every feature on
check *args:
    cargo clippy --all-features --workspace {{ args }} -- -W clippy::pedantic -D warnings -D unused_must_use

# Check formatting without modifying files
fmt-check:
    cargo fmt --all -- --check

# Apply rustfmt to the whole workspace
fmt:
    cargo fmt --all

# Run the test suite, every feature on. Usage: just test [--verbose]
test *args:
    cargo test --workspace --all-features {{ args }}

# Run doctests
doctest *args:
    cargo test --workspace --all-features --doc {{ args }}

# Full local CI gate: format, lint, tests, doctests
ci: fmt-check check test doctest
