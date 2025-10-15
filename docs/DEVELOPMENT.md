# Development Guide

## Rust Version Support

This project maintains compatibility with a **Minimum Supported Rust Version (MSRV)** of **1.90.0** while also ensuring compatibility with the latest stable Rust.

### Local Development

**Default: Stable Rust** (fast iteration)

For day-to-day development, all commands use stable Rust by default for the fastest experience:

```bash
# Quick checks with stable (fast)
just check        # Runs fmt, docs, clippy, and tests with stable
just lint         # Clippy with stable
just fmt          # Format check with stable
just docs         # Doc check with stable
just test-all     # All test combinations
```

**Pre-commit: Both Stable and MSRV** (comprehensive)

Before committing, run comprehensive checks against both Rust versions:

```bash
just precommit    # Checks both stable AND MSRV (1.90.0)
```

This ensures your code works on both the latest stable and the minimum supported version.

### Manual Version Selection

You can manually specify which Rust version to use:

```bash
# Check with MSRV
./scripts/check-all.sh 1.90.0
./scripts/check-clippy.sh 1.90.0
./scripts/check-fmt.sh 1.90.0
./scripts/check-docs.sh 1.90.0

# Check with stable (default)
./scripts/check-all.sh stable
./scripts/check-all.sh          # stable is the default

# MSRV-only check (convenience script)
./scripts/check-msrv.sh
```

### CI/CD

GitHub Actions runs the full test matrix:

- **Rust versions**: 1.90.0 (MSRV) + stable
- **Operating systems**: Ubuntu, macOS (latest), macOS (M1)
- **Feature combinations**: all-features, no-features, mip04-only

This gives us confidence that the code works across:

- 2 Rust versions (MSRV and latest)
- 3 operating systems
- 3 feature configurations
- = **18 test combinations** total

### Updating the MSRV

When you need to bump the MSRV, update these locations:

1. `/Cargo.toml` - `workspace.package.rust-version`
2. `/scripts/check-msrv.sh` - `msrv` variable
3. `/.github/workflows/ci.yml` - matrix `rust` array
4. `docs/DEVELOPMENT.md` - hard-coded MSRV version references

### Recommended Workflow

1. **During development**: Use `just check` frequently (stable, fast)
2. **Before committing**: Run `just precommit` (both versions, comprehensive)
3. **Before pushing**: Ensure CI will pass by checking locally first

This approach balances speed during development with comprehensive validation before committing.
