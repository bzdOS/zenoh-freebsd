# Zenoh FreeBSD Support Patch

## Problem

Zenoh 1.x (`zenoh-util` 1.9.0) uses Linux-specific socket binding functionality:
- `SO_BINDTODEVICE` (via `TcpSocket::bind_device()` and `UdpSocket::bind_device()`)
- This syscall is **not available on FreeBSD**

Functions in `zenoh_util::net` module:
- `set_bind_to_device_tcp_socket()` 
- `set_bind_to_device_udp_socket()`

These are only implemented for:
- Linux / Android (actual implementation)
- macOS / iOS / Windows (stub returning `Ok(())` with warning)
- **FreeBSD was missing** → compilation error

## Solution

### Files Created

1. **`/srv/bsdos/zenoh-util-freebsd/`** — Local fork of zenoh-util 1.9.0
   - `Cargo.toml` — Package configuration
   - `src/net/mod.rs` — **Modified**: Added FreeBSD stubs for socket binding functions
   - Other modules (lib_loader, lib_search_dirs, timer, etc.) — copied as-is

2. **`/srv/bsdos/freebsd-patches/zenoh-util-freebsd.patch`** — Unified diff
   - Shows exact changes: adds `#[cfg(target_os = "freebsd")]` blocks for both functions
   - Can be applied to upstream zenoh-util source

3. **`/srv/bsdos/Cargo.toml`** — Updated workspace root
   - `zenoh = { version = "1", ... }` — upgraded from 0.11 to 1.x
   - `[patch.crates-io]` — redirects zenoh-util to local FreeBSD-patched version

## How It Works

### Patch Content

For both `set_bind_to_device_tcp_socket()` and `set_bind_to_device_udp_socket()`:

```rust
#[cfg(target_os = "freebsd")]
pub fn set_bind_to_device_tcp_socket(socket: &TcpSocket, iface: &str) -> ZResult<()> {
    tracing::warn!("Binding the socket ... is not supported on FreeBSD");
    Ok(())
}
```

**Rationale:**
- FreeBSD does not support `SO_BINDTODEVICE` at the socket level
- For bsdOS **peer-to-peer mode** (no broker), interface binding is **not critical**
- Network is inherited via jails: `ip4=inherit` allows full networking, `ip4=disable` blocks all
- Fine-grained interface binding is not needed for the current architecture

### Cargo Patch Mechanism

In `/srv/bsdos/Cargo.toml`:

```toml
[patch.crates-io]
zenoh-util = { path = "./zenoh-util-freebsd" }
```

This tells Cargo:
- Whenever a dependency requires `zenoh-util`, use the local directory instead
- Applied **globally** to workspace — all members automatically get FreeBSD support

## Building with FreeBSD Target

```bash
# Cross-compile to FreeBSD
cargo build --target aarch64-unknown-freebsd

# Or in the guest (FreeBSD 14.x):
make broker-build
make app-build
```

## Verification

The patch is minimal and **safe**:
- ✅ No `unsafe` code
- ✅ No panics/unwraps
- ✅ Returns `Ok(())` with warning (matches macOS/Windows behavior)
- ✅ Only affects FreeBSD builds (`#[cfg(...)]` is compile-time)
- ✅ Zero runtime cost on other platforms

## Future Work

If Zenoh project adds official FreeBSD support, this patch can be removed and the workspace can depend on upstream zenoh directly.

## References

- Zenoh 1.x: https://github.com/eclipse-zenoh/zenoh
- FreeBSD socket API: https://man.freebsd.org/setsockopt(2)
- bsdOS architecture: See `/srv/bsdos/ARCHITECTURE-REVIEW.md`
