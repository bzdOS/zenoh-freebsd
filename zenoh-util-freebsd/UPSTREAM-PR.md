# feat(util/net): FreeBSD support for socket bind-to-device

## Summary

Add no-op stubs for `set_bind_to_device_tcp_socket` and
`set_bind_to_device_udp_socket` on `target_os = "freebsd"`.

Without these stubs the crate fails to compile on FreeBSD with a
"function not found in this scope" error whenever the
`iface` / `bind-to-device` feature is used, because the only existing
implementations are gated on `linux | android` and
`macos | ios | windows`.

## Why no-op (not a real implementation)

FreeBSD does not implement the `SO_BINDTODEVICE` socket option.  The
socket API for interface selection on FreeBSD is `IP_BOUND_IF`
(IPv4, added in 11.1) and `IPV6_BOUND_IF` (IPv6), neither of which is
exposed through the `tokio` / `socket2` `bind_device` abstraction that
the Linux path already uses.

A fully functional FreeBSD implementation would require raw `libc::setsockopt`
calls with `IP_BOUND_IF`/`IPV6_BOUND_IF` and is out of scope for this PR.
The stubs match the pattern already in place for macOS/iOS/Windows: emit a
`tracing::warn` and return `Ok(())` so callers degrade gracefully.

Reference: FreeBSD does not list `SO_BINDTODEVICE` in `socket(7)` or
`ip(4)`; the option originated in Linux and is Linux-specific.
See: https://man.freebsd.org/cgi/man.cgi?query=ip&sektion=4

## Changes

**`commons/zenoh-util/src/net/mod.rs`**

```rust
#[cfg(target_os = "freebsd")]
pub fn set_bind_to_device_tcp_socket(socket: &TcpSocket, iface: &str) -> ZResult<()> {
    tracing::warn!("Binding the socket {socket:?} to the interface {iface} is not supported on FreeBSD");
    Ok(())
}

#[cfg(target_os = "freebsd")]
pub fn set_bind_to_device_udp_socket(socket: &UdpSocket, iface: &str) -> ZResult<()> {
    tracing::warn!("Binding the socket {socket:?} to the interface {iface} is not supported on FreeBSD");
    Ok(())
}
```

No other files changed.

## How to verify

On a FreeBSD 13.x / 14.x / 15.x host or cross-compile target:

```sh
# full crate test suite
cargo test -p zenoh-util --target x86_64-unknown-freebsd

# minimal compile check (cross, no std tests)
cargo check -p zenoh-util --target x86_64-unknown-freebsd
```

Expected: compilation succeeds; no `set_bind_to_device_*` symbol errors.
The warn log is emitted only when a caller actually passes an `iface`
value, so the default Zenoh smoke tests (which use `iface: None`) are
silent.

## Related

- Existing pattern: `#[cfg(any(target_os = "macos", target_os = "ios", target_os = "windows"))]` stubs in the same file (lines ~532-553).
- Zenoh on FreeBSD is needed for embedded BSDs and jailed environments (FreeBSD jails, TrueNAS SCALE, etc.).
