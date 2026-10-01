# zenoh-freebsd

Patched [Eclipse Zenoh](https://github.com/eclipse-zenoh/zenoh) 1.9.0 crates for
FreeBSD, plus `obfs` — a DPI-resistant link transport.

| Crate | What changed |
|---|---|
| `zenoh-util-freebsd` | FreeBSD fixes in `zenoh-util` (see its `UPSTREAM-PR.md`) |
| `zenoh-link-commons-patched` | FreeBSD socket handling |
| `zenoh-link-tls-patched` | builds against the patched commons |
| `zenoh-link-patched` | link dispatcher knows the `obfs/` locator |
| `zenoh-link-obfs` | the obfs transport itself (X25519 + PSK; see its README) |

## Use

In the consuming workspace's `Cargo.toml`:

```toml
[patch.crates-io]
zenoh-util         = { git = "https://github.com/bzdOS/zenoh-freebsd" }
zenoh-link-commons = { git = "https://github.com/bzdOS/zenoh-freebsd" }
zenoh-link-tls     = { git = "https://github.com/bzdOS/zenoh-freebsd" }
zenoh-link         = { git = "https://github.com/bzdOS/zenoh-freebsd" }
```

The PSK for `obfs` comes from `BSDOS_OBFS_PSK` (base64) or the endpoint
parameter `obfs_psk_base64`; nothing secret lives in this repository.

## License

Same as upstream Zenoh: EPL-2.0 OR Apache-2.0.
