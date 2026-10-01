// START_AI_HEADER
// MODULE: mac-companion/zenoh-link-tls-patched/src/lib.rs
// PURPOSE: TLS link transport for Zenoh (patched for bsdOS DPI bypass with ALPN + cert verification skip).
// INTENT: bsdOS patched fork of zenoh-link-tls that adds ALPN (h2/http/1.1) for DPI camouflage,
//         ZENOH_TLS_SKIP_CERT_VERIFICATION env var, and the ObfsLocatorInspector pattern.
// DEPENDENCIES: async-trait, zenoh-link-commons, zenoh-protocol, zenoh-config, zenoh-result.
// PUBLIC_API: TlsLocatorInspector, TlsConfigurator, LinkUnicastTls, LinkManagerUnicastTls.
// END_AI_HEADER

//
// Copyright (c) 2023 ZettaScale Technology
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//
// Contributors:
//   ZettaScale Zenoh Team, <zenoh@zettascale.tech>
//

//! ⚠️ WARNING ⚠️
//!
//! This crate is intended for Zenoh's internal use.
//!
//! [Click here for Zenoh's documentation](https://docs.rs/zenoh/latest/zenoh)
use std::str::FromStr;

use async_trait::async_trait;
use zenoh_core::zconfigurable;
use zenoh_link_commons::LocatorInspector;
use zenoh_protocol::{
    core::{Locator, Metadata, Reliability},
    transport::BatchSize,
};
use zenoh_result::ZResult;

mod unicast;
mod utils;
pub use unicast::*;
pub use utils::TlsConfigurator;

// Default MTU (TLS PDU) in bytes.
// NOTE: Since TLS is a byte-stream oriented transport, theoretically it has
//       no limit regarding the MTU. However, given the batching strategy
//       adopted in Zenoh and the usage of 16 bits in Zenoh to encode the
//       payload length in byte-streamed, the TLS MTU is constrained to
//       2^16 - 1 bytes (i.e., 65535).
const TLS_MAX_MTU: BatchSize = BatchSize::MAX;
pub const TLS_LOCATOR_PREFIX: &str = "tls";

const IS_RELIABLE: bool = true;

#[derive(Default, Clone, Copy)]
pub struct TlsLocatorInspector;
#[async_trait]
impl LocatorInspector for TlsLocatorInspector {
    // protocol:start
//   purpose: Return the locator prefix string for this transport ("tls").
//   input:  &self.
//   output: "tls" (&str).
//   sideEffects: none (pure constant).
    fn protocol(&self) -> &str {
        TLS_LOCATOR_PREFIX
    }
    // protocol:end

    // is_multicast:start
//   purpose: Check whether TLS transport supports multicast (always false — TLS is unicast-only).
//   input:  &self, _locator: ignored.
//   output: Ok(false).
//   sideEffects: none (pure).
    async fn is_multicast(&self, _locator: &Locator) -> ZResult<bool> {
        Ok(false)
    }
    // is_multicast:end

    // is_reliable:start
//   purpose: Check whether TLS transport is reliable (always true, falls back to IS_RELIABLE constant).
//   input:  &self, locator: may carry per-endpoint reliability metadata.
//   output: Ok(true) — TLS is a stream-oriented reliable transport.
//   sideEffects: none (pure).
    fn is_reliable(&self, locator: &Locator) -> ZResult<bool> {
        if let Some(reliability) = locator
            .metadata()
            .get(Metadata::RELIABILITY)
            .map(Reliability::from_str)
            .transpose()?
        {
            Ok(reliability == Reliability::Reliable)
        } else {
            Ok(IS_RELIABLE)
        }
    }
    // is_reliable:end
}

zconfigurable! {
    // Default MTU (TLS PDU) in bytes.
    static ref TLS_DEFAULT_MTU: BatchSize = TLS_MAX_MTU;
    // The LINGER option causes the shutdown() call to block until (1) all application data is delivered
    // to the remote end or (2) a timeout expires. The timeout is expressed in seconds.
    // More info on the LINGER option and its dynamics can be found at:
    // https://blog.netherlabs.nl/articles/2009/01/18/the-ultimate-so_linger-page-or-why-is-my-tcp-not-reliable
    static ref TLS_LINGER_TIMEOUT: i32 = 10;
    // Amount of time in microseconds to throttle the accept loop upon an error.
    // Default set to 100 ms.
    static ref TLS_ACCEPT_THROTTLE_TIME: u64 = 100_000;
}
