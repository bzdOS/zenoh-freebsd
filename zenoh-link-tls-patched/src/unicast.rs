// START_AI_HEADER
// MODULE: mac-companion/zenoh-link-tls-patched/src/unicast.rs
// PURPOSE: TLS unicast link manager and link implementation for Zenoh (patched with ALPN DPI bypass).
// INTENT: Mirrors upstream zenoh-link-tls/unicast.rs with added ALPN (h2, http/1.1) for DPI camouflage
//         and cert expiration tracking via LinkCertExpirationManager.
// DEPENDENCIES: tokio (net, sync), tokio-rustls (TlsAcceptor, TlsConnector, TlsStream), rustls,
//               x509-parser, zenoh-link-commons, zenoh-protocol, zenoh-result.
// PUBLIC_API: LinkUnicastTls, LinkManagerUnicastTls.
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
use std::{
    cell::UnsafeCell,
    convert::TryInto,
    fmt::{self, Debug},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use time::OffsetDateTime;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Mutex as AsyncMutex,
};
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream};
use tokio_util::sync::CancellationToken;
use x509_parser::prelude::{FromDer, X509Certificate};
use zenoh_core::{bail, zasynclock};
use zenoh_link_commons::{
    get_ip_interface_names,
    tls::expiration::{LinkCertExpirationManager, LinkWithCertExpiration},
    LinkAuthId, LinkManagerUnicastTrait, LinkUnicast, LinkUnicastTrait, ListenersUnicastIP,
    NewLinkChannelSender, BIND_INTERFACE, BIND_SOCKET,
};
use zenoh_protocol::{
    core::{EndPoint, Locator, Priority},
    transport::BatchSize,
};
use zenoh_result::{zerror, ZResult};

use crate::{
    utils::{get_tls_addr, get_tls_host, get_tls_server_name, TlsClientConfig, TlsServerConfig},
    TLS_ACCEPT_THROTTLE_TIME, TLS_DEFAULT_MTU, TLS_LINGER_TIMEOUT, TLS_LOCATOR_PREFIX,
};

#[derive(Default, Debug, PartialEq, Eq, Hash)]
pub struct TlsCommonName(String);

pub struct LinkUnicastTls {
    // The underlying socket as returned from the async-rustls library
    // NOTE: TlsStream requires &mut for read and write operations. This means
    //       that concurrent reads and writes are not possible. To achieve that,
    //       we use an UnsafeCell for interior mutability. Using an UnsafeCell
    //       is safe in our case since the transmission and reception logic
    //       already ensures that no concurrent reads or writes can happen on
    //       the same stream: there is only one task at the time that writes on
    //       the stream and only one task at the time that reads from the stream.
    inner: UnsafeCell<TlsStream<TcpStream>>,
    // The source socket address of this link (address used on the local host)
    src_addr: SocketAddr,
    src_locator: Locator,
    // The destination socket address of this link (address used on the local host)
    dst_addr: SocketAddr,
    dst_locator: Locator,
    // Make sure there are no concurrent read or writes
    write_mtx: AsyncMutex<()>,
    read_mtx: AsyncMutex<()>,
    auth_identifier: LinkAuthId,
    mtu: BatchSize,
    expiration_manager: Option<LinkCertExpirationManager>,
}

unsafe impl Send for LinkUnicastTls {}
unsafe impl Sync for LinkUnicastTls {}

impl LinkUnicastTls {
    // new:start
//   purpose: Build TLS link from an already-handshaked TlsStream, computing MTU per RFC6691.
//   input:  socket: TLS stream, src/dst_addr: local/remote socket addresses, auth_identifier: TLS CN,
//           expiration_manager: optional cert expiration tracker.
//   output: LinkUnicastTls with configured MTU (TCP MSS-aware), NODELAY, LINGER.
//   sideEffects: Sets TCP_NODELAY + SO_LINGER on underlying TcpStream; computes MTU from socket MSS.
    fn new(
        socket: TlsStream<TcpStream>,
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        auth_identifier: LinkAuthId,
        expiration_manager: Option<LinkCertExpirationManager>,
    ) -> LinkUnicastTls {
        let (tcp_stream, _) = socket.get_ref();
        // Set the TLS nodelay option
        if let Err(err) = tcp_stream.set_nodelay(true) {
            tracing::warn!(
                "Unable to set NODEALY option on TLS link {} => {}: {}",
                src_addr,
                dst_addr,
                err
            );
        }

        // Set the TLS linger option
        #[allow(deprecated)]
        if let Err(err) = tcp_stream.set_linger(Some(Duration::from_secs(
            (*TLS_LINGER_TIMEOUT).try_into().unwrap(),
        ))) {
            tracing::warn!(
                "Unable to set LINGER option on TLS link {} => {}: {}",
                src_addr,
                dst_addr,
                err
            );
        }

        // Compute the MTU
        // See IETF RFC6691: https://datatracker.ietf.org/doc/rfc6691/
        let header = match src_addr.ip() {
            std::net::IpAddr::V4(_) => 40,
            std::net::IpAddr::V6(_) => 60,
        };
        #[allow(unused_mut)] // mut is not needed when target_family != unix
        let mut mtu = *TLS_DEFAULT_MTU - header;

        // target limitation of socket2: https://docs.rs/socket2/latest/src/socket2/sys/unix.rs.html#1544
        #[cfg(target_family = "unix")]
        {
            let socket = socket2::SockRef::from(&tcp_stream);
            // Get the MSS and divide it by 2 to ensure we can at least fill half the MSS
            let mss = socket.mss().unwrap_or(mtu as u32) / 2;
            // Compute largest multiple of TCP MSS that is smaller of default MTU
            let mut tgt = mss;
            while (tgt + mss) < mtu as u32 {
                tgt += mss;
            }
            mtu = (mtu as u32).min(tgt) as BatchSize;
        }

        // Build the Tls object
        LinkUnicastTls {
            inner: UnsafeCell::new(socket),
            src_addr,
            src_locator: Locator::new(TLS_LOCATOR_PREFIX, src_addr.to_string(), "").unwrap(),
            dst_addr,
            dst_locator: Locator::new(TLS_LOCATOR_PREFIX, dst_addr.to_string(), "").unwrap(),
            write_mtx: AsyncMutex::new(()),
            read_mtx: AsyncMutex::new(()),
            auth_identifier,
            mtu,
            expiration_manager,
        }
    }
    // new:end

    // NOTE: It is safe to suppress Clippy warning since no concurrent reads
    //       or concurrent writes will ever happen. The read_mtx and write_mtx
    //       are respectively acquired in any read and write operation.
    #[allow(clippy::mut_from_ref)]
    // get_mut_socket:start
//   purpose: Get mutable reference to inner TlsStream via UnsafeCell (serialized by read/write mutexes).
//   input:  &self (unsafe interior mutability).
//   output: &mut TlsStream<TcpStream>.
//   sideEffects: none (unsafe access, caller must hold read_mtx or write_mtx).
    fn get_mut_socket(&self) -> &mut TlsStream<TcpStream> {
        unsafe { &mut *self.inner.get() }
    }
    // get_mut_socket:end

    // close:start
//   purpose: Flush TLS stream and shut down underlying TCP connection (private helper).
//   input:  &self.
//   output: Ok(()) on success, Err on TCP shutdown failure.
//   sideEffects: Flushes TLS, calls tcp_stream.shutdown(); holds write_mtx during flush.
    async fn close(&self) -> ZResult<()> {
        tracing::trace!("Closing TLS link: {}", self);
        // Flush the TLS stream
        let _guard = zasynclock!(self.write_mtx);
        let tls_stream = self.get_mut_socket();
        let res = tls_stream.flush().await;
        tracing::trace!("TLS link flush {}: {:?}", self, res);
        // Close the underlying TCP stream
        let (tcp_stream, _) = tls_stream.get_mut();
        let res = tcp_stream.shutdown().await;
        tracing::trace!("TLS link shutdown {}: {:?}", self, res);
        res.map_err(|e| zerror!(e).into())
    }
    // close:end
}

#[async_trait]
impl LinkUnicastTrait for LinkUnicastTls {
    // close:start
//   purpose: Close TLS link (LinkUnicastTrait impl) with cert expiration awareness.
//   input:  &self (may have expiration_manager set if mTLS cert monitoring enabled).
//   output: Ok(()) on clean close, Err on shutdown failure.
//   sideEffects: May cancel expiration task; delegates to private close() which shuts down TCP stream.
    async fn close(&self) -> ZResult<()> {
        if let Some(expiration_manager) = &self.expiration_manager {
            if !expiration_manager.set_closing() {
                // expiration_task is closing link, return its returned ZResult to Transport
                return expiration_manager.wait_for_expiration_task().await;
            }
            // cancel the expiration task and close link
            expiration_manager.cancel_expiration_task();
            let res = self.close().await;
            let _ = expiration_manager.wait_for_expiration_task().await;
            return res;
        }
        self.close().await
    }
    // close:end

    // write:start
//   purpose: Write buffer to TLS stream (non-blocking, may not write all bytes).
//   input:  buffer: data to send, _priority: QoS hint (ignored for TLS).
//   output: number of bytes written, Err on write failure.
//   sideEffects: Holds write_mtx; writes to TLS stream.
    async fn write(&self, buffer: &[u8], _priority: Option<Priority>) -> ZResult<usize> {
        let _guard = zasynclock!(self.write_mtx);
        self.get_mut_socket().write(buffer).await.map_err(|e| {
            tracing::trace!("Write error on TLS link {}: {}", self, e);
            zerror!(e).into()
        })
    }
    // write:end

    // write_all:start
//   purpose: Write entire buffer to TLS stream (loops until all bytes sent).
//   input:  buffer: data to send, _priority: QoS hint (ignored).
//   output: Ok(()) on success, Err on write failure.
//   sideEffects: Holds write_mtx; writes to TLS stream until buffer exhausted.
    async fn write_all(&self, buffer: &[u8], _priority: Option<Priority>) -> ZResult<()> {
        let _guard = zasynclock!(self.write_mtx);
        self.get_mut_socket().write_all(buffer).await.map_err(|e| {
            tracing::trace!("Write error on TLS link {}: {}", self, e);
            zerror!(e).into()
        })
    }
    // write_all:end

    // read:start
//   purpose: Read decrypted bytes from TLS stream into buffer (non-blocking, non-exact).
//   input:  buffer: destination byte slice, _priority: QoS hint (ignored).
//   output: number of bytes read, 0 on EOF, Err on read failure.
//   sideEffects: Holds read_mtx; reads from TLS stream.
    async fn read(&self, buffer: &mut [u8], _priority: Option<Priority>) -> ZResult<usize> {
        let _guard = zasynclock!(self.read_mtx);
        self.get_mut_socket().read(buffer).await.map_err(|e| {
            tracing::trace!("Read error on TLS link {}: {}", self, e);
            zerror!(e).into()
        })
    }
    // read:end

    // read_exact:start
//   purpose: Read exactly buffer.len() decrypted bytes from TLS stream (loops until buffer full).
//   input:  buffer: destination byte slice, _priority: QoS hint (ignored).
//   output: Ok(()) on success, Err on premature EOF or read failure.
//   sideEffects: Holds read_mtx; reads from TLS stream until buffer filled.
    async fn read_exact(&self, buffer: &mut [u8], _priority: Option<Priority>) -> ZResult<()> {
        let _guard = zasynclock!(self.read_mtx);
        let _ = self
            .get_mut_socket()
            .read_exact(buffer)
            .await
            .map_err(|e| {
                tracing::trace!("Read error on TLS link {}: {}", self, e);
                zerror!(e)
            })?;
        Ok(())
    }
    // read_exact:end

    #[inline(always)]
    // get_src:start
//   purpose: Return source locator (local side of the link).
//   input:  &self.
//   output: &Locator with "tls/<local_addr>" format.
//   sideEffects: none (pure accessor).
    fn get_src(&self) -> &Locator {
        &self.src_locator
    }
    // get_src:end

    #[inline(always)]
    // get_dst:start
//   purpose: Return destination locator (remote side of the link).
//   input:  &self.
//   output: &Locator with "tls/<remote_addr>" format.
//   sideEffects: none (pure accessor).
    fn get_dst(&self) -> &Locator {
        &self.dst_locator
    }
    // get_dst:end

    #[inline(always)]
    // get_mtu:start
//   purpose: Return the negotiated MTU for this TLS link (RFC6691 — IP header + TCP MSS-aware).
//   input:  &self.
//   output: BatchSize (u16) — max payload per Zenoh batch.
//   sideEffects: none (pure accessor).
    fn get_mtu(&self) -> BatchSize {
        self.mtu
    }
    // get_mtu:end

    #[inline(always)]
    // get_interface_names:start
//   purpose: Return OS interface names associated with the source address.
//   input:  &self.
//   output: Vec<String> of interface names (may be empty if detection fails).
//   sideEffects: none (pure query, no I/O).
    fn get_interface_names(&self) -> Vec<String> {
        get_ip_interface_names(&self.src_addr)
    }
    // get_interface_names:end

    #[inline(always)]
    // is_reliable:start
//   purpose: Check if TLS link is reliable (always true — TLS is TCP-based).
//   input:  &self.
//   output: true.
//   sideEffects: none (pure constant).
    fn is_reliable(&self) -> bool {
        super::IS_RELIABLE
    }
    // is_reliable:end

    #[inline(always)]
    // is_streamed:start
//   purpose: Check if TLS link is stream-oriented (always true — TLS is byte-stream).
//   input:  &self.
//   output: true.
//   sideEffects: none (pure constant).
    fn is_streamed(&self) -> bool {
        true
    }
    // is_streamed:end

    #[inline(always)]
    // get_auth_id:start
//   purpose: Return authentication identifier (TLS Common Name from client/server cert).
//   input:  &self.
//   output: &LinkAuthId — Tls variant with CN string.
//   sideEffects: none (pure accessor).
    fn get_auth_id(&self) -> &LinkAuthId {
        &self.auth_identifier
    }
    // get_auth_id:end
}

#[async_trait]
impl LinkWithCertExpiration for LinkUnicastTls {
    // expire:start
//   purpose: Force-close the link due to certificate expiration (called by expiration_manager).
//   input:  &self (must have expiration_manager set).
//   output: Ok(()) if closed, Ok(()) if already closing (delegated), Err on shutdown failure.
//   sideEffects: May call close() which shuts down TCP stream.
    async fn expire(&self) -> ZResult<()> {
        let expiration_manager = self
            .expiration_manager
            .as_ref()
            .expect("expiration_manager should be set");
        if expiration_manager.set_closing() {
            return self.close().await;
        }
        // Transport is already closing the link
        Ok(())
    }
    // expire:end
}

impl Drop for LinkUnicastTls {
    // drop:start
//   purpose: Drop the TLS link — shut down underlying TCP stream (best-effort, blocks in Acceptor runtime).
//   input:  &mut self (Drop impl).
//   output: none (Drop).
//   sideEffects: Calls tcp_stream.shutdown() via zenoh_runtime::Acceptor block_in_place.
    fn drop(&mut self) {
        // Close the underlying TCP stream
        let (tcp_stream, _) = self.get_mut_socket().get_mut();
        let _ = zenoh_runtime::ZRuntime::Acceptor
            .block_in_place(async move { tcp_stream.shutdown().await });
    }
    // drop:end
}

impl fmt::Display for LinkUnicastTls {
    // fmt:start
//   purpose: Format link as "src_addr => dst_addr" for Display.
//   input:  &self, f: Formatter.
//   output: fmt::Result.
//   sideEffects: none (pure formatting).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} => {}", self.src_addr, self.dst_addr)?;
        Ok(())
    }
    // fmt:end
}

impl fmt::Debug for LinkUnicastTls {
    // fmt:start
//   purpose: Format link debug info with src/dst addresses.
//   input:  &self, f: Formatter.
//   output: fmt::Result.
//   sideEffects: none (pure formatting).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tls")
            .field("src", &self.src_addr)
            .field("dst", &self.dst_addr)
            .finish()
    }
    // fmt:end
}

pub struct LinkManagerUnicastTls {
    manager: NewLinkChannelSender,
    listeners: ListenersUnicastIP,
}

impl LinkManagerUnicastTls {
    // new:start
//   purpose: Create TLS link manager (holds channel sender for new links + IP listener registry).
//   input:  manager: sender for delivering accepted links to Zenoh transport.
//   output: LinkManagerUnicastTls.
//   sideEffects: none (pure construction).
    pub fn new(manager: NewLinkChannelSender) -> Self {
        Self {
            manager,
            listeners: ListenersUnicastIP::new(),
        }
    }
    // new:end
}

#[async_trait]
impl LinkManagerUnicastTrait for LinkManagerUnicastTls {
    // new_link:start
//   purpose: Initiate outbound TLS connection: resolve addr, load TLS config, TCP connect, TLS handshake.
//   input:  self, endpoint: target endpoint with tls/<host:port> and config (TLS certs, ciphers, etc.).
//   output: Ok(LinkUnicast) wrapping Arc<LinkUnicastTls> on success, Err on DNS/TCP/TLS/cert failure.
//   sideEffects: DNS lookup (tokio::net::lookup_host), TCP connect (socket_config.new_link),
//                TLS handshake (TlsConnector::connect), may set up cert expiration manager.
    async fn new_link(&self, endpoint: EndPoint) -> ZResult<LinkUnicast> {
        let epaddr = endpoint.address();
        let epconf = endpoint.config();

        let server_name = get_tls_server_name(&epaddr)?;
        let addr = get_tls_addr(&epaddr).await?;

        // if both `iface`, and `bind` are present, return error
        if let (Some(_), Some(_)) = (epconf.get(BIND_INTERFACE), epconf.get(BIND_SOCKET)) {
            bail!(
                "Using Config options `iface` and `bind` in conjunction is unsupported at this time {} {:?}",
                BIND_INTERFACE,
                BIND_SOCKET
            )
        }

        // Initialize the TLS Config
        let client_config = TlsClientConfig::new(&epconf)
            .await
            .map_err(|e| zerror!("Cannot create a new TLS listener to {endpoint}: {e}"))?;
        let config = Arc::new(client_config.client_config);
        let connector = TlsConnector::from(config);

        // Initialize the TcpStream
        let (tcp_stream, src_addr, dst_addr) = client_config
            .tcp_socket_config
            .new_link(&addr)
            .await
            .map_err(|e| {
                zerror!(
                    "Can not create a new TLS link bound to {:?}: {}",
                    server_name,
                    e
                )
            })?;

        // Initialize the TlsStream
        let tls_stream = connector
            .connect(server_name.to_owned(), tcp_stream)
            .await
            .map_err(|e| {
                zerror!(
                    "Can not create a new TLS link bound to {:?}: {}",
                    server_name,
                    e
                )
            })?;

        let (_, tls_conn) = tls_stream.get_ref();
        let auth_identifier = get_server_cert_common_name(tls_conn)?;
        let certchain_expiration_time = get_cert_chain_expiration(&tls_conn.peer_certificates())?
            .expect("server should have certificate chain");

        let tls_stream = TlsStream::Client(tls_stream);

        let link = Arc::<LinkUnicastTls>::new_cyclic(|weak_link| {
            let mut expiration_manager = None;
            if client_config.tls_close_link_on_expiration {
                // setup expiration manager
                expiration_manager = Some(LinkCertExpirationManager::new(
                    weak_link.clone(),
                    src_addr,
                    dst_addr,
                    TLS_LOCATOR_PREFIX,
                    certchain_expiration_time,
                ))
            }
            LinkUnicastTls::new(
                tls_stream,
                src_addr,
                dst_addr,
                auth_identifier.into(),
                expiration_manager,
            )
        });

        Ok(LinkUnicast::from(link as Arc<dyn LinkUnicastTrait>))
    }
    // new_link:end

    // new_listener:start
//   purpose: Bind TLS listener: TCP bind, TLS config + acceptor, spawn accept_task.
//   input:  self, endpoint: listen endpoint with tls/<host:port> and TLS config.
//   output: Ok(Locator) with the actual bound address, Err on bind/config failure.
//   sideEffects: TCP bind (socket_config.new_listener), spawns accept_task on ZRuntime::Acceptor,
//                registers listener in ListenersUnicastIP.
    async fn new_listener(&self, endpoint: EndPoint) -> ZResult<Locator> {
        let epaddr = endpoint.address();
        let epconf = endpoint.config();

        let addr = get_tls_addr(&epaddr).await?;
        let host = get_tls_host(&epaddr)?;

        // Initialize TlsConfig
        let tls_server_config = TlsServerConfig::new(&epconf)
            .await
            .map_err(|e| zerror!("Cannot create a new TLS listener on {addr}. {e}"))?;

        // Initialize the TcpListener
        let (socket, local_addr) = tls_server_config
            .tcp_socket_config
            .new_listener(&addr)
            .map_err(|e| zerror!("Can not create a new TLS listener on {}: {}", addr, e))?;

        let local_port = local_addr.port();

        // Initialize the TlsAcceptor
        let token = self.listeners.token.child_token();

        let task = {
            let acceptor = TlsAcceptor::from(Arc::new(tls_server_config.server_config));
            let token = token.clone();
            let manager = self.manager.clone();

            async move {
                accept_task(
                    socket,
                    acceptor,
                    token,
                    manager,
                    tls_server_config.tls_handshake_timeout,
                    tls_server_config.tls_close_link_on_expiration,
                )
                .await
            }
        };

        // Update the endpoint locator address
        let locator = Locator::new(
            endpoint.protocol(),
            format!("{host}:{local_port}"),
            endpoint.metadata(),
        )?;
        let endpoint = EndPoint::new(
            locator.protocol(),
            locator.address(),
            locator.metadata(),
            endpoint.config(),
        )?;
        self.listeners
            .add_listener(endpoint, local_addr, task, token)
            .await?;

        Ok(locator)
    }
    // new_listener:end

    // del_listener:start
//   purpose: Remove and shut down a TLS listener by address.
//   input:  self, endpoint: listener endpoint to remove.
//   output: Ok(()) on success, Err if address not found.
//   sideEffects: Cancels accept_task via CancellationToken; removes from ListenersUnicastIP.
    async fn del_listener(&self, endpoint: &EndPoint) -> ZResult<()> {
        let epaddr = endpoint.address();
        let addr = get_tls_addr(&epaddr).await?;
        self.listeners.del_listener(addr).await
    }
    // del_listener:end

    // get_listeners:start
//   purpose: Return all registered TLS listener endpoints.
//   input:  &self.
//   output: Vec<EndPoint> of active listeners.
//   sideEffects: none (pure accessor).
    async fn get_listeners(&self) -> Vec<EndPoint> {
        self.listeners.get_endpoints()
    }
    // get_listeners:end

    // get_locators:start
//   purpose: Return locators for all registered TLS listeners.
//   input:  &self.
//   output: Vec<Locator> of active listener locators.
//   sideEffects: none (pure accessor).
    async fn get_locators(&self) -> Vec<Locator> {
        self.listeners.get_locators()
    }
    // get_locators:end
}

// accept_task:start
//   purpose: Accept loop for TLS listener — accepts TCP connections, performs TLS handshake, delivers links to manager.
//   input:  socket: bound TcpListener, acceptor: TlsAcceptor with server config, token: cancellation token,
//           manager: channel for new links, tls_handshake_timeout: per-handshake deadline,
//           tls_close_link_on_expiration: whether to monitor cert expiration.
//   output: Ok(()) on normal exit (cancelled), Err on listener failure.
//   sideEffects: Accepts TCP connections; performs TLS handshakes; creates LinkUnicastTls per connection;
//                sends links to manager; throttles on accept errors; sleeps on heartbeat every 10s.
async fn accept_task(
    socket: TcpListener,
    acceptor: TlsAcceptor,
    token: CancellationToken,
    manager: NewLinkChannelSender,
    tls_handshake_timeout: Duration,
    tls_close_link_on_expiration: bool,
) -> ZResult<()> {
    let src_addr = socket.local_addr().map_err(|e| {
        let e = zerror!("Can not accept TLS connections: {}", e);
        tracing::warn!("{}", e);
        e
    })?;

    let mut listener = tls_listener::builder(acceptor)
        .handshake_timeout(tls_handshake_timeout)
        .listen(socket);

    tracing::trace!("Ready to accept TLS connections on: {:?}", src_addr);
    loop {
        tokio::select! {
            _ = token.cancelled() => break,

            res = listener.accept() => {
                match res {
                    Ok((tls_stream, dst_addr)) => {
                        let (tcp_stream, tls_conn) = tls_stream.get_ref();
                        let src_addr =  match tcp_stream.local_addr()  {
                            Ok(sa) => sa,
                            Err(e) => {
                                tracing::debug!("Can not accept TLS connection: {}", e);
                                continue;
                            }
                        };
                        let auth_identifier = match get_client_cert_common_name(tls_conn) {
                            Ok(auth_id) => auth_id,
                            Err(e) => {
                                tracing::warn!("Error getting client cert common name: {e}");
                                continue;
                            }
                        };

                        // Get certificate chain expiration
                        let mut maybe_expiration_time = None;
                        if tls_close_link_on_expiration {
                            let exp = match get_cert_chain_expiration(&tls_conn.peer_certificates()) {
                                Ok(exp) => exp,
                                Err(e) => {
                                    tracing::warn!("Error getting client cert expiration: {e}");
                                    continue;
                                }
                            };
                            match exp {
                                exp @ Some(_) => maybe_expiration_time = exp,
                                None => tracing::warn!(
                                    "Cannot monitor expiration for TLS link {:?} => {:?}: client does not have certificates",
                                    src_addr,
                                    dst_addr,
                                ),
                            }
                        }

                        tracing::debug!("Accepted TLS connection on {:?}: {:?}. {:?}.", src_addr, dst_addr, auth_identifier);
                        // Create the new link object
                        let link = Arc::<LinkUnicastTls>::new_cyclic(|weak_link| {
                            let mut expiration_manager = None;
                            if let Some(certchain_expiration_time) = maybe_expiration_time {
                                // setup expiration manager
                                expiration_manager = Some(LinkCertExpirationManager::new(
                                    weak_link.clone(),
                                    src_addr,
                                    dst_addr,
                                    TLS_LOCATOR_PREFIX,
                                    certchain_expiration_time,
                                ));
                            }
                            LinkUnicastTls::new(
                                tokio_rustls::TlsStream::Server(tls_stream),
                                src_addr,
                                dst_addr,
                                auth_identifier.into(),
                                expiration_manager,
                            )
                        });

                        // Communicate the new link to the initial transport manager
                        if let Err(e) = manager
                            .send_async(LinkUnicast::from(link as Arc<dyn LinkUnicastTrait>))
                            .await
                        {
                            tracing::error!("{}-{}: {}", file!(), line!(), e)
                        }
                    }
                    Err(e) => {
                        tracing::warn!("{}. Hint: increase the system open file limit.", e);
                        // Throttle the accept loop upon an error
                        // NOTE: This might be due to various factors. However, the most common case is that
                        //       the process has reached the maximum number of open files in the system. On
                        //       Linux systems this limit can be changed by using the "ulimit" command line
                        //       tool. In case of systemd-based systems, this can be changed by using the
                        //       "sysctl" command line tool.
                        tokio::time::sleep(Duration::from_micros(*TLS_ACCEPT_THROTTLE_TIME)).await;
                    }
                }
            }
        }
    }

    Ok(())
}
// accept_task:end

// get_client_cert_common_name:start
//   purpose: Extract the Common Name from the client certificate presented during mTLS handshake.
//   input:  tls_conn: rustls CommonState with peer_certificates().
//   output: Ok(TlsAuthId) with CN string (None if no cert or no CN), Err on DER parse failure.
//   sideEffects: none (pure parsing via x509-parser).
fn get_client_cert_common_name(tls_conn: &rustls::CommonState) -> ZResult<TlsAuthId> {
    if let Some(client_certs) = tls_conn.peer_certificates() {
        let (_, cert) = X509Certificate::from_der(client_certs[0].as_ref())?;
        let subject_name = &cert
            .subject
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok());

        Ok(TlsAuthId {
            auth_value: subject_name.map(|cn| cn.to_string()),
        })
    } else {
        Ok(TlsAuthId { auth_value: None })
    }
}
// get_client_cert_common_name:end

// get_server_cert_common_name:start
//   purpose: Extract the Common Name from the server certificate presented during TLS handshake.
//   input:  tls_conn: rustls ClientConnection with peer_certificates().
//   output: Ok(TlsAuthId) with CN from first certificate in chain (None if no CN), Err on DER parse failure.
//   sideEffects: none (pure parsing via x509-parser).
fn get_server_cert_common_name(tls_conn: &rustls::ClientConnection) -> ZResult<TlsAuthId> {
    let serv_certs = tls_conn.peer_certificates().unwrap();
    let mut auth_id = TlsAuthId { auth_value: None };

    // Need the first certificate in the chain so no need for looping
    if let Some(item) = serv_certs.iter().next() {
        let (_, cert) = X509Certificate::from_der(item.as_ref())?;
        let subject_name = &cert
            .subject
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok());

        auth_id = TlsAuthId {
            auth_value: subject_name.map(|cn| cn.to_string()),
        };
        return Ok(auth_id);
    }
    Ok(auth_id)
}
// get_server_cert_common_name:end

/// Returns the minimum value of the `not_after` field in the given certificate chain.
/// Returns `None` if the input certificate chain is empty or `None`
// get_cert_chain_expiration:start
//   purpose: Find the minimum not_after timestamp across all certificates in the peer's chain.
//   input:  cert_chain: Option<&[CertificateDer]> from TLS session.
//   output: Ok(Some(OffsetDateTime)) with earliest expiration, Ok(None) if chain empty.
//   sideEffects: none (pure parsing via x509-parser).
fn get_cert_chain_expiration(
    cert_chain: &Option<&[rustls_pki_types::CertificateDer]>,
) -> ZResult<Option<OffsetDateTime>> {
    let mut link_expiration: Option<OffsetDateTime> = None;
    if let Some(remote_certs) = cert_chain {
        for cert in *remote_certs {
            let (_, cert) = X509Certificate::from_der(cert.as_ref())?;
            let cert_expiration = cert.validity().not_after.to_datetime();
            link_expiration = link_expiration
                .map(|current_min| current_min.min(cert_expiration))
                .or(Some(cert_expiration));
        }
    }
    Ok(link_expiration)
}
// get_cert_chain_expiration:end

struct TlsAuthId {
    auth_value: Option<String>,
}

impl Debug for TlsAuthId {
    // fmt:start
//   purpose: Format TlsAuthId as "Common Name: <cn>" or "Common Name: None".
//   input:  &self, f: Formatter.
//   output: fmt::Result.
//   sideEffects: none (pure formatting).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Common Name: {}",
            self.auth_value.as_deref().unwrap_or("None")
        )
    }
    // fmt:end
}

impl From<TlsAuthId> for LinkAuthId {
    // from:start
//   purpose: Convert TlsAuthId (CN-based) to Zenoh's LinkAuthId::Tls variant.
//   input:  value: TlsAuthId with optional CN string.
//   output: LinkAuthId::Tls with cloned CN.
//   sideEffects: none (pure conversion).
    fn from(value: TlsAuthId) -> Self {
        LinkAuthId::Tls(value.auth_value.clone())
    }
    // from:end
}
