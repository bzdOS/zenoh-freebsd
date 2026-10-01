// START_AI_HEADER
// MODULE: infra/zenohd/src/main.rs
// PURPOSE: Zenoh router daemon for bsdOS mesh networking.
// INTENT: Configure and run a Zenoh peer/router with TLS, authentication, and endpoint configuration via env.
// DEPENDENCIES: zenoh, tokio, std.
// PUBLIC_API: main.
// END_AI_HEADER

use std::env;

// main:start
//   purpose: Configure from env, open Zenoh session, wait for Ctrl-C, cleanly close.
//   input:  env ZENOH_MODE, ZENOH_LISTEN, ZENOH_CONNECT, ZENOH_TLS, ZENOH_TLS_CA, ZENOH_TLS_CERT, ZENOH_TLS_KEY, ZENOH_TOKEN.
//   output: Never (blocks on Ctrl-C).
//   sideEffects: Zenoh session open with TLS/auth config, writes users conf file to /run/bsdos-zenohd-users.conf.
fn main() {
    let mut cfg = zenoh::Config::default();

    let mode = env::var("ZENOH_MODE").unwrap_or_else(|_| "router".to_string());
    cfg.insert_json5("mode", &format!("\"{}\"", mode)).unwrap();

    if let Ok(listen) = env::var("ZENOH_LISTEN") {
        cfg.insert_json5("listen/endpoints", &format!("[\"{}\"]", listen)).unwrap();
        eprintln!("[zenohd] listen: {}", listen);
    }

    if let Ok(connect) = env::var("ZENOH_CONNECT") {
        cfg.insert_json5("connect/endpoints", &format!("[\"{}\"]", connect)).unwrap();
        eprintln!("[zenohd] connect: {}", connect);
    }

    if env::var("ZENOH_TLS").as_deref() == Ok("1") {
        let ca = env::var("ZENOH_TLS_CA").unwrap_or_else(|_| "/etc/bsdos/ca.pem".to_string());
        let cert = env::var("ZENOH_TLS_CERT").unwrap_or_else(|_| "/etc/bsdos/server.pem".to_string());
        let key = env::var("ZENOH_TLS_KEY").unwrap_or_else(|_| "/etc/bsdos/server.key".to_string());

        cfg.insert_json5("transport/link/tls/root_ca_certificate", &format!("\"{}\"", ca)).unwrap();
        cfg.insert_json5("transport/link/tls/listen_certificate", &format!("\"{}\"", cert)).unwrap();
        cfg.insert_json5("transport/link/tls/listen_private_key", &format!("\"{}\"", key)).unwrap();
        cfg.insert_json5("transport/link/tls/verify_name_on_connect", "false").unwrap();
        eprintln!("[zenohd] TLS enabled");
    }

    if let Ok(token) = env::var("ZENOH_TOKEN") {
        let users_path = "/run/bsdos-zenohd-users.conf";
        std::fs::write(users_path, format!("bsdos:{}", token)).ok();
        cfg.insert_json5("transport/auth/usrpwd/dictionary_file", &format!("\"{}\"", users_path)).unwrap();
        eprintln!("[zenohd] auth enabled (user=bsdos)");
    }

    eprintln!("[zenohd] starting...");
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        match zenoh::open(cfg).await {
            Ok(session) => {
                eprintln!("[zenohd] session opened, zid={}", session.zid());
                tokio::signal::ctrl_c().await.ok();
                session.close().await.ok();
            }
            Err(e) => {
                eprintln!("[zenohd] error: {}", e);
                std::process::exit(1);
            }
        }
    });
}
// main:end
