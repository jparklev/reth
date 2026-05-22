//! Minimal `/metrics` HTTP endpoint backed by a Prometheus recorder.
//!
//! The two standalone binaries (`witness-uploader` and `witness-follower`) need
//! to expose Prometheus-style metrics without dragging in the full
//! `reth-metrics` / `reth-node-metrics` stack. This module installs a
//! [`PrometheusRecorder`] and serves its scrape output over hyper.
//!
//! `--metrics-addr 0.0.0.0:0` disables the server entirely (no recorder
//! installed) so the binaries remain runnable in test contexts.

use eyre::{Context, OptionExt};
use http_body_util::Full;
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use std::{net::SocketAddr, sync::OnceLock};
use tracing::{info, warn};

/// Install the global Prometheus recorder + spawn a tokio task serving
/// `GET /metrics` on `addr`. Returns the bound address. A `0.0.0.0:0` address
/// is treated as "disabled" — no recorder is installed and `None` is returned.
pub(crate) async fn install_and_serve(addr: SocketAddr) -> eyre::Result<Option<SocketAddr>> {
    if addr.port() == 0 && addr.ip().is_unspecified() {
        return Ok(None);
    }

    let handle = match RECORDER.get() {
        Some(h) => h.clone(),
        None => {
            let h = PrometheusBuilder::new()
                .install_recorder()
                .wrap_err("install prometheus recorder")?;
            // Best-effort set; if another caller raced us we use whichever won.
            RECORDER.set(h.clone()).ok();
            RECORDER.get().cloned().ok_or_eyre("recorder lost after set")?
        }
    };

    let listener =
        tokio::net::TcpListener::bind(addr).await.wrap_err_with(|| format!("bind {addr}"))?;
    let bound = listener.local_addr()?;
    info!(%bound, "metrics endpoint listening");

    tokio::spawn(async move {
        loop {
            let (stream, _peer) = match listener.accept().await {
                Ok(v) => v,
                Err(err) => {
                    warn!(?err, "metrics accept failed");
                    continue;
                }
            };
            let io = TokioIo::new(stream);
            let handle = handle.clone();
            tokio::spawn(async move {
                let service = hyper::service::service_fn(move |req: hyper::Request<_>| {
                    let handle = handle.clone();
                    async move {
                        let body = if req.uri().path() == "/metrics" {
                            handle.render()
                        } else {
                            String::from("# witness-emit metrics\n")
                        };
                        Ok::<_, std::convert::Infallible>(
                            hyper::Response::builder()
                                .status(200)
                                .header(
                                    hyper::header::CONTENT_TYPE,
                                    "text/plain; version=0.0.4; charset=utf-8",
                                )
                                .body(Full::new(Bytes::from(body)))
                                .unwrap(),
                        )
                    }
                });
                if let Err(err) =
                    hyper::server::conn::http1::Builder::new().serve_connection(io, service).await
                {
                    // Connection-level errors are noisy on scraper churn; debug only.
                    tracing::debug!(?err, "metrics connection ended");
                }
            });
        }
    });

    Ok(Some(bound))
}

// The Prometheus recorder is a process-global so we cache the handle to allow
// re-binding the HTTP listener (e.g. for tests) without panicking.
static RECORDER: OnceLock<PrometheusHandle> = OnceLock::new();
