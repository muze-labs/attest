//! Minimal HTTP/1.1 benchmark server for the Muze attestation hot path.
//!
//! POST /attest
//!   Request body: exactly 32 raw commitment bytes.
//!   Response body: 136-byte signed receipt followed by 36-byte binary CIDv1.
//!
//! GET /health
//!   Response body: "ok".
//!
//! IMPORTANT: this is benchmark code, not production crypto. It deliberately
//! uses a fixed signing key and deterministic per-worker RNG streams so runs are
//! repeatable and comparable. Production code must seed nonce generation from a
//! cryptographically secure OS source and protect/rotate the signing key.

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{
    Method, Request, Response, StatusCode,
    body::Incoming,
    header::{CONTENT_LENGTH, CONTENT_TYPE, HeaderValue},
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use muze_attest_bench::{
    BenchIssuer, COMMITMENT_LEN, RECEIPT_CID_LEN, SIGNED_RECEIPT_LEN,
};
use std::{
    cell::RefCell,
    convert::Infallible,
    error::Error,
    net::SocketAddr,
    sync::atomic::{AtomicUsize, Ordering},
};
use tokio::net::TcpListener;

const RESPONSE_LEN: usize = SIGNED_RECEIPT_LEN + RECEIPT_CID_LEN;
static NEXT_WORKER_SEED: AtomicUsize = AtomicUsize::new(1);

thread_local! {
    // One issuer per Tokio worker thread: no mutex and no shared mutable RNG.
    // This is intentionally deterministic benchmark state; see module warning.
    static ISSUER: RefCell<BenchIssuer> = {
        let n = NEXT_WORKER_SEED.fetch_add(1, Ordering::Relaxed);
        RefCell::new(BenchIssuer::deterministic((n as u8).wrapping_add(1)))
    };
}

type RespBody = Full<Bytes>;

#[inline]
fn fixed_response(status: StatusCode, body: &'static [u8]) -> Response<RespBody> {
    let mut response = Response::new(Full::new(Bytes::from_static(body)));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
    response
}

async fn handle(req: Request<Incoming>) -> Result<Response<RespBody>, Infallible> {
    if req.method() == Method::GET && req.uri().path() == "/health" {
        return Ok(fixed_response(StatusCode::OK, b"ok"));
    }

    if req.method() != Method::POST || req.uri().path() != "/attest" {
        return Ok(fixed_response(StatusCode::NOT_FOUND, b"not found"));
    }

    // Reject an explicitly wrong Content-Length before collecting the body.
    if let Some(value) = req.headers().get(CONTENT_LENGTH) {
        match value.to_str().ok().and_then(|s| s.parse::<usize>().ok()) {
            Some(COMMITMENT_LEN) => {}
            _ => return Ok(fixed_response(StatusCode::BAD_REQUEST, b"need 32 bytes")),
        }
    }

    let body = match req.into_body().collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => return Ok(fixed_response(StatusCode::BAD_REQUEST, b"bad body")),
    };

    if body.len() != COMMITMENT_LEN {
        return Ok(fixed_response(StatusCode::BAD_REQUEST, b"need 32 bytes"));
    }

    let mut commitment = [0u8; COMMITMENT_LEN];
    commitment.copy_from_slice(&body);

    let (receipt, cid) = ISSUER.with(|issuer| issuer.borrow_mut().issue(&commitment));

    let mut output = [0u8; RESPONSE_LEN];
    output[..SIGNED_RECEIPT_LEN].copy_from_slice(&receipt.bytes);
    output[SIGNED_RECEIPT_LEN..].copy_from_slice(&cid.bytes);

    // Bytes owns the fixed array without an additional payload copy.
    let mut response = Response::new(Full::new(Bytes::from_owner(output)));
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    Ok(response)
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let addr: SocketAddr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:3000".to_owned())
        .parse()?;

    let listener = TcpListener::bind(addr).await?;
    println!("Muze attestation HTTP benchmark server");
    println!("listening      : http://{addr}");
    println!("POST /attest   : 32 bytes -> {RESPONSE_LEN} bytes");
    println!("GET  /health   : smoke test");
    println!("tokio workers  : {}", std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1));
    println!("WARNING        : deterministic benchmark key/RNG; not production-safe");

    loop {
        let (stream, _) = listener.accept().await?;
        stream.set_nodelay(true)?;
        let io = TokioIo::new(stream);

        tokio::spawn(async move {
            // Connection teardown/errors are deliberately ignored here: load generators
            // close sockets at the end of a run and logging would distort the benchmark.
            let _ = http1::Builder::new()
                .keep_alive(true)
                .serve_connection(io, service_fn(handle))
                .await;
        });
    }
}
