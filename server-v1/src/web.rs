use crate::attestation::{self, ASSURANCE_LEVEL_1, ATTESTATION_LEN, HASH_ALG_SHA256};
use bytes::Bytes;
use ed25519_dalek::{SigningKey, VerifyingKey};
use http_body_util::{BodyExt, Full};
use hyper::{body::Incoming, header, Method, Request, Response, StatusCode};
use sha2::{Digest, Sha256};
use std::{convert::Infallible, sync::{Arc, Mutex}, time::{SystemTime, UNIX_EPOCH}};

pub type RespBody = Full<Bytes>;

#[derive(Clone)]
pub struct AppState {
    pub signing_key: Arc<SigningKey>,
    pub issuer_name: Arc<String>,
    pub public_base_url: Arc<String>,
    last_timestamp_ms: Arc<Mutex<i64>>,
}

impl AppState {
    pub fn new(signing_key: SigningKey, issuer_name: String, public_base_url: String) -> Self {
        Self {
            signing_key: Arc::new(signing_key),
            issuer_name: Arc::new(issuer_name),
            public_base_url: Arc::new(public_base_url),
            last_timestamp_ms: Arc::new(Mutex::new(0)),
        }
    }

    fn safe_now_ms(&self) -> Result<i64, &'static str> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "system clock is before Unix epoch")?;
        let ms = i64::try_from(now.as_millis()).map_err(|_| "system clock out of supported range")?;
        let mut last = self.last_timestamp_ms.lock().map_err(|_| "clock guard unavailable")?;
        if ms < *last {
            return Err("system clock moved backwards; refusing to attest");
        }
        *last = ms;
        Ok(ms)
    }
}

pub async fn handle(req: Request<Incoming>, state: AppState) -> Result<Response<RespBody>, Infallible> {
    let path = req.uri().path().to_string();
    let method = req.method().clone();

    let response = match (method, path.as_str()) {
        (Method::GET, "/") => html(StatusCode::OK, &home_page(&state)),
        (Method::GET, "/about") => html(StatusCode::OK, &about_page(&state)),
        (Method::GET, "/decode") => html(StatusCode::OK, &decode_page()),
        (Method::GET, "/keys") => html(StatusCode::OK, &keys_page(&state)),
        (Method::GET, "/health") => health(&state),
        (Method::GET, "/v1/keys/current") => key_json(&state),
        (Method::GET, "/v1/keys/current.raw") => key_raw(&state),
        (Method::GET, "/.well-known/muze-temporal-attestation-key.json") => key_json(&state),
        (Method::POST, "/v1/attest") => attest(req, &state).await,
        (Method::POST, "/v1/decode") => decode_api(req, &state).await,
        _ => text(StatusCode::NOT_FOUND, "Not found\n"),
    };
    Ok(response)
}

async fn attest(req: Request<Incoming>, state: &AppState) -> Response<RespBody> {
    let collected = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => return text(StatusCode::BAD_REQUEST, "Unable to read request body\n"),
    };
    if collected.len() != 32 {
        return text(StatusCode::BAD_REQUEST, "Request body must be exactly 32 raw bytes containing a SHA-256 digest\n");
    }
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&collected);
    let now = match state.safe_now_ms() {
        Ok(v) => v,
        Err(msg) => return text(StatusCode::SERVICE_UNAVAILABLE, &format!("Clock unhealthy: {msg}\n")),
    };
    let issued = attestation::issue(&state.signing_key, digest, now);
    let mut response = Response::new(Full::new(Bytes::copy_from_slice(&issued)));
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(header::CONTENT_TYPE, header::HeaderValue::from_static("application/vnd.muze.temporal-attestation"));
    response.headers_mut().insert(header::CACHE_CONTROL, header::HeaderValue::from_static("no-store"));
    response
}

async fn decode_api(req: Request<Incoming>, state: &AppState) -> Response<RespBody> {
    let collected = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => return json(StatusCode::BAD_REQUEST, "{\"valid\":false,\"error\":\"unable to read request body\"}"),
    };

    let decoded = match attestation::verify(&collected, &state.signing_key.verifying_key()) {
        Ok(v) => v,
        Err(e) => return json(StatusCode::BAD_REQUEST, &format!("{{\"valid\":false,\"error\":{}}}", json_string(&e.to_string()))),
    };

    let guarantee = assurance_text(decoded.assurance_level);
    let timestamp = iso8601_utc_ms(decoded.timestamp_ms);
    let body = format!(
        "{{\"valid\":true,\"formatVersion\":{},\"assuranceLevel\":{},\"assuranceMeaning\":{},\"hashAlgorithm\":{},\"digestHex\":{},\"timestampMs\":{},\"timestampUtc\":{},\"keyId\":{},\"meaning\":{}}}",
        decoded.format_version,
        decoded.assurance_level,
        json_string(guarantee),
        json_string(hash_alg_name(decoded.hash_algorithm)),
        json_string(&attestation::hex(&decoded.digest)),
        decoded.timestamp_ms,
        json_string(&timestamp),
        json_string(&attestation::hex(&decoded.key_id)),
        json_string(&format!("{} attests that the content represented by this {} digest was available to the service no later than {}.", state.issuer_name, hash_alg_name(decoded.hash_algorithm), timestamp)),
    );
    json(StatusCode::OK, &body)
}

fn key_raw(state: &AppState) -> Response<RespBody> {
    let vk = state.signing_key.verifying_key();
    let mut r = Response::new(Full::new(Bytes::copy_from_slice(vk.as_bytes())));
    *r.status_mut() = StatusCode::OK;
    r.headers_mut().insert(header::CONTENT_TYPE, header::HeaderValue::from_static("application/octet-stream"));
    r.headers_mut().insert(header::CACHE_CONTROL, header::HeaderValue::from_static("public, max-age=300"));
    r
}

fn key_json(state: &AppState) -> Response<RespBody> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    let vk = state.signing_key.verifying_key();
    let kid = attestation::key_id(&vk);
    let body = format!(
        "{{\"issuer\":{},\"keyId\":{},\"algorithm\":\"Ed25519\",\"publicKeyBase64Url\":{},\"validFrom\":\"prototype\",\"status\":\"active\",\"attestationFormatVersion\":1,\"assuranceLevels\":[1]}}",
        json_string(&state.issuer_name),
        json_string(&attestation::hex(&kid)),
        json_string(&URL_SAFE_NO_PAD.encode(vk.as_bytes())),
    );
    json(StatusCode::OK, &body)
}

fn health(state: &AppState) -> Response<RespBody> {
    let clock = match state.safe_now_ms() {
        Ok(ms) => format!("{{\"status\":\"ok\",\"clock\":\"system UTC with in-process backwards-clock guard\",\"timestampMs\":{ms},\"externalNtpHealthCheck\":false}}"),
        Err(e) => format!("{{\"status\":\"unhealthy\",\"error\":{}}}", json_string(e)),
    };
    json(StatusCode::OK, &clock)
}

fn hash_alg_name(id: u8) -> &'static str {
    match id {
        HASH_ALG_SHA256 => "SHA-256",
        _ => "unknown",
    }
}

fn assurance_text(level: u8) -> &'static str {
    match level {
        ASSURANCE_LEVEL_1 => "Level 1: trusted issuer upper-bound timestamp",
        _ => "Unknown assurance level",
    }
}

fn home_page(state: &AppState) -> String {
    page("Muze Temporal Attestation", &format!(r#"
<section class="hero">
  <p class="eyebrow">Temporal provenance infrastructure</p>
  <h1>Prove that a hash existed before a specific time.</h1>
  <p class="lead">Send this service a SHA-256 digest. It returns a small Ed25519-signed attestation saying that the digest was available to {issuer} no later than the signed UTC timestamp.</p>
  <p><a class="button" href="/decode">Decode an attestation</a> <a class="button secondary" href="/keys">Public key</a></p>
</section>
<section>
  <h2>What leaves your system?</h2>
  <pre>your data → SHA-256 (locally) → 32-byte digest → Muze</pre>
  <p>The source data is never required by the attestation API. For low-entropy private values, create a salted or nonce-based commitment before submission.</p>
</section>
<section>
  <h2>Assurance level 1</h2>
  <p>The signed statement means: <strong>{issuer} attests that this commitment was available to the service no later than time X.</strong></p>
  <p>This level requires the verifier to trust the issuer's clock and operational honesty. It does not independently prevent the issuer from backdating. Stronger assurance levels can add external anchoring later.</p>
</section>
<section>
  <h2>Try it without uploading your text</h2>
  <p>This browser hashes the text locally and sends only the 32-byte digest.</p>
  <textarea id="sample" rows="5" placeholder="Type anything here"></textarea>
  <p><button id="attest">Attest this text</button></p>
  <pre id="result">No attestation yet.</pre>
</section>
<section>
  <h2>API</h2>
  <p><code>POST /v1/attest</code> with exactly 32 raw bytes containing a SHA-256 digest. The response is a 127-byte <code>application/vnd.muze.temporal-attestation</code> object.</p>
  <p><a href="/about">Protocol and trust details</a></p>
</section>
<script>
const b64url = bytes => btoa(String.fromCharCode(...bytes)).replaceAll('+','-').replaceAll('/','_').replaceAll('=','');
document.getElementById('attest').onclick = async () => {{
  const text = new TextEncoder().encode(document.getElementById('sample').value);
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', text));
  const r = await fetch('/v1/attest', {{ method:'POST', headers:{{'Content-Type':'application/octet-stream'}}, body:digest }});
  if (!r.ok) {{ document.getElementById('result').textContent = await r.text(); return; }}
  const att = new Uint8Array(await r.arrayBuffer());
  document.getElementById('result').textContent = 'mta1_' + b64url(att);
}};
</script>
"#, issuer=html_escape(&state.issuer_name)))
}

fn about_page(state: &AppState) -> String {
    page("How it works", &format!(r#"
<h1>How the attestation works</h1>
<p>A level-1 Muze temporal attestation is a compact signed object binding a cryptographic digest to an upper-bound time.</p>
<ol>
<li>The client hashes its data locally with SHA-256.</li>
<li>The client sends only the 32-byte digest.</li>
<li>The server reads its UTC clock, builds the attestation body, and signs it with Ed25519.</li>
<li>The completed attestation is returned immediately. The service does not need to store it.</li>
</ol>
<h2>What it proves</h2>
<blockquote>{issuer} attests that it had received this exact commitment no later than the signed time.</blockquote>
<h2>What it does not prove</h2>
<ul>
<li>It does not prove the underlying statement is true.</li>
<li>It does not prove who created the underlying data.</li>
<li>It does not prove when the underlying data was first created.</li>
<li>Assurance level 1 does not protect against a dishonest issuer deliberately backdating an attestation.</li>
</ul>
<h2>Binary format</h2>
<pre>offset  size  field
0       4     magic: "MTA\\0"
4       1     format_version = 1
5       1     assurance_level = 1
6       1     hash_algorithm = 1 (SHA-256)
7       32    digest
39      8     signed big-endian Unix milliseconds UTC
47      16    key_id = first 128 bits of SHA-256(public Ed25519 key)
63      64    Ed25519 signature over bytes 0..62

total: 127 bytes</pre>
<p>The textual form is <code>mta1_</code> followed by unpadded base64url of the complete 127-byte binary object.</p>
<h2>Versions are separate from assurance</h2>
<p>The format version tells software how to parse an attestation. The assurance level tells a verifier what guarantee the attestation claims. API versioning is separately expressed by the URL path.</p>
<h2>Clock status</h2>
<p>This prototype uses the host system UTC clock plus an in-process backwards-clock guard. External NTP-health verification is intentionally disclosed as not yet implemented and is visible at <a href="/health">/health</a>.</p>
"#, issuer=html_escape(&state.issuer_name)))
}

fn keys_page(state: &AppState) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    let vk = state.signing_key.verifying_key();
    let kid = attestation::key_id(&vk);
    page("Public key", &format!(r#"
<h1>Current public signing key</h1>
<dl>
<dt>Issuer</dt><dd>{issuer}</dd>
<dt>Algorithm</dt><dd>Ed25519</dd>
<dt>Key ID</dt><dd><code>{kid}</code></dd>
<dt>Public key (base64url)</dt><dd><code>{pk}</code></dd>
</dl>
<p>Machine-readable form: <a href="/v1/keys/current">/v1/keys/current</a>; raw 32-byte public key: <a href="/v1/keys/current.raw">/v1/keys/current.raw</a></p>
<p>Well-known alias: <a href="/.well-known/muze-temporal-attestation-key.json">/.well-known/muze-temporal-attestation-key.json</a></p>
<p>Key rotation/history hardening is outside this first prototype. Do not treat this page alone as an independently timestamped key-history record.</p>
"#, issuer=html_escape(&state.issuer_name), kid=attestation::hex(&kid), pk=URL_SAFE_NO_PAD.encode(vk.as_bytes())))
}

fn decode_page() -> String {
    page("Decode an attestation", r#"
<h1>Decode and verify an attestation</h1>
<p>Paste a textual <code>mta1_…</code> attestation. The browser converts it to bytes; the server verifies the signature against its current public key and explains the statement.</p>
<textarea id="input" rows="8" placeholder="mta1_..."></textarea>
<p><button id="decode">Decode</button></p>
<pre id="output">No attestation decoded yet.</pre>
<script>
function fromB64url(s) {
  s = s.replaceAll('-','+').replaceAll('_','/');
  while (s.length % 4) s += '=';
  const raw = atob(s);
  return Uint8Array.from(raw, c => c.charCodeAt(0));
}
document.getElementById('decode').onclick = async () => {
  try {
    let s = document.getElementById('input').value.trim();
    if (!s.startsWith('mta1_')) throw new Error('Attestation must start with mta1_');
    const bytes = fromB64url(s.slice(5));
    const r = await fetch('/v1/decode', {method:'POST', headers:{'Content-Type':'application/vnd.muze.temporal-attestation'}, body:bytes});
    const obj = await r.json();
    document.getElementById('output').textContent = JSON.stringify(obj, null, 2);
  } catch(e) {
    document.getElementById('output').textContent = String(e);
  }
};
</script>
"#)
}

fn page(title: &str, body: &str) -> String {
    format!(r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} — Muze</title>
<style>
:root {{ color-scheme: light dark; font-family: ui-sans-serif, system-ui, sans-serif; }}
body {{ max-width: 900px; margin: 0 auto; padding: 2rem 1.2rem 5rem; line-height: 1.55; }}
nav {{ display:flex; gap:1rem; flex-wrap:wrap; margin-bottom:3rem; }}
nav a {{ text-decoration:none; }}
.hero {{ padding:2rem 0 1rem; }}
h1 {{ font-size: clamp(2rem, 7vw, 4.5rem); line-height:1.02; letter-spacing:-0.04em; }}
h2 {{ margin-top:2.5rem; }}
.lead {{ font-size:1.25rem; max-width:65ch; }}
.eyebrow {{ text-transform:uppercase; letter-spacing:.12em; font-size:.78rem; opacity:.7; }}
pre, code {{ font-family: ui-monospace, SFMono-Regular, Consolas, monospace; }}
pre {{ padding:1rem; overflow:auto; border:1px solid #8886; border-radius:.5rem; }}
textarea {{ width:100%; box-sizing:border-box; font:inherit; padding:.8rem; }}
button,.button {{ display:inline-block; padding:.65rem .95rem; border:1px solid currentColor; border-radius:.4rem; background:transparent; color:inherit; text-decoration:none; cursor:pointer; }}
.button.secondary {{ opacity:.75; }}
dt {{ font-weight:700; margin-top:1rem; }} dd {{ margin-left:0; overflow-wrap:anywhere; }}
blockquote {{ border-left:4px solid currentColor; padding-left:1rem; margin-left:0; font-size:1.15rem; }}
footer {{ margin-top:4rem; opacity:.7; font-size:.9rem; }}
</style>
</head>
<body>
<nav><a href="/">Home</a><a href="/about">How it works</a><a href="/decode">Decode</a><a href="/keys">Public key</a><a href="/health">Health</a></nav>
<main>{body}</main>
<footer>Muze Temporal Attestation Service — prototype assurance level 1.</footer>
</body>
</html>"#, title=html_escape(title), body=body)
}

fn html(status: StatusCode, s: &str) -> Response<RespBody> {
    let mut r = Response::new(Full::new(Bytes::copy_from_slice(s.as_bytes())));
    *r.status_mut() = status;
    r.headers_mut().insert(header::CONTENT_TYPE, header::HeaderValue::from_static("text/html; charset=utf-8"));
    r
}

fn text(status: StatusCode, s: &str) -> Response<RespBody> {
    let mut r = Response::new(Full::new(Bytes::copy_from_slice(s.as_bytes())));
    *r.status_mut() = status;
    r.headers_mut().insert(header::CONTENT_TYPE, header::HeaderValue::from_static("text/plain; charset=utf-8"));
    r
}

fn json(status: StatusCode, s: &str) -> Response<RespBody> {
    let mut r = Response::new(Full::new(Bytes::copy_from_slice(s.as_bytes())));
    *r.status_mut() = status;
    r.headers_mut().insert(header::CONTENT_TYPE, header::HeaderValue::from_static("application/json; charset=utf-8"));
    r.headers_mut().insert(header::CACHE_CONTROL, header::HeaderValue::from_static("no-store"));
    r
}

fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len()+2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c < ' ' => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn iso8601_utc_ms(ms: i64) -> String {
    // Dependency-free civil date conversion; valid for ordinary Unix-era timestamps.
    let secs = ms.div_euclid(1000);
    let millis = ms.rem_euclid(1000);
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = sod / 3600;
    let minute = (sod % 3600) / 60;
    let second = sod % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    // Howard Hinnant's civil_from_days algorithm, with Unix epoch adjustment.
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe/1460 + doe/36_524 - doe/146_096) / 365;
    let mut y = yoe + era * 400;
    let doy = doe - (365*yoe + yoe/4 - yoe/100);
    let mp = (5*doy + 2)/153;
    let d = doy - (153*mp+2)/5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    y += if m <= 2 { 1 } else { 0 };
    (y, m, d)
}

pub fn public_key_json(verifying_key: &VerifyingKey, issuer: &str) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    format!(
        "{{\"issuer\":{},\"keyId\":{},\"algorithm\":\"Ed25519\",\"publicKeyBase64Url\":{}}}",
        json_string(issuer),
        json_string(&attestation::hex(&attestation::key_id(verifying_key))),
        json_string(&URL_SAFE_NO_PAD.encode(verifying_key.as_bytes()))
    )
}
