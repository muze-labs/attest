use crate::{
    attestation::{self, ASSURANCE_LEVEL_1, ATTESTATION_LEN, HASH_ALG_SHA256},
    clock::{self, ClockMonitor},
};
use bytes::Bytes;
use ed25519_dalek::{SigningKey, VerifyingKey};
use http_body_util::{BodyExt, Full};
use hyper::{body::Incoming, header, Method, Request, Response, StatusCode};
use sha2::{Digest, Sha256};
use std::{convert::Infallible, sync::{Arc, Mutex}};

pub type RespBody = Full<Bytes>;

#[derive(Clone)]
pub struct AppState {
    pub signing_key: Arc<SigningKey>,
    pub issuer_name: Arc<String>,
    pub public_base_url: Arc<String>,
    pub clock_monitor: ClockMonitor,
    last_timestamp_ms: Arc<Mutex<i64>>,
}

impl AppState {
    pub fn new(signing_key: SigningKey, issuer_name: String, public_base_url: String, clock_monitor: ClockMonitor) -> Self {
        Self {
            signing_key: Arc::new(signing_key),
            issuer_name: Arc::new(issuer_name),
            public_base_url: Arc::new(public_base_url),
            clock_monitor,
            last_timestamp_ms: Arc::new(Mutex::new(0)),
        }
    }

    fn safe_now_ms(&self) -> Result<i64, String> {
        self.clock_monitor.is_healthy_and_fresh()?;

        // Take the lock before reading the clock so concurrent requests
        // cannot appear to move time backwards merely by being scheduled
        // out of order.
        let mut last = self
            .last_timestamp_ms
            .lock()
            .map_err(|_| "clock guard unavailable".to_string())?;

        let ms = clock::system_time_ms().map_err(|e| e.to_string())?;

        if ms < *last {
            return Err("system clock moved backwards; refusing to attest".into());
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
        (Method::GET, "/why") => html(StatusCode::OK, &why_page()),
        (Method::GET, "/decode") => html(StatusCode::OK, &decode_page()),
        (Method::GET, "/keys") => html(StatusCode::OK, &keys_page(&state)),
        (Method::GET, "/health") => html(StatusCode::OK, &health_page(&state)),
        (Method::GET, "/v1/health") => health_json(&state),
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

fn health_json(state: &AppState) -> Response<RespBody> {
    let snapshot = state.clock_monitor.snapshot();
    let config = state.clock_monitor.config();
    let fresh = state.clock_monitor.is_healthy_and_fresh().is_ok();
    let status = if snapshot.healthy && fresh { "ok" } else { "unhealthy" };
    let checked_at = snapshot.checked_at_ms.map(iso8601_utc_ms);
    let sources = snapshot.sources.iter().map(|source| {
        format!(
            "{{\"name\":{},\"reachable\":{},\"valid\":{},\"offsetMs\":{},\"roundTripMs\":{},\"stratum\":{},\"error\":{}}}",
            json_string(&source.source),
            source.reachable,
            source.valid,
            json_number_opt(source.offset_ms),
            json_number_opt(source.round_trip_ms),
            source.stratum.map(|v| v.to_string()).unwrap_or_else(|| "null".into()),
            source.error.as_deref().map(json_string).unwrap_or_else(|| "null".into()),
        )
    }).collect::<Vec<_>>().join(",");
    let body = format!(
        "{{\"status\":{},\"issuingAttestations\":{},\"reason\":{},\"checkedAt\":{},\"medianOffsetMs\":{},\"validSources\":{},\"configuredSources\":{},\"minimumValidSources\":{},\"sourceThresholdMs\":{},\"localThresholdMs\":{},\"checkIntervalSeconds\":{},\"staleAfterSeconds\":{},\"queryTimeoutMs\":{},\"sources\":[{}]}}",
        json_string(status),
        snapshot.healthy && fresh,
        json_string(&snapshot.reason),
        checked_at.as_deref().map(json_string).unwrap_or_else(|| "null".into()),
        json_number_opt(snapshot.median_offset_ms),
        snapshot.valid_sources,
        config.sources.len(),
        config.min_valid_sources,
        config.source_threshold_ms,
        config.local_threshold_ms,
        config.check_interval.as_secs(),
        config.stale_after.as_secs(),
        config.query_timeout.as_millis(),
        sources,
    );
    let code = if snapshot.healthy && fresh { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE };
    json(code, &body)
}

fn health_page(state: &AppState) -> String {
    let snapshot = state.clock_monitor.snapshot();
    let config = state.clock_monitor.config();
    let fresh = state.clock_monitor.is_healthy_and_fresh().is_ok();
    let healthy = snapshot.healthy && fresh;
    let checked_at = snapshot.checked_at_ms
        .map(iso8601_utc_ms)
        .unwrap_or_else(|| "not checked yet".into());
    let median = snapshot.median_offset_ms
        .map(|v| format!("{v:+.3} ms"))
        .unwrap_or_else(|| "unavailable".into());
    let rows = snapshot.sources.iter().map(|source| {
        let status = if source.valid { "valid" } else if source.reachable { "rejected" } else { "unreachable" };
        let offset = source.offset_ms.map(|v| format!("{v:+.3} ms")).unwrap_or_else(|| "—".into());
        let rtt = source.round_trip_ms.map(|v| format!("{v:.3} ms")).unwrap_or_else(|| "—".into());
        let stratum = source.stratum.map(|v| v.to_string()).unwrap_or_else(|| "—".into());
        let note = source.error.as_deref().unwrap_or("");
        format!(
            "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            html_escape(&source.source), status, offset, rtt, stratum, html_escape(note)
        )
    }).collect::<Vec<_>>().join("\n");

    page("Clock health", &format!(r#"
<h1>Clock health</h1>
<p class="lead"><strong>{status}</strong> — issuing attestations: <strong>{issuing}</strong></p>
<p>{reason}</p>
<dl>
<dt>Last check</dt><dd>{checked_at}</dd>
<dt>Valid sources</dt><dd>{valid} of {configured}; minimum {minimum}</dd>
<dt>Median local-clock offset</dt><dd>{median}</dd>
<dt>Maximum source disagreement</dt><dd>±{source_threshold:.0} ms from source median</dd>
<dt>Maximum local clock offset</dt><dd>±{local_threshold:.0} ms</dd>
<dt>Check interval</dt><dd>{interval} seconds</dd>
<dt>Health expires after</dt><dd>{stale} seconds without a successful fresh check</dd>
<dt>Per-source query timeout</dt><dd>{timeout} ms</dd>
</dl>
<h2>Clock sources</h2>
<p>The service checks {configured} independently operated public NTP sources. A source that differs from the source median by more than the configured threshold is rejected. The service requires at least three valid sources, and separately requires their median to agree with the local system clock.</p>
<table><thead><tr><th>Source</th><th>Status</th><th>Offset</th><th>RTT</th><th>Stratum</th><th>Note</th></tr></thead><tbody>{rows}</tbody></table>
<h2>Trust note</h2>
<p>These checks use ordinary NTP as a cross-check of the local clock. They substantially reduce accidental clock errors and single-source failures, but ordinary NTP is not cryptographically authenticated. Network Time Security (NTS) is a possible later hardening step.</p>
<p>Machine-readable status: <a href="/v1/health"><code>/v1/health</code></a>.</p>
"#,
        status=if healthy { "HEALTHY" } else { "UNHEALTHY" },
        issuing=if healthy { "YES" } else { "NO" },
        reason=html_escape(&snapshot.reason),
        checked_at=html_escape(&checked_at),
        valid=snapshot.valid_sources,
        configured=config.sources.len(),
        minimum=config.min_valid_sources,
        median=median,
        source_threshold=config.source_threshold_ms,
        local_threshold=config.local_threshold_ms,
        interval=config.check_interval.as_secs(),
        stale=config.stale_after.as_secs(),
        timeout=config.query_timeout.as_millis(),
        rows=rows,
    ))
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
  <p><a class="button" href="/decode">Decode an attestation</a> <a class="button secondary" href="/why">Why this is needed</a> <a class="button secondary" href="/keys">Public key</a></p>
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
  <p><a href="/about">Protocol and trust details</a> · <a href="/why">Why temporal attestation matters</a></p>
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
<h2>What Assurance Level 1 proves</h2>
<blockquote>{issuer} attests that it had received this exact commitment no later than the signed time.</blockquote>
<p>A Level 1 attestation establishes an <strong>upper bound on when these exact committed bytes must already have existed</strong>.</p>
<p>For example, a document may contain a date claiming it was created on 1 January. If its Muze attestation is dated 8 October, the attestation provides no evidence that the document existed in January. It establishes only that these exact bytes existed by 8 October.</p>
<p>This makes retrospective fabrication detectable: someone cannot create evidence today, put an old date inside it, and use a later Muze attestation as proof that the evidence already existed on that old date.</p>
<h2>What you are trusting</h2>
<p>Level 1 relies on trusting {issuer} to operate its clock and signing service honestly. The cryptographic signature proves that Muze issued the attestation and that the signed digest, timestamp, assurance level, and other signed fields have not been changed.</p>
<p>The service checks its local clock against multiple independent public time sources before issuing attestations. However, the Level 1 attestation by itself cannot cryptographically prevent Muze from deliberately signing a false historical timestamp. A future independently anchored assurance level can provide that stronger guarantee.</p>
<h2>What it does not prove</h2>
<ul>
<li>It does not prove the contents of the data are true.</li>
<li>It does not prove who created the underlying data.</li>
<li>It does not prove that dates written inside the data are correct.</li>
<li>It does not prove when the underlying data was first created.</li>
<li>It does not prove that the data did not exist before the attested time.</li>
</ul>
<p><strong>In short:</strong> these exact committed bytes existed no later than the signed timestamp, assuming the Muze Temporal Attestation Service is trusted to operate its clock and signing service honestly.</p>
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
<p>The service checks its local clock against five independently operated public NTP sources. At least three must agree within the configured source threshold, and their median must remain within the configured local-clock threshold. Clock-health data also expires if checks become stale. If any of those conditions fail, attestation issuance fails closed.</p>
<p>The configured sources, offsets, thresholds, and current issuance decision are public at <a href="/health">/health</a>.</p>
"#, issuer=html_escape(&state.issuer_name)))
}

fn why_page() -> String {
    page("Why this is needed", r#"
<h1>Why temporal attestation?</h1>
<p class="lead">As AI makes digital information cheap to generate and regenerate, internal consistency is no longer enough. We need independent evidence that particular information was already present at a particular point in time.</p>

<h2>The problem with dates inside data</h2>
<p>A signed document can contain a date. A Verifiable Credential can contain an issuance date. A provenance record can say that an event happened last month.</p>
<p>Those dates are still claims made by the data or its issuer. A perfectly valid signature proves who signed those bytes; it does not, by itself, prove that those bytes already existed on the date written inside them.</p>
<p>Temporal attestation adds an observation from outside the data:</p>
<blockquote>By this time, the attestation service had already seen this exact cryptographic commitment.</blockquote>
<p>If evidence claims to come from January but its earliest independent temporal attestation is from October, the attestation does not support the January claim. That gap remains visible no matter how convincing the surrounding material looks.</p>

<h2>Why AI makes this more important</h2>
<p>AI can cheaply create coherent sets of documents, messages, logs, explanations and provenance records that all agree with one another. A fabricated history can therefore be internally consistent without being historical.</p>
<p>Temporal evidence does not tell us whether a claim is true. It gives us a narrower fact that generated content cannot simply assert about itself:</p>
<blockquote>This exact committed information was already present by this point in time.</blockquote>

<h2>AI as infrastructure</h2>
<p>This service grew out of a broader infrastructure direction we are exploring at Muze.</p>
<p>We expect independent systems increasingly to expose local AI agents that understand their own data, semantics and capabilities. A client AI can ask for information in terms of meaning rather than a pre-agreed API shape, while the remote AI translates that request into local queries and returns an appropriate answer.</p>
<p>That can make interoperability dramatically easier, but it also makes trust infrastructure more important. When AIs exchange claims for people and organizations, we need several independent answers:</p>
<dl>
<dt>Identity</dt><dd>Who or what is making this claim?</dd>
<dt>Authorization</dt><dd>Were they allowed to make or disclose it?</dd>
<dt>Signature</dt><dd>Did they really issue this exact statement?</dd>
<dt>Provenance</dt><dd>What information did the claim depend on?</dd>
<dt>Temporal attestation</dt><dd>By when did this exact evidence already exist?</dd>
</dl>
<p>No single mechanism answers all of those questions. Temporal attestation is intended to be one small, composable primitive in that larger trust layer.</p>

<h2>Cheap enough to use by default</h2>
<p>Traditional trusted timestamps are often associated with contracts and archival documents. Our goal is to make the primitive inexpensive enough for software to use routinely: for an AI claim, a message, a provenance event, a policy revision or an ephemeral machine interaction.</p>
<p>The basic service is therefore deliberately small. The client sends only a cryptographic hash. Muze returns a signed temporal attestation. Muze does not need the original data and does not need to retain the completed attestation.</p>

<h2>Assurance level 1: trusted temporal attestation</h2>
<p>The current service provides the simplest useful guarantee:</p>
<blockquote>These exact committed bytes existed no later than the signed timestamp, assuming the Muze Temporal Attestation Service is trusted to operate its clock and signing service honestly.</blockquote>
<p>This is enough to stop a submitter from creating evidence later, putting an older date inside it, and using the Muze attestation as proof that it existed on that older date.</p>
<p>The service checks its clock against several independently operated public time sources and stops issuing attestations when sufficient agreement cannot be established.</p>

<h2>Future assurance: independent anchoring</h2>
<p>Level 1 still asks the verifier to trust Muze as the time authority. A stronger assurance profile can remove much of that trust.</p>
<p>Issued attestations can be aggregated into Merkle trees and their roots anchored with one or more independent temporal witnesses. Once such an anchor exists, Muze cannot later create an additional attestation claiming to predate that boundary without contradicting evidence held outside Muze.</p>
<blockquote>The attestation existed before an independently established temporal boundary, even if Muze itself is no longer fully trusted.</blockquote>
<p>We have already benchmarked the computational part of this design and found the aggregation itself inexpensive at infrastructure scale. The additional costs come mainly from retaining and distributing proofs and using independent anchors. We therefore intend to keep it separate from the cheapest service and implement it if demand warrants it.</p>

<h2>Future assurance: bounded time</h2>
<p>Some applications need not only an upper bound—<em>existed no later than X</em>—but also a lower bound—<em>could not have been constructed before Y</em>.</p>
<p>A future profile can provide this using an unpredictable freshness challenge issued after Y and incorporated into the commitment. Combined with the normal upper-bound attestation, this bounds creation of the attested representation to an interval.</p>
<p>This requires an additional round trip and solves a different problem, so it does not belong in the basic service.</p>

<h2>Other possible assurance profiles</h2>
<p>If there is demand, future profiles may add multiple independent witnesses, ordered event streams, tighter timing guarantees, long-term cryptographic renewal, or regulated timestamp providers.</p>
<p>These are not necessarily a simple numeric ladder. The <code>assurance_level</code> in an attestation identifies a precisely documented trust model: what is proven, what must still be trusted, and what is explicitly not proven.</p>

<h2>What temporal attestation does not solve</h2>
<p>Temporal attestation does not prove that information is true, that an AI reasoned correctly, that a source was honest, that all relevant evidence was included, or that a signer had authority.</p>
<p>It proves something deliberately narrower:</p>
<blockquote>This exact cryptographic commitment was already present by this point in time.</blockquote>
<p>That modest fact becomes powerful when it composes with identity, signatures, authorization and provenance.</p>

<h2>The larger goal</h2>
<p>Future systems may exchange more machine-generated information than humans could ever manually inspect. Trust therefore cannot live only in the content; useful trust properties need to travel with it.</p>
<p>Our aim is to make one of those properties—time—cheap enough to attach almost everywhere.</p>
<p>If that works, an AI-generated world does not have to become a world without history. Important claims can carry independently checkable evidence of <strong>when they were already there</strong>.</p>
"#)
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
<section class="assurance-note">
<h2>How to interpret Assurance Level 1</h2>
<p><strong>What it establishes:</strong> the exact content represented by the signed digest existed no later than the attested timestamp.</p>
<p>A date written inside the content is only part of the content. If the content claims an earlier date, the attestation does not prove that earlier date; it proves only that the exact committed bytes existed by the Muze timestamp.</p>
<p><strong>Trust assumption:</strong> Level 1 relies on trusting the Muze Temporal Attestation Service to operate its clock and signing service honestly. The signature prevents anyone else from altering the timestamp or digest without detection, but Level 1 does not independently prevent Muze itself from signing a false historical timestamp.</p>
</section>
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
table {{ width:100%; border-collapse:collapse; font-size:.95rem; }}
th, td {{ text-align:left; padding:.55rem .45rem; border-bottom:1px solid #8885; vertical-align:top; }}
footer {{ margin-top:4rem; opacity:.7; font-size:.9rem; }}
</style>
</head>
<body>
<nav><a href="/">Home</a><a href="/about">How it works</a><a href="/why">Why this is needed</a><a href="/decode">Decode</a><a href="/keys">Public key</a><a href="/health">Health</a></nav>
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

fn json_number_opt(v: Option<f64>) -> String {
    match v {
        Some(n) if n.is_finite() => format!("{n:.3}"),
        _ => "null".into(),
    }
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
