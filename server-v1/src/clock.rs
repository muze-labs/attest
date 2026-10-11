use std::{
    net::SocketAddr,
    sync::{Arc, RwLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{net::UdpSocket, time};

const NTP_UNIX_EPOCH_OFFSET_SECS: i128 = 2_208_988_800;
const NTP_PACKET_LEN: usize = 48;

#[derive(Clone, Debug)]
pub struct ClockConfig {
    pub sources: Vec<String>,
    pub min_valid_sources: usize,
    pub source_threshold_ms: f64,
    pub local_threshold_ms: f64,
    pub check_interval: Duration,
    pub stale_after: Duration,
    pub query_timeout: Duration,
}

impl Default for ClockConfig {
    fn default() -> Self {
        Self {
            sources: vec![
                "time.cloudflare.com".into(),
                "time.nist.gov".into(),
                "time.windows.com".into(),
                "ntp.ubuntu.com".into(),
                "time.meta.com".into(),
            ],
            min_valid_sources: 3,
            source_threshold_ms: 100.0,
            local_threshold_ms: 250.0,
            check_interval: Duration::from_secs(30),
            stale_after: Duration::from_secs(90),
            query_timeout: Duration::from_millis(2_000),
        }
    }
}

#[derive(Clone, Debug)]
pub struct SourceHealth {
    pub source: String,
    pub reachable: bool,
    pub valid: bool,
    pub offset_ms: Option<f64>,
    pub round_trip_ms: Option<f64>,
    pub stratum: Option<u8>,
    pub error: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ClockHealth {
    pub healthy: bool,
    pub checked_at_ms: Option<i64>,
    pub median_offset_ms: Option<f64>,
    pub valid_sources: usize,
    pub reason: String,
    pub sources: Vec<SourceHealth>,
}

impl ClockHealth {
    fn pending(config: &ClockConfig) -> Self {
        Self {
            healthy: false,
            checked_at_ms: None,
            median_offset_ms: None,
            valid_sources: 0,
            reason: format!(
                "waiting for initial clock check (need {} of {} valid sources)",
                config.min_valid_sources,
                config.sources.len()
            ),
            sources: config
                .sources
                .iter()
                .map(|s| SourceHealth {
                    source: s.clone(),
                    reachable: false,
                    valid: false,
                    offset_ms: None,
                    round_trip_ms: None,
                    stratum: None,
                    error: Some("not checked yet".into()),
                })
                .collect(),
        }
    }
}

#[derive(Clone)]
pub struct ClockMonitor {
    config: Arc<ClockConfig>,
    state: Arc<RwLock<ClockHealth>>,
}

impl ClockMonitor {
    pub fn new(config: ClockConfig) -> Self {
        let state = ClockHealth::pending(&config);
        Self {
            config: Arc::new(config),
            state: Arc::new(RwLock::new(state)),
        }
    }

    pub fn config(&self) -> &ClockConfig {
        &self.config
    }

    pub fn snapshot(&self) -> ClockHealth {
        match self.state.read() {
            Ok(v) => v.clone(),
            Err(_) => ClockHealth {
                healthy: false,
                checked_at_ms: None,
                median_offset_ms: None,
                valid_sources: 0,
                reason: "clock-health state lock unavailable".into(),
                sources: Vec::new(),
            },
        }
    }

    pub fn is_healthy_and_fresh(&self) -> Result<(), String> {
        let snapshot = self.snapshot();
        if !snapshot.healthy {
            return Err(snapshot.reason);
        }
        let checked = snapshot
            .checked_at_ms
            .ok_or_else(|| "clock has not yet been checked".to_string())?;
        let now = system_time_ms().map_err(|e| e.to_string())?;
        let age_ms = now.saturating_sub(checked);
        if age_ms < 0 || age_ms as u128 > self.config.stale_after.as_millis() {
            return Err(format!(
                "clock-health check is stale ({} ms old; maximum {} ms)",
                age_ms,
                self.config.stale_after.as_millis()
            ));
        }
        Ok(())
    }

    pub fn spawn(self) {
        tokio::spawn(async move {
            loop {
                self.check_once().await;
                time::sleep(self.config.check_interval).await;
            }
        });
    }

    pub async fn check_once(&self) {
        let mut tasks = Vec::with_capacity(self.config.sources.len());
        for source in self.config.sources.iter().cloned() {
            let timeout = self.config.query_timeout;
            tasks.push(tokio::spawn(async move {
                let result = time::timeout(timeout, query_ntp(&source)).await;
                match result {
                    Ok(Ok(sample)) => SourceHealth {
                        source,
                        reachable: true,
                        valid: false,
                        offset_ms: Some(sample.offset_ms),
                        round_trip_ms: Some(sample.round_trip_ms),
                        stratum: Some(sample.stratum),
                        error: None,
                    },
                    Ok(Err(e)) => SourceHealth {
                        source,
                        reachable: false,
                        valid: false,
                        offset_ms: None,
                        round_trip_ms: None,
                        stratum: None,
                        error: Some(e),
                    },
                    Err(_) => SourceHealth {
                        source,
                        reachable: false,
                        valid: false,
                        offset_ms: None,
                        round_trip_ms: None,
                        stratum: None,
                        error: Some(format!("timeout after {} ms", timeout.as_millis())),
                    },
                }
            }));
        }

        let mut sources = Vec::with_capacity(tasks.len());
        for task in tasks {
            match task.await {
                Ok(sample) => sources.push(sample),
                Err(e) => sources.push(SourceHealth {
                    source: "unknown".into(),
                    reachable: false,
                    valid: false,
                    offset_ms: None,
                    round_trip_ms: None,
                    stratum: None,
                    error: Some(format!("clock-check task failed: {e}")),
                }),
            }
        }

        let reachable_offsets: Vec<f64> = sources.iter().filter_map(|s| s.offset_ms).collect();
        let source_median = median(&reachable_offsets);

        if let Some(median) = source_median {
            for source in &mut sources {
                if let Some(offset) = source.offset_ms {
                    let delta = (offset - median).abs();
                    if delta <= self.config.source_threshold_ms {
                        source.valid = true;
                    } else {
                        source.valid = false;
                        source.error = Some(format!(
                            "source differs from source median by {:.3} ms (maximum {:.3} ms)",
                            delta, self.config.source_threshold_ms
                        ));
                    }
                }
            }
        }

        let valid_offsets: Vec<f64> = sources
            .iter()
            .filter(|s| s.valid)
            .filter_map(|s| s.offset_ms)
            .collect();
        let valid_sources = valid_offsets.len();
        let median_offset_ms = median(&valid_offsets);
        let checked_at_ms = system_time_ms().ok();

        let (healthy, reason) = if valid_sources < self.config.min_valid_sources {
            (
                false,
                format!(
                    "only {} valid clock sources; need at least {}",
                    valid_sources, self.config.min_valid_sources
                ),
            )
        } else if let Some(offset) = median_offset_ms {
            if offset.abs() > self.config.local_threshold_ms {
                (
                    false,
                    format!(
                        "local clock differs from source consensus by {:.3} ms; maximum {:.3} ms",
                        offset, self.config.local_threshold_ms
                    ),
                )
            } else {
                (
                    true,
                    format!(
                        "{} valid sources; median local-clock offset {:.3} ms",
                        valid_sources, offset
                    ),
                )
            }
        } else {
            (false, "unable to calculate source consensus".into())
        };

        let next = ClockHealth {
            healthy,
            checked_at_ms,
            median_offset_ms,
            valid_sources,
            reason,
            sources,
        };
        if let Ok(mut state) = self.state.write() {
            *state = next;
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct NtpSample {
    offset_ms: f64,
    round_trip_ms: f64,
    stratum: u8,
}

async fn query_ntp(source: &str) -> Result<NtpSample, String> {
    let mut addresses: Vec<SocketAddr> = tokio::net::lookup_host((source, 123))
        .await
        .map_err(|e| format!("DNS lookup failed: {e}"))?
        .collect();
    // Prefer IPv4 first so an unusable IPv6 route does not consume the whole source timeout.
    addresses.sort_by_key(|addr| if addr.is_ipv4() { 0 } else { 1 });
    if addresses.is_empty() {
        return Err("DNS lookup returned no addresses".into());
    }

    let mut last_error = None;
    for addr in addresses {
        match query_ntp_addr(addr).await {
            Ok(sample) => return Ok(sample),
            Err(e) => last_error = Some(e),
        }
    }
    Err(last_error.unwrap_or_else(|| "no usable NTP address".into()))
}

async fn query_ntp_addr(addr: SocketAddr) -> Result<NtpSample, String> {
    let bind_addr = if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let socket = UdpSocket::bind(bind_addr)
        .await
        .map_err(|e| format!("UDP bind failed: {e}"))?;
    socket
        .connect(addr)
        .await
        .map_err(|e| format!("UDP connect failed: {e}"))?;

    let mut request = [0u8; NTP_PACKET_LEN];
    request[0] = 0x23; // LI=0, VN=4, Mode=3 (client)

    let t1 = system_time_ns().map_err(|e| e.to_string())?;
    let sent_timestamp = unix_ns_to_ntp_timestamp(t1)?;
    request[40..48].copy_from_slice(&sent_timestamp);
    socket
        .send(&request)
        .await
        .map_err(|e| format!("NTP send failed: {e}"))?;

    let mut response = [0u8; NTP_PACKET_LEN];
    let n = socket
        .recv(&mut response)
        .await
        .map_err(|e| format!("NTP receive failed: {e}"))?;
    let t4 = system_time_ns().map_err(|e| e.to_string())?;

    if n < NTP_PACKET_LEN {
        return Err(format!("short NTP response: {n} bytes"));
    }

    let leap = response[0] >> 6;
    let mode = response[0] & 0x07;
    let stratum = response[1];
    if leap == 3 {
        return Err("NTP source reports unsynchronized clock".into());
    }
    if mode != 4 && mode != 5 {
        return Err(format!("unexpected NTP mode {mode}"));
    }
    if !(1..=15).contains(&stratum) {
        return Err(format!("invalid NTP stratum {stratum}"));
    }

    if response[24..32] != sent_timestamp[..] {
        return Err("NTP response origin timestamp does not match request".into());
    }

    let t2 = ntp_timestamp_to_unix_ns(&response[32..40], t4)?;
    let t3 = ntp_timestamp_to_unix_ns(&response[40..48], t4)?;

    let offset_ns = ((t2 - t1) + (t3 - t4)) / 2;
    let network_ns = (t4 - t1) - (t3 - t2);

    Ok(NtpSample {
        offset_ms: offset_ns as f64 / 1_000_000.0,
        round_trip_ms: network_ns.max(0) as f64 / 1_000_000.0,
        stratum,
    })
}

fn unix_ns_to_ntp_timestamp(unix_ns: i128) -> Result<[u8; 8], String> {
    let unix_secs = unix_ns.div_euclid(1_000_000_000i128);
    let nanos = unix_ns.rem_euclid(1_000_000_000i128);
    let ntp_secs = unix_secs + NTP_UNIX_EPOCH_OFFSET_SECS;
    if ntp_secs < 0 {
        return Err("time predates NTP epoch".into());
    }
    // NTP transmits only the low 32 bits of seconds; era is inferred by the receiver.
    let secs_low = (ntp_secs & 0xffff_ffff) as u32;
    let frac = ((nanos << 32) / 1_000_000_000i128) as u32;
    let mut out = [0u8; 8];
    out[..4].copy_from_slice(&secs_low.to_be_bytes());
    out[4..].copy_from_slice(&frac.to_be_bytes());
    Ok(out)
}

fn ntp_timestamp_to_unix_ns(bytes: &[u8], reference_unix_ns: i128) -> Result<i128, String> {
    if bytes.len() != 8 {
        return Err("invalid NTP timestamp length".into());
    }
    let raw_secs = u32::from_be_bytes(bytes[0..4].try_into().unwrap()) as i128;
    let frac = u32::from_be_bytes(bytes[4..8].try_into().unwrap()) as i128;

    // Resolve the 32-bit NTP era to the candidate closest to our local receive time.
    // This keeps the implementation valid across the 2036 NTP era rollover.
    let reference_unix_secs = reference_unix_ns.div_euclid(1_000_000_000i128);
    let reference_ntp_secs = reference_unix_secs + NTP_UNIX_EPOCH_OFFSET_SECS;
    let era_span = 1i128 << 32;
    let approximate_era = (reference_ntp_secs - raw_secs).div_euclid(era_span);
    let candidates = [approximate_era - 1, approximate_era, approximate_era + 1];
    let full_ntp_secs = candidates
        .iter()
        .map(|era| raw_secs + *era * era_span)
        .min_by_key(|candidate| (*candidate - reference_ntp_secs).abs())
        .ok_or_else(|| "unable to resolve NTP era".to_string())?;

    let unix_secs = full_ntp_secs - NTP_UNIX_EPOCH_OFFSET_SECS;
    let frac_ns = (frac * 1_000_000_000i128) >> 32;
    Ok(unix_secs * 1_000_000_000i128 + frac_ns)
}

fn system_time_ns() -> Result<i128, &'static str> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock is before Unix epoch")?;
    Ok(now.as_secs() as i128 * 1_000_000_000i128 + now.subsec_nanos() as i128)
}

pub fn system_time_ms() -> Result<i64, &'static str> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock is before Unix epoch")?;
    i64::try_from(now.as_millis()).map_err(|_| "system clock out of supported range")
}

fn median(values: &[f64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.total_cmp(b));
    let mid = sorted.len() / 2;
    if sorted.len() % 2 == 1 {
        Some(sorted[mid])
    } else {
        Some((sorted[mid - 1] + sorted[mid]) / 2.0)
    }
}

#[cfg(test)]
mod tests {
    use super::median;

    #[test]
    fn median_odd() {
        assert_eq!(median(&[10.0, 1.0, 2.0]), Some(2.0));
    }

    #[test]
    fn median_even() {
        assert_eq!(median(&[10.0, 4.0, 2.0, 6.0]), Some(5.0));
    }
}
