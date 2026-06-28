use std::env;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;
use std::thread;

use chrono::{DateTime, Utc};
use gethostname::gethostname;
use openssl::asn1::Asn1Time;
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use openssl::x509::X509;
use serde::{Deserialize, Serialize};

const DEFAULT_PORT: u16 = 443;
const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 10;
const MAX_THRESHOLDS_PER_ENDPOINT: usize = 255;
const TLS_FLUSH_BUF_BYTES: usize = 512;
const LOG_UNKNOWN_HOST: &str = "unknown";
const LOG_TAG_PREFIX: &str = "tls-identity-manager";
const SHELL: &str = "sh";
const SHELL_FLAG: &str = "-c";
const FLAG_DEBUG: &str = "-d";
const FLAG_QUIET: &str = "-q";
const MILLIS_PER_SEC: u64 = 1_000;
const JITTER_RESOLUTION_MS: u64 = 100;

fn default_connect_timeout() -> u64 { DEFAULT_CONNECT_TIMEOUT_SECS }
fn default_port() -> u16 { DEFAULT_PORT }

#[derive(Debug, Deserialize, Serialize, Clone)]
struct DaemonConfig {
    interval_seconds: u64,
    jitter_max_hours: f64,
    #[serde(default = "default_connect_timeout")]
    connect_timeout_seconds: u64,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct ExpiryThreshold {
    days_before_expiry: u8,
    commands: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct EndpointConfig {
    host: String,
    #[serde(default = "default_port")]
    port: u16,
    #[serde(default)]
    sni: Option<String>,
    thresholds: Vec<ExpiryThreshold>,
}

#[derive(Debug, Deserialize, Serialize)]
struct Policy {
    daemon: DaemonConfig,
    endpoints: Vec<EndpointConfig>,
}

struct EndpointState {
    fired: Vec<bool>,
}

impl EndpointState {
    fn new(n_thresholds: usize) -> Self {
        Self { fired: vec![false; n_thresholds] }
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
enum LogLevel { Quiet = 0, Warn = 1, Debug = 2 }

struct Logger {
    level: LogLevel,
    hostname: String,
}

impl Logger {
    fn new(level: LogLevel) -> Self {
        let hostname = gethostname()
            .into_string()
            .unwrap_or_else(|_| LOG_UNKNOWN_HOST.to_string());
        Self { level, hostname }
    }

    fn tag(&self) -> String {
        let now: DateTime<Utc> = Utc::now();
        format!(
            "[{}] - {} - \"{}\"",
            now.format("%Y-%m-%dT%H:%M:%SZ"),
            LOG_TAG_PREFIX,
            self.hostname,
        )
    }

    fn info(&self, msg: &str) {
        if self.level >= LogLevel::Warn {
            println!("{} - INFO  - {}", self.tag(), msg);
        }
    }

    fn warn(&self, msg: &str) {
        if self.level >= LogLevel::Warn {
            eprintln!("{} - WARN  - {}", self.tag(), msg);
        }
    }

    fn debug(&self, msg: &str) {
        if self.level >= LogLevel::Debug {
            println!("{} - DEBUG - {}", self.tag(), msg);
        }
    }

    fn error(&self, msg: &str) {
        eprintln!("{} - ERROR - {}", self.tag(), msg);
    }
}

fn random_jitter_millis(max_hours: f64) -> u64 {
    let max_ms = (max_hours * 3_600_000.0) as u64;
    if max_ms == 0 {
        return 0;
    }
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0) as u64;
    let lcg = seed.wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    lcg % (max_ms + 1)
}

fn days_until_expiry(
    host: &str,
    port: u16,
    sni_override: Option<&str>,
    timeout_secs: u64,
) -> Result<i64, String> {
    let sni_name = sni_override.unwrap_or(host);

    let mut builder = SslConnector::builder(SslMethod::tls())
        .map_err(|e| format!("SslConnector::builder: {}", e))?;
    builder.set_verify(SslVerifyMode::PEER);

    let connector = builder.build();

    let addr = format!("{}:{}", host, port);
    let tcp = TcpStream::connect(&addr)
        .map_err(|e| format!("TCP connect to {} failed: {}", addr, e))?;
    tcp.set_read_timeout(Some(Duration::from_secs(timeout_secs)))
        .map_err(|e| format!("set_read_timeout: {}", e))?;
    tcp.set_write_timeout(Some(Duration::from_secs(timeout_secs)))
        .map_err(|e| format!("set_write_timeout: {}", e))?;

    let mut stream = connector
        .connect(sni_name, tcp)
        .map_err(|e| format!("TLS handshake with '{}' failed: {}", sni_name, e))?;

    let req = format!(
        "HEAD / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        sni_name
    );
    let _ = stream.write_all(req.as_bytes());
    let mut buf = [0u8; TLS_FLUSH_BUF_BYTES];
    let _ = stream.read(&mut buf);

    let cert: X509 = stream
        .ssl()
        .peer_certificate()
        .ok_or_else(|| "no peer certificate returned".to_string())?;

    let not_after = cert.not_after();
    let now = Asn1Time::days_from_now(0)
        .map_err(|e| format!("Asn1Time::days_from_now: {}", e))?;

    let diff = now
        .diff(not_after)
        .map_err(|e| format!("Asn1Time::diff: {}", e))?;

    Ok(diff.days as i64)
}

fn spawn_commands(
    commands: Vec<String>,
    display: String,
    jitter_ms: u64,
    log: Arc<Logger>,
) {
    thread::spawn(move || {
        if jitter_ms > 0 {
            log.info(&format!(
                "[{}] jitter delay {:.2}h -> commands deferred",
                display,
                jitter_ms as f64 / 3_600_000.0,
            ));
            let mut remaining = jitter_ms;
            while remaining > 0 {
                let step = remaining.min(JITTER_RESOLUTION_MS);
                thread::sleep(Duration::from_millis(step));
                remaining = remaining.saturating_sub(step);
            }
        }
        for cmd in &commands {
            log.info(&format!("[{}] running reaction: {}", display, cmd));
            match Command::new(SHELL).arg(SHELL_FLAG).arg(cmd).output() {
                Ok(out) => {
                    if !out.status.success() {
                        let stderr = String::from_utf8_lossy(&out.stderr);
                        log.warn(&format!(
                            "[{}] command exited {:?}: {}",
                            display,
                            out.status.code(),
                            stderr.trim()
                        ));
                    } else {
                        log.debug(&format!("[{}] command ok (exit 0)", display));
                    }
                }
                Err(e) => {
                    log.error(&format!("[{}] failed to spawn '{}': {}", display, cmd, e));
                }
            }
        }
    });
}

#[cfg(target_os = "openbsd")]
fn sandbox() {
    use pledge::pledge_promises;
    pledge_promises![Stdio Inet Rpath Getpw Unveil Exec Dns Proc].unwrap();
    // use unveil::unveil;
    // TODO
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: tls-identity-manager <policy.yaml> [-d|-w|-q]");
        std::process::exit(1);
    }

    let policy_path = &args[1];
    let log_level = match args.get(2).map(|s| s.as_str()).unwrap_or(FLAG_QUIET) {
        FLAG_DEBUG => LogLevel::Debug,
        FLAG_QUIET => LogLevel::Quiet,
        _          => LogLevel::Warn,
    };

    let log = Arc::new(Logger::new(log_level));

    let policy_text = std::fs::read_to_string(policy_path).unwrap_or_else(|e| {
        eprintln!("ERROR: cannot read policy file '{}': {}", policy_path, e);
        std::process::exit(1);
    });

    let policy: Policy = yaml_serde::from_str(&policy_text).unwrap_or_else(|e| {
        eprintln!("ERROR: failed to parse policy YAML '{}': {}", policy_path, e);
        std::process::exit(1);
    });

    for ep in &policy.endpoints {
        if ep.thresholds.len() > MAX_THRESHOLDS_PER_ENDPOINT {
            eprintln!(
                "ERROR: endpoint '{}' has {} thresholds -> maximum is {}",
                ep.host,
                ep.thresholds.len(),
                MAX_THRESHOLDS_PER_ENDPOINT,
            );
            std::process::exit(1);
        }
    }

    sandbox();

    log.info(&format!(
        "{} v{} started  policy={}  interval={}s  jitter_max={:.2}h  connect_timeout={}s",
        LOG_TAG_PREFIX,
        env!("CARGO_PKG_VERSION"),
        policy_path,
        policy.daemon.interval_seconds,
        policy.daemon.jitter_max_hours,
        policy.daemon.connect_timeout_seconds,
    ));

    for ep in &policy.endpoints {
        log.info(&format!(
            "watching '{}:{}' -> {} threshold(s)",
            ep.host, ep.port, ep.thresholds.len()
        ));
    }

    let mut states: Vec<EndpointState> = policy
        .endpoints
        .iter()
        .map(|ep| EndpointState::new(ep.thresholds.len()))
        .collect();

    loop {
        let loop_start = std::time::Instant::now();

        for (ep_idx, ep) in policy.endpoints.iter().enumerate() {
            let sni = ep.sni.as_deref();
            let display = format!("{}:{}", ep.host, ep.port);

            match days_until_expiry(&ep.host, ep.port, sni, policy.daemon.connect_timeout_seconds) {
                Err(e) => {
                    log.error(&format!("[{}] certificate check failed: {}", display, e));
                    for f in states[ep_idx].fired.iter_mut() { *f = false; }
                }
                Ok(days) => {
                    log.debug(&format!("[{}] {} day(s) until expiry", display, days));

                    for (t_idx, threshold) in ep.thresholds.iter().enumerate() {
                        let trigger_days = threshold.days_before_expiry as i64;
                        let state = &mut states[ep_idx];

                        if days <= trigger_days {
                            if !state.fired[t_idx] {
                                let jitter_ms = random_jitter_millis(policy.daemon.jitter_max_hours);
                                log.warn(&format!(
                                    "[{}] {} day(s) remaining -> {}d threshold reached -> scheduling {} reaction(s) after {:.2}h jitter",
                                    display, days, trigger_days,
                                    threshold.commands.len(),
                                    jitter_ms as f64 / 3_600_000.0,
                                ));
                                spawn_commands(
                                    threshold.commands.clone(),
                                    display.clone(),
                                    jitter_ms,
                                    Arc::clone(&log),
                                );
                                state.fired[t_idx] = true;
                            } else {
                                log.debug(&format!(
                                    "[{}] {} day(s) -> {}d threshold still active (already fired)",
                                    display, days, trigger_days,
                                ));
                            }
                        } else {
                            if state.fired[t_idx] {
                                log.info(&format!(
                                    "[{}] recovered above {}d threshold -> now {} day(s) remaining",
                                    display, trigger_days, days
                                ));
                                state.fired[t_idx] = false;
                            }
                        }
                    }
                }
            }
        }

        let elapsed_ms = loop_start.elapsed().as_millis();
        let interval_ms = (policy.daemon.interval_seconds * MILLIS_PER_SEC) as u128;
        let sleep_ms = interval_ms.saturating_sub(elapsed_ms);

        log.debug(&format!("cycle completed {}ms -> sleeping {}ms", elapsed_ms, sleep_ms));
        thread::sleep(Duration::from_millis(sleep_ms as u64));
    }
}
