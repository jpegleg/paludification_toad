use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use actix_files::NamedFile;
use actix_session::{
    config::PersistentSession,
    storage::CookieSessionStore,
    SessionMiddleware,
    SessionExt,
};
use actix_web::{
    cookie::{self, Key},
    get,
    middleware,
    middleware::Condition,
    web,
    App, HttpRequest, HttpServer,
};
use actix_web_lab::header::StrictTransportSecurity;
use actix_web_lab::middleware::RedirectHttps;
use chrono::prelude::*;
use log::LevelFilter;
use openssl::{
    pkey::{PKey, Private},
    ssl::{SslAcceptor, SslMethod},
};
use serde::Deserialize;
use unveil::unveil;
use pledge::pledge_promises;

const PROTECTED_HEADERS: &[&str] = &[
    "x-content-type-options",
    "x-frame-options",
    "x-xss-protection",
];

const DEFAULT_TTL_HOURS: i64 = 2;

#[derive(Deserialize)]
struct Config {
    workers: Option<usize>,
    web: WebConfig,
    listeners: Vec<ListenerConfig>,
    pkipath: String
}

#[derive(Deserialize, Clone)]
struct WebConfig {
    static_dir: String,
    #[serde(default)]
    rewrites: HashMap<String, String>,
    #[serde(default)]
    session: SessionConfig,
    #[serde(default)]
    headers: HashMap<String, String>,
}

#[derive(Deserialize, Clone)]
struct PageConfig {
    index_first_visit: String,
    index_returning_visit: Option<String>,
    session_age_gt_value: Option<String>,
    session_age_lte_value: Option<String>,
}

#[derive(Deserialize, Clone)]
struct SessionSecureConfig {
    key_path: String,
}

#[derive(Deserialize, Clone)]
struct HeaderRequirement {
    name: String,
    value: Option<String>,
}

#[derive(Deserialize, Clone)]
struct Ipv4Requirement {
    addresses: Vec<String>,
}

#[derive(Deserialize, Clone)]
struct Ipv6Requirement {
    addresses: Vec<String>,
}

#[derive(Deserialize, Clone)]
struct SessionRequiredConfig {
    header: Option<HeaderRequirement>,
    ipv4: Option<Ipv4Requirement>,
    ipv6: Option<Ipv6Requirement>,
}

#[derive(Deserialize, Clone)]
struct SessionConfig {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    ttl_hours: i64,
    #[serde(default)]
    secure_cookie: bool,
    value: Option<i16>,
    secure: Option<SessionSecureConfig>,
    required: Option<SessionRequiredConfig>,
    pages: Option<PageConfig>,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            ttl_hours: DEFAULT_TTL_HOURS,
            secure_cookie: false,
            value: None,
            secure: None,
            required: None,
            pages: None,
        }
    }
}

#[derive(Deserialize, Clone)]
struct ListenerConfig {
    port: u16,
    tls: Option<TlsConfig>,
}

#[derive(Deserialize, Clone)]
struct TlsConfig {
    cert_path: String,
    key_path: String,
}

#[derive(Deserialize)]
struct Age {
    pub fage: i32,
}

#[derive(Clone, Copy)]
struct Ipv4Cidr {
    network: u32,
    prefix_len: u32,
}

impl Ipv4Cidr {
    fn parse(s: &str) -> Result<Self, String> {
        if let Some((addr_part, prefix_part)) = s.split_once('/') {
            let addr: Ipv4Addr = addr_part
                .trim()
                .parse()
                .map_err(|_| format!("invalid IPv4 address '{}' in CIDR '{}'", addr_part, s))?;
            let prefix_len: u32 = prefix_part
                .trim()
                .parse()
                .map_err(|_| format!("invalid prefix length '{}' in CIDR '{}'", prefix_part, s))?;
            if prefix_len > 32 {
                return Err(format!("prefix length out of range in CIDR '{}'", s));
            }
            let mask = if prefix_len == 0 {
                0u32
            } else {
                u32::MAX << (32 - prefix_len)
            };
            let network = u32::from(addr) & mask;
            Ok(Self {
                network,
                prefix_len,
            })
        } else {
            let addr: Ipv4Addr = s
                .trim()
                .parse()
                .map_err(|_| format!("invalid IPv4 address '{}'", s))?;
            Ok(Self {
                network: u32::from(addr),
                prefix_len: 32,
            })
        }
    }

    fn contains(&self, addr: Ipv4Addr) -> bool {
        let mask = if self.prefix_len == 0 {
            0u32
        } else {
            u32::MAX << (32 - self.prefix_len)
        };
        (u32::from(addr) & mask) == self.network
    }
}

#[derive(Clone, Copy)]
struct Ipv6Cidr {
    network: u128,
    prefix_len: u32,
}

impl Ipv6Cidr {
    fn parse(s: &str) -> Result<Self, String> {
        if let Some((addr_part, prefix_part)) = s.split_once('/') {
            let addr: Ipv6Addr = addr_part
                .trim()
                .parse()
                .map_err(|_| format!("invalid IPv6 address '{}' in CIDR '{}'", addr_part, s))?;
            let prefix_len: u32 = prefix_part
                .trim()
                .parse()
                .map_err(|_| format!("invalid prefix length '{}' in CIDR '{}'", prefix_part, s))?;
            if prefix_len > 128 {
                return Err(format!("prefix length out of range in CIDR '{}'", s));
            }
            let mask = if prefix_len == 0 {
                0u128
            } else {
                u128::MAX << (128 - prefix_len)
            };
            let network = u128::from(addr) & mask;
            Ok(Self {
                network,
                prefix_len,
            })
        } else {
            let addr: Ipv6Addr = s
                .trim()
                .parse()
                .map_err(|_| format!("invalid IPv6 address '{}'", s))?;
            Ok(Self {
                network: u128::from(addr),
                prefix_len: 128,
            })
        }
    }

    fn contains(&self, addr: Ipv6Addr) -> bool {
        let mask = if self.prefix_len == 0 {
            0u128
        } else {
            u128::MAX << (128 - self.prefix_len)
        };
        (u128::from(addr) & mask) == self.network
    }
}

#[allow(unused)]
#[derive(Clone)]
struct ResolvedSession {
    enabled: bool,
    ttl_hours: i64,
    secure_cookie: bool,
    age_value: Option<i16>,
    signing_key: Option<Vec<u8>>,
    required_header: Option<HeaderRequirement>,
    required_ipv4: Option<Vec<Ipv4Cidr>>,
    required_ipv6: Option<Vec<Ipv6Cidr>>,
    pages: Option<PageConfig>,
}

#[derive(Clone)]
struct AppState {
    static_dir: PathBuf,
    rewrites: HashMap<String, String>,
    session: ResolvedSession,
}

fn validate_config(config: &Config) -> Result<(), String> {
    let sess = &config.web.session;

    if !sess.enabled {
        if sess.pages.is_some() {
            return Err(
                "Sessions have been disabled so the `pages` block cannot be included in \
                 morph.yaml unless session is also enabled."
                    .into(),
            );
        }
        if sess.value.is_some() {
            return Err(
                "Sessions have been disabled so `session.value` cannot be included in \
                 morph.yaml unless session is also enabled."
                    .into(),
            );
        }
        if sess.secure.is_some() {
            return Err(
                "Sessions have been disabled so `session.secure` cannot be included in \
                 morph.yaml unless session is also enabled."
                    .into(),
            );
        }
        if sess.required.is_some() {
            return Err(
                "Sessions have been disabled so `session.required` cannot be included in \
                 morph.yaml unless session is also enabled."
                    .into(),
            );
        }
        return Ok(());
    }

    if sess.value.is_none() {
        return Err("`session.value` is required when sessions are enabled. \
             Set it to an integer between 0 and 32767."
            .into());
    }

    let pages = sess
        .pages
        .as_ref()
        .ok_or("The `session.pages` block is required when sessions are enabled.")?;

    let mut missing: Vec<&str> = Vec::new();
    if pages.index_returning_visit.is_none() {
        missing.push("index_returning_visit");
    }
    if pages.session_age_gt_value.is_none() {
        missing.push("session_age_gt_value");
    }
    if pages.session_age_lte_value.is_none() {
        missing.push("session_age_lte_value");
    }
    if !missing.is_empty() {
        return Err(format!(
            "Sessions are enabled but the following required page(s) are missing from \
             `session.pages` in morph.yaml: {}.",
            missing.join(", ")
        ));
    }
    if let Some(sec) = &sess.secure
        && !Path::new(&sec.key_path).is_file()
    {
        return Err(format!(
            "`session.secure.key_path` '{}' does not exist or is not a file.",
            sec.key_path
        ));
    }

    if let Some(required) = &sess.required {
        if let Some(ipv4) = &required.ipv4 {
            if ipv4.addresses.is_empty() {
                return Err(
                    "`session.required.ipv4.addresses` must contain at least one address or \
                     CIDR range."
                        .into(),
                );
            }
            for entry in &ipv4.addresses {
                Ipv4Cidr::parse(entry).map_err(|e| {
                    format!("invalid entry in `session.required.ipv4.addresses`: {}", e)
                })?;
            }
        }

        if let Some(ipv6) = &required.ipv6 {
            if ipv6.addresses.is_empty() {
                return Err(
                    "`session.required.ipv6.addresses` must contain at least one address or \
                     CIDR range."
                        .into(),
                );
            }
            for entry in &ipv6.addresses {
                Ipv6Cidr::parse(entry).map_err(|e| {
                    format!("invalid entry in `session.required.ipv6.addresses`: {}", e)
                })?;
            }
        }
    }

    Ok(())
}

fn load_signing_key(path: &str) -> Vec<u8> {
    let mut f =
        File::open(path).unwrap_or_else(|e| panic!("cannot open signing key '{}': {}", path, e));
    let mut pem_bytes = Vec::new();
    f.read_to_end(&mut pem_bytes)
        .unwrap_or_else(|e| panic!("cannot read signing key '{}': {}", path, e));
    pem_bytes
}

fn required_header_satisfied(req: &HttpRequest, requirement: &Option<HeaderRequirement>) -> bool {
    let Some(req_cfg) = requirement else {
        return true;
    };

    let header_val = req
        .headers()
        .get(&req_cfg.name)
        .and_then(|v| v.to_str().ok());

    match (&header_val, &req_cfg.value) {
        (None, _) => false,
        (Some(_), None) => true,
        (Some(actual), Some(expected)) => actual == expected,
    }
}

fn required_ip_satisfied(
    req: &HttpRequest,
    allowed_v4: &Option<Vec<Ipv4Cidr>>,
    allowed_v6: &Option<Vec<Ipv6Cidr>>,
) -> bool {
    if allowed_v4.is_none() && allowed_v6.is_none() {
        return true;
    }

    let peer_addr = match req.peer_addr() {
        Some(addr) => addr.ip(),
        None => return false,
    };

    match peer_addr {
        IpAddr::V4(v4) => {
            if let Some(allowed) = allowed_v4
                && allowed.iter().any(|cidr| cidr.contains(v4))
            {
                return true;
            }
            if let Some(allowed) = allowed_v6 {
                let mapped = v4.to_ipv6_mapped();
                if allowed.iter().any(|cidr| cidr.contains(mapped)) {
                    return true;
                }
            }
            false
        }
        IpAddr::V6(v6) => {
            if let Some(allowed) = allowed_v6
                && allowed.iter().any(|cidr| cidr.contains(v6))
            {
                return true;
            }
            if let Some(allowed) = allowed_v4
                && let Some(v4) = v6.to_ipv4_mapped()
                && allowed.iter().any(|cidr| cidr.contains(v4))
            {
                return true;
            }
            false
        }
    }
}

#[get("/session")]
async fn newcook(
    req: HttpRequest,
    info: web::Query<Age>,
    state: web::Data<Arc<AppState>>,
) -> actix_web::Result<NamedFile> {
    if !required_header_satisfied(&req, &state.session.required_header) {
        return Err(actix_web::error::ErrorForbidden(
            "Forbidden, your request was not authorized.",
        ));
    }

    if !required_ip_satisfied(
        &req,
        &state.session.required_ipv4,
        &state.session.required_ipv6,
    ) {
        return Err(actix_web::error::ErrorForbidden(
            "Forbidden, your request was not authorized.",
        ));
    }

    let sess = &state.session;
    let threshold = sess.age_value.unwrap() as i32;
    let pages = sess.pages.as_ref().unwrap();

    if info.fage > threshold {
        if sess.enabled {
            let session = req.get_session();
            let counter = session.get::<i32>("counter").ok().flatten().unwrap_or(0) + 1;
            let _ = session.insert("counter", counter);
        }
        open_configured_file(
            &state.static_dir,
            pages.session_age_gt_value.as_deref().unwrap(),
        )
        .await
    } else {
        open_configured_file(
            &state.static_dir,
            pages.session_age_lte_value.as_deref().unwrap(),
        )
        .await
    }
}

#[get("/")]
async fn index(req: HttpRequest, state: web::Data<Arc<AppState>>) -> actix_web::Result<NamedFile> {
    let sess = &state.session;
    if sess.enabled {
        let pages = sess.pages.as_ref().unwrap();
        let session = req.get_session();
        if let Ok(Some(count)) = session.get::<i32>("counter") {
            let _ = session.insert("counter", count + 1);
            return open_configured_file(
                &state.static_dir,
                pages.index_returning_visit.as_deref().unwrap(),
            )
            .await;
        }
        return open_configured_file(&state.static_dir, &pages.index_first_visit).await;
    }

    open_path_under_static_root(&state.static_dir, "/index.html").await
}

async fn static_with_rewrites(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
) -> actix_web::Result<NamedFile> {
    let request_path = req.path();
    let rewritten = state
        .rewrites
        .get(request_path)
        .map(String::as_str)
        .unwrap_or(request_path);

    if !state.session.enabled {
        return open_path_under_static_root(&state.static_dir, rewritten).await;
    }

    if is_public_path(
        request_path,
        rewritten,
        state.session.pages.as_ref().unwrap(),
    ) {
        return open_path_under_static_root(&state.static_dir, rewritten).await;
    }

    let session = req.get_session();
    if let Ok(Some(count)) = session.get::<i32>("counter") {
        let _ = session.insert("counter", count + 1);
        return open_path_under_static_root(&state.static_dir, rewritten).await;
    }

    let first = &state.session.pages.as_ref().unwrap().index_first_visit;
    open_configured_file(&state.static_dir, first).await
}

fn is_public_path(request_path: &str, rewritten_path: &str, pages: &PageConfig) -> bool {
    let lte = pages.session_age_lte_value.as_deref().unwrap_or("");
    path_matches_page(request_path, &pages.index_first_visit)
        || path_matches_page(rewritten_path, &pages.index_first_visit)
        || path_matches_page(request_path, lte)
        || path_matches_page(rewritten_path, lte)
        || request_path == "/"
}

fn path_matches_page(path: &str, page: &str) -> bool {
    normalize_url_like(path) == normalize_url_like(page)
}

fn normalize_url_like(input: &str) -> String {
    let trimmed = input.trim();
    if trimmed.is_empty() || trimmed == "/" {
        return "/".to_string();
    }
    let mut s = if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{}", trimmed)
    };
    while s.len() > 1 && s.ends_with('/') {
        s.pop();
    }
    s
}

fn load_encrypted_private_key(mut config_key: File) -> PKey<Private> {
    let mut buffer = Vec::new();
    config_key.read_to_end(&mut buffer).expect("Failed to read file");
    let binding = env::var("MORPHOP").expect("failed to read MORPHOP");
    let pem_password = binding.as_bytes();
    PKey::private_key_from_pem_passphrase(&buffer, pem_password).unwrap()
}

fn sanitize_relative_path(input: &str) -> Option<PathBuf> {
    let trimmed = input.trim_start_matches('/');
    let path = Path::new(trimmed);
    let mut clean = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => clean.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    Some(clean)
}

async fn open_configured_file(
    static_dir: &Path,
    relative_path: &str,
) -> actix_web::Result<NamedFile> {
    open_path_under_static_root(static_dir, relative_path).await
}

async fn open_path_under_static_root(
    static_dir: &Path,
    relative_path: &str,
) -> actix_web::Result<NamedFile> {
    let safe_rel_path = sanitize_relative_path(relative_path)
        .ok_or_else(|| actix_web::error::ErrorBadRequest("invalid configured path"))?;

    let full_path = static_dir.join(safe_rel_path);
    if full_path.is_file() {
        return NamedFile::open_async(full_path)
            .await
            .map_err(|_| actix_web::error::ErrorNotFound("file not found"));
    }
    if full_path.is_dir() {
        let index_path = full_path.join("index.html");
        if index_path.is_file() {
            return NamedFile::open_async(index_path)
                .await
                .map_err(|_| actix_web::error::ErrorNotFound("file not found"));
        }
    }
    Err(actix_web::error::ErrorNotFound("file not found"))
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> eyre::Result<()> {
    pledge_promises![Stdio Inet Rpath Getpw Unveil].unwrap();

    env_logger::Builder::new()
        .filter_level(LevelFilter::Info)
        .filter_module("actix_server", LevelFilter::Warn)
        .format(|buf, record| writeln!(buf, "{}", record.args()))
        .init();

    let readi = Utc::now().to_rfc3339();
    let runid = env::var("RUN_ID").unwrap_or("kiabluejaybsd".to_string());

    log::info!(
        "{{\"event\":\"initialized version 0.1.701\",\"time\":\"{}\",\"run_id\":\"{}\"}}",
        readi,
        runid
    );

    let config_file = File::open("morph.yaml").expect("Failed to open morph.yaml");
    let config: Config = serde_yml::from_reader(config_file).expect("failed to read morph.yaml");
    let webpath = config.web.static_dir.clone();

    unveil(webpath, "r")
      .or_else(unveil::Error::ignore_platform)
      .unwrap();

    let certpath = &tls.pki_path.clone();

    unveil(certpath, "r")
      .or_else(unveil::Error::ignore_platform)
      .unwrap();

    let skipped: Vec<String> = config
        .web
        .headers
        .keys()
        .filter(|k| PROTECTED_HEADERS.contains(&k.to_lowercase().as_str()))
        .cloned()
        .collect();

    if !skipped.is_empty() {
        log::info!(
            "{{\"event\":\"protected_headers_skipped\",\"headers\":\"{}\",\"run_id\":\"{}\"}}",
            skipped.join(", "),
            runid
        );
    }
    
    let custom_headers: Vec<(String, String)> = config
        .web
        .headers
        .iter()
        .filter(|(k, _)| !PROTECTED_HEADERS.contains(&k.to_lowercase().as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    
    let raw_sess = &config.web.session;
    let signing_key: Option<Vec<u8>> = raw_sess
        .secure
        .as_ref()
        .map(|s| load_signing_key(&s.key_path));

    let required_ipv4: Option<Vec<Ipv4Cidr>> = raw_sess
        .required
        .as_ref()
        .and_then(|r| r.ipv4.as_ref())
        .map(|ipv4| {
            ipv4.addresses
                .iter()
                .map(|s| Ipv4Cidr::parse(s).expect("invalid ipv4 address in morph.yaml"))
                .collect()
        });

    let required_ipv6: Option<Vec<Ipv6Cidr>> = raw_sess
        .required
        .as_ref()
        .and_then(|r| r.ipv6.as_ref())
        .map(|ipv6| {
            ipv6.addresses
                .iter()
                .map(|s| Ipv6Cidr::parse(s).expect("invalid ipv6 address in morph.yaml"))
                .collect()
        });

    let resolved_session = ResolvedSession {
        enabled: raw_sess.enabled,
        ttl_hours: if raw_sess.ttl_hours == 0 {
            DEFAULT_TTL_HOURS
        } else {
            raw_sess.ttl_hours
        },
        secure_cookie: raw_sess.secure_cookie,
        age_value: raw_sess.value,
        signing_key: signing_key.clone(),
        required_header: raw_sess.required.as_ref().and_then(|r| r.header.clone()),
        required_ipv4,
        required_ipv6,
        pages: raw_sess.pages.clone(),
    };
    
    let state = Arc::new(AppState {
        static_dir: PathBuf::from(config.web.static_dir.clone()),
        rewrites: config.web.rewrites.clone(),
        session: resolved_session.clone(),
    });

    let readi = Utc::now().to_rfc3339();
    log::info!(
        "{{\"event\":\"configuration_loaded\",\"workers\":\"{}\",\"listeners\":\"{}\",\"timestamp\":\"{}\",\"run_id\":\"{}\"}}",
        config.workers.unwrap_or(2),
        config.listeners.len(),
        readi,
        runid
    );

    let session_enabled = resolved_session.enabled;
    let session_ttl_hours = resolved_session.ttl_hours;
    let secure_cookie = resolved_session.secure_cookie;
    let workers = config.workers.unwrap_or(2);
    let cookie_key = signing_key
        .map(|bytes| Key::from(&bytes))
        .unwrap_or_else(|| Key::from(&[0; 64]));

    let mut server = HttpServer::new(move || {
        let mut custom_default_headers = middleware::DefaultHeaders::new();
        for (name, value) in &custom_headers {
            custom_default_headers = custom_default_headers.add((name.as_str(), value.as_str()));
        }

        App::new()
            .app_data(web::Data::new(state.clone()))
            .wrap(RedirectHttps::default())
            .wrap(RedirectHttps::with_hsts(
                StrictTransportSecurity::recommended(),
            ))
            .wrap(
                middleware::DefaultHeaders::new().add(("x-content-type-options", "nosniff")),
            )
            .wrap(middleware::DefaultHeaders::new().add(("x-frame-options", "SAMEORIGIN")))
            .wrap(
                middleware::DefaultHeaders::new().add(("x-xss-protection", "1; mode=block")),
            )
            .wrap(custom_default_headers)
            .wrap(middleware::Logger::new(
                "{\"event\":\"ingress_http\",\"client_address\":\"%a\",\"request_start_time\":\"%t\",\"HTTP\":\"%s\",\"http_request_first_line\":\"%r\",\"size\":\"%b\",\"server_time\":\"%T\",\"referer\":\"%{Referer}i\",\"user_agent\":\"%{User-Agent}i\",\"run_id\":\"%{RUN_ID}e\"}",
            ))
            .wrap(Condition::new(
                session_enabled,
                SessionMiddleware::builder(
                    CookieSessionStore::default(),
                    cookie_key.clone(),
                )
                .cookie_secure(secure_cookie)
                .session_lifecycle(
                    PersistentSession::default()
                        .session_ttl(cookie::time::Duration::hours(session_ttl_hours)),
                )
                .build(),
            ))
            .service(index)
            .service(newcook)
            .route("/{tail:.*}", web::get().to(static_with_rewrites))
    })
    .workers(workers);

    for listener in &config.listeners.clone() {
        let addr = format!("0.0.0.0:{}", listener.port);

        match &listener.tls {
            Some(_tls) => {
                let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
                let key_file = File::open(<std::option::Option<TlsConfig> as Clone>::clone(&listener.tls).unwrap().key_path.clone()).unwrap();
                builder.set_private_key(&load_encrypted_private_key(key_file)).unwrap();
                builder.set_certificate_chain_file(&<std::option::Option<TlsConfig> as Clone>::clone(&listener.tls).unwrap().cert_path.clone()).unwrap();
                server = server.bind_openssl(&addr, builder)?;
                let listeni = Utc::now().to_rfc3339();
                log::info!(
                    "{{\"event\":\"server_listening_https\",\"addr\":\"{}\",\"time\":\"{}\",\"run_id\":\"{}\"}}",
                    addr,
                    listeni,
                    runid
                );
            }
            None => {
                server = server.bind(&addr)?;
                let listeni = Utc::now().to_rfc3339();
                log::info!(
                    "{{\"event\":\"server_listening_http\",\"addr\":\"{}\",\"time\":\"{}\",\"run_id\":\"{}\"}}",
                    addr,
                    listeni,
                    runid
                );
            }
        }
    }

    server.run().await?;

    let stopi = Utc::now().to_rfc3339();
    log::info!(
        "{{\"event\":\"server_shutdown_arrived\",\"time\":\"{}\",\"run_id\":\"{}\"}}",
        stopi,
        runid
    );

    Ok(())
}
