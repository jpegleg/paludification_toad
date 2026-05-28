use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

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
    pages: PageConfig,
    #[serde(default)]
    session: SessionConfig,
    #[serde(default)]
    headers: HashMap<String, String>,
}

#[derive(Deserialize, Clone)]
struct PageConfig {
    index_first_visit: String,
    index_returning_visit: String,
    session_age_gt_20: String,
    session_age_lte_20: String,
}

#[derive(Deserialize, Clone)]
struct SessionConfig {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    ttl_hours: i64,
    #[serde(default)]
    secure_cookie: bool,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            ttl_hours: DEFAULT_TTL_HOURS,
            secure_cookie: false,
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

#[derive(Clone)]
struct AppState {
    static_dir: PathBuf,
    rewrites: HashMap<String, String>,
    pages: PageConfig,
    session: SessionConfig,
}

#[get("/session")]
async fn newcook(
    req: HttpRequest,
    info: web::Query<Age>,
    state: web::Data<Arc<AppState>>,
) -> actix_web::Result<NamedFile> {
    let id = info.fage;
    if id > 20 {
        if state.session.enabled {
            let session = req.get_session();
            let counter = session.get::<i32>("counter").ok().flatten().unwrap_or(0) + 1;
            let _ = session.insert("counter", counter);
        }

        open_configured_file(&state.static_dir, &state.pages.session_age_gt_20).await
    } else {
        open_configured_file(&state.static_dir, &state.pages.session_age_lte_20).await
    }
}

#[get("/")]
async fn index(req: HttpRequest, state: web::Data<Arc<AppState>>) -> actix_web::Result<NamedFile> {
    if state.session.enabled {
        let session = req.get_session();
        if let Ok(Some(count)) = session.get::<i32>("counter") {
            let _ = session.insert("counter", count + 1);
            return open_configured_file(&state.static_dir, &state.pages.index_returning_visit)
                .await;
        }

        return open_configured_file(&state.static_dir, &state.pages.index_first_visit).await;
    }

    open_configured_file(&state.static_dir, &state.pages.index_first_visit).await
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

    if is_public_path(request_path, rewritten, &state.pages) {
        return open_path_under_static_root(&state.static_dir, rewritten).await;
    }

    let session = req.get_session();
    if let Ok(Some(count)) = session.get::<i32>("counter") {
        let _ = session.insert("counter", count + 1);
        return open_path_under_static_root(&state.static_dir, rewritten).await;
    }

    open_configured_file(&state.static_dir, &state.pages.index_first_visit).await
}

fn is_public_path(request_path: &str, rewritten_path: &str, pages: &PageConfig) -> bool {
    path_matches_page(request_path, &pages.index_first_visit)
        || path_matches_page(rewritten_path, &pages.index_first_visit)
        || path_matches_page(request_path, &pages.session_age_lte_20)
        || path_matches_page(rewritten_path, &pages.session_age_lte_20)
        || request_path == "/"
}

fn path_matches_page(path: &str, page: &str) -> bool {
    let normalized_path = normalize_url_like(path);
    let normalized_page = normalize_url_like(page);
    normalized_path == normalized_page
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
        "{{\"event\":\"initialized version 0.1.700\",\"time\":\"{}\",\"run_id\":\"{}\"}}",
        readi,
        runid
    );

    let config_file = File::open("morph.yaml").expect("Failed to open morph.yaml");
    let config: Config = serde_yml::from_reader(config_file).expect("failed to read morph.yaml");
    let webpath = config.web.static_dir.clone();

    unveil(webpath, "r")
      .or_else(unveil::Error::ignore_platform)
      .unwrap();

    let certpath = config.pkipath.clone();

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

    let state = Arc::new(AppState {
        static_dir: PathBuf::from(config.web.static_dir.clone()),
        rewrites: config.web.rewrites.clone(),
        pages: config.web.pages.clone(),
        session: config.web.session.clone(),
    });

    let readi = Utc::now().to_rfc3339();
    log::info!(
        "{{\"event\":\"configuration_loaded\",\"workers\":\"{}\",\"listeners\":\"{}\",\"timestamp\":\"{}\",\"run_id\":\"{}\"}}",
        config.workers.unwrap_or(2),
        config.listeners.len(),
        readi,
        runid
    );

    let session_enabled = state.session.enabled;
    let session_ttl_hours = state.session.ttl_hours;
    let secure_cookie = state.session.secure_cookie;
    let workers = config.workers.unwrap_or(2);

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
                SessionMiddleware::builder(CookieSessionStore::default(), Key::from(&[0; 64]))
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
