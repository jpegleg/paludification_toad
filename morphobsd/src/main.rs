use std::path::Path;
use std::fs::File;
use std::io::Read;
use std::env;

use actix_web::{
    App, get, Responder, HttpRequest, HttpResponse, HttpServer, http::header::ContentType, middleware, web,
};
use actix_files::{Files, NamedFile};
use log::debug;
use notify::{Event, RecursiveMode, Watcher as _};
use openssl::{
    pkey::{PKey, Private},
    ssl::{SslAcceptor, SslMethod},
};
use tokio::sync::mpsc;
use unveil::unveil;
use pledge::pledge_promises;
use chrono::prelude::*;

use actix_web_lab::middleware::RedirectHttps;
use actix_web_lab::header::StrictTransportSecurity;

#[derive(Debug)]
struct TlsUpdated;

#[get("/")]
async fn index(req: HttpRequest) -> HttpResponse {
    debug!("{req:?}");
    NamedFile::open_async("./static/index.html").await
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> eyre::Result<()> {

    pledge_promises![Stdio Inet Rpath Getpw Unveil].unwrap();

    let webpath = "./static/";

    unveil(webpath, "r")
      .or_else(unveil::Error::ignore_platform)
      .unwrap();

    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));

    let (reload_tx, mut reload_rx) = mpsc::channel(1);

    let mut file_watcher =
        notify::recommended_watcher(move |res: notify::Result<Event>| match res {
            Ok(ev) => {
                log::info!("files changed: {:?}", ev.paths);
                reload_tx.blocking_send(TlsUpdated).unwrap();
            }
            Err(err) => {
                log::error!("file watch error: {err}");
            }
        })
        .unwrap();


    let certpath = "/opt/morpho/cert.pem";
    let keypath = "/opt/morpho/key.pem";

    unveil(certpath, "r")
      .or_else(unveil::Error::ignore_platform)
      .unwrap();
    unveil(keypath, "r")
      .or_else(unveil::Error::ignore_platform)
      .unwrap();

    file_watcher
      .watch(Path::new("/opt/morpho/cert.pem"), RecursiveMode::NonRecursive)
      .unwrap();
    file_watcher
      .watch(Path::new("/opt/morpho/key.pem"), RecursiveMode::NonRecursive)
      .unwrap();

    let readi: DateTime<Utc> = Utc::now();
    log::info!("morphobsd initialized at {} >>> starting HTTPS server on port 3443 using openssl (libressl)", readi);

    loop {
        
        let mut builder = SslAcceptor::mozilla_modern_v5(SslMethod::tls()).unwrap();

        builder.set_private_key(&load_encrypted_private_key()).unwrap();
        builder.set_certificate_chain_file("/opt/morpho/cert.pem").unwrap();
        
        let mut server = HttpServer::new(|| {
            App::new()
              .wrap(RedirectHttps::default())
              .wrap(RedirectHttps::with_hsts(StrictTransportSecurity::recommended()))
              .wrap(middleware::DefaultHeaders::new().add(("x-content-type-options", "nosniff")))
              .wrap(middleware::DefaultHeaders::new().add(("x-frame-options", "SAMEORIGIN")))
              .wrap(middleware::DefaultHeaders::new().add(("x-xss-protection", "1; mode=block")))
              .wrap(middleware::Logger::new("%{txid}e %a -> HTTP %s %r size: %b server-time: %T %{Referer}i %{User-Agent}i"))
              .service(index)
              .service(Files::new("/", "static"))
        })
        .workers(2)
        .bind_openssl("0.0.0.0:3443", builder)?
        .bind("0.0.0.0:8080")?
        .run();

        let server_hnd = server.handle();

        tokio::select! {
            res = &mut server => {
                log::info!("server shutdown arrived");
                res?;
                break;
            },

            Some(_) = reload_rx.recv() => {
                log::info!("TLS cert or key updated");
                drop(server_hnd.stop(true));
                server.await?;
                continue;
            }
        }
    }

    Ok(())
}

fn load_encrypted_private_key() -> PKey<Private> {
    let keypath = "/opt/morpho/key.pem";

    unveil(keypath, "r")
      .or_else(unveil::Error::ignore_platform)
      .unwrap();

    let mut file = File::open("/opt/morpho/key.pem").unwrap();
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).expect("Failed to read file");

    let binding = env::var("MORPHOP").expect("failed to read MORPHOP");
    let pem_password = binding.as_bytes();
    PKey::private_key_from_pem_passphrase(&buffer, pem_password).unwrap()
}
