#![forbid(unsafe_code)]
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, Duration};
use chrono::{SecondsFormat, Utc};
use uuid::Uuid;
use pledge::pledge_promises;
use unveil::unveil;
use std::time::SystemTime;
use std::io;
use std::env;
use std::process;

async fn retry_connect(txid: &str, address: &str, max_retries: u32, delay: Duration) -> io::Result<TcpStream> {
    let mut retries = 0;

    while retries < max_retries {
        match TcpStream::connect(address).await {
            Ok(stream) => {
                return Ok(stream);
            }
            Err(e) => {
                retries += 1;
                let ts = chrono::DateTime::<Utc>::from(SystemTime::now()).to_rfc3339_opts(SecondsFormat::Millis, true);
                println!("{ts} - {txid} - ERROR: Failed to connect (attempt {} of {}) - {:?}", retries, max_retries, e);
                if retries < max_retries {
                    sleep(delay).await;
                } else {
                    return Err(e);
                }
            }
        }
    }

   Err(io::Error::other("max retries reached"))

}

async fn health(addr: &str) -> bool {
    TcpStream::connect(addr).await.is_ok()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    pledge_promises![Stdio Inet Unveil].unwrap();
    let bogonconfig = "/0";
    unveil(&bogonconfig, "r")
      .or_else(unveil::Error::ignore_platform)
      .unwrap();
    let listenerstr = match env::var("LISTENER") {
        Ok(val) => val,
        Err(_) => {
            println!("Set the environment variable LISTENER to the endpoint kiaproxy is to listen on.");
            println!("Example:");
            println!("  export LISTENER=0.0.0.0:443");
            process::exit(1);
        }

    };
    let srversstr = match env::var("SERVERS") {
        Ok(val) => val,
        Err(_) => {
            println!("Set the environment variable SERVERS to the ordered list of backends for kiaproxy to proxy and route to.");
            println!("Example:");
            println!("  export SERVERS=192.168.1.120:443,192.168.1.121:443,192.168.1.122:443");
            process::exit(1);
        }

    };

    let listener = TcpListener::bind(listenerstr).await?;
    let servers: Vec<String> = srversstr
        .split(',')
        .map(|s| s.trim().to_string())
        .collect();

    let strt = chrono::DateTime::<Utc>::from(SystemTime::now()).to_rfc3339_opts(SecondsFormat::Millis, true);
    println!("{strt} - INIT - INFO: kiaproxy v0.1.3 TCP load balancer listening on {:?} with backends {:?}", listener, servers);

    loop {
        let (mut inbound, addr) = listener.accept().await?;
        let servers = servers.clone();
        tokio::spawn(async move {
            let txid = Uuid::new_v4().to_string();
            let max_retries = 28;
            let delay = Duration::from_secs(1);

            let mut selected = servers[0].clone();

            for srv in servers {
                let ts = chrono::DateTime::<Utc>::from(SystemTime::now()).to_rfc3339_opts(SecondsFormat::Millis, true);
                println!("{ts} - {txid} - INFO: checking for backend {srv}");

                if health(&srv).await {
                    selected = srv.clone();
                    let ts = chrono::DateTime::<Utc>::from(SystemTime::now()).to_rfc3339_opts(SecondsFormat::Millis, true);
                    println!("{ts} - {txid} - INFO: selected first online backend {srv}");
                    break;
                }
            }

            match retry_connect(&txid, &selected, max_retries, delay).await {
                Ok(mut stream) => {
                    let ts = chrono::DateTime::<Utc>::from(SystemTime::now()).to_rfc3339_opts(SecondsFormat::Millis, true);
                    println!("{ts} - {txid} - INFO: {addr} connecting to backend {:?}", stream.peer_addr());

                    if let Err(e) = tokio::io::copy_bidirectional(&mut inbound, &mut stream).await {
                        let ts = chrono::DateTime::<Utc>::from(SystemTime::now()).to_rfc3339_opts(SecondsFormat::Millis, true);
                        println!("{ts} - {txid} - INFO: connection drop {addr} - {e}");
                    }
                }
                Err(e) => {
                    let ts = chrono::DateTime::<Utc>::from(SystemTime::now()).to_rfc3339_opts(SecondsFormat::Millis, true);
                    println!("{ts} - {txid} - ERROR: Failed to connect after {} retries for {addr} - {:?}", max_retries, e);
                }
            }
        });
    }
}
