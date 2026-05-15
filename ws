use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task;
use std::env;
use std::fs::File;
use std::io::{self as stdio, Read};
use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::time::Duration;
use yaml_rust::{YamlLoader, Yaml};

const BUFLEN: usize = 8196 * 8;
const TIMEOUT_SECONDS: u64 = 60;

static IP: &str = "0.0.0.0";
static mut PORT: u16 = 10015;
static mut RESPONSE: Vec<u8> = Vec::new();
static mut DEFAULT_HOSTS: Vec<String> = Vec::new();

fn load_custom_status() -> String {
    let response_file = "/usr/bin/custom_response.txt";
    let default_status = "HTTP/1.1 101 <p style=\"text-align:center;\"><big><b><font color=\"#30e528\">SCRIPT&nbsp;</font><font color=\"#ffffffff\">BY&nbsp;</font><font color=\"#f9cf10\">CHAPEEY</font>&nbsp;<small>(<font color=\"blue\">Telegram</font>: t.me/chapeey) </big></font></p>";

    if let Ok(mut file) = File::open(response_file) {
        let mut custom_status = String::new();
        if file.read_to_string(&mut custom_status).is_ok() {
            let custom_status = custom_status.trim().to_string();
            if !custom_status.is_empty() && !custom_status.starts_with("HTTP/1.1 101") {
                return format!("HTTP/1.1 101 {}", custom_status);
            }
            return custom_status;
        }
    }
    default_status.to_string()
}

fn build_response() -> Vec<u8> {
    let custom_status = load_custom_status();
    let headers = "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: foo\r\nX-Powered-By: Chapeey\r\n\r\n";
    (custom_status + headers).into_bytes()
}

fn load_config() -> Vec<String> {
    let config_file = "/usr/bin/tun.conf";
    let default_hosts = vec!["127.0.0.1:22".to_string()];

    let mut file_content = String::new();
    if let Ok(mut file) = File::open(config_file) {
        if file.read_to_string(&mut file_content).is_err() {
            eprintln!("[WARN] Error reading tun.conf, using default hosts");
            return default_hosts;
        }
    } else {
        eprintln!("[WARN] tun.conf not found, using default hosts");
        return default_hosts;
    }

    let docs = YamlLoader::load_from_str(&file_content).unwrap_or_else(|_| {
        eprintln!("[ERROR] YAML parsing error, using default hosts");
        vec![]
    });

    if let Some(config) = docs.first() {
        if let Some(listen_entries) = config["listen"].as_vec() {
            let mut hosts = Vec::new();
            for entry in listen_entries {
                if let (Some(target_host), Some(target_port)) = (
                    entry["target_host"].as_str(),
                    entry["target_port"].as_i64(),
                ) {
                    hosts.push(format!("{}:{}", target_host, target_port));
                }
            }
            if !hosts.is_empty() {
                return hosts;
            }
        }
    }

    eprintln!("[WARN] Invalid config format in tun.conf, using default hosts");
    default_hosts
}

fn find_header(head: &str, header: &str) -> String {
    let prefix = format!("{}: ", header);
    if let Some(start_idx) = head.find(&prefix) {
        let start_of_value = start_idx + prefix.len();
        if let Some(end_idx) = head[start_of_value..].find("\r\n") {
            return head[start_of_value..start_of_value + end_idx].to_string();
        }
        return head[start_of_value..].to_string();
    }
    "".to_string()
}

async fn transfer(mut reader: impl AsyncReadExt + Unpin, mut writer: impl AsyncWriteExt + Unpin) -> io::Result<()> {
    let mut buf = vec![0; BUFLEN];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        writer.write_all(&buf[..n]).await?;
    }
    Ok(())
}

async fn handle_client(mut client_stream: TcpStream) {
    let client_addr = client_stream.peer_addr().map(|a| a.to_string()).unwrap_or_else(|_| "unknown".to_string());
    println!("[INFO] Accepted connection from {}", client_addr);

    let mut initial_buf = vec![0; BUFLEN];
    let n = tokio::time::timeout(Duration::from_secs(30),
        client_stream.read(&mut initial_buf)
    ).await.unwrap_or(Ok(0)).unwrap_or(0);

    if n == 0 {
        println!("[DEBUG] No data received from {}", client_addr);
        return;
    }

    let head = String::from_utf8_lossy(&initial_buf[..n]);
    let host_port = find_header(&head, "X-Real-Host");
    let split = find_header(&head, "X-Split");

    if !split.is_empty() {
        tokio::time::timeout(Duration::from_secs(5),
            client_stream.read(&mut initial_buf) // Read to discard
        ).await.ok();
    }

    let mut possible_hosts = unsafe { DEFAULT_HOSTS.clone() };
    if !host_port.is_empty() {
        possible_hosts = vec![host_port];
    }

    let mut target_stream_option: Option<TcpStream> = None;
    let mut last_err: Option<io::Error> = None;

    for host in possible_hosts {
        let host = host.trim();
        if host.is_empty() {
            continue;
        }

        println!("[INFO] Trying to connect to {} for client {}", host, client_addr);
        match tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(host)).await {
            Ok(Ok(stream)) => {
                println!("[INFO] Connected to {} for client {}", host, client_addr);
                target_stream_option = Some(stream);
                break;
            },
            Ok(Err(e)) => {
                println!("[WARN] Connection to {} failed for client {}: {}", host, client_addr, e);
                last_err = Some(e);
            },
            Err(_) => {
                println!("[WARN] Connection to {} timed out for client {}", host, client_addr);
                last_err = Some(io::Error::new(io::ErrorKind::TimedOut, "connection timed out"));
            }
        }
    }

    let mut target_stream = match target_stream_option {
        Some(stream) => stream,
        None => {
            eprintln!("[ERROR] All connection attempts failed for client {}. Last error: {:?}", client_addr, last_err);
            let _ = client_stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n").await;
            return;
        }
    };

    let _ = client_stream.write_all(unsafe { &RESPONSE }).await;

    let (mut client_reader, mut client_writer) = client_stream.into_split();
    let (mut target_reader, mut target_writer) = target_stream.into_split();

    let client_to_target = transfer(&mut client_reader, &mut target_writer);
    let target_to_client = transfer(&mut target_reader, &mut client_writer);

    tokio::select! {
        _ = client_to_target => {},
        _ = target_to_client => {},
    }

    println!("[INFO] Connection handler for {} finished", client_addr);
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        if let Ok(p) = args[1].parse::<u16>() {
            unsafe { PORT = p; }
        } else {
            eprintln!("[WARN] Invalid port argument: {}, using default {}", args[1], unsafe { PORT });
        }
    }

    unsafe {
        RESPONSE = build_response();
        DEFAULT_HOSTS = load_config();
    }

    println!("\x1b[0;34m━"*8);
    println!("\x1b[1;32m PROXY SOCKS (RUST)");
    println!("\x1b[0;34m━"*8);
    println!("\x1b[1;33mIP:\x1b[1;32m {}", IP);
    println!("\x1b[1;33mPORT:\x1b[1;32m {}", unsafe { PORT });
    println!("\x1b[1;33mDefault Hosts:\x1b[1;32m {:?}", unsafe { DEFAULT_HOSTS });
    println!("\x1b[0;34m━"*10);
    println!("\x1b[1;32m SSHPLUS");
    println!("\x1b[0;34m━\x1b[1;37m"*11);
    println!("\n");

    let addr = format!("{}:{}", IP, unsafe { PORT });
    let listener = TcpListener::bind(&addr).await?;
    println!("[INFO] Server running on {}", addr);

    loop {
        let (client_stream, _) = listener.accept().await?;
        task::spawn(handle_client(client_stream));
    }
}
