use std::net::{SocketAddr, Shutdown};
use std::net::{Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::time::Duration;

use anyhow::Context;
use colored::*;
use futures::{future, TryFutureExt};
use lettre::{ClientSecurity, Transport};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::sync::Mutex;
use tokio::time::timeout;

mod config;

use config::Config;

type VoidRes = Result<(), anyhow::Error>;
type EmailType = lettre_email::Email;

lazy_static::lazy_static! {
    static ref CONFIG: Config = Config::from_env();
    static ref SPAM_LIMITER: Arc<Mutex<HashMap<Ipv6Addr, usize>>> = Arc::new(Mutex::new(HashMap::new()));
    static ref CONN_COUNTER: Arc<Mutex<HashMap<Ipv6Addr, i8>>> = Arc::new(Mutex::new(HashMap::new()));
}

#[tokio::main]
async fn main() -> VoidRes {
    env_logger::builder().format_timestamp(None).init();
    log::info!("Starting up with configuration {:#?}", *CONFIG);

    let (email_tx, email_rx) = mpsc::unbounded_channel();

    tokio::select! {
        res = email_queue(email_rx) => log::error!("email queue stopped {:?}", res),
        res = ipv4_listener() => log::error!("ipv4 listener stopped {:?}", res),
        res = ipv6_listener(email_tx) => log::error!("ipv6 listener stopped {:?}", res),
    };

    log::info!("Exiting");
    Ok(())
}

async fn email_queue(mut rx: UnboundedReceiver<EmailType>) -> Result<(), anyhow::Error> {
    let mut smtp = lettre::SmtpClient::new(
        (CONFIG.smtp_forward_host.as_str(), 25),
        ClientSecurity::None,
    )?
    .transport();

    while let Some(msg) = rx.recv().await {
        tokio::task::block_in_place(|| smtp.send(msg.into()))?;
        log::info!("Mail sent");
    }

    log::info!("Exiting email loop");
    Ok(())
}

async fn ipv4_listener() -> VoidRes {
    let bind_addr = format!("{}:{}", CONFIG.ipv4_addr, CONFIG.public_port);
    let mut listener = TcpListener::bind(bind_addr).await?;
    log::info!("Listening ipv4");
    loop {
        let (socket, client_addr) = listener.accept().await?;
        let addr = match client_addr {
            SocketAddr::V4(addr) => addr,
            _ => unreachable!()
        };
        tokio::spawn(handle_ipv4(socket, addr)
            .inspect_err(|e| log::error!("handling ipv4failed {:?}", e)));
    }
}

async fn ipv6_listener(email_tx: UnboundedSender<EmailType>) -> VoidRes {
    let bind_addr = format!("{}:{}", CONFIG.ipv6_addr, CONFIG.public_port);
    let mut listener = TcpListener::bind(bind_addr).await?;
    log::info!("Listening ipv6");
    loop {
        let (socket, client_addr) = listener.accept().await?;
        let addr = match client_addr {
            SocketAddr::V6(addr) => addr,
            _ => unreachable!()
        };
        tokio::spawn(handle_ipv6(socket, addr, email_tx.clone())
            .inspect_err(|e| log::error!("handling ipv6 failed {:?}", e)));
    }
}

async fn handle_ipv4(mut socket: TcpStream, addr: SocketAddrV4) -> VoidRes {
    log::info!("Connection from {}", addr);
    let msg = format!(
        "\n\
            You connected to the IPv4 version of the service.\n\
            To force netcat to use IPv6, do\n\
            \n\
            $ nc -6 {hostname} {port}\n\
            \n\
            If it fails to connect or you see this msg again, you\n\
            don't have IPv6 connectivity and this tool is of no use\n\
            for you.\n\
            \n\
            Find sources of this tool from:\n\
            \n\
            \thttps://github.com/vvilhonen/ipv6shell\n\
            \n",
        hostname = CONFIG.public_hostname,
        port = CONFIG.public_port
    );
    let timeout_fut = timeout(Duration::from_secs(2), socket.write_all(msg.as_bytes())).await;
    if let Err(_) = timeout_fut {
        log::warn!("Timeout sending ipv4");
    }
    Ok(())
}

async fn handle_ipv6(
    socket: TcpStream,
    addr: SocketAddrV6,
    email_tx: UnboundedSender<EmailType>,
) -> VoidRes {
    let ip_addr = *addr.ip();

    log::info!("Connection open {}", addr);

    track_conn(ip_addr, 1).await?;

    let mut shell = Shell::new(socket, ip_addr, email_tx);

    let result = run_session(&mut shell).await;
    if let Err(e) = shell.save_debug_log().await {
        log::error!("Saving debug log failed {}", e);
    }
    if let Err(e) = shell.socket.shutdown(Shutdown::Both) {
        log::error!("Shutdown failed {}", e);
    }
    log::info!("Connection close {}", addr);

    track_conn(ip_addr, -1).await?;

    result
}

async fn track_conn(addr: Ipv6Addr, delta: i8) -> VoidRes {
    let mut conn_counter = CONN_COUNTER.lock().await;
    let entry = conn_counter.entry(addr).or_insert(0);
    if *entry > 5 && delta > 0 {
        anyhow::bail!("Too many connections from {}", addr);
    } else {
        *entry += delta;
    }
    Ok(())
}

async fn run_session(shell: &mut Shell) -> VoidRes {
    shell.print_banner().await?;

    loop {
        shell.prompt().await?;
        let cmd = shell.read_cmd().await?;
        let parts = cmd.split_whitespace().collect::<Vec<_>>();
        match &parts[..] {
            ["scan"] => shell.scan(PORTS).await?,
            ["scan", port] => match port.parse::<u16>() {
                Ok(port) => {
                    shell.scan(&[port]).await?;
                }
                _ => shell.write_all("Invalid port\n").await?,
            },
            ["support"] => shell.support().await?,
            ["quit"] => {
                shell.end().await?;
                break;
            },
            other => {
                shell
                    .write_all(&format!("Unknown/empty command: {:?}\n", other))
                    .await?
            }
        };
    }
    Ok(())
}

struct Shell {
    socket: TcpStream,
    log: String,
    addr: Ipv6Addr,
    email_tx: UnboundedSender<EmailType>,
}

impl Shell {
    pub fn new(socket: TcpStream, addr: Ipv6Addr, email_tx: UnboundedSender<EmailType>) -> Self {
        socket.set_nodelay(true).unwrap();
        socket.set_recv_buffer_size(1024).unwrap();
        socket.set_send_buffer_size(1024).unwrap();

        // let (rx, tx) = socket.into_split();
        Shell {
            socket,
            log: format!("Connection from {}\n", addr),
            addr,
            email_tx,
        }
    }

    pub async fn print_banner(&mut self) -> VoidRes {
        let addr_text = format!("{}", self.addr);
        let msg = format!("\n{header}\n\
            \n\
            You are connected from:\n\
            \n\
            \t{addr}\n\
            \n\
            IPv6 addresses are routable in the public internet by default\n\
            and you might have your current computer behind IPv4 NAT\n\
            unexpectedly exposed this way.\n\
            \n\
            This tool allows you to scan yourself for open ports\n\
            and if it shows your known open ports closed, your\n\
            firewall or something else on the way is blocking \n\
            the connection attempts as it should.\n\
            \n\
            Commands:\n\
            \n\
            \tscan        - scans some common ports\n\
            \tscan <port> - scans <port>\n\
            \tsupport     - contact support\n\
            \tquit\n\
            \n\
            Find sources of this tool from:\n\
            \n\
            \thttps://github.com/vvilhonen/ipv6shell\n\
            \n\
        ",
          header="==== ipv6shell ====".bold(),
          addr=addr_text.red().bold());

        self.write_all(&msg).await?;
        Ok(())
    }

    pub async fn end(&mut self) -> VoidRes {
        self.write_all("Thanks, see you soon again!\n").await?;
        Ok(())
    }

    pub async fn prompt(&mut self) -> VoidRes {
        self.write_all(&"$ ".green()).await?;
        Ok(())
    }

    pub async fn scan(&mut self, ports: &[u16]) -> VoidRes {
        self.write_all("Scanning ports\n").await?;
        let ports_open_fut = ports.iter().map(|port| Self::scan_port(&self.addr, *port));
        let ports_open: Vec<bool> = future::join_all(ports_open_fut).await;

        self.write_all("  port  status\n  ====  ======\n").await?;
        for (port, open) in ports.iter().zip(ports_open) {
            let open_text = if open {
                "OPEN".red().bold()
            } else {
                "CLOSED".green().bold()
            };
            let msg = format!("{:6}  {}\n", port, open_text);
            self.write_all(&msg.red().bold()).await?;
        }
        Ok(())
    }

    async fn scan_port(ip: &Ipv6Addr, port: u16) -> bool {
        let addr: SocketAddr = (*ip, port).into();
        let connect = TcpStream::connect(addr);
        let res = timeout(Duration::from_secs(2), connect).await;
        match res {
            Ok(Ok(_)) => true,
            _ => false,
        }
    }

    pub async fn support(&mut self) -> VoidRes {
        self.write_all("Write your message and end the msg with empty line\n")
            .await?;
        let mut buf = Vec::new();
        while buf.len() < 1024 {
            let mut chunk = [0u8; 256];
            let n = timeout(Duration::from_secs(500), self.socket.read(&mut chunk)).await??;
            buf.extend(&chunk[..n]);
            let empty = buf
                .iter()
                .zip(buf.iter().skip(1))
                .any(|(a, b)| *a == b'\n' && *b == b'\n');
            if empty {
                break;
            }
        }
        let msg = std::str::from_utf8(&buf)?.trim().to_owned();
        let email = lettre_email::EmailBuilder::new()
            .to((CONFIG.email_to_addr.as_str(), CONFIG.email_to_name.as_str()))
            .from(CONFIG.email_from.as_str())
            .subject("Ascii6 support msg!")
            .text(msg)
            .build()?;

        let mut spam = SPAM_LIMITER.lock().await;
        let entry = spam.entry(self.addr).or_insert(0);
        if *entry > 5 {
            self.write_all("Sorry, we have enough support requests already\n")
                .await?;
        } else {
            *entry += 1;
            self.email_tx.send(email)?;
            self.write_all("Thanks! We \"sent\" your message to support.\nWe'll reply if you included any contact details.\n").await?;
        }

        Ok(())
    }

    pub async fn read_cmd(&mut self) -> Result<String, anyhow::Error> {
        let mut buf = vec![0; 200];
        let timeout_fut = timeout(Duration::from_secs(10), self.socket.read(&mut buf)).await;
        let n = match timeout_fut {
            Err(e) => {
                self.write_all("Idle, closing..\n").await?;
                return Err::<_, anyhow::Error>(e.into()).context("read timeout");
            }
            Ok(read) => read?,
        };
        if n == 0 {
            anyhow::bail!("closed input");
        }
        let data = std::str::from_utf8(&buf[..n])?.trim().to_owned();
        self.log.push_str(&data);
        Ok(data)
    }

    async fn write_all(&mut self, src: &str) -> VoidRes {
        self.log.push_str(src);
        let timeout_fut = timeout(Duration::from_secs(2), self.socket.write_all(src.as_bytes())).await;
        match timeout_fut {
            Err(e) => {
                self.log.push_str("<write timeout, closing>\n");
                return Err::<_, anyhow::Error>(e.into()).context("write timeout");
            }
            Ok(write) => write?,
        };
        Ok(())
    }

    async fn save_debug_log(&self) -> VoidRes {
        if let Some(ref debug_dir) = &CONFIG.debug_dir {
            let time = chrono::Local::now().to_rfc3339();
            let path = format!("{}/{}_{}.log", debug_dir, time, self.addr);
            ::tokio::fs::write(path, &self.log).await?;
        }
        Ok(())
    }
}

const PORTS: &[u16] = &[
    20, 21, 22, 23, 25, 80, 443, 445, 465, 3000, 5000, 8000, 8080,
];
