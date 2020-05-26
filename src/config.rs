use std::env;

#[derive(Debug)]
pub struct Config {
    pub smtp_forward_host: String,
    pub email_to_name: String,
    pub email_to_addr: String,
    pub email_from: String,
    pub debug_dir: Option<String>,
    pub public_hostname: String,
    pub public_port: u16,
    pub ipv4_addr: String,
    pub ipv6_addr: String,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            smtp_forward_host: from_env("SMTP_FORWARD_HOST"),
            email_to_name: from_env("SMTP_EMAIL_TO_NAME"),
            email_to_addr: from_env("SMTP_EMAIL_TO_ADDR"),
            email_from: from_env("SMTP_EMAIL_FROM"),
            debug_dir: env::var("DEBUG_DIR").ok(),
            public_hostname: from_env("PUBLIC_HOSTNAME"),
            public_port: from_env("PUBLIC_PORT")
                .parse::<u16>()
                .expect("invalid port"),
            ipv4_addr: from_env("IPV4_BIND_ADDR"),
            ipv6_addr: from_env("IPV6_BIND_ADDR"),
        }
    }
}

fn from_env(key: &str) -> String {
    env::var(key).expect(&format!("env variable {} missing", key))
}
