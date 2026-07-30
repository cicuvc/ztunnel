mod config;
mod proxy;

use std::io::Write;
use std::path::PathBuf;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use clap::Parser;
use zt_common::token::{self, TokenPurpose};

#[derive(Parser)]
#[command(name = "ssh-nat", version)]
enum Cli {
    /// SSH into a host via NAT traversal
    #[command(name = "ssh", trailing_var_arg = true)]
    Ssh {
        user_at_host: String,
        #[arg(last = true)]
        ssh_args: Vec<String>,
    },
    /// Gate proxy subcommand (used as ssh ProxyCommand).
    /// Discover endpoint from registry automatically.
    GateProxy {
        host: String,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli {
        Cli::Ssh { user_at_host, ssh_args } => cmd_ssh(&user_at_host, &ssh_args),
        Cli::GateProxy { host } => proxy::run(&host),
    }
}

fn cmd_ssh(user_at_host: &str, ssh_args: &[String]) -> anyhow::Result<()> {
    let secret = config::Config::load_secret()
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    let cfg = config::Config::load();
    let registry = cfg.registry_url();
    let hostname = user_at_host.split('@').nth(1).unwrap_or(user_at_host);

    let offset = sync_time(&registry);
    let window = token::adjusted_window(offset);
    let dis_token = token::generate(&secret, TokenPurpose::Discover, window);
    let url = format!("{}/api?w={}&t={}", registry, window, dis_token);
    eprintln!("[ssh-nat] fetching endpoint from {}", registry);

    let response = ureq::get(&url)
        .call()
        .map_err(|e| anyhow::anyhow!("failed to fetch endpoint: {}", e))?;

    let body = response
        .into_body()
        .read_to_string()
        .map_err(|e| anyhow::anyhow!("failed to read response: {}", e))?;
    let data: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| anyhow::anyhow!("invalid response JSON: {}", e))?;

    if let Some(err) = data.get("error") {
        anyhow::bail!("registry error: {}", err);
    }

    let _ip = data["ip"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing ip"))?;
    let port = data["port"]
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("missing port"))? as u16;
    let host_pubkey = data["host_pubkey"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing host_pubkey"))?;
    let stale = data["stale"].as_bool().unwrap_or(true);

    if stale {
        eprintln!("[ssh-nat] warning: endpoint is stale (last heartbeat > 90s ago)");
    }

    if data["status"] == "down" {
        eprintln!("[ssh-nat] warning: host reports status=down");
    }

    let tmp = temp_known_hosts(hostname, host_pubkey)?;

    let proxy_cmd = format!("ssh-nat gate-proxy {}", hostname);
    let mut cmd = std::process::Command::new("ssh");
    cmd.arg("-o")
        .arg(format!("ProxyCommand={}", proxy_cmd))
        .arg("-o")
        .arg(format!("HostKeyAlias={}", hostname))
        .arg("-o")
        .arg(format!("UserKnownHostsFile={}", tmp.display()))
        .arg("-o")
        .arg("StrictHostKeyChecking=yes")
        .arg("-o")
        .arg("PasswordAuthentication=no")
        .arg("-p")
        .arg(port.to_string())
        .arg(user_at_host);

    for arg in ssh_args {
        cmd.arg(arg);
    }

    let err = cmd.status();
    match err {
        Ok(status) => {
            if !status.success() {
                std::process::exit(status.code().unwrap_or(1));
            }
        }
        Err(e) => {
            anyhow::bail!("ssh execution failed: {}", e);
        }
    }

    Ok(())
}

fn sync_time(registry_url: &str) -> i64 {
    let url = format!("{}/api?cmd=time", registry_url);
    match ureq::get(&url).call() {
        Ok(resp) => {
            if let Ok(body) = resp.into_body().read_to_string() {
                if let Ok(data) = serde_json::from_str::<serde_json::Value>(&body) {
                    if let Some(ts) = data["ts"].as_i64() {
                        let local = token::now_secs();
                        return ts - local;
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("[ssh-nat] time sync failed: {}, using local clock", e);
        }
    }
    0
}

fn temp_known_hosts(hostname: &str, pubkey: &str) -> anyhow::Result<PathBuf> {
    let tmp = std::env::temp_dir().join("ssh_nat_known_hosts");
    // Always overwrite with fresh content; file is not cleaned up eagerly since
    // ssh reads it after this function returns (we exec ssh).  The OS /tmp
    // cleaner or the next invocation handles cleanup.
    let mut f = std::fs::File::create(&tmp)?;
    #[cfg(unix)]
    f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    writeln!(f, "{} {}", hostname, pubkey)?;
    Ok(tmp)
}
