use std::{
    fs::{OpenOptions, create_dir_all},
    io::Write,
    net::SocketAddr,
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use codex_tunnel_bench::{
    BENCHMARK_BYTES, EndpointReport, EndpointSample, compare_p95_us, endpoint_report,
    first_byte_sample, memory_per_active_connection_kib, serve, stream_sample,
};
use serde::Serialize;
use tokio::{net::TcpListener, time::timeout};

#[derive(Debug, Parser)]
#[command(about = "Release benchmark harness for the Codex Secure Tunnel")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Temporary responder for the byte-stream and flushed-write benchmark.
    Serve {
        #[arg(long)]
        listen: SocketAddr,
    },
    /// Compare direct and tunnel paths and write an explicit JSON evidence file.
    Run {
        /// Direct compatibility-service benchmark endpoint.
        #[arg(long)]
        direct: SocketAddr,
        /// Local tunnel listener that reaches the same benchmark endpoint.
        #[arg(long)]
        tunnel: SocketAddr,
        /// Independent small-write samples per path. A p95 is calculated from these.
        #[arg(long, default_value_t = 20, value_parser = clap::value_parser!(u16).range(1..))]
        samples: u16,
        #[arg(long, default_value_t = 30)]
        timeout_seconds: u64,
        /// A new output file outside source control. The harness refuses overwrite.
        #[arg(long)]
        output: PathBuf,
        /// Required description of the identical client/remote hardware and route.
        #[arg(long)]
        hardware_note: String,
        /// Baseline RSS (KiB) for the client+ingress tunnel processes, after startup and before load.
        #[arg(long, requires_all = ["memory_active_rss_kib", "memory_active_connections"])]
        memory_baseline_rss_kib: Option<u64>,
        /// RSS (KiB) for the same processes while the stated number of tunnel connections are active.
        #[arg(long, requires_all = ["memory_baseline_rss_kib", "memory_active_connections"])]
        memory_active_rss_kib: Option<u64>,
        /// Number of active tunnel connections at the active RSS sample.
        #[arg(long, requires_all = ["memory_baseline_rss_kib", "memory_active_rss_kib"], value_parser = clap::value_parser!(u32).range(1..))]
        memory_active_connections: Option<u32>,
    },
    /// Print resident memory in KiB for use with the documented release method.
    Rss {
        #[arg(long)]
        pid: u32,
    },
}

#[derive(Debug, Serialize)]
struct Report {
    schema_version: u8,
    measured_at_unix_seconds: u64,
    hardware_note: String,
    stream_bytes_each_direction: u64,
    small_flushed_write_bytes: usize,
    samples_per_path: u16,
    direct: EndpointReport,
    tunnel: EndpointReport,
    comparison: Comparison,
    gates: Gates,
    memory: MemoryReport,
    method: Method,
}

#[derive(Debug, Serialize)]
struct Comparison {
    additional_first_byte_p95_us: i128,
    tunnel_throughput_fraction_of_direct: f64,
}

#[derive(Debug, Serialize)]
struct Gates {
    additional_first_byte_p95_le_10ms: bool,
    tunnel_throughput_at_least_90_percent_of_direct: bool,
    tunnel_owned_memory_per_active_connection_le_1mib: Option<bool>,
}

#[derive(Debug, Serialize)]
struct MemoryReport {
    status: &'static str,
    method: &'static str,
    baseline_rss_kib: Option<u64>,
    active_rss_kib: Option<u64>,
    active_connections: Option<u32>,
    tunnel_owned_memory_per_active_connection_kib: Option<f64>,
}

#[derive(Debug, Serialize)]
struct Method {
    first_byte: &'static str,
    throughput: &'static str,
    memory: &'static str,
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Serve { listen } => {
            let listener = TcpListener::bind(listen).await?;
            eprintln!(
                "benchmark responder listening on {}",
                listener.local_addr()?
            );
            serve(listener).await
        }
        Command::Run {
            direct,
            tunnel,
            samples,
            timeout_seconds,
            output,
            hardware_note,
            memory_baseline_rss_kib,
            memory_active_rss_kib,
            memory_active_connections,
        } => {
            if hardware_note.trim().is_empty() {
                bail!("--hardware-note must not be empty");
            }
            let report = run(
                direct,
                tunnel,
                samples,
                Duration::from_secs(timeout_seconds),
                hardware_note,
                memory_baseline_rss_kib
                    .zip(memory_active_rss_kib)
                    .zip(memory_active_connections),
            )
            .await?;
            write_new_json(&output, &report)?;
            println!("release evidence written to {}", output.display());
            Ok(())
        }
        Command::Rss { pid } => {
            println!("{}", rss_kib(pid)?);
            Ok(())
        }
    }
}

async fn run(
    direct: SocketAddr,
    tunnel: SocketAddr,
    samples: u16,
    per_operation_timeout: Duration,
    hardware_note: String,
    memory: Option<((u64, u64), u32)>,
) -> Result<Report> {
    let direct_samples = collect_samples(direct, samples, per_operation_timeout).await?;
    let direct_stream = timeout(per_operation_timeout, stream_sample(direct))
        .await
        .context("direct stream benchmark timed out")??;
    let tunnel_samples = collect_samples(tunnel, samples, per_operation_timeout).await?;
    let tunnel_stream = timeout(per_operation_timeout, stream_sample(tunnel))
        .await
        .context("tunnel stream benchmark timed out")??;
    let direct = endpoint_report(&direct_samples, direct_stream)?;
    let tunnel = endpoint_report(&tunnel_samples, tunnel_stream)?;
    let additional_first_byte_p95_us =
        compare_p95_us(direct.first_byte_p95_us, tunnel.first_byte_p95_us);
    let throughput_fraction = tunnel.bidirectional_throughput_bytes_per_second
        / direct.bidirectional_throughput_bytes_per_second;
    let memory = memory_report(memory)?;
    let memory_gate = memory
        .tunnel_owned_memory_per_active_connection_kib
        .map(|value| value <= 1024.0);
    Ok(Report {
        schema_version: 1,
        measured_at_unix_seconds: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock predates Unix epoch")?
            .as_secs(),
        hardware_note,
        stream_bytes_each_direction: BENCHMARK_BYTES,
        small_flushed_write_bytes: 9,
        samples_per_path: samples,
        direct,
        tunnel,
        comparison: Comparison {
            additional_first_byte_p95_us,
            tunnel_throughput_fraction_of_direct: throughput_fraction,
        },
        gates: Gates {
            additional_first_byte_p95_le_10ms: additional_first_byte_p95_us <= 10_000,
            tunnel_throughput_at_least_90_percent_of_direct: throughput_fraction >= 0.90,
            tunnel_owned_memory_per_active_connection_le_1mib: memory_gate,
        },
        memory,
        method: Method {
            first_byte: "Each sample records from a flushed 9-byte request until the responder's first byte; TCP connection setup is separately reported.",
            throughput: "A single persistent TCP connection concurrently sends and receives exactly 67,108,864 bytes; bytes in both directions divided by elapsed wall time.",
            memory: "See docs/benchmarking.md: sample combined client+ingress RSS at idle and N active connections, then divide the delta by N.",
        },
    })
}

async fn collect_samples(
    endpoint: SocketAddr,
    samples: u16,
    per_operation_timeout: Duration,
) -> Result<Vec<EndpointSample>> {
    let mut result = Vec::with_capacity(samples.into());
    for _ in 0..samples {
        result.push(
            timeout(per_operation_timeout, first_byte_sample(endpoint))
                .await
                .context("first-byte benchmark timed out")??,
        );
    }
    Ok(result)
}

fn memory_report(memory: Option<((u64, u64), u32)>) -> Result<MemoryReport> {
    let Some(((baseline_rss_kib, active_rss_kib), active_connections)) = memory else {
        return Ok(MemoryReport {
            status: "not_measured",
            method: "not measured; follow docs/benchmarking.md before approving a release",
            baseline_rss_kib: None,
            active_rss_kib: None,
            active_connections: None,
            tunnel_owned_memory_per_active_connection_kib: None,
        });
    };
    let per_connection =
        memory_per_active_connection_kib(baseline_rss_kib, active_rss_kib, active_connections)?;
    Ok(MemoryReport {
        status: "measured_from_operator_rss_samples",
        method: "combined client+ingress RSS delta divided by active connection count; collection procedure is in docs/benchmarking.md",
        baseline_rss_kib: Some(baseline_rss_kib),
        active_rss_kib: Some(active_rss_kib),
        active_connections: Some(active_connections),
        tunnel_owned_memory_per_active_connection_kib: Some(per_connection),
    })
}

fn write_new_json(path: &std::path::Path, report: &Report) -> Result<()> {
    if path.exists() {
        bail!(
            "refusing to overwrite existing release evidence {}",
            path.display()
        );
    }
    if let Some(parent) = path.parent() {
        create_dir_all(parent)
            .with_context(|| format!("create output directory {}", parent.display()))?;
    }
    let encoded = serde_json::to_vec_pretty(report)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("create release evidence {}", path.display()))?;
    output.write_all(&encoded)?;
    output.write_all(b"\n")?;
    output.sync_all()?;
    Ok(())
}

fn rss_kib(pid: u32) -> Result<u64> {
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string(format!("/proc/{pid}/status"))
            .with_context(|| format!("read /proc/{pid}/status"))?;
        let line = status
            .lines()
            .find(|line| line.starts_with("VmRSS:"))
            .context("VmRSS unavailable; the process may have exited")?;
        return line
            .split_whitespace()
            .nth(1)
            .context("malformed VmRSS value")?
            .parse()
            .context("invalid VmRSS value");
    }
    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("ps")
            .args(["-o", "rss=", "-p", &pid.to_string()])
            .output()
            .context("run ps for RSS")?;
        if !output.status.success() {
            bail!("ps failed while reading RSS for pid {pid}");
        }
        return String::from_utf8(output.stdout)?
            .trim()
            .parse()
            .context("invalid ps RSS value");
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    bail!("RSS sampling is only implemented for Linux and macOS; use the documented OS method")
}
