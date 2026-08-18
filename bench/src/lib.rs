//! Reproducible release measurements for the Secure Tunnel.
//!
//! The wire protocol in this crate is deliberately limited to a temporary test
//! responder. It is not part of the deployed tunnel protocol or the
//! compatibility-service API.

use std::{
    cmp::Ordering,
    io,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use serde::Serialize;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

/// The release-required amount in *each* direction of the stream test.
pub const BENCHMARK_BYTES: u64 = 64 * 1024 * 1024;
/// The request that exercises a partial encrypted record is deliberately far
/// below the tunnel's 16 KiB record limit.
pub const SMALL_FLUSH_REQUEST_BYTES: usize = 9;
const MAGIC: [u8; 8] = *b"CDXBCH01";
const OP_FIRST_BYTE: u8 = 1;
const OP_STREAM: u8 = 2;
const FIRST_BYTE_REPLY: u8 = 0xa5;
const COPY_CHUNK_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct EndpointSample {
    pub connection_setup: Duration,
    pub first_byte: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct StreamSample {
    /// Bytes sent by the benchmark client.
    pub sent_bytes: u64,
    /// Bytes received by the benchmark client.
    pub received_bytes: u64,
    pub elapsed: Duration,
}

impl StreamSample {
    /// Counts both directions because the acceptance criterion is
    /// bidirectional sustained throughput.
    pub fn bidirectional_throughput_bytes_per_second(self) -> Result<f64> {
        throughput_bytes_per_second(
            self.sent_bytes
                .checked_add(self.received_bytes)
                .context("bidirectional byte counter overflow")?,
            self.elapsed,
        )
    }
}

/// Nearest-rank p95. This is deterministic and avoids interpolating a value
/// that was never observed.
pub fn percentile_95(samples: &[Duration]) -> Duration {
    assert!(!samples.is_empty(), "p95 requires at least one sample");
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let rank = (95 * sorted.len()).div_ceil(100);
    sorted[rank - 1]
}

pub fn throughput_bytes_per_second(bytes: u64, elapsed: Duration) -> Result<f64> {
    if elapsed.is_zero() {
        bail!("throughput duration must be non-zero");
    }
    Ok(bytes as f64 / elapsed.as_secs_f64())
}

/// Calculate tunnel-owned resident memory per live connection from the combined
/// tunnel-client and tunnel-ingress RSS samples. The caller must exclude the
/// compatibility service and benchmark responder from both samples.
pub fn memory_per_active_connection_kib(
    baseline_rss_kib: u64,
    active_rss_kib: u64,
    active_connections: u32,
) -> Result<f64> {
    if active_connections == 0 {
        bail!("active connection count must be non-zero");
    }
    let delta = active_rss_kib
        .checked_sub(baseline_rss_kib)
        .context("active RSS cannot be lower than baseline RSS for this measurement")?;
    Ok(delta as f64 / f64::from(active_connections))
}

/// Serve the temporary benchmark protocol until the listener is closed.
pub async fn serve(listener: TcpListener) -> Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        tokio::spawn(async move {
            if let Err(error) = serve_connection(stream).await {
                eprintln!("benchmark peer {peer} failed: {error:#}");
            }
        });
    }
}

/// Run a small, promptly-flushed write against `endpoint`.
///
/// `first_byte` starts after the TCP connection succeeds. `connection_setup`
/// is recorded independently so a slow route is not disguised as tunnel
/// forwarding overhead.
pub async fn first_byte_sample(endpoint: std::net::SocketAddr) -> Result<EndpointSample> {
    let connect_started = Instant::now();
    let mut stream = TcpStream::connect(endpoint)
        .await
        .with_context(|| format!("connect to benchmark endpoint {endpoint}"))?;
    stream.set_nodelay(true)?;
    let connection_setup = connect_started.elapsed();

    let mut request = Vec::with_capacity(SMALL_FLUSH_REQUEST_BYTES);
    request.extend_from_slice(&MAGIC);
    request.push(OP_FIRST_BYTE);
    debug_assert_eq!(request.len(), SMALL_FLUSH_REQUEST_BYTES);
    let first_write = Instant::now();
    stream.write_all(&request).await?;
    stream.flush().await?;
    let mut reply = [0_u8; 1];
    stream.read_exact(&mut reply).await?;
    if reply[0] != FIRST_BYTE_REPLY {
        bail!("benchmark responder sent an invalid first-byte reply");
    }
    Ok(EndpointSample {
        connection_setup,
        first_byte: first_write.elapsed(),
    })
}

/// Transfer exactly 64 MiB concurrently in each direction.
pub async fn stream_sample(endpoint: std::net::SocketAddr) -> Result<StreamSample> {
    let mut stream = TcpStream::connect(endpoint)
        .await
        .with_context(|| format!("connect to benchmark endpoint {endpoint}"))?;
    stream.set_nodelay(true)?;
    stream.write_all(&MAGIC).await?;
    stream.write_u8(OP_STREAM).await?;
    stream.flush().await?;

    let started = Instant::now();
    let (mut read_half, mut write_half) = stream.into_split();
    let writer = tokio::spawn(async move {
        let buffer = [0x5a_u8; COPY_CHUNK_BYTES];
        let mut remaining = BENCHMARK_BYTES;
        while remaining > 0 {
            let count = remaining.min(buffer.len() as u64) as usize;
            write_half.write_all(&buffer[..count]).await?;
            remaining -= count as u64;
        }
        write_half.shutdown().await?;
        Ok::<u64, io::Error>(BENCHMARK_BYTES)
    });
    let reader = tokio::spawn(async move {
        let mut buffer = [0_u8; COPY_CHUNK_BYTES];
        let mut remaining = BENCHMARK_BYTES;
        while remaining > 0 {
            let count = remaining.min(buffer.len() as u64) as usize;
            read_half.read_exact(&mut buffer[..count]).await?;
            remaining -= count as u64;
        }
        Ok::<u64, io::Error>(BENCHMARK_BYTES)
    });
    let sent_bytes = writer.await.context("stream writer task panicked")??;
    let received_bytes = reader.await.context("stream reader task panicked")??;
    Ok(StreamSample {
        sent_bytes,
        received_bytes,
        elapsed: started.elapsed(),
    })
}

async fn serve_connection(mut stream: TcpStream) -> Result<()> {
    stream.set_nodelay(true)?;
    let mut magic = [0_u8; MAGIC.len()];
    stream.read_exact(&mut magic).await?;
    if magic != MAGIC {
        bail!("invalid benchmark protocol magic");
    }
    match stream.read_u8().await? {
        OP_FIRST_BYTE => {
            // The peer sent only nine bytes. Explicitly flushing makes this a
            // direct test of partial-record forwarding in the tunnel.
            stream.write_u8(FIRST_BYTE_REPLY).await?;
            stream.flush().await?;
        }
        OP_STREAM => {
            let (mut reader, mut writer) = stream.into_split();
            // The client is writing and reading concurrently. Copying each
            // received chunk straight back therefore creates a full-duplex
            // 64 MiB-per-direction transfer without a complete-message buffer.
            tokio::io::copy(&mut reader, &mut writer).await?;
        }
        operation => bail!("unknown benchmark operation {operation}"),
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
pub struct EndpointReport {
    pub connection_setup_p95_us: u128,
    pub first_byte_p95_us: u128,
    pub first_byte_samples_us: Vec<u128>,
    pub stream_sent_bytes: u64,
    pub stream_received_bytes: u64,
    pub stream_elapsed_us: u128,
    pub bidirectional_throughput_bytes_per_second: f64,
}

pub fn endpoint_report(samples: &[EndpointSample], stream: StreamSample) -> Result<EndpointReport> {
    if samples.is_empty() {
        bail!("at least one first-byte sample is required");
    }
    Ok(EndpointReport {
        connection_setup_p95_us: percentile_95(
            &samples
                .iter()
                .map(|sample| sample.connection_setup)
                .collect::<Vec<_>>(),
        )
        .as_micros(),
        first_byte_p95_us: percentile_95(
            &samples
                .iter()
                .map(|sample| sample.first_byte)
                .collect::<Vec<_>>(),
        )
        .as_micros(),
        first_byte_samples_us: samples
            .iter()
            .map(|sample| sample.first_byte.as_micros())
            .collect(),
        stream_sent_bytes: stream.sent_bytes,
        stream_received_bytes: stream.received_bytes,
        stream_elapsed_us: stream.elapsed.as_micros(),
        bidirectional_throughput_bytes_per_second: stream
            .bidirectional_throughput_bytes_per_second()?,
    })
}

pub fn compare_p95_us(direct: u128, tunnel: u128) -> i128 {
    match tunnel.cmp(&direct) {
        Ordering::Greater | Ordering::Equal => (tunnel - direct) as i128,
        Ordering::Less => -((direct - tunnel) as i128),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nearest_rank_p95_uses_an_observed_sample() {
        let samples = (1..=20).map(Duration::from_millis).collect::<Vec<_>>();
        assert_eq!(percentile_95(&samples), Duration::from_millis(19));
    }

    #[test]
    fn throughput_rejects_zero_duration() {
        assert!(throughput_bytes_per_second(1, Duration::ZERO).is_err());
    }
}
