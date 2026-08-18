# Release benchmarking

This is a production-release gate, not a claim about an unmeasured build. The
benchmark harness writes a fresh JSON evidence file only after both paths have
been measured. The result is deliberately not committed: pass a path in an
operator-controlled release-evidence directory, and retain the resulting JSON
with the release notes.

## What is compared

Use the same client hardware, remote-host hardware, route, tunnel
configuration, and test responder for both paths:

```text
direct client -> compatibility-service benchmark endpoint
tunnel client -> Noise/TLS tunnel -> same compatibility-service benchmark endpoint
```

The endpoint implements only a temporary benchmark protocol; it is not
reachable through the production public service and is removed after the
measurement. For the tunnel path, configure the ingress's existing fixed
loopback destination to this responder for the measurement. For the direct
path, make that *same* endpoint available through a controlled direct route.
Do not compare different destination machines or use a public Internet route
as the direct private-LAN baseline.

The current compatibility service does not expose this protocol. Consequently,
the `serve` command is a staging responder for the tunnel transport's required
64 MiB byte-stream and small-flush checks. It is not evidence that the live
application compatibility deployment has met every release gate; production evidence
must use a controlled, release-approved benchmark endpoint on that deployment.

## Repeatable invocation

Build the exact release candidate first, not a debug binary:

```sh
cargo build --release -p secure-tunnel-bench
```

On the remote host, start the temporary responder at the fixed loopback port
configured as the ingress destination for this measurement:

```sh
./target/release/secure-tunnel-bench serve --listen 127.0.0.1:19090
```

Start the tunnel server/client with their release configuration. Arrange the
controlled direct route and the local tunnel listener, then run the client-host
command with explicit endpoints and an out-of-tree output path:

```sh
./target/release/secure-tunnel-bench run \
  --direct DIRECT_BENCHMARK_HOST:PORT \
  --tunnel 127.0.0.1:18787 \
  --samples 20 \
  --timeout-seconds 30 \
  --hardware-note 'client: …; remote: …; route: private LAN; build: SHA-256 …' \
  --output /var/tmp/secure-tunnel-release-evidence/release-YYYYMMDD.json
```

`run` refuses to overwrite an evidence file. It performs, on **each** path:

* 20 independent 9-byte request/one-byte response exchanges. Each request and
  response is explicitly flushed; p95 is the nearest-rank observed sample.
  TCP connection setup p95 is retained separately from first-byte p95.
* One persistent connection that concurrently sends and receives exactly
  67,108,864 bytes (64 MiB) in each direction. Throughput is the sum of both
  directions divided by the elapsed wall time.

The JSON includes raw first-byte samples, p95 values, throughput values, the
tunnel/direct throughput ratio, and automated latency/throughput gate outcomes.
It does not invent a memory result: without RSS inputs its memory status is
`not_measured` and its memory gate is `null`.

## Memory method

Measure steady-state, tunnel-owned process memory as the combined resident set
size (RSS) of the tunnel client and tunnel ingress. Capture each value after a
30-second settling interval and use the median of five samples taken one second
apart. Keep the compatibility service and the temporary responder out of the
sum; they belong to both paths and are not tunnel-owned.

1. Start the release tunnel processes and wait 30 seconds with no benchmark
   connections. On each host, run `secure-tunnel-bench rss --pid PID` five times;
   sum corresponding client and ingress samples, then retain the median as
   `BASELINE_KIB`.
2. Hold `N` persistent tunnel benchmark connections active for at least 30
   seconds (use a load controller that retains the streams; do not use a short
   completed transfer). Repeat the same five combined RSS samples and retain
   their median as `ACTIVE_KIB`.
3. Record those values with the result:

```sh
./target/release/secure-tunnel-bench run ... \
  --memory-baseline-rss-kib BASELINE_KIB \
  --memory-active-rss-kib ACTIVE_KIB \
  --memory-active-connections N
```

The harness records `(ACTIVE_KIB - BASELINE_KIB) / N` and evaluates the 1 MiB
(1024 KiB) per active connection gate. It rejects an active RSS below baseline,
rather than turning it into a misleading negative allocation. On Linux `rss`
reads `/proc/PID/status` `VmRSS`; on macOS it uses `ps -o rss=`. Record the
operating system, process PIDs, `N`, five raw samples, and median calculation in
the release notes alongside the JSON; the JSON records only the supplied median
inputs.

## CPU method

CPU has no numeric release threshold in §39, but it is still required release
evidence. During the same `N`-connection steady-state window used for RSS,
record five one-second process CPU samples for the tunnel client and ingress;
report the per-process samples and their combined mean in the release notes.
On Linux use `pidstat -u -p CLIENT_PID,INGRESS_PID 1 5`; on macOS use the
corresponding per-process sample in Activity Monitor or `top -pid`. Do not
substitute overall-host CPU: unrelated work makes it neither comparable nor
tunnel-owned. The harness intentionally does not synthesize CPU usage from its
short transfer duration.

## Release decision

For the private-LAN baseline, approve only when the evidence shows:

```text
p95(tunnel first-byte) - p95(direct first-byte) <= 10 ms
tunnel bidirectional throughput / direct throughput >= 0.90
tunnel-owned RSS delta / active connection <= 1 MiB
```

If hardware or route differs materially, retain the normal baseline and record
the changed threshold plus an explicit release decision. A missing measurement,
a `null` memory gate, or any false gate means the benchmark requirement is not
complete.

The runnable unit and loopback contract tests are deterministic and suitable
for CI. The numeric release gates intentionally are not CI assertions: their
values are hardware- and route-dependent, and a CI result would be fabricated
release evidence.
