use std::time::Duration;

use secure_tunnel_bench::{
    BENCHMARK_BYTES, memory_per_active_connection_kib, percentile_95, throughput_bytes_per_second,
};

#[test]
fn benchmark_contract_is_exactly_64_mib_and_reports_p95_and_throughput() {
    assert_eq!(BENCHMARK_BYTES, 64 * 1024 * 1024);
    assert_eq!(
        percentile_95(&[Duration::from_millis(1); 20]),
        Duration::from_millis(1)
    );
    assert_eq!(
        throughput_bytes_per_second(1024, Duration::from_secs(2)).expect("valid duration"),
        512.0
    );
}

#[test]
fn memory_contract_uses_combined_rss_delta_per_active_connection() {
    assert_eq!(
        memory_per_active_connection_kib(10_000, 14_096, 4).expect("RSS delta"),
        1024.0
    );
    assert!(memory_per_active_connection_kib(10_001, 10_000, 1).is_err());
    assert!(memory_per_active_connection_kib(10_000, 10_001, 0).is_err());
}
