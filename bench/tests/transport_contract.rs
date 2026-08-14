use std::time::Duration;

use codex_tunnel_bench::{
    BENCHMARK_BYTES, SMALL_FLUSH_REQUEST_BYTES, first_byte_sample, serve, stream_sample,
};
use tokio::{net::TcpListener, time::timeout};

const _: () = assert!(SMALL_FLUSH_REQUEST_BYTES < 16 * 1024);

#[tokio::test]
async fn responder_exercises_a_prompt_small_write_and_a_64_mib_bidirectional_stream() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let endpoint = listener.local_addr().expect("address");
    let responder = tokio::spawn(serve(listener));

    let first = timeout(Duration::from_secs(2), first_byte_sample(endpoint))
        .await
        .expect("first byte did not arrive promptly")
        .expect("first-byte sample");
    assert!(first.first_byte < Duration::from_secs(2));
    let stream = timeout(Duration::from_secs(10), stream_sample(endpoint))
        .await
        .expect("stream timed out")
        .expect("stream sample");
    assert_eq!(stream.sent_bytes, BENCHMARK_BYTES);
    assert_eq!(stream.received_bytes, BENCHMARK_BYTES);
    assert!(
        stream
            .bidirectional_throughput_bytes_per_second()
            .expect("throughput")
            > 0.0
    );

    responder.abort();
}
