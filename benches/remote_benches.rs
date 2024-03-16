use criterion::{criterion_group, criterion_main, Criterion};
use slog::{o, Drain, Logger};

use adlt::{
    dlt::{DltChar4, DltMessage, DltStandardHeader},
    utils::remote_utils::{process_stream_new_msgs, StreamContext},
};
const DLT_STD_HDR_HAS_TIMESTAMP: u8 = 1 << 4;

fn new_logger() -> Logger {
    let decorator = slog_term::PlainSyncDecorator::new(slog_term::TestStdoutWriter);
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    Logger::root(drain, o!())
}
fn msg_for_test(index: u32) -> DltMessage {
    let timestamp_us = 100u64 * (1 + index as u64);
    DltMessage {
        index,
        reception_time_us: 100_000 + timestamp_us,
        ecu: if index % 2 == 0 {
            DltChar4::from_buf(b"ECU0")
        } else {
            DltChar4::from_buf(b"ECU1")
        },
        timestamp_dms: (timestamp_us / 100) as u32,
        standard_header: DltStandardHeader {
            htyp: DLT_STD_HDR_HAS_TIMESTAMP,
            len: 0,
            mcnt: 0,
        },
        extended_header: None,
        payload: [].to_vec(),
        payload_text: None,
        lifecycle: 0,
    }
}
pub fn process_stream_new_msgs_query(c: &mut Criterion) {
    let mut group = c.benchmark_group("process_stream_new_msgs_query");
    group.bench_function("query", |b| {
        let mut msgs = vec![];
        for i in 1..=100_000 {
            msgs.push(msg_for_test(i as u32));
        }
        b.iter(|| {
            let log = new_logger();
            let mut sc = StreamContext::from(
                &log,
                "query",
                r#"{"filters":[{"type":0,"ecu":"ECU0|NA"}],"window":[0,10000]}"#,
            )
            .unwrap();
            assert!(!sc.is_stream);
            process_stream_new_msgs(&mut sc, 0, &msgs[0..], 3_000_000);
            assert_eq!(sc.filtered_msgs.len(), 10_000);
            for (idx, val) in sc.filtered_msgs.iter().enumerate() {
                assert_eq!(*val, (idx * 2) + 1, "#{} = {}", idx, val);
            }
        })
    });
    group.bench_function("stream", |b| {
        let mut msgs = vec![];
        for i in 1..=100_000 {
            msgs.push(msg_for_test(i as u32));
        }
        b.iter(|| {
            let log = new_logger();
            let mut sc = StreamContext::from(
                &log,
                "stream",
                r#"{"filters":[{"type":0,"ecu":"ECU0"}],"window":[0,10000]}"#,
            )
            .unwrap();
            assert!(sc.is_stream);
            process_stream_new_msgs(&mut sc, 0, &msgs[0..], 3_000_000);
            assert_eq!(sc.filtered_msgs.len(), 50_000);
            for (idx, val) in sc.filtered_msgs.iter().enumerate() {
                assert_eq!(*val, (idx * 2) + 1, "#{} = {}", idx, val);
            }
        })
    });
    group.finish();
}

criterion_group!(remote_benches, process_stream_new_msgs_query);
criterion_main!(remote_benches);
