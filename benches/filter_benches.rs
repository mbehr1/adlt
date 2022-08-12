use criterion::{/*black_box,*/ criterion_group, criterion_main, Criterion};

use adlt::{
    dlt::{DltChar4, DltMessage, DltStandardHeader, DltStorageHeader, DLT_MIN_STD_HEADER_SIZE},
    filter::Filter,
    utils::hex_to_bytes,
};

pub fn filter_from_json(c: &mut Criterion) {
    c.bench_function("filter_from_json", |b| {
        b.iter(|| {
            let f =
                Filter::from_json(r#"{"type": 0, "payload":"foo|^bla", "ignoreCasePayload":true}"#)
                    .unwrap();
            assert!(f.ignore_case_payload);
            let f = Filter::from_json(
                r#"{"type": 0, "payloadRegex":"(foo)|(bla)", "ignoreCasePayload":true}"#,
            )
            .unwrap();
            assert!(f.ignore_case_payload);
        })
    });
}

pub fn filter_payload_cs(c: &mut Criterion) {
    c.bench_function("filter_payload_cs", |b| {
        let v = hex_to_bytes("3d 0a 00 af 4d 4d 4d 41 00 00 03 48 00 75 7d 16 41 08 4c 52 4d 46 55 44 53 00 00 82 00 00 1c 00 46 69 6e 61 6c 20 61 6e 73 77 65 72 20 61 72 72 69 76 65 64 20 61 66 74 65 72 20 00 23 00 00 00 93 01 00 00 00 82 00 00 21 00 75 73 20 66 72 6f 6d 20 74 68 65 20 6a 6f 62 20 68 61 6e 64 6c 65 72 20 5b 73 74 61 74 65 3a 20 00 00 82 00 00 0a 00 41 6e 73 77 65 72 69 6e 67 00 00 82 00 00 0b 00 2c 20 61 6e 73 77 65 72 3a 20 00 10 00 00 00 01 00 82 00 00 10 00 5d 20 66 6f 72 20 72 65 71 75 65 73 74 20 23 00 43 00 00 00 dc 05 00 00").unwrap();
        let sh = DltStorageHeader {
            secs: 0,
            micros: 0,
            ecu: DltChar4::from_buf(b"ECU1"),
        };
        let stdh = DltStandardHeader::from_buf(&v).unwrap();
        let payload_offset = stdh.std_ext_header_size() as usize;
        let m = DltMessage::from_headers(
            1423084,
            sh,
            stdh,
            &v[DLT_MIN_STD_HEADER_SIZE..payload_offset],
            v[payload_offset..].to_vec(),
        );
        let f_m =
                Filter::from_json(r#"{"type": 0, "payload":"after  403 us", "ignoreCasePayload":false}"#)
                    .unwrap();
            assert!(!f_m.ignore_case_payload);
            let f_n =
            Filter::from_json(r#"{"type": 0, "payload":"after 403 us", "ignoreCasePayload":false}"#)
                .unwrap();
        assert!(!f_n.ignore_case_payload);

        b.iter(|| {
            assert!(f_m.matches(&m));
            assert!(!f_n.matches(&m));
        })
    });
}

pub fn filter_payload_ci(c: &mut Criterion) {
    c.bench_function("filter_payload_ci", |b| {
        let v = hex_to_bytes("3d 0a 00 af 4d 4d 4d 41 00 00 03 48 00 75 7d 16 41 08 4c 52 4d 46 55 44 53 00 00 82 00 00 1c 00 46 69 6e 61 6c 20 61 6e 73 77 65 72 20 61 72 72 69 76 65 64 20 61 66 74 65 72 20 00 23 00 00 00 93 01 00 00 00 82 00 00 21 00 75 73 20 66 72 6f 6d 20 74 68 65 20 6a 6f 62 20 68 61 6e 64 6c 65 72 20 5b 73 74 61 74 65 3a 20 00 00 82 00 00 0a 00 41 6e 73 77 65 72 69 6e 67 00 00 82 00 00 0b 00 2c 20 61 6e 73 77 65 72 3a 20 00 10 00 00 00 01 00 82 00 00 10 00 5d 20 66 6f 72 20 72 65 71 75 65 73 74 20 23 00 43 00 00 00 dc 05 00 00").unwrap();
        let sh = DltStorageHeader {
            secs: 0,
            micros: 0,
            ecu: DltChar4::from_buf(b"ECU1"),
        };
        let stdh = DltStandardHeader::from_buf(&v).unwrap();
        let payload_offset = stdh.std_ext_header_size() as usize;
        let m = DltMessage::from_headers(
            1423084,
            sh,
            stdh,
            &v[DLT_MIN_STD_HEADER_SIZE..payload_offset],
            v[payload_offset..].to_vec(),
        );
        let f_m =
                Filter::from_json(r#"{"type": 0, "payload":"After  403 us", "ignoreCasePayload":true}"#)
                    .unwrap();
            assert!(f_m.ignore_case_payload);
            let f_n =
            Filter::from_json(r#"{"type": 0, "payload":"After 403 us", "ignoreCasePayload":true}"#)
                .unwrap();
        assert!(f_n.ignore_case_payload);

        b.iter(|| {
            assert!(f_m.matches(&m));
            assert!(!f_n.matches(&m));
        })
    });
}

pub fn filter_payload_regex_cs(c: &mut Criterion) {
    c.bench_function("filter_payload_regex_cs", |b| {
        let v = hex_to_bytes("3d 0a 00 af 4d 4d 4d 41 00 00 03 48 00 75 7d 16 41 08 4c 52 4d 46 55 44 53 00 00 82 00 00 1c 00 46 69 6e 61 6c 20 61 6e 73 77 65 72 20 61 72 72 69 76 65 64 20 61 66 74 65 72 20 00 23 00 00 00 93 01 00 00 00 82 00 00 21 00 75 73 20 66 72 6f 6d 20 74 68 65 20 6a 6f 62 20 68 61 6e 64 6c 65 72 20 5b 73 74 61 74 65 3a 20 00 00 82 00 00 0a 00 41 6e 73 77 65 72 69 6e 67 00 00 82 00 00 0b 00 2c 20 61 6e 73 77 65 72 3a 20 00 10 00 00 00 01 00 82 00 00 10 00 5d 20 66 6f 72 20 72 65 71 75 65 73 74 20 23 00 43 00 00 00 dc 05 00 00").unwrap();
        let sh = DltStorageHeader {
            secs: 0,
            micros: 0,
            ecu: DltChar4::from_buf(b"ECU1"),
        };
        let stdh = DltStandardHeader::from_buf(&v).unwrap();
        let payload_offset = stdh.std_ext_header_size() as usize;
        let m = DltMessage::from_headers(
            1423084,
            sh,
            stdh,
            &v[DLT_MIN_STD_HEADER_SIZE..payload_offset],
            v[payload_offset..].to_vec(),
        );
        let f_m =
                Filter::from_json(r#"{"type": 0, "payloadRegex":"after  (\\d+) us", "ignoreCasePayload":false}"#)
                    .unwrap();
            assert!(!f_m.ignore_case_payload);
            let f_n =
            Filter::from_json(r#"{"type": 0, "payloadRegex":"after (\\d+) us", "ignoreCasePayload":false}"#)
                .unwrap();
        assert!(!f_n.ignore_case_payload);

        b.iter(|| {
            assert!(f_m.matches(&m));
            assert!(!f_n.matches(&m));
        })
    });
}

pub fn filter_payload_regex_ci(c: &mut Criterion) {
    c.bench_function("filter_payload_regex_ci", |b| {
        let v = hex_to_bytes("3d 0a 00 af 4d 4d 4d 41 00 00 03 48 00 75 7d 16 41 08 4c 52 4d 46 55 44 53 00 00 82 00 00 1c 00 46 69 6e 61 6c 20 61 6e 73 77 65 72 20 61 72 72 69 76 65 64 20 61 66 74 65 72 20 00 23 00 00 00 93 01 00 00 00 82 00 00 21 00 75 73 20 66 72 6f 6d 20 74 68 65 20 6a 6f 62 20 68 61 6e 64 6c 65 72 20 5b 73 74 61 74 65 3a 20 00 00 82 00 00 0a 00 41 6e 73 77 65 72 69 6e 67 00 00 82 00 00 0b 00 2c 20 61 6e 73 77 65 72 3a 20 00 10 00 00 00 01 00 82 00 00 10 00 5d 20 66 6f 72 20 72 65 71 75 65 73 74 20 23 00 43 00 00 00 dc 05 00 00").unwrap();
        let sh = DltStorageHeader {
            secs: 0,
            micros: 0,
            ecu: DltChar4::from_buf(b"ECU1"),
        };
        let stdh = DltStandardHeader::from_buf(&v).unwrap();
        let payload_offset = stdh.std_ext_header_size() as usize;
        let m = DltMessage::from_headers(
            1423084,
            sh,
            stdh,
            &v[DLT_MIN_STD_HEADER_SIZE..payload_offset],
            v[payload_offset..].to_vec(),
        );
        let f_m =
                Filter::from_json(r#"{"type": 0, "payloadRegex":"After  (\\d+) us", "ignoreCasePayload":true}"#)
                    .unwrap();
            assert!(f_m.ignore_case_payload);
            let f_n =
            Filter::from_json(r#"{"type": 0, "payloadRegex":"After (\\d+) us", "ignoreCasePayload":true}"#)
                .unwrap();
        assert!(f_n.ignore_case_payload);

        b.iter(|| {
            assert!(f_m.matches(&m));
            assert!(!f_n.matches(&m));
        })
    });
}

criterion_group!(
    filter_benches,
    filter_from_json,
    filter_payload_cs,
    filter_payload_ci,
    filter_payload_regex_cs,
    filter_payload_regex_ci
);
criterion_main!(filter_benches);
