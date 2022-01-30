use criterion::{/*black_box,*/ criterion_group, criterion_main, Criterion};

use adlt::dlt::*;
use adlt::utils::hex_to_bytes;

pub fn dlt_bench1(c: &mut Criterion) {
    let v = hex_to_bytes("3d 0a 00 af 4d 4d 4d 41 00 00 03 48 00 75 7d 16 41 08 4c 52 4d 46 55 44 53 00 00 82 00 00 1c 00 46 69 6e 61 6c 20 61 6e 73 77 65 72 20 61 72 72 69 76 65 64 20 61 66 74 65 72 20 00 23 00 00 00 93 01 00 00 00 82 00 00 21 00 75 73 20 66 72 6f 6d 20 74 68 65 20 6a 6f 62 20 68 61 6e 64 6c 65 72 20 5b 73 74 61 74 65 3a 20 00 00 82 00 00 0a 00 41 6e 73 77 65 72 69 6e 67 00 00 82 00 00 0b 00 2c 20 61 6e 73 77 65 72 3a 20 00 10 00 00 00 01 00 82 00 00 10 00 5d 20 66 6f 72 20 72 65 71 75 65 73 74 20 23 00 43 00 00 00 dc 05 00 00").unwrap();
    c.bench_function("dlt_args1", |b|b.iter(|| {
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
            assert_eq!(m.noar(), 8);
            let args = m.into_iter();
            assert_eq!(args.count(), 8);
            assert_eq!(m.payload_as_text().unwrap(), "Final answer arrived after  403 us from the job handler [state:  Answering , answer:  true ] for request # 1500");
        }));
}

criterion_group!(dlt_benches, dlt_bench1);
criterion_main!(dlt_benches);
