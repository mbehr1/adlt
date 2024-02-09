use criterion::{
    /*black_box,*/ criterion_group, criterion_main, BenchmarkId, Criterion, Throughput,
};
use criterion::{AxisScale, PlotConfiguration};
use std::fs::File;
use std::io::prelude::*;
use std::io::BufWriter;
use tempfile::NamedTempFile;

use adlt::{
    dlt::*,
    dlt_args,
    utils::{
        sorting_multi_readeriterator::{SequentialMultiIterator, SortingMultiReaderIterator},
        *,
    },
};

pub fn dlt_bench_is_storage_header_pattern(c: &mut Criterion) {
    let pat1 = [b'D', b'L', b'T', 1u8];
    let pat2 = [b'D', b'L', b'T', 2u8];
    let pat3 = [b'D', b'L', b'T', 2u8, b'D', b'L', b'T', 1u8];

    c.bench_function("is_storage_header_pattern", |b| {
        b.iter(|| {
            assert!(is_storage_header_pattern(&pat1));
            assert!(!is_storage_header_pattern(&pat1[1..]));
            assert!(!is_storage_header_pattern(&pat1[..3]));
            assert!(!is_storage_header_pattern(&pat2));
            assert!(!is_storage_header_pattern(&pat3));
            assert!(is_storage_header_pattern(&pat3[4..]));
        })
    });
}

pub fn dlt_bench_buf_as_hex_to_write(c: &mut Criterion) {
    let mut buf = [0u8; 2048];
    for (i, c) in buf.iter_mut().enumerate() {
        *c = (i % 256) as u8;
    }

    c.bench_function("buf_as_hex_to_write", |b| {
        b.iter(|| {
            let mut v = Vec::with_capacity(buf.len() * 3);
            assert!(buf_as_hex_to_io_write(&mut v, &buf).is_ok());
            assert_eq!(hex_to_bytes(&String::from_utf8_lossy(&v)).unwrap(), buf);

            let mut s = String::with_capacity(buf.len() * 3);
            assert!(buf_as_hex_to_write(&mut s, &buf).is_ok());
            assert_eq!(hex_to_bytes(&s).unwrap(), buf);
        })
    });
}

pub fn dlt_header_as_text_to_write(c: &mut Criterion) {
    let v = hex_to_bytes("3d 0a 00 af 4d 4d 4d 41 00 00 03 48 00 75 7d 16 41 08 4c 52 4d 46 55 44 53 00 00 82 00 00 1c 00 46 69 6e 61 6c 20 61 6e 73 77 65 72 20 61 72 72 69 76 65 64 20 61 66 74 65 72 20 00 23 00 00 00 93 01 00 00 00 82 00 00 21 00 75 73 20 66 72 6f 6d 20 74 68 65 20 6a 6f 62 20 68 61 6e 64 6c 65 72 20 5b 73 74 61 74 65 3a 20 00 00 82 00 00 0a 00 41 6e 73 77 65 72 69 6e 67 00 00 82 00 00 0b 00 2c 20 61 6e 73 77 65 72 3a 20 00 10 00 00 00 01 00 82 00 00 10 00 5d 20 66 6f 72 20 72 65 71 75 65 73 74 20 23 00 43 00 00 00 dc 05 00 00").unwrap();
    let sh = DltStorageHeader {
        secs: (1640995200000000 / adlt::utils::US_PER_SEC) as u32,
        micros: 471815,
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

    c.bench_function("header_as_text_to_write", |b| {
        b.iter(|| {
            let v = Vec::with_capacity(1024);
            let mut writer = BufWriter::new(v);

            assert!(m.header_as_text_to_write(&mut writer).is_ok());
        })
    });
}

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

pub fn dlt_bench2(c: &mut Criterion) {
    // create a test file with 1M DLT messages:
    let mut file = NamedTempFile::new().unwrap();
    let file_path = String::from(file.path().to_str().unwrap());

    let persisted_msgs: adlt::dlt::DltMessageIndexType = 1_000_000;
    let ecu = DltChar4::from_buf(b"ECU1");
    for i in 0..persisted_msgs {
        let sh = adlt::dlt::DltStorageHeader {
            secs: (1640995200000000 / US_PER_SEC) as u32, // 1.1.22, 00:00:00 as GMT
            micros: 0,
            ecu,
        };
        let standard_header = adlt::dlt::DltStandardHeader {
            htyp: 1 << 5, // vers 1
            mcnt: (i % 256) as u8,
            len: 4,
        };

        let m = adlt::dlt::DltMessage::from_headers(i, sh, standard_header, &[], vec![]);
        m.to_write(&mut file).unwrap(); // will persist with timestamp
    }
    file.flush().unwrap();
    let file_size = std::fs::metadata(&file_path).unwrap().len();

    // benchmark opening the file, reading the content and parsing the header:
    let mut group = c.benchmark_group("dlt_parse");
    // group.measurement_time(dur)
    group.sample_size(10);
    for buf_capacity in [
        128 * 1024,
        256 * 1024,
        512 * 1024,
        1024 * 1024,
        2 * 1024 * 1024,
        4 * 1024 * 1024,
    ]
    .iter()
    {
        group.throughput(Throughput::Bytes(file_size));
        group.bench_with_input(
            BenchmarkId::from_parameter(buf_capacity),
            buf_capacity,
            |b, &buf_capacity| {
                b.iter(|| {
                    let fi = File::open(&file_path).unwrap();
                    let mut buf_reader =
                        LowMarkBufReader::new(fi, buf_capacity, DLT_MAX_STORAGE_MSG_SIZE);
                    let mut messages_processed = 0;
                    loop {
                        match parse_dlt_with_storage_header(
                            messages_processed,
                            buf_reader.fill_buf().unwrap(),
                        ) {
                            Ok((res, msg)) => {
                                buf_reader.consume(res);
                                messages_processed += 1;
                                drop(msg);
                            }
                            Err(error) => match error.kind() {
                                ErrorKind::InvalidData(_str) => {
                                    buf_reader.consume(1);
                                }
                                _ => {
                                    break;
                                }
                            },
                        }
                    }
                    assert_eq!(persisted_msgs, messages_processed);
                })
            },
        );
    }
    group.finish();
}

pub fn dlt_iterator1(c: &mut Criterion) {
    // create a test file with 1M DLT messages:
    let mut file = NamedTempFile::new().unwrap();
    let file_path = String::from(file.path().to_str().unwrap());

    let persisted_msgs: adlt::dlt::DltMessageIndexType = 1_000_000;
    let ecu = DltChar4::from_buf(b"ECU1");
    for i in 0..persisted_msgs {
        let sh = adlt::dlt::DltStorageHeader {
            secs: (1640995200000000 / US_PER_SEC) as u32, // 1.1.22, 00:00:00 as GMT
            micros: 0,
            ecu,
        };
        let standard_header = adlt::dlt::DltStandardHeader {
            htyp: 1 << 5, // vers 1
            mcnt: (i % 256) as u8,
            len: 4,
        };

        let m = adlt::dlt::DltMessage::from_headers(i, sh, standard_header, &[], vec![]);
        m.to_write(&mut file).unwrap(); // will persist with timestamp
    }
    file.flush().unwrap();
    let file_size = std::fs::metadata(&file_path).unwrap().len();

    // benchmark opening the file, reading the content and parsing the header:
    let mut group = c.benchmark_group("dlt_iterator");
    // group.measurement_time(dur)
    group.sample_size(10);
    {
        let buf_capacity = 512 * 1024usize;
        group.throughput(Throughput::Bytes(file_size));
        group.bench_with_input(
            "get_dlt_message_iterator", // BenchmarkId::from_parameter(buf_capacity),
            &buf_capacity,
            |b, &buf_capacity| {
                b.iter(|| {
                    let namespace = get_new_namespace();
                    let fi = File::open(&file_path).unwrap();
                    let buf_reader =
                        LowMarkBufReader::new(fi, buf_capacity, DLT_MAX_STORAGE_MSG_SIZE);
                    let mut messages_processed = 0;
                    let mut it = get_dlt_message_iterator(
                        "dlt",
                        messages_processed,
                        buf_reader,
                        namespace,
                        None,
                        None,
                        None,
                    );
                    for msg in it.by_ref() {
                        messages_processed += 1;
                        drop(msg);
                    }
                    assert_eq!(persisted_msgs, messages_processed);
                })
            },
        );
        group.bench_with_input(
            "sorting_multi_readeriterator", // BenchmarkId::from_parameter(buf_capacity),
            &buf_capacity,
            |b, &buf_capacity| {
                b.iter(|| {
                    let namespace = get_new_namespace();
                    let fi = File::open(&file_path).unwrap();
                    let buf_reader =
                        LowMarkBufReader::new(fi, buf_capacity, DLT_MAX_STORAGE_MSG_SIZE);
                    let mut messages_processed = 0;
                    let it = get_dlt_message_iterator(
                        "dlt",
                        messages_processed,
                        buf_reader,
                        namespace,
                        None,
                        None,
                        None,
                    );
                    let it = SortingMultiReaderIterator::new(0, vec![it]);
                    for msg in it {
                        messages_processed += 1;
                        drop(msg);
                    }
                    assert_eq!(persisted_msgs, messages_processed);
                })
            },
        );
        group.bench_with_input(
            "sorting_multi_readeriterator_new_or_single_it", // BenchmarkId::from_parameter(buf_capacity),
            &buf_capacity,
            |b, &buf_capacity| {
                b.iter(|| {
                    let namespace = get_new_namespace();
                    let fi = File::open(&file_path).unwrap();
                    let buf_reader =
                        LowMarkBufReader::new(fi, buf_capacity, DLT_MAX_STORAGE_MSG_SIZE);
                    let mut messages_processed = 0;
                    let it = get_dlt_message_iterator(
                        "dlt",
                        messages_processed,
                        buf_reader,
                        namespace,
                        None,
                        None,
                        None,
                    );
                    let it = SortingMultiReaderIterator::new_or_single_it(0, vec![it]);
                    for msg in it {
                        messages_processed += 1;
                        drop(msg);
                    }
                    assert_eq!(persisted_msgs, messages_processed);
                })
            },
        );

        group.bench_with_input(
            "sequential_multi_iterator", // BenchmarkId::from_parameter(buf_capacity),
            &buf_capacity,
            |b, &buf_capacity| {
                b.iter(|| {
                    let files = vec![&file_path];
                    let namespace = get_new_namespace();
                    let its = files.into_iter().map(|file_name| {
                        let buf_reader = LowMarkBufReader::new(
                            File::open(file_name).unwrap(),
                            buf_capacity,
                            DLT_MAX_STORAGE_MSG_SIZE,
                        );
                        get_dlt_message_iterator("dlt", 0, buf_reader, namespace, None, None, None)
                    });

                    let it = SequentialMultiIterator::new(0, its);
                    let mut messages_processed = 0;
                    for msg in it {
                        messages_processed += 1;
                        drop(msg);
                    }
                    assert_eq!(persisted_msgs, messages_processed);
                })
            },
        );
        group.bench_with_input(
            "sequential_multi_iterator_new_or_single_it", // BenchmarkId::from_parameter(buf_capacity),
            &buf_capacity,
            |b, &buf_capacity| {
                b.iter(|| {
                    let files = vec![&file_path];
                    let namespace = get_new_namespace();
                    let its = files.into_iter().map(|file_name| {
                        let buf_reader = LowMarkBufReader::new(
                            File::open(file_name).unwrap(),
                            buf_capacity,
                            DLT_MAX_STORAGE_MSG_SIZE,
                        );
                        get_dlt_message_iterator("dlt", 0, buf_reader, namespace, None, None, None)
                    });

                    let it = SequentialMultiIterator::new_or_single_it(0, its);
                    let mut messages_processed = 0;
                    for msg in it {
                        messages_processed += 1;
                        drop(msg);
                    }
                    assert_eq!(persisted_msgs, messages_processed);
                })
            },
        );

        /* todo could try itertools::kmerge and apply/update (for the index) group.bench_with_input(
            "sorting_multi_readeriterator by kmerge", // BenchmarkId::from_parameter(buf_capacity),
            &buf_capacity,
            |b, &buf_capacity| {
                b.iter(|| {
                    let namespace = get_new_namespace();
                    let fi = File::open(&file_path).unwrap();
                    let buf_reader =
                        LowMarkBufReader::new(fi, buf_capacity, DLT_MAX_STORAGE_MSG_SIZE);
                    let mut messages_processed = 0;
                    let it = get_dlt_message_iterator(
                        "dlt",
                        messages_processed,
                        buf_reader,
                        namespace,
                        None,
                    );
                    let it = vec![it].into_iter().kmerge();
                    for msg in it {
                        messages_processed += 1;
                        drop(msg);
                    }
                    assert_eq!(persisted_msgs, messages_processed);
                })
            },
        );*/
    }
    group.finish();
}

/// bench the payload_as_text method for verbose messages
fn dlt_payload_verb(c: &mut Criterion) {
    let mut group = c.benchmark_group("dlt_payload_verb");
    group.sample_size(20);
    let plot_config = PlotConfiguration::default().summary_scale(AxisScale::Logarithmic);
    group.plot_config(plot_config);
    for nr_args in [0, 8, 16, 32, 64, 128, 0xff - 8].iter() {
        let mut payloads = Vec::with_capacity(*nr_args);
        let mut got_nr_args = 0usize;
        while got_nr_args < *nr_args {
            let (noar, payload) = dlt_args!(
                nr_args % 2 == 0,
                42u8,
                0x4243u16,
                -0x42434445i32,
                0x4243444546474849u64,
                "floats coming",
                1.0_f32,
                -2.0_f64
            )
            .unwrap();
            payloads.push(payload);
            got_nr_args += noar as usize;
        }
        let m = DltMessage {
            index: 0,
            reception_time_us: 0,
            ecu: DltChar4::from_buf(b"ECU1"),
            timestamp_dms: 0,
            standard_header: DltStandardHeader {
                htyp: if cfg!(target_endian = "big") {
                    0x20 | 0x02
                } else {
                    0x20_u8
                }, // little end
                len: 100,
                mcnt: 0,
            },
            extended_header: Some(DltExtendedHeader {
                verb_mstp_mtin: 1,
                noar: got_nr_args as u8,
                apid: DltChar4::from_buf(b"APID"),
                ctid: DltChar4::from_buf(b"CTID"),
            }),
            lifecycle: 0,
            payload: payloads.into_iter().flatten().collect(),
            payload_text: None,
        };
        assert_eq!(m.noar() as usize, got_nr_args);
        // let args = m.into_iter();
        group.bench_function(BenchmarkId::from_parameter(*nr_args + 1), |b| {
            b.iter(|| {
                let text = m.payload_as_text();
                assert!(text.is_ok());
            })
        });
    }
}

/// bench the payload_as_text method for verbose messages
fn dlt_payload_nonverb(c: &mut Criterion) {
    let mut group = c.benchmark_group("dlt_payload_nonverb");
    //group.sample_size(10);
    group.warm_up_time(std::time::Duration::new(1, 0));
    group.measurement_time(std::time::Duration::new(2, 0));
    let plot_config = PlotConfiguration::default().summary_scale(AxisScale::Logarithmic);
    group.plot_config(plot_config);
    for payload_len in [0u16, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 0xffff - 4].iter() {
        let mut payloads = Vec::with_capacity(2);
        let message_id: u32 = 0xf0000000 + *payload_len as u32;
        payloads.push(message_id.to_be_bytes().to_vec());
        payloads.push(vec![0u8; *payload_len as usize]);
        let m = DltMessage {
            index: 0,
            reception_time_us: 0,
            ecu: DltChar4::from_buf(b"ECU1"),
            timestamp_dms: 0,
            standard_header: DltStandardHeader {
                htyp: 0x20 | 0x02, // big end
                len: 100,
                mcnt: 0,
            },
            extended_header: None,
            lifecycle: 0,
            payload: payloads.into_iter().flatten().collect(),
            payload_text: None,
        };
        // let args = m.into_iter();
        group.bench_function(BenchmarkId::new("random", *payload_len + 1), |b| {
            b.iter(|| {
                let text = m.payload_as_text();
                assert!(text.is_ok());
            })
        });
        let mut payloads = Vec::with_capacity(2);
        let message_id: u32 = 0xf0000000 + *payload_len as u32;
        payloads.push(message_id.to_be_bytes().to_vec());
        payloads.push(vec![b'A'; *payload_len as usize]);
        let m = DltMessage {
            index: 0,
            reception_time_us: 0,
            ecu: DltChar4::from_buf(b"ECU1"),
            timestamp_dms: 0,
            standard_header: DltStandardHeader {
                htyp: 0x20 | 0x02, // big end
                len: 100,
                mcnt: 0,
            },
            extended_header: None,
            lifecycle: 0,
            payload: payloads.into_iter().flatten().collect(),
            payload_text: None,
        };
        // let args = m.into_iter();
        group.bench_function(BenchmarkId::new("ascii_only", *payload_len + 1), |b| {
            b.iter(|| {
                let text = m.payload_as_text();
                assert!(text.is_ok());
            })
        });
    }
}

criterion_group!(
    dlt_benches,
    dlt_iterator1,
    dlt_bench_is_storage_header_pattern,
    dlt_bench_buf_as_hex_to_write,
    dlt_header_as_text_to_write,
    dlt_bench1,
    dlt_bench2,
    dlt_payload_verb,
    dlt_payload_nonverb
);
criterion_main!(dlt_benches);
