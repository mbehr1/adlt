use std::fs::File;
use std::io::Read;
use std::io::Seek;

use adlt::utils::eac_stats::EacStats;
use criterion::{
    /*black_box,*/ criterion_group, criterion_main, BenchmarkId, Criterion, Throughput,
};

use adlt::dlt::*;
use adlt::utils::*;

pub fn eac_stats1(c: &mut Criterion) {
    let persisted_msgs: adlt::dlt::DltMessageIndexType = 1_000_000;
    let ecus = vec![
        DltChar4::from_buf(b"ECU1"),
        DltChar4::from_buf(b"AECU"),
        DltChar4::from_buf(b"ZEC2"),
    ];

    let apids = vec![
        DltChar4::from_buf(b"api1"),
        DltChar4::from_buf(b"api2"),
        DltChar4::from_buf(b"api3"),
        DltChar4::from_buf(b"api4"),
        DltChar4::from_buf(b"api5"),
        DltChar4::from_buf(b"api6"),
        DltChar4::from_buf(b"api7"),
        //DltChar4::from_buf(b"api8"),
        //DltChar4::from_buf(b"api9"),
    ];

    let ctids = vec![
        DltChar4::from_buf(b"cti1"),
        DltChar4::from_buf(b"cti2"),
        DltChar4::from_buf(b"cti3"),
        DltChar4::from_buf(b"cti4"),
        DltChar4::from_buf(b"cti5"),
        DltChar4::from_buf(b"cti6"),
        DltChar4::from_buf(b"cti7"),
        DltChar4::from_buf(b"cti8"),
        DltChar4::from_buf(b"cti9"),
        DltChar4::from_buf(b"ctiA"),
        DltChar4::from_buf(b"ctiB"),
    ];

    let mut msgs = Vec::with_capacity(persisted_msgs as usize);
    for i in 0..persisted_msgs {
        let sh = adlt::dlt::DltStorageHeader {
            secs: (1640995200000000 / US_PER_SEC) as u32, // 1.1.22, 00:00:00 as GMT
            micros: 0,
            ecu: ecus[i as usize % ecus.len()],
        };
        let standard_header = adlt::dlt::DltStandardHeader {
            htyp: 1 << 5, // vers 1
            mcnt: (i % 256) as u8,
            len: 4,
        };

        let ext_header = DltExtendedHeader {
            verb_mstp_mtin: 0,
            noar: 0,
            apid: apids[i as usize % apids.len()],
            ctid: ctids[i as usize % ctids.len()],
        };

        let mut m = adlt::dlt::DltMessage::from_headers(i, sh, standard_header, &[], vec![]);
        m.extended_header = Some(ext_header);
        msgs.push(m);
    }

    let mut group = c.benchmark_group("eac_stats");
    group.sample_size(10);
    group.throughput(Throughput::Elements(persisted_msgs as u64));
    group.bench_function(BenchmarkId::from_parameter(persisted_msgs), |b| {
        b.iter(|| {
            let mut eac_stats = EacStats::new();
            for m in &msgs {
                eac_stats.add_msg(m);
            }
            assert_eq!(eac_stats.ecu_map.len(), ecus.len());
            assert_eq!(
                eac_stats.ecu_map.get(&ecus[0]).unwrap().apids.len(),
                apids.len()
            );
        })
    });
    group.finish();
}

pub fn asc_iterator1(c: &mut Criterion) {
    let path = std::path::Path::new("./tests/can_example1.asc");
    let mut fi = File::open(path).ok().unwrap();
    let mut buf = vec![0u8; 10 * 1024usize];
    let read_size = fi.read(&mut buf).unwrap();
    let expected_msgs = 101_u64;
    let mut group = c.benchmark_group("asc_iterator");
    group.throughput(Throughput::Elements(expected_msgs));
    group.bench_function("asc_iterator 10k", |b| {
        let namespace = get_new_namespace();
        b.iter(|| {
            let mut it = Asc2DltMsgIterator::new(0, &buf[0..read_size], namespace, None, None);
            let mut iterated_msgs: u64 = 0;
            for _m in &mut it {
                iterated_msgs += 1;
                // todo verify payload println!("m={:?}", m);
            }
            assert_eq!(iterated_msgs, expected_msgs);
        })
    });
    group.finish();
}

pub fn file_info(c: &mut Criterion) {
    let path = std::path::Path::new("./tests/can_example1.asc");
    let mut fi = File::open(path).ok().unwrap();
    let read_size = 512 * 1024;
    let mut group = c.benchmark_group("get_dlt_infos_from_file");
    /*
    group.bench_function("get_first_message", |b| {
        let namespace = get_new_namespace();
        b.iter(|| {
            fi.rewind().unwrap();
            assert!(get_first_message_from_file("asc", &mut fi, read_size, namespace).is_some());
        });
    });*/
    group.bench_function("get_dlt_infos_from_file", |b| {
        let namespace = get_new_namespace();
        b.iter(|| {
            fi.rewind().unwrap();
            let dfi = get_dlt_infos_from_file("asc", &mut fi, read_size, namespace);
            assert!(dfi.is_ok());
            assert!(dfi.unwrap().first_msg.is_some());
        });
    });

    group.finish();
}

criterion_group!(util_benches, eac_stats1, asc_iterator1, file_info);
criterion_main!(util_benches);
