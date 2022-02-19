use std::sync::mpsc::Receiver;
use std::sync::mpsc::Sender;

use crate::dlt::DltChar4;
use crate::dlt::DltMessage;
use crate::dlt::Error;
use crate::dlt::ErrorKind;
use crate::filter::{Filter, FilterKind};

pub fn filter_as_streams(
    filters: &[Filter],
    input: &Receiver<DltMessage>,
    output: &Sender<DltMessage>,
) -> Result<(usize, usize), Error> {
    let mut passed: usize = 0;
    let mut filtered: usize = 0;

    // split filters into pos, neg
    let pos_filters: Vec<&Filter> = filters
        .iter()
        .filter(|f| f.enabled && f.kind == FilterKind::Positive)
        .collect();
    let neg_filters: Vec<&Filter> = filters
        .iter()
        .filter(|f| f.enabled && f.kind == FilterKind::Negative)
        .collect();

    loop {
        let recv = input.recv();
        if recv.is_err() {
            break;
        }
        let msg = recv.unwrap();

        // if we have no pos. filters we let it pass.
        let found_after_pos_filters: bool = if !pos_filters.is_empty() {
            // any matching pos filter adds the message
            pos_filters.iter().any(|f| f.matches(&msg))
        } else {
            true
        };
        let mut found_after_neg_filters: bool = found_after_pos_filters;
        if found_after_neg_filters && !neg_filters.is_empty() {
            // any matching neg filters removes the message
            found_after_neg_filters = !neg_filters.iter().any(|f| f.matches(&msg));
        }
        if found_after_neg_filters {
            match output.send(msg) {
                Err(msg2) => {
                    return Err(Error::new(ErrorKind::OtherFatal(format!(
                        "filter_as_stream: output.send failed sending msg {}",
                        msg2
                    ))))
                }
                _ => {
                    passed += 1;
                }
            }
        } else {
            filtered += 1;
        }
    }
    Ok((passed, filtered))
}

/// parse filters from a dlt-viewer compatible dlf file
///
/// The dlf file has to contain a 'dltfilter' element otherwise an error is returned.
pub fn filters_from_dlf<B: std::io::BufRead>(reader: B) -> Result<Vec<Filter>, quick_xml::Error> {
    let mut filters = Vec::new();
    let mut reader = quick_xml::Reader::from_reader(reader);
    reader.trim_text(false); // we dont want whitespace to be trimmed

    let mut found_dltfilter_start = false;
    let mut found_dltfilter_end = false;

    let mut buf = Vec::new();
    loop {
        match reader.read_event(&mut buf) {
            Ok(quick_xml::events::Event::Start(ref e)) => match e.local_name() {
                b"dltfilter" => {
                    found_dltfilter_start = true;
                    found_dltfilter_end = false;
                }
                b"filter" => {
                    if found_dltfilter_start && !found_dltfilter_end {
                        let filter = Filter::from_quick_xml_reader(&mut reader);
                        filters.push(filter?);
                    } else {
                        // we ignore those
                        //println!("ignoring filter as outside dltfilter!");
                    }
                }
                _ => {
                    // println!("ignoring start '{:?}'", e.local_name())
                }
            },
            Ok(quick_xml::events::Event::End(ref e)) => {
                if let b"dltfilter" = e.local_name() {
                    found_dltfilter_end = true;
                }
            }
            Ok(quick_xml::events::Event::Text(_)) => {}
            Ok(quick_xml::events::Event::Eof) => break,
            Err(e) => return Err(e),
            _ => {} // CData, Decl, PI, Empty, Comment
        }
        buf.clear();
    }

    if !found_dltfilter_start || !found_dltfilter_end {
        return Err(quick_xml::Error::TextNotFound);
    }

    Ok(filters)
}

/// parse filters from dlt-convert filter file format
///
/// format consists of:
/// \<apid> \<ctid> ...
/// each apid/ctid is exactly 4 bytes (filled with -).
/// first char '-' indicated apid/ctid end
pub fn filters_from_convert_format<B: std::io::BufRead>(
    mut reader: B,
) -> Result<Vec<Filter>, std::io::Error> {
    let mut filters: Vec<Filter> = Vec::new();
    let mut buf = Vec::<u8>::with_capacity(8 * 1024);
    let res = reader.read_to_end(&mut buf)?;
    let mut offset = 0;
    while offset + 10 <= res {
        let mut char4_buf = [0u8, 0, 0, 0];
        let mut char4_len = 0;
        while char4_len < 4 && buf[offset + char4_len] != b'-' {
            char4_buf[char4_len] = buf[offset + char4_len];
            char4_len += 1;
        }
        let apid = DltChar4::from_buf(&char4_buf);
        offset += 5;
        let mut char4_buf = [0u8, 0, 0, 0];
        let mut char4_len = 0;
        while char4_len < 4 && buf[offset + char4_len] != b'-' {
            char4_buf[char4_len] = buf[offset + char4_len];
            char4_len += 1;
        }
        let ctid = DltChar4::from_buf(&char4_buf);
        offset += 5;
        let mut f = Filter::new(FilterKind::Positive);
        f.apid = Some(apid);
        f.ctid = Some(ctid);
        filters.push(f);
    }

    Ok(filters)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dlt::DltChar4;
    use std::sync::mpsc::channel;

    mod filters_from_dlt {
        use super::*;

        #[test]
        fn empty() {
            let r = filters_from_dlf(r#""#.as_bytes());
            assert!(r.is_err());
        }
        #[test]
        fn no_dltfilter() {
            let r = filters_from_dlf(r#"<?xml version="1.0" encoding="UTF-8"?>"#.as_bytes());
            assert!(r.is_err());
        }
        #[test]
        fn empty_dltfilter() {
            let r = filters_from_dlf(
                r#"<?xml version="1.0" encoding="UTF-8"?>
            <dltfilter>
            "#
                .as_bytes(),
            );
            assert!(r.is_err());

            let r = filters_from_dlf(
                r#"<?xml version="1.0" encoding="UTF-8"?>
            <dltfilter></dltfilter>
            "#
                .as_bytes(),
            );
            assert!(r.is_ok());
            assert!(r.unwrap().is_empty());
        }

        #[test]
        fn filter1() {
            // invalid filter
            let r = filters_from_dlf(
                r#"<?xml version="1.0" encoding="UTF-8"?>
            <dltfilter>
                <filter>
            </dltfilter>
            "#
                .as_bytes(),
            );
            assert!(r.is_err());

            // one proper filter
            let r = filters_from_dlf(
                r#"<?xml version="1.0" encoding="UTF-8"?>
            <dltfilter>
                <filter></filter>
            </dltfilter>
            "#
                .as_bytes(),
            );
            assert!(r.is_ok());
            assert_eq!(r.unwrap().len(), 1);

            // two filter
            let r = filters_from_dlf(
                r#"<?xml version="1.0" encoding="UTF-8"?>
            <dltfilter>
                <filter></filter>
                <filter></filter>
            </dltfilter>
            "#
                .as_bytes(),
            );
            assert!(r.is_ok());
            assert_eq!(r.unwrap().len(), 2);
        }
    }

    mod filters_from_convert_format {
        use super::*;
        use std::str::FromStr;

        #[test]
        fn empty() {
            let r = filters_from_convert_format(r#""#.as_bytes());
            assert!(r.is_ok());
            assert!(r.unwrap().is_empty());
        }

        #[test]
        fn invalid() {
            // too short (we expect exactly 10 chars per pair/filter)
            let r = filters_from_convert_format(r#"APID CTID"#.as_bytes());
            assert!(r.is_ok());
            assert!(r.unwrap().is_empty());

            // too short (we expect exactly 10 chars per pair/filter) (but dlt-convert accepts those... but persists differently todo)
            let r = filters_from_convert_format(r#"SYS JOUR "#.as_bytes());
            assert!(r.is_ok());
            assert!(r.unwrap().is_empty());
        }
        #[test]
        fn valid() {
            // too short (we expect exactly 10 chars per pair/filter)
            let r = filters_from_convert_format(r#"APID CTID "#.as_bytes()).unwrap();
            assert_eq!(r.len(), 1);
            assert_eq!(r[0].apid, DltChar4::from_str("APID").ok());
            assert_eq!(r[0].ctid, DltChar4::from_str("CTID").ok());

            let r = filters_from_convert_format(r#"APID CTID SYS- JOUR "#.as_bytes()).unwrap();
            assert_eq!(r.len(), 2);
            assert_eq!(r[0].apid, DltChar4::from_str("APID").ok());
            assert_eq!(r[0].ctid, DltChar4::from_str("CTID").ok());
            assert_eq!(r[1].apid, DltChar4::from_str("SYS").ok()); // this get's shortened! (- ignored)
            assert_eq!(r[1].ctid, DltChar4::from_str("JOUR").ok());
        }
    }

    mod filter_as_streams {
        use super::*;
        use crate::dlt::DltMessage;
        #[test]
        fn no_filters() {
            let (tx, rx) = channel();
            let (tx2, rx2) = channel();
            tx.send(DltMessage::for_test()).unwrap();
            drop(tx);
            // no filters means -> pass all msgs
            let (passed, filtered) = filter_as_streams(&[], &rx, &tx2).unwrap();
            // check return value:
            assert_eq!(passed, 1);
            assert_eq!(filtered, 0);
            // check whether the msg is available as well:
            rx2.try_recv().unwrap();
        }

        #[test]
        fn no_filters_disabled_pos() {
            let (tx, rx) = channel();
            let (tx2, rx2) = channel();
            tx.send(DltMessage::for_test()).unwrap();
            drop(tx);
            // no filters means -> pass all msgs
            // disabled filters dont count
            let mut pos_filter = Filter::new(FilterKind::Positive);
            pos_filter.enabled = false;
            let (passed, filtered) = filter_as_streams(&[pos_filter], &rx, &tx2).unwrap();
            // check return value:
            assert_eq!(passed, 1);
            assert_eq!(filtered, 0);
            // check whether the msg is available as well:
            rx2.try_recv().unwrap();
        }

        #[test]
        fn no_filters_disabled_pos_and_neg() {
            let (tx, rx) = channel();
            let (tx2, rx2) = channel();
            tx.send(DltMessage::for_test()).unwrap();
            drop(tx);
            // no filters means -> pass all msgs
            // disabled filters dont count
            let mut pos_filter = Filter::new(FilterKind::Positive);
            pos_filter.enabled = false;
            let mut neg_filter = Filter::new(FilterKind::Negative);
            neg_filter.enabled = false;

            let (passed, filtered) =
                filter_as_streams(&[neg_filter, pos_filter], &rx, &tx2).unwrap();
            // check return value:
            assert_eq!(passed, 1);
            assert_eq!(filtered, 0);
            // check whether the msg is available as well:
            rx2.try_recv().unwrap();
        }

        #[test]
        fn positive_match_empty_pos() {
            let (tx, rx) = channel();
            let (tx2, rx2) = channel();
            tx.send(DltMessage::for_test()).unwrap();
            drop(tx);
            // one pos. filter (but without any criteria -> should match)
            let (passed, filtered) =
                filter_as_streams(&[Filter::new(FilterKind::Positive)], &rx, &tx2).unwrap();
            // check return value:
            assert_eq!(passed, 1);
            assert_eq!(filtered, 0);
            // check whether the msg is available as well:
            rx2.try_recv().unwrap();
        }

        #[test]
        fn positive_match_empty_pos_and_neg() {
            let (tx, rx) = channel();
            let (tx2, rx2) = channel();
            tx.send(DltMessage::for_test()).unwrap();
            drop(tx);
            // one pos. filter (but without any criteria -> should match)
            // one neg. filter -> should remove
            let (passed, filtered) = filter_as_streams(
                &[
                    Filter::new(FilterKind::Positive),
                    Filter::new(FilterKind::Negative),
                ],
                &rx,
                &tx2,
            )
            .unwrap();
            // check return value:
            assert_eq!(passed, 0);
            assert_eq!(filtered, 1);
            // check whether the msg is available as well:
            rx2.try_recv().expect_err("rx2 should be empty!");
        }

        #[test]
        fn positive_dont_match() {
            let (tx, rx) = channel();
            let (tx2, rx2) = channel();
            tx.send(DltMessage::for_test()).unwrap();
            drop(tx);
            // one pos. filter should not match
            let mut pos_filter = Filter::new(FilterKind::Positive);
            pos_filter.ecu = Some(DltChar4::from_buf(b"ECU2"));
            let (passed, filtered) = filter_as_streams(&[pos_filter], &rx, &tx2).unwrap();
            // check return value:
            assert_eq!(passed, 0);
            assert_eq!(filtered, 1);
            // check whether the msg is available as well:
            rx2.try_recv().expect_err("rx2 should be empty!");
        }

        #[test]
        fn negative_dont_match() {
            let (tx, rx) = channel();
            let (tx2, rx2) = channel();
            tx.send(DltMessage::for_test()).unwrap();
            drop(tx);
            // one neg. filter -> should stay
            let mut neg_filter = Filter::new(FilterKind::Negative);
            neg_filter.ecu = Some(DltChar4::from_buf(b"ECU2"));
            let (passed, filtered) = filter_as_streams(&[neg_filter], &rx, &tx2).unwrap();
            // check return value:
            assert_eq!(passed, 1);
            assert_eq!(filtered, 0);
            // check whether the msg is available as well:
            rx2.try_recv().unwrap();
        }

        #[test]
        fn positive_match_empty_pos_and_not_neg() {
            let (tx, rx) = channel();
            let (tx2, rx2) = channel();
            // one pos. filter (but without any criteria -> should match)
            // one neg that does not match -> should stay
            let mut neg_filter = Filter::new(FilterKind::Negative);
            neg_filter.ecu = Some(DltChar4::from_buf(b"ECU2"));
            let msg = DltMessage::for_test();
            assert!(!neg_filter.matches(&msg));
            tx.send(DltMessage::for_test()).unwrap();
            drop(tx);
            let (passed, filtered) =
                filter_as_streams(&[Filter::new(FilterKind::Positive), neg_filter], &rx, &tx2)
                    .unwrap();
            // check return value:
            assert_eq!(passed, 1);
            assert_eq!(filtered, 0);
            // check whether the msg is available as well:
            rx2.try_recv().unwrap();
        }
    }
}
