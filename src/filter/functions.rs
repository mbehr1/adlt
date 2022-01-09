use std::sync::mpsc::Receiver;
use std::sync::mpsc::Sender;

use crate::filter::{Filter, FilterKind};
use crate::dlt::DltMessage;
use crate::dlt::Error;
use crate::dlt::ErrorKind;

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
        let found_after_pos_filters: bool;

        if !pos_filters.is_empty() {
            // any matching pos filter adds the message
            found_after_pos_filters = pos_filters.iter().any(|f| f.matches(&msg));
        } else {
            found_after_pos_filters = true;
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::channel;
    use crate::dlt::DltChar4;

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

            let (passed, filtered) = filter_as_streams(&[neg_filter, pos_filter], &rx, &tx2).unwrap();
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
            let (passed, filtered) =
                filter_as_streams(&[Filter::new(FilterKind::Positive),Filter::new(FilterKind::Negative)], &rx, &tx2).unwrap();
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
            let (passed, filtered) =
                filter_as_streams(&[pos_filter], &rx, &tx2).unwrap();
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
            let (passed, filtered) =
                filter_as_streams(&[neg_filter], &rx, &tx2).unwrap();
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
                filter_as_streams(&[Filter::new(FilterKind::Positive),neg_filter], &rx, &tx2).unwrap();
            // check return value:
            assert_eq!(passed, 1);
            assert_eq!(filtered, 0);
            // check whether the msg is available as well:
            rx2.try_recv().unwrap();
        }
    }
}
