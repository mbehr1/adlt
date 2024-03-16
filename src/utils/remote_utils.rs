use crate::{
    dlt::DltMessage,
    filter::{Filter, FilterKind, FilterKindContainer},
};
use rayon::prelude::*;
use slog::debug;
use std::sync::atomic::{AtomicUsize, Ordering};
#[derive(Debug)]
pub struct StreamContext {
    pub id: u32,
    pub is_done: bool,   // stop message is sent
    pub is_stream: bool, // else one-time query
    pub binary: bool,
    pub filters_active: bool,
    pub filters: FilterKindContainer<Vec<Filter>>,
    pub filtered_msgs: Vec<usize>,            // indizes to all_msgs vec
    pub all_msgs_last_processed_len: usize,   // last len of all_msgs reflected in filtered_msgs
    pub msgs_to_send: std::ops::Range<usize>, // the requested window
    pub msgs_sent: std::ops::Range<usize>,
}

/// next stream id. Zero is used as "no lifecycle" so first one must start with 1
static NEXT_STREAM_ID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);

impl StreamContext {
    pub fn from(
        log: &slog::Logger,
        command: &str,
        json_str: &str,
    ) -> Result<StreamContext, Box<dyn std::error::Error>> {
        // parse json
        let v = serde_json::from_str::<serde_json::Value>(json_str)?;
        debug!(
            log,
            "StreamContext::from({}:{}) = {:?}", command, json_str, v
        );

        let is_stream = command == "stream";

        let mut start_idx = 0;
        let mut end_idx = 20; // todo
        let mut filters: FilterKindContainer<Vec<Filter>> = Default::default();

        match &v["window"] {
            serde_json::Value::Array(a) => {
                debug!(log, "StreamContext window={:?}", a);
                if a.len() != 2 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("'window' expects array with two elements. got {}", a.len()),
                    )
                    .into());
                } else {
                    start_idx = a[0].as_u64().unwrap_or(0) as usize; // todo better err and not ignore
                    end_idx = a[1].as_u64().unwrap_or(20) as usize; // todo better err and not default 20
                }
            }
            serde_json::Value::Null => {} // keep defaults
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "wrong type for 'window'",
                )
                .into());
            }
        }

        match &v["filters"] {
            serde_json::Value::Array(a) => {
                for filter in a {
                    debug!(log, "StreamContext filters got '{}'", filter.to_string());
                    let filter_struct = Filter::from_json(&filter.to_string())?;
                    debug!(log, "StreamContext filters parsed as '{:?}'", filter_struct);
                    if filter_struct.enabled {
                        // otherwise the no pos filter -> ... logic doesnt work
                        filters[filter_struct.kind].push(filter_struct);
                    }
                }
            }
            serde_json::Value::Null => {} // no filters
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "wrong type for 'filters'",
                )
                .into());
            }
        }

        let binary = match &v["binary"] {
            serde_json::Value::Bool(b) => b,
            _ => {
                if is_stream {
                    &false
                } else {
                    &true
                }
            } // we default to binary for all but stream (yet)
        };

        // todo think about Marker, Event...
        let filters_active = filters[FilterKind::Positive].len()
            + filters[FilterKind::Negative].len()
            + filters[FilterKind::Event].len()
            > 0;

        Ok(StreamContext {
            id: NEXT_STREAM_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            is_done: false,
            is_stream,
            binary: *binary,
            filters,
            filters_active,
            filtered_msgs: Vec::new(),
            all_msgs_last_processed_len: 0,
            msgs_to_send: std::ops::Range {
                start: start_idx,
                end: end_idx,
            },
            msgs_sent: std::ops::Range {
                start: start_idx,
                end: start_idx,
            },
        })
    }

    pub fn new_id(&mut self) {
        self.id = NEXT_STREAM_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

pub fn process_stream_new_msgs(
    stream: &mut StreamContext,
    new_msgs_offset: usize,
    new_msgs: &[DltMessage],
    max_chunk_size: usize,
) {
    if !new_msgs.is_empty() {
        let new_msgs_len = new_msgs.len();
        if stream.filters_active {
            let have_pos_filters = !stream.filters[FilterKind::Positive].is_empty();
            let have_event_filters = !stream.filters[FilterKind::Event].is_empty();

            // break after some searching max_chunk_size of messages to improve reaction time
            let max_idx = std::cmp::min(new_msgs_len, max_chunk_size);
            let get_matching_idxs = || -> Vec<usize> {
                new_msgs[0..max_idx]
                    .par_iter()
                    .enumerate()
                    .filter(|(_i, msg)| {
                        match_filters(msg, &stream.filters, have_pos_filters, have_event_filters)
                    })
                    .map(|(i, _msg)| new_msgs_offset + i) // done in parallel
                    .collect() // serializing here
            };

            if stream.is_stream {
                // we want to filter/identify all stream msgs even though the window
                // might just send a few ones...
                let mut matching_idxs: Vec<usize> = get_matching_idxs();
                // rayon collect seems to keep the order. not needed: matching_idxs.par_sort_unstable();
                // https://github.com/rayon-rs/rayon/issues/551#issuecomment-371657900
                stream.filtered_msgs.append(&mut matching_idxs);
                stream.all_msgs_last_processed_len = new_msgs_offset + max_idx;
            } else {
                // for non streams (aka queries) we need to consider that the window might change later via stream_change_window.
                // the problem is: how to end up once enough items are collected
                // we cannot do this with an atomic cnt and while_some as the adding/comparing
                // would then be done in parallel.
                // so we just use a full search and then limit the results:
                // we could iterate over a few max_chunk_size fragments... (but might not be worth the benefit)

                let max_matching = stream.msgs_to_send.end;
                if stream.filtered_msgs.len() < max_matching {
                    let nr_wanted = max_matching - stream.filtered_msgs.len();

                    let mut matching_idxs: Vec<usize> = get_matching_idxs();
                    /*
                    let cnt_found = AtomicUsize::new(0);
                    let cnt_found_idx = AtomicUsize::new(usize::MAX);
                                        let mut matching_idxs: Vec<usize> = new_msgs[0..max_idx]
                                            .par_iter()
                                            .enumerate()
                                            .filter(|(_i, msg)| {
                                                match_filters(
                                                    msg,
                                                    &stream.filters,
                                                    have_pos_filters,
                                                    have_event_filters,
                                                )
                                            })
                                            .map(|(i, _msg)| {
                                                if cnt_found.fetch_add(1, Ordering::SeqCst) == nr_wanted - 1 {
                                                    cnt_found_idx.store(i, Ordering::SeqCst);
                                                }
                                                // we can stop collecting the results from all idxs that are larger than the one we found
                                                if i <= cnt_found_idx.load(Ordering::SeqCst) {
                                                    Some(new_msgs_offset + i)
                                                } else {
                                                    None
                                                }
                                            }) // done in parallel
                                            .while_some()
                                            .collect(); // serializing here
                    */
                    // if we found more than wanted, we need to ensure that the next search
                    // restarts at the unwanted one...
                    if matching_idxs.len() <= nr_wanted {
                        stream.all_msgs_last_processed_len = new_msgs_offset + max_idx;
                    } else {
                        // found more than wanted:
                        let first_unwanted = matching_idxs[nr_wanted];
                        stream.all_msgs_last_processed_len = first_unwanted;
                        matching_idxs.truncate(nr_wanted);
                    }
                    stream.filtered_msgs.append(&mut matching_idxs);
                }
            }
        } else {
            stream.all_msgs_last_processed_len += new_msgs_len;
        }
    }
}

pub fn match_filters(
    msg: &DltMessage,
    filters: &FilterKindContainer<Vec<Filter>>,
    have_pos_filters: bool,
    have_event_filters: bool,
) -> bool {
    let mut matches = !have_pos_filters;

    // for now do a simple support of pos. and neg. filters
    for filter in &filters[FilterKind::Positive] {
        if filter.matches(msg) {
            matches = true;
            // debug!(log, "stream {} got pos matching msg idx={}", stream.id, i);
            break;
        }
    }
    if matches {
        // and neg that removes the msg?
        for filter in &filters[FilterKind::Negative] {
            if filter.matches(msg) {
                matches = false;
                // debug!(log, "stream {} got neg matching msg idx={}", stream.id, i);
                break;
            }
        }
    }

    // report/event filter?
    // if any is set it has to match as well
    // so they are applied after the pos/neg filters
    // todo think about it... (could be treated as pos filter as well)
    // it's currently used for dlt-logs search as multiple not/negative filters
    // don't work.
    // so the search uses the event filters as pos. filters to be applied after
    // any pos/neg filters (which might currently be active in the document)
    if matches && have_event_filters {
        matches = false;
        for filter in &filters[FilterKind::Event] {
            if filter.matches(msg) {
                matches = true;
                /*debug!(
                    log,
                    "stream {} got pos matching event msg idx={}", stream.id, i
                );*/
                break;
            }
        }
    }
    matches
}

#[cfg(test)]
mod tests {
    use slog::{o, Drain, Logger};

    use super::*;
    use crate::dlt::{DltChar4, DltMessage, DltStandardHeader};
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
    #[test]
    fn stream_context_1() {
        let log = new_logger();
        let sc = StreamContext::from(&log, "stream", "");
        assert!(sc.is_err()); // not a json object
                              // valid one with defaults:
        let sc = StreamContext::from(&log, "stream", "{}").unwrap();
        assert!(!sc.filters_active);

        // with empty filters:
        let sc = StreamContext::from(&log, "stream", r#"{"filters":[]}"#).unwrap();
        assert!(!sc.filters_active);
        assert_eq!(sc.filters[FilterKind::Positive].len(), 0);
        assert_eq!(sc.filters[FilterKind::Negative].len(), 0);
        assert_eq!(sc.filters[FilterKind::Marker].len(), 0);
        assert_eq!(sc.filters[FilterKind::Event].len(), 0);

        // with a neg filters:
        let sc = StreamContext::from(&log, "stream", r#"{"filters":[{"type":1}]}"#).unwrap();
        assert!(sc.filters_active);
        assert_eq!(sc.filters[FilterKind::Positive].len(), 0);
        assert_eq!(sc.filters[FilterKind::Negative].len(), 1);
        assert_eq!(sc.filters[FilterKind::Marker].len(), 0);
        assert_eq!(sc.filters[FilterKind::Event].len(), 0);

        // with a window (but empty -> invalid)
        assert!(StreamContext::from(&log, "stream", r#"{"window":[]}"#).is_err());
        // with a window (but 1 value -> invalid)
        assert!(StreamContext::from(&log, "stream", r#"{"window":[1]}"#).is_err());
        // with a window (but 3 values -> invalid)
        assert!(StreamContext::from(&log, "stream", r#"{"window":[1,2,3]}"#).is_err());
        // with a valid window (todo order, wrong types.... to be added)
        let sc = StreamContext::from(&log, "stream", r#"{"window":[1,2]}"#).unwrap();
        println!("sc with windows={:?}", sc); // we can debug print it
        assert_eq!(sc.msgs_to_send.start, 1);
        assert_eq!(sc.msgs_to_send.end, 2);
    }

    #[test]
    fn process_stream_new_msgs_no_filters() {
        let log = new_logger();
        let mut sc = StreamContext::from(&log, "stream", r#"{"filters":[]}"#).unwrap();
        assert_eq!(sc.all_msgs_last_processed_len, 0);
        process_stream_new_msgs(&mut sc, 0, &[], 1);
        assert_eq!(sc.all_msgs_last_processed_len, 0);
        process_stream_new_msgs(&mut sc, 0, &[], 1);
        assert_eq!(sc.all_msgs_last_processed_len, 0);
        process_stream_new_msgs(&mut sc, 0, &[msg_for_test(0)], 1);
        assert_eq!(sc.filtered_msgs.len(), 0); // shall not be added if no filters are active
        assert_eq!(sc.all_msgs_last_processed_len, 1);
    }
    #[test]
    fn process_stream_new_msgs_is_stream_no_window() {
        let log = new_logger();
        let mut sc =
            StreamContext::from(&log, "stream", r#"{"filters":[{"type":0,"ecu":"^ECU."}]}"#)
                .unwrap();
        assert!(sc.is_stream);
        assert_eq!(sc.msgs_sent.start, 0); // no msgs sent yet
        assert_eq!(sc.msgs_sent.end, 0);

        assert_eq!(sc.msgs_to_send.start, 0); // wanted from idx 0
        assert!(sc.msgs_to_send.end >= 2); // to larger...

        assert_eq!(sc.all_msgs_last_processed_len, 0);

        let mut msgs = vec![];
        msgs.push(msg_for_test(0));
        msgs.push(msg_for_test(10));
        for i in 11..10_000 {
            msgs.push(msg_for_test(i as u32));
        }

        process_stream_new_msgs(&mut sc, 0, &msgs[0..0], 10);
        assert_eq!(sc.all_msgs_last_processed_len, 0);

        process_stream_new_msgs(&mut sc, 0, &msgs[0..1], 10);
        assert_eq!(sc.filtered_msgs.len(), 1); // and idx = 0...
        assert_eq!(sc.filtered_msgs, [0]);
        assert_eq!(sc.all_msgs_last_processed_len, 1);

        process_stream_new_msgs(&mut sc, 10, &msgs[1..2], 1);
        assert_eq!(sc.filtered_msgs.len(), 2); // and idx = 10...
        assert_eq!(sc.filtered_msgs, [0, 10]);
        assert_eq!(sc.all_msgs_last_processed_len, 11);

        process_stream_new_msgs(&mut sc, 11, &msgs[2..], 10_000);
        assert_eq!(sc.filtered_msgs.len(), msgs.len());

        for (idx, val) in sc.filtered_msgs[2..].iter().enumerate() {
            assert_eq!(*val, idx + 11, "#{} = {}", idx, val);
        }
    }

    #[test]
    fn process_stream_new_msgs_query_window() {
        let log = new_logger();
        let mut sc = StreamContext::from(
            &log,
            "query",
            r#"{"filters":[{"type":0,"ecu":"^ECU."}],"window":[1,2]}"#,
        )
        .unwrap();
        assert!(!sc.is_stream);
        assert_eq!(sc.msgs_sent.start, 1); // no msgs sent yet, wanted only idx 1... (so assuming we do fill all filtered_msgs)
        assert_eq!(sc.msgs_sent.end, 1);

        assert_eq!(sc.msgs_to_send.start, 1); // wanted from idx 0
        assert_eq!(sc.msgs_to_send.end, 2); // to 2

        assert_eq!(sc.all_msgs_last_processed_len, 0);

        let msgs = [msg_for_test(0), msg_for_test(1), msg_for_test(2)];

        process_stream_new_msgs(&mut sc, 0, &msgs[0..0], 10);
        assert_eq!(sc.all_msgs_last_processed_len, 0);

        process_stream_new_msgs(&mut sc, 0, &msgs[0..1], 10);
        assert_eq!(sc.filtered_msgs.len(), 1); // and idx = 0...
        assert_eq!(sc.filtered_msgs, [0]);
        assert_eq!(sc.all_msgs_last_processed_len, 1);

        process_stream_new_msgs(&mut sc, 10, &msgs[1..2], 1);
        assert_eq!(sc.filtered_msgs.len(), 2); // and idx = 10...
        assert_eq!(sc.filtered_msgs, [0, 10]);
        assert_eq!(sc.all_msgs_last_processed_len, 11);

        process_stream_new_msgs(&mut sc, 20, &msgs[2..], 10);
        assert_eq!(sc.filtered_msgs.len(), 2); // no more wanted.
        assert_eq!(sc.filtered_msgs, [0, 10]);
        assert_eq!(sc.all_msgs_last_processed_len, 11); // we keep the old one to continue searh on window change.

        // change the window: (now we want more msgs)
        sc.msgs_to_send.end = 1000;
        process_stream_new_msgs(&mut sc, 20, &msgs[2..], 10);
        assert_eq!(sc.filtered_msgs.len(), msgs.len());
        assert_eq!(sc.filtered_msgs, [0, 10, 20]);
        assert_eq!(sc.all_msgs_last_processed_len, 21);
    }

    #[test]
    fn process_stream_new_msgs_query_window_large() {
        let log = new_logger();
        let mut sc = StreamContext::from(
            &log,
            "query",
            r#"{"filters":[{"type":0,"ecu":"ECU0"}],"window":[0,100]}"#,
        )
        .unwrap();
        assert!(!sc.is_stream);
        assert_eq!(sc.msgs_sent.start, 0); // no msgs sent yet, wanted only idx 1... (so assuming we do fill all filtered_msgs)
        assert_eq!(sc.msgs_sent.end, 0);

        assert_eq!(sc.msgs_to_send.start, 0); // wanted from idx 0
        assert_eq!(sc.msgs_to_send.end, 100); // to 2

        assert_eq!(sc.all_msgs_last_processed_len, 0);

        let mut msgs = vec![];
        for i in 1..=1000 {
            msgs.push(msg_for_test(i as u32));
        }

        process_stream_new_msgs(&mut sc, 0, &msgs[0..0], 5000);
        assert_eq!(sc.all_msgs_last_processed_len, 0);

        process_stream_new_msgs(&mut sc, 0, &msgs[0..], 500);
        assert_eq!(sc.filtered_msgs.len(), 100); // we do only want 100 from current window

        assert_eq!(sc.filtered_msgs[0..5], [1, 3, 5, 7, 9]);
        for (idx, val) in sc.filtered_msgs.iter().enumerate() {
            assert_eq!(*val, (idx * 2) + 1, "#{} = {}", idx, val);
        }
        assert_eq!(
            sc.all_msgs_last_processed_len,
            201,
            "got {} filtered_msgs",
            sc.filtered_msgs.len()
        );

        // next call should not change anything:
        process_stream_new_msgs(&mut sc, 201, &msgs[201..], 500);
        assert_eq!(sc.filtered_msgs.len(), 100); // we do only want 100 from current window
        assert_eq!(sc.all_msgs_last_processed_len, 201);

        // change the window: (now we want more msgs)
        sc.msgs_to_send.end = 1000;
        // trigger to stop with less than wanted (so due to max_chunk_size)
        process_stream_new_msgs(&mut sc, 201, &msgs[201..], 500);
        assert_eq!(sc.filtered_msgs.len(), 350);
        assert_eq!(sc.all_msgs_last_processed_len, 701);
        for (idx, val) in sc.filtered_msgs.iter().enumerate() {
            assert_eq!(*val, (idx * 2) + 1, "#{} = {}", idx, val);
        }

        // now ending due to end of all msgs
        process_stream_new_msgs(&mut sc, 701, &msgs[701..801], 500);
        assert_eq!(sc.all_msgs_last_processed_len, 801);
        assert_eq!(sc.filtered_msgs.len(), 400);
        for (idx, val) in sc.filtered_msgs.iter().enumerate() {
            assert_eq!(*val, (idx * 2) + 1, "#{} = {}", idx, val);
        }

        // now ending due to end of window = end of all msgs
        process_stream_new_msgs(&mut sc, 801, &msgs[801..], 500);
        assert_eq!(sc.all_msgs_last_processed_len, 1000);
        assert_eq!(sc.filtered_msgs.len(), 500);
        for (idx, val) in sc.filtered_msgs.iter().enumerate() {
            assert_eq!(*val, (idx * 2) + 1, "#{} = {}", idx, val);
        }
        assert_eq!(sc.all_msgs_last_processed_len, 1000);
    }
}
