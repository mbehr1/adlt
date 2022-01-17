use std::sync::mpsc::{Receiver, Sender};

// const MS_PER_SEC:u32 = 1_000;

/// const for micro-secs (us) per second
pub const US_PER_SEC: u64 = 1_000_000;

pub fn utc_time_from_us(time_us: u64) -> chrono::NaiveDateTime {
    chrono::NaiveDateTime::from_timestamp_opt(
        // todo get rid of all those mult/%...
        (time_us / US_PER_SEC) as i64,
        1_000u32 * (time_us % 1_000_000) as u32,
    )
    .unwrap_or_else(|| chrono::NaiveDateTime::from_timestamp(0, 0))
}

/// output a buffer as hex dump to a Writer.
/// Each byte is output as two lower-case digits.
/// A space is output between each byte.
/// e.g. "0f 00"
pub fn buf_as_hex_to_write(
    writer: &mut impl std::fmt::Write,
    buf: &[u8],
) -> Result<(), std::fmt::Error> {
    //for i in 0..buf.len() {
    for (i, item) in buf.iter().enumerate() {
        if i > 0 {
            write!(writer, " {:02x}", item)?;
        } else {
            write!(writer, "{:02x}", item)?;
        }
    }

    Ok(())
}

/// Convert a hex encoded string like "3d 0a 00..."
/// to a Vec of u8.
///
/// We expect
/// - exactly two chars per byte,
/// - upper or lower case
/// - a space in between each byte
/// - but not at start or end
pub fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
    // we expect len 2 or 5 or 8 (so 2 + x*3)
    if s.len() < 2 || (s.len() - 2) % 3 != 0 {
        None
    } else {
        (0..s.len())
            .step_by(3)
            .map(|i| {
                s.get(i..i + 2)
                    .and_then(|sub| u8::from_str_radix(sub, 16).ok())
            })
            .collect()
    }
}

pub enum BufferElementsAmount {
    NumberElements(usize),
}

/// options for buffer_elements.
/// Preparing as a struct to e.g. later add optional parameter
pub struct BufferElementsOptions {
    pub amount: BufferElementsAmount,
}

/// buffers / delays the output of elements from a stream to a stream
/// Acts like a fifo-buffer that will be filled first with options.amount elements.
/// Once the buffer contains the amount of message any new message will be output in fifo order.
/// On end of the stream the buffered elements will be output.
/// # Note:
/// On async processing this can be used to "delay" further processing of e.g. DltMessages to let e.g. lifecycles stabilize.
pub fn buffer_elements<T>(inflow: Receiver<T>, outflow: Sender<T>, options: BufferElementsOptions) {
    match options.amount {
        BufferElementsAmount::NumberElements(number_elems) => {
            let mut buffer = std::collections::VecDeque::<T>::with_capacity(number_elems);
            for e in inflow {
                if buffer.len() == number_elems {
                    outflow.send(buffer.pop_front().unwrap()).unwrap(); // todo or other way to return error?
                }
                buffer.push_back(e);
            }
            // put buffer to outflow
            for e in buffer.into_iter() {
                outflow.send(e).unwrap();
            }
        }
    }
}

/// buffer and insert sorted the elements from a stream to a stream.
/// All the elements will be inserted sorted - so considered with the comparison at time of inserting.
/// Once the buffer amount is filled the first (smallest) element will be output.
pub fn buffer_sort_elements<T>(
    inflow: Receiver<T>,
    outflow: Sender<T>,
    options: BufferElementsOptions,
) where
    T: std::cmp::Ord,
{
    match options.amount {
        BufferElementsAmount::NumberElements(number_elems) => {
            let mut buffer = std::collections::VecDeque::<T>::with_capacity(number_elems);
            for e in inflow {
                // convert to sortStruct
                if buffer.len() == number_elems {
                    outflow.send(buffer.pop_front().unwrap()).unwrap();
                    // todo or other way to return error?
                }
                // we insert sorted:
                let idx = buffer.binary_search(&e).unwrap_or_else(|x| x); // todo this is not stable!
                buffer.insert(idx, e);
            }
            // put buffer to outflow
            for e in buffer.into_iter() {
                outflow.send(e).unwrap();
            }
        }
    }
}

/// Struct/Wrapper around DltMessage that adds std::cmp::Ord based on the lifecycle and timestamp
///
/// If the lifecycle is the same only the timestamp is used. If the lifecycle is different the lifecycle start times are considered as well.
struct SortedDltMessage {
    m: crate::dlt::DltMessage,
    calculated_time_us: u64, // lc.start_time + m.timestamp_us
}
impl std::cmp::PartialEq for SortedDltMessage {
    fn eq(&self, other: &Self) -> bool {
        self.calculated_time_us == other.calculated_time_us // todo index as well?
    }
}
impl std::cmp::Ord for SortedDltMessage {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        if self.m.lifecycle == other.m.lifecycle {
            if self.m.timestamp_dms == other.m.timestamp_dms {
                self.m.index.cmp(&other.m.index) // keep the initial order on same timestamp
            } else {
                self.m.timestamp_dms.cmp(&other.m.timestamp_dms)
            }
        } else if self.calculated_time_us == other.calculated_time_us {
            self.m.index.cmp(&other.m.index) // keep the initial order on same timestamp
        } else {
            self.calculated_time_us.cmp(&other.calculated_time_us)
        }
    }
}
impl std::cmp::PartialOrd for SortedDltMessage {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl std::cmp::Eq for SortedDltMessage {}

/// sort DltMessages by time
///
/// This function tries to calculate an upper bound for the buffering delay and buffers the message within that time
/// and sorts messages older than that delay.
/// The buffering delay is calculated over a sliding window of `windows_size_secs` and a minimum time of
/// `min_buffer_delay_us` is added.
/// The algorithm assumes that the buffering delays get only shorter within a lifecycle or increase maximum by `min_buffer_delay_us` within the sliding window! Thus you should specify a reasonable `min_buffer_delay_us`.
/// The algorithm defines for each lifecycle the max buffer delay within the last `windows_size_secs` seconds of recording time and
/// buffers the messages for at least that timeframe.
/// #### Note Make sure that the messages are not delayed/buffered longer than the `min_buffer_delay_us`. Otherwise the result will not be sorted correctly.
/// #### Note The lifecycle start times are not changed during the processing but are cached with the first value. So if the times slightly change any messages from parallel lifecycles will be wrongly sorted.
pub fn buffer_sort_messages<M, S>(
    inflow: Receiver<crate::dlt::DltMessage>,
    outflow: Sender<crate::dlt::DltMessage>,
    lcs_r: &evmap::ReadHandle<crate::lifecycle::LifecycleId, crate::lifecycle::LifecycleItem, M, S>,
    windows_size_secs: u8,
    min_buffer_delay_us: u64,
) -> Result<(), std::sync::mpsc::SendError<crate::dlt::DltMessage>>
where
    S: std::hash::BuildHasher + Clone,
    M: 'static + Clone,
{
    let mut buffer = std::collections::VecDeque::<SortedDltMessage>::new();
    // cache with lifecycle start times:
    // lets not use a vec which would work for most cases but for the lifecycle ids can be larger for longer runs (e.g. processing multiple files)
    let mut lc_map = std::collections::BTreeMap::<crate::lifecycle::LifecycleId, u64>::new();
    // todo why mut for get_lc_start_time???
    let mut get_lc_start_time = |ref x: crate::lifecycle::LifecycleId| -> u64 {
        match lc_map.get(x) {
            Some(t) => *t,
            None => {
                // get from lcr, add to map and return
                let start_time = match lcs_r.read() {
                    Some(map_read_ref) => {
                        let l = map_read_ref.get_one(x);
                        match l {
                            Some(l) => l.start_time,
                            None => 0,
                        }
                    }
                    None => 0,
                };
                lc_map.insert(*x, start_time);
                println!("added lc_map {} {}", x, start_time);
                start_time
            }
        }
    };

    // vector with buffering delays:
    struct MaxBufferDelayEntry {
        start_time: u64, // start reception time for this entry
        max_buffering_delay: u64,
    }

    // we need to keep the vector with max buffering delays per ecu/lifecycle
    // so we store a map with ecu as key and a tuple of (lifecycle_id, vector<MaxBufferDelayEntry>, max_buffering_delay) as value
    let mut max_buffering_delays = std::collections::HashMap::<
        crate::dlt::DltChar4,
        (
            crate::lifecycle::LifecycleId,
            std::collections::VecDeque<MaxBufferDelayEntry>,
            u64,
        ),
    >::new();
    let mut max_buffer_time_us = min_buffer_delay_us;

    let mut update_max_buffering_delays =
        |max_buffer_time_us: u64,
         ecu: &crate::dlt::DltChar4,
         lifecycle_id: &crate::lifecycle::LifecycleId,
         msg_reception_time_us: u64,
         buffering_delay: u64| {
            let mut entry = max_buffering_delays.entry(*ecu).or_insert_with(|| {
                (
                    *lifecycle_id,
                    std::collections::VecDeque::with_capacity(windows_size_secs as usize),
                    0,
                )
            });
            // is it from an older lifecycle?
            let mut recalc_max_buffer_time_us = false;

            if entry.0 != *lifecycle_id {
                entry.1.clear();
                entry.0 = *lifecycle_id;
                entry.2 = buffering_delay;
                recalc_max_buffer_time_us = true;
            }
            let mut recalc_buffering_delay = false;
            // from same lifecycle now
            let insert_new = entry.1.is_empty()
                || entry.1.back().unwrap().start_time + crate::utils::US_PER_SEC
                    < msg_reception_time_us;
            if insert_new {
                // do we need to remove one first?
                if entry.1.len() == windows_size_secs as usize {
                    if entry.1.front().unwrap().max_buffering_delay == entry.2 {
                        recalc_buffering_delay = true; // we removed the cur. max
                    }
                    entry.1.pop_front(); // remove oldest
                }
                // now insert new one
                entry.1.push_back(MaxBufferDelayEntry {
                    start_time: msg_reception_time_us,
                    max_buffering_delay: buffering_delay,
                });
                if buffering_delay > entry.2 {
                    recalc_buffering_delay = false;
                    entry.2 = buffering_delay;
                }
                recalc_max_buffer_time_us = true; // could be optimized but we do need a recheck every sec anyhow
            } else {
                // update
                let last = entry.1.back_mut().unwrap();
                if last.max_buffering_delay < buffering_delay {
                    last.max_buffering_delay = buffering_delay;
                    if buffering_delay > entry.2 {
                        recalc_buffering_delay = false;
                        recalc_max_buffer_time_us = true;
                        entry.2 = buffering_delay;
                    }
                }
            }
            if recalc_buffering_delay {
                entry.2 = entry
                    .1
                    .iter()
                    .max_by_key(|x| x.max_buffering_delay)
                    .unwrap()
                    .max_buffering_delay;
                recalc_max_buffer_time_us = true;
            }
            if recalc_max_buffer_time_us {
                let new_max_buffer_time_us = min_buffer_delay_us + {
                    let x = max_buffering_delays
                        .iter()
                        .max_by_key(|x| {
                            if x.1 .1.front().unwrap().start_time
                                + (windows_size_secs - 1) as u64 * crate::utils::US_PER_SEC
                                > msg_reception_time_us
                            {
                                1000 * crate::utils::US_PER_SEC
                            } else {
                                x.1 .2
                            }
                        })
                        .unwrap();
                    if x.1 .1.front().unwrap().start_time
                        + (windows_size_secs - 1) as u64 * crate::utils::US_PER_SEC
                        > msg_reception_time_us
                    {
                        1000 * crate::utils::US_PER_SEC
                    } else {
                        x.1 .2
                    }
                };
                if new_max_buffer_time_us != max_buffer_time_us
                    && new_max_buffer_time_us > min_buffer_delay_us * 2
                {
                    println!("max_buffer_time_us={}", new_max_buffer_time_us);
                }
                new_max_buffer_time_us
            } else {
                max_buffer_time_us
            }
        };

    for m in inflow {
        let msg_reception_time_us = m.reception_time_us;
        // add message sorted into buffer
        let mut calculated_time_us: u64 = if m.is_ctrl_request() {
            m.reception_time_us
        } else {
            get_lc_start_time(m.lifecycle) + m.timestamp_us()
        };
        // assert!(calculated_time_us <= msg_reception_time_us, "m failed {:?} is_ctrl_request()={} calctime={} lc_start_time={}", m, m.is_ctrl_request(), calculated_time_us, get_lc_start_time(m.lifecycle));
        if calculated_time_us > msg_reception_time_us {
            // this can happen in case of clock drift or due to lc_start_time not adjusted
            //println!("calc>recp={}", calculated_time_us - msg_reception_time_us);
            calculated_time_us = msg_reception_time_us;
        }
        let buffering_delay = msg_reception_time_us - calculated_time_us;
        // update max_buffering_delays:
        max_buffer_time_us = update_max_buffering_delays(
            max_buffer_time_us,
            &m.ecu,
            &m.lifecycle,
            msg_reception_time_us,
            buffering_delay,
        );

        // println!("max_buffer_time_us={}", max_buffer_time_us);

        let sm = SortedDltMessage {
            m,
            calculated_time_us,
        };
        let idx = buffer.binary_search(&sm).unwrap_or_else(|x| x); // this is not stable but shouldn't matter as we added index to cmp::Ord
        buffer.insert(idx, sm);

        // remove all messages from buffer that have a time more than max_buffer_time_us earlier

        while let Some(sm) = buffer.front() {
            if sm.calculated_time_us + max_buffer_time_us < msg_reception_time_us {
                let sm2 = buffer.pop_front().unwrap();
                outflow.send(sm2.m)?;
            } else {
                break; // msgs are sorted so we stop here and check after next msg
            }
        }
    }
    for sm in buffer.into_iter() {
        outflow.send(sm.m)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::dlt::DltMessage;
    use crate::lifecycle::*;
    use crate::utils::*;
    use std::sync::mpsc::channel;
    //    use std::time::Instant;
    use chrono::{Datelike, Timelike};

    #[test]
    fn time_utc() {
        let utc_time = utc_time_from_us(1640995200000001); // epoch timestamp for GMT 1.1.2022, 0:00:00.001 (1ms)
        assert_eq!(utc_time.date().day(), 1);
        assert_eq!(utc_time.date().month(), 1);
        assert_eq!(utc_time.date().year(), 2022);
        assert_eq!(utc_time.time().hour(), 0);
        assert_eq!(utc_time.time().minute(), 0);
        assert_eq!(utc_time.time().second(), 0);
        assert_eq!(utc_time.time().nanosecond(), 1000);

        // and an invalid one:
        let utc_time = utc_time_from_us((i64::MAX as u64) + 42); // seems internally an i64 is used as it can reflect time before 1.1.1970 as well
        assert_eq!(utc_time.timestamp(), 0);
        assert_eq!(utc_time.date().day(), 1);
        assert_eq!(utc_time.date().month(), 1);
        assert_eq!(utc_time.date().year(), 1970);
    }

    #[test]
    fn buf_as_hex() {
        let mut s = String::new();
        buf_as_hex_to_write(&mut s, &[]).unwrap();
        assert_eq!(s.len(), 0);

        buf_as_hex_to_write(&mut s, &[0x0f_u8]).unwrap();
        assert_eq!(s, "0f");

        let mut s = String::new();
        buf_as_hex_to_write(&mut s, &[0x0f_u8, 0x00_u8, 0xff_u8]).unwrap();
        assert_eq!(s, "0f 00 ff");
    }

    #[test]
    fn hex_to_bytes1() {
        assert!(hex_to_bytes("").is_none());
        assert!(hex_to_bytes("1").is_none());
        assert_eq!(hex_to_bytes("12").unwrap(), vec![0x12]);
        assert!(hex_to_bytes("123").is_none());
        assert!(hex_to_bytes("12 ").is_none());
        assert!(hex_to_bytes("12 3").is_none());
        assert_eq!(hex_to_bytes("12 34").unwrap(), vec![0x12, 0x34]);
        assert!(hex_to_bytes("12 34 ").is_none());
        assert!(hex_to_bytes("12 34 5").is_none());
        assert_eq!(hex_to_bytes("ff dd").unwrap(), vec![0xff, 0xdd]);
        assert_eq!(hex_to_bytes("fF Dd").unwrap(), vec![0xff, 0xdd]);
    }

    #[test]
    fn buffer_messages() {
        let (tx, rx) = channel();
        const NUMBER_MSGS: usize = 1_000;
        for _ in 0..NUMBER_MSGS {
            tx.send(DltMessage::for_test()).unwrap();
        }
        let (tx2, rx2) = channel();
        let t = std::thread::spawn(move || {
            buffer_elements(
                rx,
                tx2,
                BufferElementsOptions {
                    amount: BufferElementsAmount::NumberElements(NUMBER_MSGS),
                },
            )
        });
        // till now there must be no message in tx:
        assert!(rx2
            .recv_timeout(std::time::Duration::from_millis(50))
            .is_err());
        // now send another batch of messages:
        for _ in 0..NUMBER_MSGS {
            tx.send(DltMessage::for_test()).unwrap();
        }
        // now the first messages should arrive:
        let mut last_time_stamp = 0;
        for i in 0..NUMBER_MSGS {
            let mr = rx2.recv_timeout(std::time::Duration::from_millis(50));
            assert!(mr.is_ok(), "failed to get msg#{}", i);
            let m = mr.unwrap();
            assert!(
                m.timestamp_dms > last_time_stamp,
                "msg#{} has wrong order/time_stamp! {} vs. exp. > {}",
                i,
                m.timestamp_dms,
                last_time_stamp
            );
            last_time_stamp = m.timestamp_dms;
        }
        // till now there must be no further message in tx:
        assert!(rx2
            .recv_timeout(std::time::Duration::from_millis(50))
            .is_err());
        // close the sender:
        drop(tx);
        // now the remaining messages should arrive:
        t.join().unwrap();
        for i in 0..NUMBER_MSGS {
            let mr = rx2.recv();
            assert!(mr.is_ok(), "failed to get last msg#{}", i);
            let m = mr.unwrap();
            assert!(
                m.timestamp_dms > last_time_stamp,
                "msg#{} has wrong order/time_stamp! {} vs. exp. > {}",
                NUMBER_MSGS + i,
                m.timestamp_dms,
                last_time_stamp
            );
            last_time_stamp = m.timestamp_dms;
        }
        assert!(rx2
            .recv_timeout(std::time::Duration::from_millis(50))
            .is_err());
    }

    struct SortedMsg(DltMessage);
    impl std::cmp::Ord for SortedMsg {
        fn cmp(&self, other: &Self) -> std::cmp::Ordering {
            self.0.timestamp_dms.cmp(&other.0.timestamp_dms)
        }
    }
    impl std::cmp::PartialOrd for SortedMsg {
        fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
            Some(self.0.timestamp_dms.cmp(&other.0.timestamp_dms))
        }
    }
    impl PartialEq for SortedMsg {
        fn eq(&self, other: &Self) -> bool {
            self.0.timestamp_dms == other.0.timestamp_dms
        }
    }
    impl Eq for SortedMsg {}
    impl From<DltMessage> for SortedMsg {
        fn from(msg: DltMessage) -> Self {
            Self(msg)
        }
    }

    #[test]
    fn buffer_sort_elements2() {
        let (tx, rx) = channel();
        const NUMBER_MSGS: usize = 1_000;
        let mut msgs: std::vec::Vec<SortedMsg> = std::vec::Vec::with_capacity(NUMBER_MSGS);
        for _ in 0..NUMBER_MSGS {
            msgs.push(SortedMsg::from(crate::dlt::DltMessage::for_test()));
        }
        msgs.reverse();
        let mut last_time_stamp = u32::MAX;
        for m in msgs {
            assert!(
                m.0.timestamp_dms <= last_time_stamp,
                "msg has wrong order/time_stamp! {} vs. exp. > {}",
                m.0.timestamp_dms,
                last_time_stamp
            );
            last_time_stamp = m.0.timestamp_dms;
            tx.send(m).unwrap();
        }

        let (tx2, rx2) = channel();
        let t = std::thread::spawn(move || {
            buffer_sort_elements(
                rx,
                tx2,
                BufferElementsOptions {
                    amount: BufferElementsAmount::NumberElements(NUMBER_MSGS),
                },
            )
        });
        // till now there must be no message in tx:
        assert!(rx2
            .recv_timeout(std::time::Duration::from_millis(50))
            .is_err());
        // close the sender:
        drop(tx);
        // now the first messages should arrive sorted by time_stamp:
        let mut last_time_stamp = 0;
        for i in 0..NUMBER_MSGS {
            let mr = rx2.recv_timeout(std::time::Duration::from_millis(50));
            assert!(mr.is_ok(), "failed to get msg#{}", i);
            let m = mr.unwrap().0;
            assert!(
                m.timestamp_dms > last_time_stamp,
                "msg#{} has wrong order/time_stamp! {} vs. exp. > {}",
                i,
                m.timestamp_dms,
                last_time_stamp
            );
            last_time_stamp = m.timestamp_dms;
        }
        // till now there must be no further message in tx:
        assert!(rx2
            .recv_timeout(std::time::Duration::from_millis(50))
            .is_err());
        t.join().unwrap();
        assert!(rx2
            .recv_timeout(std::time::Duration::from_millis(50))
            .is_err());
    }

    #[test]
    fn buffer_sort_elements3() {
        // check that if more elements are added than the BufferElementsAmount
        // that then the smallest one gets pushed out.
        // here: buffer is one smaller than elements
        // so the last elements processed leads to one element being
        // pushed out. Which should be the 2nd smallest one. As the last one
        // is the smallest one.
        let (tx, rx) = channel();
        const NUMBER_MSGS: usize = 1_000;
        let mut msgs: std::vec::Vec<SortedMsg> = std::vec::Vec::with_capacity(NUMBER_MSGS);
        let mut second_msg_timestamp = 0;
        for i in 0..NUMBER_MSGS {
            let m = crate::dlt::DltMessage::for_test();
            if i == 1 {
                second_msg_timestamp = m.timestamp_us()
            }
            msgs.push(SortedMsg::from(m));
        }
        msgs.reverse();
        let mut last_time_stamp = u32::MAX;
        for m in msgs {
            assert!(
                m.0.timestamp_dms <= last_time_stamp,
                "msg has wrong order/time_stamp! {} vs. exp. > {}",
                m.0.timestamp_dms,
                last_time_stamp
            );
            last_time_stamp = m.0.timestamp_dms;
            tx.send(m).unwrap();
        }

        let (tx2, rx2) = channel();
        let t = std::thread::spawn(move || {
            buffer_sort_elements(
                rx,
                tx2,
                BufferElementsOptions {
                    amount: BufferElementsAmount::NumberElements(NUMBER_MSGS - 1),
                },
            )
        });
        // till now there must be exactly one message in tx:
        let m = rx2.recv().unwrap();
        assert_eq!(m.0.timestamp_us(), second_msg_timestamp); // msg with 2nd lowest timestamp
        assert!(rx2
            .recv_timeout(std::time::Duration::from_millis(50))
            .is_err());
        // close the sender:
        drop(tx);
        // now the first messages should arrive sorted by time_stamp:
        let mut last_time_stamp = 0;
        for i in 0..NUMBER_MSGS - 1 {
            let mr = rx2.recv_timeout(std::time::Duration::from_millis(50));
            assert!(mr.is_ok(), "failed to get msg#{}", i);
            let m = mr.unwrap().0;
            assert!(
                m.timestamp_dms > last_time_stamp,
                "msg#{} has wrong order/time_stamp! {} vs. exp. > {}",
                i,
                m.timestamp_dms,
                last_time_stamp
            );
            last_time_stamp = m.timestamp_dms;
        }
        t.join().unwrap();
    }

    #[test]
    fn buffer_sort_message_sorted_basic1() {
        // a very basic test...
        // 1 ecu, msgs already sorted properly. see whether we keep same order
        // we do need lc calculated as well, could do this manually... (or use the None -> 0 start case)
        let (tx, parse_lc_in) = channel();
        // 0s buffering delay assumed, lc start at 0
        tx.send(DltMessage::for_test_rcv_tms_ms(1_000, 1_000))
            .unwrap();
        // 0.1s buffering delay
        tx.send(DltMessage::for_test_rcv_tms_ms(1_200, 1_100))
            .unwrap();
        drop(tx);

        let (parse_lc_out, sort_in) = channel();
        let (sort_out, rx) = channel();

        let (lcs_r, lcs_w) = evmap::new::<LifecycleId, LifecycleItem>();

        let _lcs_w = parse_lifecycles_buffered_from_stream(lcs_w, parse_lc_in, parse_lc_out);
        assert_eq!(1, lcs_r.len(), "wrong number of lcs!");

        let res = buffer_sort_messages(sort_in, sort_out, &lcs_r, 3, 2_000_000);
        assert!(res.is_ok());
        // check whether the messages are in same (= sorted by timestamp) order
        let mut last_timestamp = 0;
        for _ in 0..2 {
            let m = rx.recv().unwrap();
            assert!(m.timestamp_us() > last_timestamp);
            last_timestamp = m.timestamp_us();
        }
    }

    #[test]
    fn buffer_sort_message_sorted_basic2() {
        // a very basic test...
        // this time lifecycle detection is skipped
        // 1 ecu, msgs already sorted properly. see whether we keep same order
        let (tx, sort_in) = channel();
        // 0s buffering delay assumed, lc start at 0
        tx.send(DltMessage::for_test_rcv_tms_ms(1_000, 1_000))
            .unwrap();
        // 0.1s buffering delay
        tx.send(DltMessage::for_test_rcv_tms_ms(1_200, 1_100))
            .unwrap();
        drop(tx);

        let (sort_out, rx) = channel();

        let (lcs_r, _lcs_w) = evmap::new::<LifecycleId, LifecycleItem>();

        let res = buffer_sort_messages(sort_in, sort_out, &lcs_r, 3, 2_000_000);
        assert!(res.is_ok());
        // check whether the messages are in same (= sorted by timestamp) order
        let mut last_timestamp = 0;
        for _ in 0..2 {
            let m = rx.recv().unwrap();
            assert!(m.timestamp_us() > last_timestamp);
            last_timestamp = m.timestamp_us();
        }
    }

    #[test]
    fn buffer_sort_message_sorted_basic3() {
        // a very basic test...
        // this time lifecycle detection is skipped
        // 1 ecu, msgs rev sorted. see whether they will be sorted
        let (tx, sort_in) = channel();
        // first message received is not the one with lowest timestamp
        let mut m1 = DltMessage::for_test_rcv_tms_ms(0, 1_100);

        // we need to provide a lifecycle as otherwise sorting doesn't work! (todo fix (check with setting lc.start_time to 0))
        let mut lc = Lifecycle::new(&mut m1);

        tx.send(m1).unwrap();
        // 2nd one is slightly earlier... (so has 0.099 less buffering delay)
        let mut m2 = DltMessage::for_test_rcv_tms_ms(1, 1_000);
        assert!(lc.update(&mut m2).is_none());

        tx.send(m2).unwrap();
        drop(tx);

        let (sort_out, rx) = channel();

        let (lcs_r, mut lcs_w) = evmap::new::<LifecycleId, LifecycleItem>();
        lcs_w.insert(lc.id(), lc);
        lcs_w.refresh();

        let res = buffer_sort_messages(sort_in, sort_out, &lcs_r, 3, 2_000_000);
        assert!(res.is_ok());
        // check whether the messages are in same (= sorted by timestamp) order
        let mut last_timestamp = 0;
        for i in 0..2 {
            let m = rx.recv().unwrap();
            assert!(
                m.timestamp_us() > last_timestamp,
                "wrong order at msg#{}: {:?}",
                i,
                m
            );
            last_timestamp = m.timestamp_us();
        }
    }

    // todo add buffer_sort_message test that:
    // - are longer than the window_size
    // - that have within the buffer a larger buffer_delay and wont get sorted
    // - have a really huge initial buffer delay within the window_size
    // - have multiple lifecycles
    // - are from multiple (independent) ecus
}
