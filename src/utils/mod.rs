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
    calculated_time: u64, // lc.start_time + m.timestamp_us
}
impl std::cmp::PartialEq for SortedDltMessage {
    fn eq(&self, other: &Self) -> bool {
        self.calculated_time == other.calculated_time // todo index as well?
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
        } else {
            if self.calculated_time == other.calculated_time {
                self.m.index.cmp(&other.m.index) // keep the initial order on same timestamp
            } else {
                self.calculated_time.cmp(&other.calculated_time)
            }
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
/// The messages get buffered for the specified `buffered_time_us`.
/// #### Note Make sure that the messages are not delayed/buffered longer than the timeframe. Otherwise the result will not be sorted correctly.
/// #### Note The lifecycle start times are not changed during the processing but are cached with the first value. So if the times slightly change any messages from parallel lifecycles will be wrongly sorted.
pub fn buffer_sort_messages<'a, M, S>(
    inflow: Receiver<crate::dlt::DltMessage>,
    outflow: Sender<crate::dlt::DltMessage>,
    lcs_r: &'a evmap::ReadHandle<
        crate::lifecycle::LifecycleId,
        crate::lifecycle::LifecycleItem,
        M,
        S,
    >,
    buffer_time_us: u64,
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
                    },
                    None => 0,
                };
                lc_map.insert(*x, start_time);
                println!("added lc_map {} {}", x, start_time);
                start_time
            }
        }
    };

    for m in inflow {
        let last_reception_time_us = m.reception_time_us;
        // add message sorted into buffer
        let calculated_time: u64 = if m.is_ctrl_request() {
            if m.index<100 {println!("m.is_ctrl_request!");}
            m.reception_time_us
        } else {
            get_lc_start_time(m.lifecycle) + m.timestamp_us()
        };
        let sm = SortedDltMessage { m, calculated_time };
        let idx = buffer.binary_search(&sm).unwrap_or_else(|x| x); // this is not stable but shouldn't matter as we added index to cmp::Ord
        if sm.m.index < 100 {
            println!("adding calc_time={} lrt={} buf={} idx={} len={}", calculated_time, last_reception_time_us, last_reception_time_us-calculated_time, idx, buffer.len());
        } 

        buffer.insert(idx, sm);
        // remove all messages from buffer that have a time more than buffer_time_us earlier
        loop {
            match buffer.front() {
                Some(sm) => {
                    if sm.calculated_time + buffer_time_us < last_reception_time_us {
                        let sm2 = buffer.pop_front().unwrap();
                        outflow.send(sm2.m)?;
                    } else {
                        break; // msgs are sorted so we stop here and check after next msg
                    }
                }
                None => {
                    break;
                }
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
    use crate::utils::*;
    use std::sync::mpsc::channel;
    //    use std::time::Instant;
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
    fn buffer_sort_messages() {
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
}
