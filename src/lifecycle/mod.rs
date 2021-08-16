// todos:
// use https://lib.rs/crates/loom for concurrency testing
// use https://lib.rs/crates/lasso for string interner or
// https://lib.rs/crates/arccstr or https://lib.rs/crates/arcstr
// once_cell for one time inits.
use crate::{DltChar4, DltMessage};
use std::hash::{Hash, Hasher};
use std::sync::mpsc::{Receiver, Sender};

pub type LifecycleId = u32;
pub type LifecycleItem = Lifecycle; // Box<Lifecycle>; V needs to be Eq+Hash+ShallowCopy (and Send?)
                                    // std::cell::RefCell misses ShallowCopy (makes sense as the destr wont be called properly to determine refcounts)
                                    // std::rc::Rc misses Send
                                    // std::sync::Arc ... cannot borrow data in an Arc as mutable -> mod.rs:149
                                    // RwLock&Mutex misses ShallowCopy, Eq and Hash

fn new_lifecycle_item(lc: Lifecycle) -> LifecycleItem {
    LifecycleItem::from(lc) // Box::from(lc)
                            //std::sync::Arc::new(std::cell::Cell::from(lc))
}

#[derive(Debug, Clone, Copy)]
pub struct Lifecycle {
    /// unique id
    id: LifecycleId,
    ecu: DltChar4,
    pub nr_msgs: u32,
    pub start_time: u64,     // start time in us.
    pub max_time_stamp: u64, // max. timestamp of the messages assigned to this lifecycle. Used to determine end_time()
}

impl evmap::ShallowCopy for Lifecycle {
    unsafe fn shallow_copy(&self) -> std::mem::ManuallyDrop<Self> {
        std::mem::ManuallyDrop::new(*self)
    }
}

impl PartialEq for Lifecycle {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}
impl Eq for Lifecycle {}
impl Hash for Lifecycle {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

/// next lifecycle id. Zero is used as "no lifecycle" so first one must start with 1
static NEXT_LC_ID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);

impl Lifecycle {
    pub fn get_id(&self) -> u32 {
        self.id
    }
    pub fn get_end_time(&self) -> u64 {
        return self.start_time + self.max_time_stamp;
    }
    pub fn new(msg: &mut DltMessage) -> Lifecycle {
        // println!("new lifecycle created by {:?}", msg);
        let alc = Lifecycle {
            id: NEXT_LC_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            ecu: msg.ecu.clone(),
            nr_msgs: 1,
            start_time: msg.received_time - msg.time_stamp,
            max_time_stamp: msg.time_stamp,
        };
        msg.lifecycle = alc.id;
        alc
    }

    /// merge another lifecycle into this one
    /// the other lifecycle afterwards indicates that it was
    /// merged with get_was_merged() and point with
    /// get_final_lc() to this lifecycle
    pub fn merge(&mut self, lc_to_merge: &mut Lifecycle) {
        assert_ne!(lc_to_merge.nr_msgs, 0);
        self.nr_msgs += lc_to_merge.nr_msgs;
        lc_to_merge.nr_msgs = 0; // this indicates a merged lc
        if lc_to_merge.max_time_stamp > self.max_time_stamp {
            self.max_time_stamp = lc_to_merge.max_time_stamp;
        }
        if lc_to_merge.start_time < self.start_time {
            self.start_time = lc_to_merge.start_time;
        }
        // we mark this in the merged lc as max_time_stamp <- id
        lc_to_merge.max_time_stamp = self.id as u64;
        lc_to_merge.start_time = u64::MAX;
    }

    pub fn get_was_merged(&self) -> Option<u32> {
        if self.nr_msgs == 0 {
            Some(self.max_time_stamp as u32)
        } else {
            None
        }
    }

    pub fn get_final_lc<'a>(
        &'a self,
        interims_lcs: &'a std::collections::HashMap<LifecycleId, &Lifecycle>,
    ) -> &'a Lifecycle {
        if self.nr_msgs == 0 {
            interims_lcs.get(&(self.max_time_stamp as u32)).unwrap()
        } else {
            self
        }
    }

    /// update the Lifecycle. If this msg doesn't seem to belong to the current one
    /// a new lifecycle is created and returned.
    pub fn update(&mut self, msg: &mut DltMessage) -> Option<Lifecycle> {
        // check whether this msg belongs to the lifecycle:
        // 1) the calc start time needs to be no later than the current end time
        // println!("update: lifecycle triggered to LC:{:?}", &self);
        let msg_lc_start = msg.received_time - msg.time_stamp;
        let cur_end_time = self.get_end_time();
        if msg_lc_start <= cur_end_time {
            // ok belongs to this lifecycle

            if self.max_time_stamp < msg.time_stamp {
                self.max_time_stamp = msg.time_stamp;
            }

            // does it move the start to earlier? (e.g. has a smaller buffering delay)
            if msg_lc_start < self.start_time {
                self.start_time = msg_lc_start;
            }
            msg.lifecycle = self.id;
            self.nr_msgs += 1;
            // println!("update: lifecycle updated by {:?} to LC:{:?}", msg, &self);
            None
        } else {
            println!(
                "update: new lifecycle created by {:?} as msg_lc_start {} > {} LC:{:?}",
                msg, msg_lc_start, cur_end_time, &self
            );
            // new lifecycle:
            Some(Lifecycle::new(msg))
        }
    }
}

/// Calculate lifecycles from a stream of DltMessages.
/// # Assumptions:
/// * the stream is per ecu in the order as generated by the ecu. So messages are not in random order.
/// * if the origin are multiple files they are sorted by reception time already before sending to here
///
/// The messages are passed via a stream and will be forwarded to one after processing.
///
/// # Examples
/// ````
/// let (tx, rx) = std::sync::mpsc::channel();
/// let (tx2, _rx2) = std::sync::mpsc::channel();
/// // add msgs here to the tx side
/// // tx.send(msg);
/// drop(tx); // close the channel tx to indicate last msg otherwise the function wont end
/// let (_lcs_r, lcs_w) = evmap::new::<adlt::lifecycle::LifecycleId, adlt::lifecycle::LifecycleItem>();
/// let lcs_w = adlt::lifecycle::parse_lifecycles_from_stream(lcs_w, rx, tx2);
/// ````
/// # Note
/// As soon as the lcs_w is dropped the lcs_r returns no data. That's why the lcs_w is returned and
/// can be used e.g. by the caller even if a thread is spawned like
/// ````
/// let (tx, rx) = std::sync::mpsc::channel();
/// let (tx2, _rx2) = std::sync::mpsc::channel();
/// // add msgs here to the tx side
/// // tx.send(msg);
/// drop(tx); // close the channel tx to indicate last msg otherwise the function wont end
/// let (lcs_r, lcs_w) = evmap::new::<adlt::lifecycle::LifecycleId, adlt::lifecycle::LifecycleItem>();
/// let t = std::thread::spawn(move || adlt::lifecycle::parse_lifecycles_from_stream(lcs_w, rx, tx2));
/// let lcs_w = t.join().unwrap();
/// // now lcs_r still contains valid data!
/// ````
pub fn parse_lifecycles_from_stream<M, S>(
    mut lcs_w: evmap::WriteHandle<LifecycleId, LifecycleItem, M, S>,
    inflow: Receiver<DltMessage>,
    outflow: Sender<DltMessage>,
) -> evmap::WriteHandle<LifecycleId, LifecycleItem, M, S>
where
    S: std::hash::BuildHasher + Clone,
    M: 'static + Clone,
{
    /*
        let lc1 = Lifecycle::new(&mut DltMessage::for_test());
        lcs_w.insert(lc1.id, Box::from(lc1));
        let lc2 = Lifecycle::new(&mut DltMessage::for_test());
        lcs_w.insert(lc2.id, Box::from(lc2));
        lcs_w.refresh(); // even if we use lcs_w.read we get the "refreshed"/committed values only.
    */
    // create a map of ecu:vec<lifecycle.id>
    // we can maintain that here as we're the only one modifying the lcs_ evmap
    let mut ecu_map: std::collections::HashMap<DltChar4, Vec<Lifecycle>> =
        std::collections::HashMap::new();

    for lci in lcs_w.read().iter() {
        for (_id, b) in lci {
            let lc = b.get_one().unwrap();
            match ecu_map.get_mut(&lc.ecu) {
                None => {
                    //ecu_map.insert(lc.ecu.clone(), [lc.id].to_vec());
                    ecu_map.insert(lc.ecu.clone(), [lc.clone()].to_vec());
                }
                Some(v) => v.push(lc.clone()),
            }
        }
    }

    println!("Have ecu_map.len={}", ecu_map.len());
    for (k, v) in &ecu_map {
        println!("Have for ecu {:?} {:?}", &k, &v);
    }

    let mut last_last_lc_id = 0;

    for mut msg in inflow {
        // println!("last_last_lc_id {} got msg:{:?}", last_last_lc_id, msg);
        // get the lifecycles for the ecu from that msg:
        let ecu_lcs = ecu_map.entry(msg.ecu.clone()).or_insert_with(|| Vec::new());

        let ecu_lcs_len = ecu_lcs.len();
        if ecu_lcs_len > 0 {
            // get LC with that id:
            let (last_lc, rest_lcs) = ecu_lcs.as_mut_slice().split_last_mut().unwrap();
            let lc2 = last_lc; // : &mut Lifecycle = &mut last_lcs[ecu_lcs_len - 1]; // [ecu_lcs_len - 1]; //  ecu_lcs.last_mut().unwrap();
            assert_eq!(last_last_lc_id, lc2.id);
            let mut remove_last_lc = false;
            match lc2.update(&mut msg) {
                None => {
                    // lc2 was updated

                    // now we have to check whether it overlaps with the prev. one and needs to be merged:
                    if ecu_lcs_len > 1 {
                        let prev_lc = rest_lcs.last_mut().unwrap(); // : &mut Lifecycle = &mut last_lcs[ecu_lcs_len - 2];
                        if lc2.start_time <= prev_lc.get_end_time() {
                            println!("merge needed:\n {:?}\n {:?}", prev_lc, lc2);
                            // we merge into the prev. one (so use the prev.one only)
                            prev_lc.merge(lc2);
                            lcs_w.update(prev_lc.id, *prev_lc);
                            last_last_lc_id = prev_lc.id;
                            // we will store lc2 later as the msgs still point to this one
                            // but we have to make sure that this is not ecu_lcs anymore
                            remove_last_lc = true;
                            // check whether prev_lc now overlaps with the prevprev one... todo
                        }
                    }
                    lcs_w.update(lc2.id, *lc2);
                    // todo refresh logic needed, e.g. by option every x sec or every x msgs
                    // for now only at the end or if a new lc is created
                    //lcs_w.refresh();
                }
                Some(lc3) => {
                    // new lc was created
                    last_last_lc_id = lc3.id;
                    lcs_w.insert(lc3.id, new_lifecycle_item(lc3));
                    ecu_lcs.push(lc3);

                    // have to refresh here as a new lc was created to ensure that lcs always contains all lcs referenced by the msgs
                    lcs_w.refresh();
                    for a in lcs_w.read().iter() {
                        for (id, b) in a {
                            println!("lcs_w content id={:?} lc={:?}", id, b);
                        }
                    }
                }
            }
            if remove_last_lc {
                ecu_lcs.remove(ecu_lcs_len - 1);
            }
        } else {
            let lc = Lifecycle::new(&mut msg);
            last_last_lc_id = lc.id;
            lcs_w.insert(lc.id, new_lifecycle_item(lc));
            ecu_lcs.push(lc);
            // have to refresh here as a new lc was created to ensure that lcs always contains all lcs referenced by the msgs
            lcs_w.refresh();
        }

        // pass msg to outflow
        outflow.send(msg).unwrap(); // todo how handle errors?
    }
    lcs_w.refresh();
    println!(
        "After processing stream: Have ecu_map.len={}",
        ecu_map.len()
    );
    for (k, v) in &ecu_map {
        println!("Have for ecu {:?} {:?}", &k, &v);
    }

    for a in lcs_w.read().iter() {
        println!("lcs_w a...");
        for (id, b) in a {
            println!("lcs_w content id={:?} lc={:?}", id, b);
        }
    }
    lcs_w
}

#[cfg(test)]
mod tests {
    //use super::*;
    use crate::lifecycle::*;
    use std::sync::mpsc::channel;
    use std::time::Instant;
    extern crate nohash_hasher;
    #[test]
    fn one_ecu() {
        let (tx, rx) = channel();
        const NUMBER_ITERATIONS: usize = 2_000_000;
        let start = Instant::now();
        for _ in 0..NUMBER_ITERATIONS {
            tx.send(crate::DltMessage::for_test()).unwrap();
        }
        let duration = start.elapsed();
        println!(
            "Time elapsed sending {}msgs is: {:?}",
            NUMBER_ITERATIONS, duration
        );
        let (tx2, rx2) = channel();
        drop(tx);
        let (lcs_r, lcs_w) = evmap::Options::default()
            .with_hasher(nohash_hasher::BuildNoHashHasher::<LifecycleId>::default())
            .construct::<LifecycleId, LifecycleItem>(); //  evmap::new::<u32, Box<Lifecycle>>();
        let start = Instant::now();
        let t = std::thread::spawn(move || parse_lifecycles_from_stream(lcs_w, rx, tx2));
        for a in lcs_r.read().iter() {
            println!("lcs_r content before join {:?}", a);
        }
        let lcs_w = t.join().unwrap();
        let duration = start.elapsed();
        println!(
            "Time elapsed parse_lifecycles {}msgs is: {:?}",
            NUMBER_ITERATIONS, duration
        );
        // all messages should be passed on
        let start = Instant::now();
        {
            let read_handle = lcs_r.read();
            assert_eq!(read_handle.is_some(), true);
            let read_handle = read_handle.unwrap();
            for i in 0..NUMBER_ITERATIONS {
                // check whether all msgs have a lifecycle:
                let m = rx2.recv();
                assert_eq!(m.is_ok(), true, "{}th message missing", i + 1);
                let msg = m.unwrap();
                assert_ne!(msg.lifecycle, 0, "{}th message without lifecycle", i + 1);
                // check that the lifecycle is known as well: (this seems time consuming! around if omitted 90ms instead of 180ms)
                //let l = lcs_r.get_one(&msg.lifecycle);
                // using the read_handle its a lot faster: 106ms instead of 180ms/90ms
                let l = read_handle.get_one(&msg.lifecycle);
                assert_eq!(l.is_some(), true);
            }
        }
        let duration = start.elapsed();
        println!(
            "Time elapsed reading/verifying {}msgs is: {:?}",
            NUMBER_ITERATIONS, duration
        );
        assert_ne!(rx2.recv().is_ok(), true);
        // and lifecycle info be available
        for a in lcs_r.read().iter() {
            println!("lcs_r content {:?}", a);
        }
        for a in lcs_w.read().iter() {
            for (id, b) in a {
                println!("lcs_w2 content id={:?} lc={:?}", id, b);
            }
        }
        assert_eq!(lcs_r.is_empty(), false, "empty lcs!");
        assert_eq!(lcs_r.len(), 1, "wrong number of lcs!");
    }
    #[test]
    fn basics() {
        let (tx, rx) = channel();
        let (tx2, rx2) = channel();
        drop(tx);
        let (_lcs_r, lcs_w) = evmap::new::<LifecycleId, LifecycleItem>();
        parse_lifecycles_from_stream(lcs_w, rx, tx2);
        assert_eq!(rx2.recv().is_err(), true);
    }
    #[test]
    fn basics_read_in_different_thread() {
        let (tx, rx) = channel();
        let (tx2, rx2) = channel();
        drop(tx);
        let (lcs_r, lcs_w) = evmap::new::<LifecycleId, LifecycleItem>();
        parse_lifecycles_from_stream(lcs_w, rx, tx2);
        assert_eq!(rx2.recv().is_err(), true);
        let r = lcs_r.clone();
        let t = std::thread::spawn(move || {
            for a in r.read().iter() {
                println!("r content {:?}", a);
            }
            assert_eq!(r.len(), 0);
        });
        t.join().unwrap();
    }

    /// a generator for messages to ease test scenarios for lifecycles
    struct MessageGenerator {
        msgs: std::vec::Vec<DltMessage>,
    }

    impl MessageGenerator {
        fn new(
            lc_start_time: u64,
            initial_delays: &[(u64, u64)],
            nr_msgs: usize,
        ) -> MessageGenerator {
            let mut msgs: std::vec::Vec<DltMessage> = std::vec::Vec::new();
            for (buf_delay, start_delay) in initial_delays {
                for i in 0..nr_msgs {
                    let time_stamp = start_delay + ((i as u64) * 1_000); // frequency
                    let min_send_time = std::cmp::max(buf_delay + (i as u64), time_stamp);
                    msgs.push(DltMessage {
                        received_time: lc_start_time + min_send_time,
                        time_stamp,
                        lifecycle: 0,
                        ecu: DltChar4 {
                            char4: [0x41, 0x42, 0x43, 0x45],
                        },
                    });
                }
            }
            // sort msgs by received time
            msgs.sort_by(|a, b| a.received_time.cmp(&b.received_time));
            MessageGenerator { msgs }
        }
    }

    impl Iterator for MessageGenerator {
        type Item = DltMessage;
        fn next(&mut self) -> Option<Self::Item> {
            // Check to see if we've finished counting or not.
            if self.msgs.len() > 0 {
                let r = Some(self.msgs.remove(0));
                r
            } else {
                None
            }
        }
    }

    #[test]
    fn gen_two_lcs() {
        let (tx, rx) = channel();
        let (tx2, rx2) = channel();
        const NUMBER_PER_MSG_CAT: usize = 50;
        const MSG_DELAYS: [(u64, u64); 2] = [(45_000, 0), (30_000, 10_000)];
        const LC_START_TIMES: [u64; 2] = [1_000_000, 1_060_000];
        const NUMBER_MSGS: usize = LC_START_TIMES.len() * NUMBER_PER_MSG_CAT * MSG_DELAYS.len();
        let gen_lc1 = MessageGenerator::new(LC_START_TIMES[0], &MSG_DELAYS, NUMBER_PER_MSG_CAT);
        for m in gen_lc1 {
            tx.send(m).unwrap();
        }
        let gen_lc2 = MessageGenerator::new(LC_START_TIMES[1], &MSG_DELAYS, NUMBER_PER_MSG_CAT);
        for m in gen_lc2 {
            tx.send(m).unwrap();
        }
        drop(tx);
        let (lcs_r, lcs_w) = evmap::new::<LifecycleId, LifecycleItem>();
        let _lcs_w = parse_lifecycles_from_stream(lcs_w, rx, tx2);
        // now check the lifecycles:
        println!("have {} interims lifecycles", lcs_r.len());
        if let Some(a) = lcs_r.read() {
            println!("have interims lifecycles");
            for (id, b) in a.iter() {
                println!("lcs_r content id={:?} lc={:?}", id, b);
            }
            // view on final lifecycles:
            let mut final_lcs: std::vec::Vec<&Lifecycle> = a
                .iter()
                .filter(|(_id, b)| b.get_one().unwrap().get_was_merged().is_none())
                .map(|(_id, b)| b.get_one().unwrap())
                .collect();
            println!("have {} final lifecycles", final_lcs.len());
            final_lcs.sort_by(|a, b| a.start_time.cmp(&b.start_time));
            for (i, lc) in final_lcs.iter().enumerate() {
                println!("lc={:?}", lc);
                match i {
                    0 => {
                        assert_eq!(lc.start_time, LC_START_TIMES[0]);
                        assert_eq!(lc.nr_msgs as usize, NUMBER_PER_MSG_CAT * MSG_DELAYS.len());
                        assert_eq!(
                            lc.get_end_time(),
                            LC_START_TIMES[0]
                                + ((NUMBER_PER_MSG_CAT as u64 - 1) * 1_000)
                                + MSG_DELAYS[1].1
                        );
                    }
                    1 => {
                        assert_eq!(lc.start_time, LC_START_TIMES[1]);
                        assert_eq!(lc.nr_msgs as usize, NUMBER_PER_MSG_CAT * MSG_DELAYS.len());
                        assert_eq!(
                            lc.get_end_time(),
                            LC_START_TIMES[1]
                                + ((NUMBER_PER_MSG_CAT as u64 - 1) * 1_000)
                                + MSG_DELAYS[1].1
                        );
                    }
                    _ => {
                        assert_eq!(true, false, "too many lifecycles detected {}", i)
                    }
                }
            }

            // create a lifecycle view mapping the interims to the final lifecycles:
            let interims_lcs: std::collections::HashMap<LifecycleId, &Lifecycle> = a
                .iter()
                .map(|(id, b)| (*id, b.get_one().unwrap()))
                .collect();
            println!("have {} mapped lifecycles", interims_lcs.len());

            let mapped_lcs: std::collections::HashMap<LifecycleId, &Lifecycle> = a
                .iter()
                .map(|(id, b)| (*id, b.get_one().unwrap()))
                .map(|(id, l)| (id, l.get_final_lc(&interims_lcs)))
                .collect();
            println!("have mapped lifecycles: {:?}", mapped_lcs);
            // now check whether each message has a valid lifecycle in mapped_lcs:
            // the msg has only an interims lifecycle id which might point to a
            // lifecycle that has been merged into a different one later on
            // or will be merged later on.
            // We could modify the msg as well to point to the final lc.id but
            // for streaming that doesn't really work as the ids might change later
            // so using the mapped lifecycles gives the current view
            for _i in 0..NUMBER_MSGS {
                let rm = rx2.recv();
                assert_eq!(rm.is_err(), false);
                let m = rm.unwrap();
                assert!(m.lifecycle != 0);
                assert!(mapped_lcs.get(&m.lifecycle).is_some());
                assert!(mapped_lcs
                    .get(&m.lifecycle)
                    .unwrap()
                    .get_was_merged()
                    .is_none());
                //println!("got msg:{:?}", rm.unwrap());
            }
            assert_eq!(rx2.recv().is_err(), true);
        } else {
            assert_eq!(true, false);
        };
    }
}
