// todos:
// use https://lib.rs/crates/loom for concurrency testing (atomics,...)
// use https://lib.rs/crates/lasso for string interner or
// https://lib.rs/crates/arccstr or https://lib.rs/crates/arcstr
// once_cell for one time inits.
// use chrono::{Local, TimeZone};
use crate::dlt::{DltChar4, DltMessage};
use std::hash::{Hash, Hasher};
use std::sync::mpsc::{Receiver, Sender};

pub type LifecycleId = u32;
pub type LifecycleItem = Lifecycle; // Box<Lifecycle>; V needs to be Eq+Hash+ShallowCopy (and Send?)
                                    // std::cell::RefCell misses ShallowCopy (makes sense as the destr wont be called properly to determine refcounts)
                                    // std::rc::Rc misses Send
                                    // std::sync::Arc ... cannot borrow data in an Arc as mutable -> mod.rs:149
                                    // RwLock&Mutex misses ShallowCopy, Eq and Hash

fn new_lifecycle_item(lc: Lifecycle) -> LifecycleItem {
    lc
    //LifecycleItem::from(lc) // Box::from(lc)
                            //std::sync::Arc::new(std::cell::Cell::from(lc))
}

#[derive(Debug, Clone, Copy)]
pub struct Lifecycle {
    /// unique id
    id: LifecycleId,
    pub ecu: DltChar4,
    /// contains the number of messages belonging to this lifecycle. `0` indicates that this lifecycle is not valid anymore, e.g. was merged into different one.
    pub nr_msgs: u32,
    /// number of control request messages. They are counted additionaly to identify lifecycles that consists of only control request messages. See [Self::only_control_requests()].
    /// # Note: control request messages are treated differently as their timestamp is from a different clock domain (usually the logging device)
    pub nr_control_req_msgs: u32,
    /// contains the start time of this lifecycle. See [Self::end_time()] as well. During processing this start_time is adjusted.
    /// # Note:
    /// This is not the reception time of the first message but the calculated start time of that lifecycle.
    ///
    /// It's determined by MIN(reception time - timestamp) of all messages.
    ///
    /// The real start time will be slightly earlier as there is a minimal buffering time that is not considered / unknown.
    ///
    pub start_time: u64, // start time in us.
    initial_start_time: u64,
    max_timestamp_us: u64, // max. timestamp of the messages assigned to this lifecycle. Used to determine end_time()
    last_reception_time: u64, // last (should be max.) reception_time (i.e. from last message)
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
    /// returns the unique id of this lifecycle.
    /// # Note:
    /// `0` is never used. And is / can be used as "no lifecycle".
    ///
    /// Take care: lifecycle ids are unique above the overall process run time. So don't rely on the first one being 1.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// returns the end time of this lifecycle.
    /// The end_time is the start_time plus the maximum timestamp of the messages belonging to this lifecycle.
    /// # Note:
    /// This can be either:
    /// * the time of the last log message of this lifecycle or
    /// * the time until the logs have been recorded but the lifecycle might be continued.
    pub fn end_time(&self) -> u64 {
        self.start_time + self.max_timestamp_us
    }

    /// returns whether this lifecycle contains only control request messages.
    /// ### Note: the info is wrong on merged lifecycles (we want to get rid of them anyhow)
    pub fn only_control_requests(&self) -> bool {
        self.nr_control_req_msgs >= self.nr_msgs
    }

    /// create a new lifecycle with the first msg passed as parameter
    pub fn new(msg: &mut DltMessage) -> Lifecycle {
        // println!("new lifecycle created by {:?}", msg);
        let is_ctrl_request = msg.is_ctrl_request();
        let timestamp_us = if is_ctrl_request {
            0
        } else {
            msg.timestamp_us()
        };

        let alc = Lifecycle {
            id: NEXT_LC_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            ecu: msg.ecu,
            nr_msgs: 1,
            nr_control_req_msgs: if is_ctrl_request { 1 } else { 0 },
            start_time: msg.reception_time_us - timestamp_us,
            initial_start_time: msg.reception_time_us - timestamp_us,
            max_timestamp_us: timestamp_us,
            last_reception_time: msg.reception_time_us,
        };
        msg.lifecycle = alc.id;
        alc
    }

    /// merge another lifecycle into this one.
    ///
    /// The other lifecycle afterwards indicates that it was merged with [Self::was_merged()] and points with
    /// [Self::final_lc()] to this lifecycle
    pub fn merge(&mut self, lc_to_merge: &mut Lifecycle) {
        assert_ne!(lc_to_merge.nr_msgs, 0);
        self.nr_msgs += lc_to_merge.nr_msgs;
        self.nr_control_req_msgs += lc_to_merge.nr_control_req_msgs;
        lc_to_merge.nr_msgs = 0; // this indicates a merged lc
        if lc_to_merge.max_timestamp_us > self.max_timestamp_us {
            self.max_timestamp_us = lc_to_merge.max_timestamp_us;
        }
        if lc_to_merge.start_time < self.start_time {
            self.start_time = lc_to_merge.start_time;
            self.initial_start_time = lc_to_merge.initial_start_time;
        }
        if lc_to_merge.last_reception_time > self.last_reception_time {
            self.last_reception_time = lc_to_merge.last_reception_time;
        }
        // we mark this in the merged lc as max_timestamp_dms <- id
        lc_to_merge.max_timestamp_us = self.id as u64;
        lc_to_merge.start_time = u64::MAX;
    }

    /// returns the final lifecycle struct for this lifecycle.
    /// If this lifecycle wasn't merged self is returned.
    ///
    /// If this lifecycle was merged recursively the last merged-into lifecycle is returned.
    pub fn final_lc<'a>(
        &'a self,
        interims_lcs: &'a std::collections::HashMap<LifecycleId, &Lifecycle>,
    ) -> &'a Lifecycle {
        if self.nr_msgs == 0 {
            interims_lcs
                .get(&(self.max_timestamp_us as u32))
                .unwrap()
                .final_lc(interims_lcs)
        } else {
            self
        }
    }

    /// returns whether this lifecycled was merged (so is not valid any longer) into a different lifecycle.
    /// Returns None if not merged otherwise the interims lifecycle id of the lifecycle it was merged into.
    /// # Note:
    /// Take care the returned lifecycle id is interims as well and could be or will be merged as well into another lifecycle!
    /// See [Self::final_lc()] if you want to get the final lifecycle (aka a non merged one)
    ///
    pub fn was_merged(&self) -> Option<u32> {
        if self.nr_msgs == 0 {
            Some(self.max_timestamp_us as u32)
        } else {
            None
        }
    }

    /// update the Lifecycle. If this msg doesn't seem to belong to the current one
    /// a new lifecycle is created and returned.
    /// # TODOs:
    /// * ignore/handle control messages
    /// * if the lifecycle is longer than time x (e.g. a few mins) stop adjusting starttime to reduce impact of different clock speed/skews between recorder and ecu
    ///
    pub fn update(&mut self, msg: &mut DltMessage) -> Option<Lifecycle> {
        // check whether this msg belongs to the lifecycle:
        // 0) ignore any CTRL REQUEST msgs:
        if msg.is_ctrl_request() {
            // we dont check any params but
            // simply add to this one
            msg.lifecycle = self.id;
            self.nr_msgs += 1;
            self.nr_control_req_msgs += 1;
            return None;
        }

        // 1) the calc start time needs to be no later than the current end time
        // or
        // 2) the reception_time - timestamp <= reception_time from last msg
        // rationale for 2): there must be at least a gap of timestamp_us to last message if the message is from a new lifecycle
        let msg_timestamp_us = msg.timestamp_us();
        let msg_lc_start = msg.reception_time_us - msg_timestamp_us;
        let cur_end_time = self.end_time();
        if msg_lc_start <= cur_end_time || 
            msg_lc_start <= self.last_reception_time
         {
            // ok belongs to this lifecycle

            if self.max_timestamp_us < msg_timestamp_us {
                self.max_timestamp_us = msg_timestamp_us;
            }

            if self.last_reception_time > msg.reception_time_us {
                // seems like a bug in dltviewer... 
                // println!("msg.update reception time going backwards! LC:{:?} {:?} {}", self.last_reception_time, msg.reception_time_us, msg.index);
            }
            self.last_reception_time = msg.reception_time_us;

            // does it move the start to earlier? (e.g. has a smaller buffering delay)
            // todo this can as well be caused by clock drift. Need to add clock_drift detection/compensation.
            // the clock drift is relative to the recording devices time clock.
            if msg_lc_start < self.start_time {
                /*println!(
                    "update: lc {} #{} moving lc start_time by {}us to {} initial diff {}us",
                    self.id, self.nr_msgs, self.start_time - msg_lc_start, msg_lc_start, self.initial_start_time - msg_lc_start
                );*/
                self.start_time = msg_lc_start;
            }
            msg.lifecycle = self.id;
            self.nr_msgs += 1;
            // println!("update: lifecycle updated by {:?} to LC:{:?}", msg, &self);
            None
        } else {
            /*println!(
                "update: new lifecycle created by {:?} as msg_lc_start {} > {} LC:{:?}",
                msg, chrono::Local
                .from_utc_datetime(&crate::utils::utc_time_from_us(msg_lc_start))
                .format("%Y/%m/%d %H:%M:%S%.6f"), chrono::Local
                .from_utc_datetime(&crate::utils::utc_time_from_us(cur_end_time))
                .format("%Y/%m/%d %H:%M:%S%.6f"), &self
            );*/
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
/// This unbuffered version assigns "interims" lifecycles that later on might be merged into the previous one.
/// If you want to avoid that you can use the [parse_lifecycles_buffered_from_stream] version.
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
                    ecu_map.insert(lc.ecu, [*lc].to_vec());
                }
                Some(v) => v.push(*lc),
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
        let ecu_lcs = ecu_map.entry(msg.ecu).or_insert_with(Vec::new);

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
                        if lc2.start_time <= prev_lc.end_time() {
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
                    // this version creates interims lifecycles. An alternative approach is implemented in [parse_lifecycles_buffered_from_stream]
                    last_last_lc_id = lc3.id;
                    lcs_w.insert(lc3.id, new_lifecycle_item(lc3));
                    ecu_lcs.push(lc3);

                    // have to refresh here as a new lc was created to ensure that lcs always contains all lcs referenced by the msgs
                    lcs_w.refresh();
                    /* for a in lcs_w.read().iter() {
                        for (id, b) in a {
                            println!("lcs_w content id={:?} lc={:?}", id, b);
                        }
                    }*/
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
    /*
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
    }*/
    lcs_w
}

/// Calculate lifecycles from a stream of DltMessages.
/// # Assumptions:
/// * the stream is per ecu in the order as generated by the ecu. So messages are not in random order.
/// * if the origin are multiple files they are sorted by reception time already before sending to here
///
/// The messages are passed via a stream and will be forwarded to one after processing.
/// Messages might be buffered internally and are only forwarded as soon as the lifecycle is determined.
///
///
/// # Examples
/// ````
/// let (tx, rx) = std::sync::mpsc::channel();
/// let (tx2, _rx2) = std::sync::mpsc::channel();
/// // add msgs here to the tx side
/// // tx.send(msg);
/// drop(tx); // close the channel tx to indicate last msg otherwise the function wont end
/// let (_lcs_r, lcs_w) = evmap::new::<adlt::lifecycle::LifecycleId, adlt::lifecycle::LifecycleItem>();
/// let lcs_w = adlt::lifecycle::parse_lifecycles_buffered_from_stream(lcs_w, rx, tx2);
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
/// let t = std::thread::spawn(move || adlt::lifecycle::parse_lifecycles_buffered_from_stream(lcs_w, rx, tx2));
/// let lcs_w = t.join().unwrap();
/// // now lcs_r still contains valid data!
/// ````
pub fn parse_lifecycles_buffered_from_stream<M, S>(
    mut lcs_w: evmap::WriteHandle<LifecycleId, LifecycleItem, M, S>,
    inflow: Receiver<DltMessage>,
    outflow: Sender<DltMessage>,
) -> evmap::WriteHandle<LifecycleId, LifecycleItem, M, S>
where
    S: std::hash::BuildHasher + Clone,
    M: 'static + Clone,
{
    let max_buffering_delay: u64 = 60_000;
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
                    ecu_map.insert(lc.ecu, [*lc].to_vec());
                }
                Some(v) => v.push(*lc),
            }
        }
    }

    /*
    println!("Have ecu_map.len={}", ecu_map.len());
    for (k, v) in &ecu_map {
        println!("Have for ecu {:?} {:?}", &k, &v);
    }*/

    let mut buffered_msgs: std::vec::Vec<DltMessage> = std::vec::Vec::new();
    let mut buffered_lcs: std::collections::HashSet<LifecycleId> = std::collections::HashSet::new();

    // todo add check that msg.received times increase monotonically!
    let mut merged_needed_id : LifecycleId = 0;

    for mut msg in inflow {
        // println!("last_last_lc_id {} got msg:{:?}", last_last_lc_id, msg);
        // get the lifecycles for the ecu from that msg:
        let msg_ecu = msg.ecu;//.clone();
        let ecu_lcs = ecu_map.entry(msg_ecu).or_insert_with(Vec::new);

        let ecu_lcs_len = ecu_lcs.len();
        if ecu_lcs_len > 0 {
            // get LC with that id:
            let (last_lc, rest_lcs) = ecu_lcs.as_mut_slice().split_last_mut().unwrap();
            let lc2 = last_lc;
            let mut remove_last_lc = false;
            match lc2.update(&mut msg) {
                None => {
                    // lc2 was updated

                    // now we have to check whether it overlaps with the prev. one and needs to be merged:
                    if ecu_lcs_len > 1 {
                        let prev_lc = rest_lcs.last_mut().unwrap(); // : &mut Lifecycle = &mut last_lcs[ecu_lcs_len - 2];
                        if lc2.start_time <= prev_lc.end_time() {
                            // todo consider clock skew here. the earliest start time needs to be close to the prev start time and not just within...
                            if merged_needed_id != lc2.id {
                                println!("merge needed:\n {:?}\n {:?}", prev_lc, lc2);
                                merged_needed_id = lc2.id;
                            }
                        }
                        if false /* && lc2.start_time <= prev_lc.end_time() */ {
                            // todo consider clock skew here. the earliest start time needs to be close to the prev start time and not just within...
                            println!("merge needed:\n {:?}\n {:?}", prev_lc, lc2);
                            // we merge into the prev. one (so use the prev.one only)
                            let is_buffered = buffered_lcs.contains(&lc2.id);
                            if is_buffered {
                                // the buffered lcs shall be merged again.
                                // this is easy now:
                                prev_lc.merge(lc2);
                                msg.lifecycle = prev_lc.id;
                                // and now update the buffered msgs:
                                {
                                    buffered_msgs.iter_mut().for_each(|m| {
                                        println!(
                                            "modifying lifecycle from {} to {} for {:?}",
                                            lc2.id, prev_lc.id, m
                                        );
                                        if m.lifecycle == lc2.id {
                                            (*m).lifecycle = prev_lc.id;
                                        }
                                    });
                                    buffered_msgs.iter().for_each(|m| {
                                        assert_ne!(m.lifecycle, lc2.id);
                                    });
                                };
                                // we can delete the buffered_lcs elem now:
                                buffered_lcs.remove(&lc2.id);
                                remove_last_lc = true;
                                // if we have no more yet, send the other msgs:
                                if buffered_lcs.is_empty() {
                                    while !buffered_msgs.is_empty() {
                                        // todo really inefficient!!!! use drain???
                                        let msg = buffered_msgs.remove(0);
                                        // println!("sending early buffered_msg {:?}", msg);
                                        outflow.send(msg).unwrap();
                                    }
                                    assert_eq!(buffered_msgs.len(), 0);
                                }
                            } else {
                                panic!("todo shouldn't happen yet!");
                                // this is the rare case where there had been already 2 lifecycles from prev. run and now
                                // the 2nd got merged... todo think about how to handle that... as we dont want to have our callers
                                // have to support/handle interims lifecycles!
                                /*
                                prev_lc.merge(lc2);
                                lcs_w.update(prev_lc.id, *prev_lc);
                                // we will store lc2 later as the msgs still point to this one
                                // but we have to make sure that this is not ecu_lcs anymore
                                remove_last_lc = true;
                                // check whether prev_lc now overlaps with the prevprev one... todo
                                */
                            }
                        }
                        // can we close the buffered lifecycle now?
                        let is_buffered = buffered_lcs.contains(&lc2.id);
                        if is_buffered {
                            // lets calc the earliest possible lc start time assuming the current message has max buffering delays:
                            let min_lc_start_time =
                                (msg.reception_time_us - msg.timestamp_us()) - max_buffering_delay;
                            // if this is not earlier than the prev_lc start-time we can conclude its a new lifecycle
                            if min_lc_start_time > prev_lc.start_time {
                                // println!("confirmed buffered lc {} as min_lc_start_time {} > prev_lc.start_time {}, lc={:?}", lc2.id, min_lc_start_time, prev_lc.start_time, lc2);
                                buffered_lcs.remove(&lc2.id);
                                lcs_w.insert(lc2.id, new_lifecycle_item(*lc2));
                                lcs_w.refresh();
                                // if we have no more yet, send the other msgs:
                                if buffered_lcs.is_empty() {
                                    while !buffered_msgs.is_empty() {
                                        // todo really inefficient!!!! use drain???
                                        let msg = buffered_msgs.remove(0);
                                        // println!("sending early buffered_msg {:?}", msg);
                                        outflow.send(msg).unwrap();
                                    }
                                    assert_eq!(buffered_msgs.len(), 0);
                                }
                            }
                        }
                    }
                    // if we have buffered lifecycles check whether we can stop buffering them and mark as valid ones:
                    // once the lifecycle start even including a max buffering delay can not fit into the prev one any longer:
                    if !buffered_lcs.is_empty() {
                        // we compare all lcs vs. the current msg received time (as we do assume that messages are sorted by received time even across ecus)
                        // todo let _rcvd_time = msg.reception_time_us;
                        // todo impl this as well to close e.g. lifecycles with very few messages from ecus earlier
                    }

                    if lcs_w.contains_key(&lc2.id) {
                        lcs_w.update(lc2.id, *lc2);
                        lcs_w.refresh(); // only needed if start_time changed
                    }
                    // todo refresh logic needed, e.g. by option every x sec or every x msgs
                    // for now only at the end or if a new lc is created
                    //lcs_w.refresh();
                }
                Some(lc3) => {
                    // new lc was created (as calc. lc start_time was past prev lc end time)

                    // we buffer here the messages until its clear that this is really
                    // a new lifecycle and wont be merged soonish into the prev. lifecycle!
                    // this would allow us to still correct the msgs and dont have to handle the "interims" lifecycles later on!
                    // disadvantage is that we'd need to delay here the output. But we might have to do so anyhow later.
                    // can we define an upper limit on the time to delay? or some criteria on when to stop buffering?
                    // possible criteria:
                    // 1. once the new lifecycle overlaps the prev. one -> and needs a merge (see above)
                    // 2. once the new lifecycle contains messages with timestamp > x (max buffering at (start plus at runtime) buffer)
                    // println!("added lc id {} to buffered_lcs", lc3.id);
                    buffered_lcs.insert(lc3.id);
                    ecu_lcs.push(lc3); // we (sadly?) have copy trait for lifecycle
                                       /*
                                       lcs_w.insert(lc3.id, new_lifecycle_item(lc3));
                                       ecu_lcs.push(lc3);

                                       // have to refresh here as a new lc was created to ensure that lcs always contains all lcs referenced by the msgs
                                       lcs_w.refresh();
                                       for a in lcs_w.read().iter() {
                                           for (id, b) in a {
                                               println!("lcs_w content id={:?} lc={:?}", id, b);
                                           }
                                       }*/
                }
            }
            if remove_last_lc {
                let removed = ecu_lcs.remove(ecu_lcs_len - 1);
                assert!(!buffered_lcs.contains(&removed.id));
            }
        } else {
            assert_eq!(
                buffered_lcs.len(),
                0,
                "buffered_lcs exist already. not yet implemented/tested!"
            );
            let lc = Lifecycle::new(&mut msg);
            lcs_w.insert(lc.id, new_lifecycle_item(lc));
            ecu_lcs.push(lc);
            // have to refresh here as a new lc was created to ensure that lcs always contains all lcs referenced by the msgs
            lcs_w.refresh();
        }

        // pass msg to outflow only if we dont have buffered lcs:
        if !buffered_lcs.is_empty() {
            buffered_msgs.push(msg);
        } else {
            // todo slog... println!("sending non-buffered_msg {:?}", msg);
            outflow.send(msg).unwrap(); // todo how handle errors?
        }
    }

    // if we have still buffered lcs we have to make them valid now:
    //println!("adding {} buffered_lcs to lcs_w at end", buffered_lcs.len());
    for lc_id in buffered_lcs {
        'outer: for vs in ecu_map.values() {
            for v in vs {
                if v.id == lc_id {
                    lcs_w.insert(lc_id, new_lifecycle_item(*v));
                    // println!("lcs_w content added at end id={:?} lc={:?}", lc_id, *v);
                    break 'outer;
                }
            }
        }
    }
    lcs_w.refresh();

    // if we have buffered msgs we have to output them now:
    for m in buffered_msgs.into_iter() {
        // println!("sending buffered_msg {:?}", m);
        outflow.send(m).unwrap();
    }

    /*
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
    }*/
    lcs_w
}

/// Get hashmap/view with "interims lifecycles"
/// This is a hash LifecycleId -> &Lifecycle where the "interims" aka merged into others
/// lifecycles are included as well.
/// This is basically an easier to use interface for the lcs_r MapReadRef returned from
/// [parse_lifecycles_from_stream()].
/// # Example
/// see [get_mapped_lifecycles_as_hashmap]
pub fn get_interims_lifecycles_as_hashmap<'a, M, S>(
    lcr: &'a evmap::MapReadRef<LifecycleId, LifecycleItem, M, S>,
) -> std::collections::HashMap<LifecycleId, &'a Lifecycle>
where
    S: std::hash::BuildHasher + Clone,
    M: 'static + Clone,
{
    lcr.iter()
        .map(|(id, b)| (*id, b.get_one().unwrap()))
        .collect()
}

/// Get hashmap/view with "mapped lifecycles"
/// This is a hash LifecycleId -> &Lifecycle where as id the interims ids from messages
/// can be used but the result is the final lifecycle.
/// So messages pointing to interims (aka merged into others) lifecycles can be used as index
/// # Example
/// ````
/// let (lcs_r, _lcs_w) = evmap::new::<adlt::lifecycle::LifecycleId, adlt::lifecycle::LifecycleItem>();
/// if let Some(lcr) = lcs_r.read() {
///     let interims_lcs = adlt::lifecycle::get_interims_lifecycles_as_hashmap(&lcr);
///     let mapped_lcs = adlt::lifecycle::get_mapped_lifecycles_as_hashmap(&interims_lcs);
///     let msgs: std::vec::Vec<adlt::dlt::DltMessage> = std::vec::Vec::new();
///     // ... init with some msgs for a real loop...
///     for m in msgs {
///         let lc = mapped_lcs.get(&m.lifecycle);
///     }
/// };
/// ````
pub fn get_mapped_lifecycles_as_hashmap<'a>(
    interims_lcs: &'a std::collections::HashMap<LifecycleId, &'a Lifecycle>,
) -> std::collections::HashMap<LifecycleId, &'a Lifecycle> {
    interims_lcs
        .iter()
        .map(|(id, l)| (*id, l.final_lc(interims_lcs)))
        .collect()
}

/// return a vector of lifecycles sorted by start_time
/// asserts if an interims lifecycle is contained!
/// todo add example
pub fn get_sorted_lifecycles_as_vec<'a, M, S>(
    lcr: &'a evmap::MapReadRef<LifecycleId, LifecycleItem, M, S>,
) -> std::vec::Vec<&'a Lifecycle>
where
    S: std::hash::BuildHasher + Clone,
    M: 'static + Clone,
{
    let mut sorted_lcs: std::vec::Vec<&'a Lifecycle> = lcr
        .iter()
        .map(|(id, b)| {
            let lc = b.get_one().unwrap();
            assert_eq!(&lc.id, id);
            lc
        })
        .collect();
    sorted_lcs.sort_by(|a, b| a.start_time.cmp(&b.start_time));
    sorted_lcs
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
            tx.send(crate::dlt::DltMessage::for_test()).unwrap();
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
        let t = std::thread::spawn(move || parse_lifecycles_buffered_from_stream(lcs_w, rx, tx2));
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
        parse_lifecycles_buffered_from_stream(lcs_w, rx, tx2);
        assert_eq!(rx2.recv().is_err(), true);
    }
    #[test]
    fn basics_read_in_different_thread() {
        let (tx, rx) = channel();
        let (tx2, rx2) = channel();
        drop(tx);
        let (lcs_r, lcs_w) = evmap::new::<LifecycleId, LifecycleItem>();
        parse_lifecycles_buffered_from_stream(lcs_w, rx, tx2);
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
    struct MessageGeneratorOptions {
        frequency: u64,
        ecu: DltChar4,
    }
    impl Default for MessageGeneratorOptions {
        fn default() -> Self {
            MessageGeneratorOptions {
                frequency: 1_000,
                ecu: DltChar4::from_buf(&[0x41, 0x42, 0x43, 0x45]),
            }
        }
    }

    impl MessageGenerator {
        fn new(
            lc_start_time: u64,
            initial_delays: &[(u64, u64)],
            nr_msgs: usize,
            options: MessageGeneratorOptions,
        ) -> MessageGenerator {
            let mut msgs: std::vec::Vec<DltMessage> = std::vec::Vec::new();
            for (buf_delay, start_delay) in initial_delays {
                for i in 0..nr_msgs {
                    let timestamp_us = start_delay + ((i as u64) * options.frequency); // frequency
                    let min_send_time = std::cmp::max(buf_delay + (i as u64), timestamp_us);
                    msgs.push(DltMessage {
                        index: i as crate::dlt::DltMessageIndexType,
                        reception_time_us: lc_start_time + min_send_time,
                        timestamp_dms: (timestamp_us / 100) as u32,
                        lifecycle: 0,
                        ecu: options.ecu,
                        standard_header: crate::dlt::DltStandardHeader {
                            htyp: 1,
                            len: 0,
                            mcnt: 0,
                        },
                        extended_header: None,
                        payload: [].to_vec(),
                    });
                }
            }
            // sort msgs by reception time
            msgs.sort_by(|a, b| a.reception_time_us.cmp(&b.reception_time_us));
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
        let gen_lc1 = MessageGenerator::new(
            LC_START_TIMES[0],
            &MSG_DELAYS,
            NUMBER_PER_MSG_CAT,
            Default::default(),
        );
        for m in gen_lc1 {
            tx.send(m).unwrap();
        }
        let gen_lc2 = MessageGenerator::new(
            LC_START_TIMES[1],
            &MSG_DELAYS,
            NUMBER_PER_MSG_CAT,
            Default::default(),
        );
        for m in gen_lc2 {
            tx.send(m).unwrap();
        }
        drop(tx);
        let (lcs_r, lcs_w) = evmap::new::<LifecycleId, LifecycleItem>();
        let _lcs_w = parse_lifecycles_buffered_from_stream(lcs_w, rx, tx2);
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
                .filter(|(_id, b)| b.get_one().unwrap().was_merged().is_none())
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
                            lc.end_time(),
                            LC_START_TIMES[0]
                                + ((NUMBER_PER_MSG_CAT as u64 - 1) * 1_000)
                                + MSG_DELAYS[1].1
                        );
                    }
                    1 => {
                        assert_eq!(lc.start_time, LC_START_TIMES[1]);
                        assert_eq!(lc.nr_msgs as usize, NUMBER_PER_MSG_CAT * MSG_DELAYS.len());
                        assert_eq!(
                            lc.end_time(),
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
            let interims_lcs = get_interims_lifecycles_as_hashmap(&a);

            println!("have {} interims lifecycles", interims_lcs.len());

            let mapped_lcs = get_mapped_lifecycles_as_hashmap(&interims_lcs);

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
                assert!(
                    mapped_lcs.get(&m.lifecycle).is_some(),
                    "no mapped_lcs for lc id {}",
                    &m.lifecycle
                );
                assert!(mapped_lcs.get(&m.lifecycle).unwrap().was_merged().is_none());
                //println!("got msg:{:?}", rm.unwrap());
            }
            assert_eq!(rx2.recv().is_err(), true);
        } else {
            assert_eq!(true, false);
        };
    }
    #[test]
    fn gen_two_lcs_two_ecus() {
        let (tx, rx1) = channel();
        let (tx1, rx) = channel();
        let (tx2, rx2) = channel();
        const NUMBER_PER_MSG_CAT: usize = 50;
        const MSG_DELAYS: [(u64, u64); 2] = [(45_000, 0), (30_000, 10_000)];
        const LC_START_TIMES: [u64; 2] = [1_000_000, 1_060_000];
        const NUMBER_MSGS: usize = LC_START_TIMES.len() * NUMBER_PER_MSG_CAT * MSG_DELAYS.len();
        for ecu in 0x45..0x47 {
            let gen_lc1 = MessageGenerator::new(
                LC_START_TIMES[0],
                &MSG_DELAYS,
                NUMBER_PER_MSG_CAT,
                MessageGeneratorOptions {
                    ecu: DltChar4::from_buf(&[0x41, 0x42, 0x43, ecu]),
                    ..Default::default()
                },
            );
            for m in gen_lc1 {
                tx.send(m).unwrap();
            }
            let gen_lc2 = MessageGenerator::new(
                LC_START_TIMES[1],
                &MSG_DELAYS,
                NUMBER_PER_MSG_CAT,
                MessageGeneratorOptions {
                    ecu: DltChar4::from_buf(&[0x41, 0x42, 0x43, ecu]),
                    ..Default::default()
                },
            );
            for m in gen_lc2 {
                tx.send(m).unwrap();
            }
        }
        drop(tx);
        // need to sort again: (buffer_sort_elements is somewhat unuseable...)
        let mut sort_buffer: std::vec::Vec<DltMessage> =
            std::vec::Vec::with_capacity(2 * NUMBER_MSGS);
        for m in rx1 {
            sort_buffer.push(m);
        }
        sort_buffer.sort_by(|a, b| a.reception_time_us.cmp(&b.reception_time_us));
        for m in sort_buffer.into_iter() {
            tx1.send(m).unwrap();
        }
        drop(tx1);

        let (lcs_r, lcs_w) = evmap::new::<LifecycleId, LifecycleItem>();
        let _lcs_w = parse_lifecycles_buffered_from_stream(lcs_w, rx, tx2);
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
                .filter(|(_id, b)| b.get_one().unwrap().was_merged().is_none())
                .map(|(_id, b)| b.get_one().unwrap())
                .collect();
            println!("have {} final lifecycles", final_lcs.len());
            final_lcs.sort_by(|a, b| {
                if a.start_time == b.start_time {
                    a.id.cmp(&b.id)
                } else {
                    a.start_time.cmp(&b.start_time)
                }
            });
            for (i, lc) in final_lcs.iter().enumerate() {
                println!("lc={:?}", lc);
                match i {
                    0 | 1 => {
                        assert_eq!(lc.start_time, LC_START_TIMES[0]);
                        assert_eq!(lc.nr_msgs as usize, NUMBER_PER_MSG_CAT * MSG_DELAYS.len());
                        assert_eq!(
                            lc.end_time(),
                            LC_START_TIMES[0]
                                + ((NUMBER_PER_MSG_CAT as u64 - 1) * 1_000)
                                + MSG_DELAYS[1].1
                        );
                    }
                    2 | 3 => {
                        assert_eq!(lc.start_time, LC_START_TIMES[1]);
                        assert_eq!(lc.nr_msgs as usize, NUMBER_PER_MSG_CAT * MSG_DELAYS.len());
                        assert_eq!(
                            lc.end_time(),
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
            let interims_lcs = get_interims_lifecycles_as_hashmap(&a);

            println!("have {} interims lifecycles", interims_lcs.len());

            let mapped_lcs = get_mapped_lifecycles_as_hashmap(&interims_lcs);

            println!("have mapped lifecycles: {:?}", mapped_lcs);
            // now check whether each message has a valid lifecycle in mapped_lcs:
            // the msg has only an interims lifecycle id which might point to a
            // lifecycle that has been merged into a different one later on
            // or will be merged later on.
            // We could modify the msg as well to point to the final lc.id but
            // for streaming that doesn't really work as the ids might change later
            // so using the mapped lifecycles gives the current view
            for _i in 0..2 * NUMBER_MSGS {
                let rm = rx2.recv();
                assert_eq!(rm.is_err(), false);
                let m = rm.unwrap();
                assert!(m.lifecycle != 0);
                assert!(
                    mapped_lcs.get(&m.lifecycle).is_some(),
                    "no mapped_lcs for lc id {}",
                    &m.lifecycle
                );
                assert!(mapped_lcs.get(&m.lifecycle).unwrap().was_merged().is_none());
                //println!("got msg:{:?}", rm.unwrap());
            }
            assert_eq!(rx2.recv().is_err(), true);
        } else {
            assert_eq!(true, false);
        };
    }

    struct SortedDltMessage {
        m: DltMessage,
        lc_start_time: u64,
    }
    impl std::cmp::PartialEq for SortedDltMessage {
        fn eq(&self, other: &Self) -> bool {
            self.lc_start_time + self.m.timestamp_us()
                == other.lc_start_time + other.m.timestamp_us()
        }
    }
    impl std::cmp::Ord for SortedDltMessage {
        fn cmp(&self, other: &Self) -> std::cmp::Ordering {
            if self.m.lifecycle == other.m.lifecycle {
                self.m.timestamp_dms.cmp(&other.m.timestamp_dms)
            } else {
                let t1 = self.lc_start_time + self.m.timestamp_us();
                let t2 = other.lc_start_time + other.m.timestamp_us();
                t1.cmp(&t2)
            }
        }
    }
    impl std::cmp::PartialOrd for SortedDltMessage {
        fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
            Some(self.cmp(other))
        }
    }
    impl std::cmp::Eq for SortedDltMessage {}

    #[test]
    fn async_lc_export_sorted() {
        use crate::utils::*;
        // lets try to model a real use-case:
        // export sorted messages async from a stream
        let (tx, rx) = channel();
        let (tx2, rx2) = channel();
        const NUMBER_PER_MSG_CAT: usize = 50;
        const MSG_DELAYS: [(u64, u64); 2] = [(45_000, 0), (30_000, 10_000)];
        const LC_START_TIMES: [u64; 2] = [1_000_000, 1_060_000];
        // const NUMBER_MSGS: usize = LC_START_TIMES.len() * NUMBER_PER_MSG_CAT * MSG_DELAYS.len();
        let t1 = std::thread::spawn(move || {
            let gen_lc1 = MessageGenerator::new(
                LC_START_TIMES[0],
                &MSG_DELAYS,
                NUMBER_PER_MSG_CAT,
                Default::default(),
            );
            for m in gen_lc1 {
                tx.send(m).unwrap();
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            let gen_lc2 = MessageGenerator::new(
                LC_START_TIMES[1],
                &MSG_DELAYS,
                NUMBER_PER_MSG_CAT,
                Default::default(),
            );
            for m in gen_lc2 {
                tx.send(m).unwrap();
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            // not needed as done autom. drop(tx);
        });
        let (lcs_r, lcs_w) = evmap::new::<LifecycleId, LifecycleItem>();
        let t2 = std::thread::spawn(move || parse_lifecycles_buffered_from_stream(lcs_w, rx, tx2));
        // now we need to buffer/delay the messages, to let the lcs settle a bit
        let (tx3, rx3) = channel();
        let t3 = std::thread::spawn(move || {
            buffer_elements(
                rx2,
                tx3,
                BufferElementsOptions {
                    amount: BufferElementsAmount::NumberElements(40),
                },
            )
        });
        // now sort them:
        let t4 = std::thread::spawn(move || {
            let mut buffer = std::collections::VecDeque::<SortedDltMessage>::with_capacity(100);
            let mut last_time = 0;
            for m in rx3 {
                // todo that's still poor... slow...
                // we need to get the .read() but while keeping it we do block the writer...
                // we need to get a view on the current lifecycles:
                let read = lcs_r.read().unwrap();
                let interims_lcs = get_interims_lifecycles_as_hashmap(&read);
                let lc_start_time = interims_lcs
                    .get(&m.lifecycle)
                    .unwrap()
                    .final_lc(&interims_lcs)
                    .start_time;
                let s_m = SortedDltMessage {
                    m: m,
                    lc_start_time,
                };
                if buffer.len() == buffer.capacity() {
                    let s_m2 = buffer.pop_front().unwrap();
                    // todo verify
                    let s_m2_time = s_m2.lc_start_time + s_m2.m.timestamp_us();
                    println!(
                        "received msg with lc_start_time {} {:?}",
                        s_m2.lc_start_time, s_m2.m
                    );
                    assert!(
                        last_time <= s_m2_time,
                        "last_time={} vs {} with msg {:?}",
                        last_time,
                        s_m2_time,
                        s_m2.m
                    );
                    last_time = s_m2_time;
                }
                let idx = buffer.binary_search(&s_m).unwrap_or_else(|x| x); // todo this is not stable!
                buffer.insert(idx, s_m);
            }
            while buffer.len() > 0 {
                let s_m2 = buffer.pop_front().unwrap();
                // todo verify
                let s_m2_time = s_m2.lc_start_time + s_m2.m.timestamp_us();
                assert!(
                    last_time <= s_m2_time,
                    "last_time={} vs {}",
                    last_time,
                    s_m2_time
                );
                last_time = s_m2_time;
            }
        });

        t1.join().unwrap();
        let _lcs_w = t2.join().unwrap();
        t3.join().unwrap();
        t4.join().unwrap();
    }
}
