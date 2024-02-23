// todos:
// use https://lib.rs/crates/loom for concurrency testing (atomics,...)
// use https://lib.rs/crates/lasso for string interner or
// https://lib.rs/crates/arccstr or https://lib.rs/crates/arcstr
// once_cell for one time inits.
// use chrono::{Local, TimeZone};
use crate::{
    dlt::{
        control_msgs::parse_ctrl_sw_version_payload, DltChar4, DltMessage, DltMessageIndexType,
        SERVICE_ID_GET_SOFTWARE_VERSION,
    },
    utils::US_PER_SEC,
    SendMsgFnReturnType,
};
use nohash_hasher::BuildNoHashHasher;
use std::hash::{Hash, Hasher};
use std::sync::mpsc::Receiver;

pub type LifecycleId = u32;
pub type LifecycleItem = Lifecycle; // Box<Lifecycle>; V needs to be Eq+Hash+ShallowCopy (and Send?)
                                    // std::cell::RefCell misses ShallowCopy (makes sense as the destr wont be called properly to determine refcounts)
                                    // std::rc::Rc misses Send
                                    // std::sync::Arc ... cannot borrow data in an Arc as mutable -> mod.rs:149
                                    // RwLock&Mutex misses ShallowCopy, Eq and Hash

fn new_lifecycle_item(lc: &Lifecycle, idx: DltMessageIndexType) -> LifecycleItem {
    let mut lc = lc.clone();
    // we have to update the max_msg_index_update here as well as
    // otherwise buffered lcs are broadcasted with a too old index
    // and thus not send via remote
    if idx > lc.max_msg_index_update {
        lc.max_msg_index_update = idx;
    }
    lc
}

#[derive(Debug, Clone)]
pub struct ResumeLcInfo {
    pub id: LifecycleId,
    max_timestamp_us: u64,
    start_time: u64,
}

#[derive(Debug, Clone)]
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
    min_timestamp_us: u64, // min. timestamp of the messages assigned to this lifecycle.
    max_timestamp_us: u64, // max. timestamp of the messages assigned to this lifecycle. Used to determine end_time()
    last_reception_time: u64, // last (should be max.) reception_time (i.e. from last message)

    /// was this a resumed lifecycle from another one?
    resume_lc: Option<ResumeLcInfo>,

    /// sw version detected for this lifecycle
    /// this is parsed from the control messages GET_SW_VERSION
    pub sw_version: Option<String>,

    /// the highest/maximum index of the msg that lead to an update
    /// this can be used as a heuristics to see whether the lifecycle was changed
    /// minor (time wise) updates will not be reflected due to buffering delays
    pub max_msg_index_update: DltMessageIndexType,
}

impl evmap::ShallowCopy for Lifecycle {
    unsafe fn shallow_copy(&self) -> std::mem::ManuallyDrop<Self> {
        std::mem::ManuallyDrop::new(self.clone())
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
    /// but we dont support a "persisted" id for filters as this would need a more complex logic for lookup.
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
        if self.max_timestamp_us == 0 {
            // for lifecyces without max_timestamp_us we return the last reception time
            self.last_reception_time
        } else {
            self.start_time + self.max_timestamp_us
        }
    }

    /// returns the resume time of this lifecycle in us.
    /// If no resume was detected this is equal to the start_time
    pub fn resume_time(&self) -> u64 {
        if let Some(resume_lc) = &self.resume_lc {
            self.start_time + self.min_timestamp_us
                - if resume_lc.start_time < self.start_time {
                    self.start_time - resume_lc.start_time
                } else {
                    0
                }
        } else {
            self.start_time
        }
    }

    /// returns the start time with a special handling for cases
    /// where the start time of the resume lifecycle is earlier
    /// than the start time of the resumed one. In this case the
    /// start time of the resumed one is used + 1us.
    ///
    /// This leads to a more logical sorting of lifecycles for cases
    /// where resumes are e.g. detected due to a small log gap
    pub fn resume_start_time(&self) -> u64 {
        if let Some(resume_lc) = &self.resume_lc {
            if self.start_time <= resume_lc.start_time {
                // we enforce that the start time of a resume lifecycle is always later than from the resumed one
                return resume_lc.start_time + 1;
            }
        }
        self.start_time
    }

    /// returns the suspend duration of this lifecycle in us.
    /// If no resume was detected this is 0.
    /// Gets calculated by the distance of the calculated start times
    /// of this lc vs. the resumed one.
    pub fn suspend_duration(&self) -> u64 {
        if let Some(resume_lc) = &self.resume_lc {
            if resume_lc.start_time < self.start_time {
                self.start_time - resume_lc.start_time
            } else {
                0
            }
        } else {
            0
        }
    }

    /// returns whether this lifecycle contains only control request messages.
    /// ### Note: the info is wrong on merged lifecycles (we want to get rid of them anyhow)
    pub fn only_control_requests(&self) -> bool {
        self.nr_control_req_msgs >= self.nr_msgs
    }

    /// returns whether this lifecycle is a "suspend/resume" lifecycle.
    pub fn is_resume(&self) -> bool {
        self.resume_lc.is_some()
    }

    /// create a new lifecycle with the first msg passed as parameter
    pub fn new(msg: &mut DltMessage) -> Lifecycle {
        // println!("new lifecycle created by {:?}", msg);
        let is_ctrl_request = msg.is_ctrl_request();
        let timestamp_us = if is_ctrl_request {
            0
        } else {
            let tmsp = msg.timestamp_us();
            if tmsp > msg.reception_time_us {
                0 // tmsp > reception_tims_us is invalid, we ignore the tmsp!
            } else {
                tmsp
            }
        };

        let alc = Lifecycle {
            id: NEXT_LC_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            ecu: msg.ecu,
            nr_msgs: 1,
            nr_control_req_msgs: u32::from(is_ctrl_request),
            start_time: msg.reception_time_us - timestamp_us,
            initial_start_time: msg.reception_time_us - timestamp_us,
            min_timestamp_us: timestamp_us,
            max_timestamp_us: timestamp_us,
            last_reception_time: msg.reception_time_us,
            resume_lc: None,
            sw_version: None, // might be wrongif the first message is a GET_SW_VERSION but we ignore this case
            max_msg_index_update: msg.index,
        };
        msg.lifecycle = alc.id;
        alc
    }

    /// merge another lifecycle into this one.
    ///
    /// The other lifecycle afterwards indicates that it was merged with [Self::was_merged()]
    pub fn merge(&mut self, lc_to_merge: &mut Lifecycle) {
        assert_ne!(lc_to_merge.nr_msgs, 0);
        self.nr_msgs += lc_to_merge.nr_msgs;
        self.nr_control_req_msgs += lc_to_merge.nr_control_req_msgs;
        lc_to_merge.nr_msgs = 0; // this indicates a merged lc
        if lc_to_merge.max_timestamp_us > self.max_timestamp_us {
            self.max_timestamp_us = lc_to_merge.max_timestamp_us;
        }
        if lc_to_merge.min_timestamp_us < self.min_timestamp_us {
            self.min_timestamp_us = lc_to_merge.min_timestamp_us;
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

        // if the lc_to_merge has a sw_version and we not, we do use that one:
        if self.sw_version.is_none() && lc_to_merge.sw_version.is_some() {
            self.sw_version = lc_to_merge.sw_version.take();
        }

        if lc_to_merge.max_msg_index_update > self.max_msg_index_update {
            self.max_msg_index_update = lc_to_merge.max_msg_index_update;
        }
    }

    /// returns whether this lifecycled was merged (so is not valid any longer) into a different lifecycle.
    /// Returns None if not merged otherwise the interims lifecycle id of the lifecycle it was merged into.
    /// # Note:
    /// Take care the returned lifecycle id is interims as well and could be or will be merged as well into another lifecycle!
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
    pub fn update(
        &mut self,
        msg: &mut DltMessage,
        max_buffering_delay_us: u64,
    ) -> Option<Lifecycle> {
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
        //   todo we removed this 2) below for the idlt traces (internally recorded traces where the new lifecycle starts with a
        //   persisted time and thus the calculated slightly overlaps (and even the real as after persisting some logs might still be generated))
        // 3) msg has no timestamp. This is for logs without a timestamp (e.g. from SER) where no lifecycle detection is possible.
        let msg_timestamp_us = msg.timestamp_us();
        let msg_reception_time_us = msg.reception_time_us;
        let msg_lc_start = msg.reception_time_us - msg_timestamp_us;
        let cur_end_time = self.end_time();

        // check for lc_ex005 use case:
        // the msg lc start time is "slightly overlapping" if msg_lc_start is within the last 2s of the current lifecycle and the current lifecycle
        // is at least 10s long.
        // We should check here as well that the msg has a smaller timestamp than the last msg from same apid/ctid (TODO!)

        let is_msg_lc_start_slightly_overlapping = msg_lc_start <= cur_end_time
            && (msg_lc_start + (US_PER_SEC * 2)) > cur_end_time
            && cur_end_time > (self.start_time + (US_PER_SEC * 10));

        let is_part_of_cur_lc = (!is_msg_lc_start_slightly_overlapping
            && (msg_lc_start <= cur_end_time/*|| msg_lc_start <= self.last_reception_time disabled as part of fixing lc_ex006 (idlts)*/))
            || !msg.standard_header.has_timestamp();

        let would_move_start_time_us = if msg_lc_start < self.start_time {
            self.start_time - msg_lc_start
        } else {
            0
        };

        if is_part_of_cur_lc
            && would_move_start_time_us > max_buffering_delay_us
            && self.max_timestamp_us > 0
        // a heuristic to ignore those very short lifecycles created by (most of the time invalid msgs with timestamp 0)
        {
            // we ignore this as it's likely wrong timestamp
            println!(
                "update: ignoring msg as it would move start time by {}s\n{:?}\nLC:{:?}",
                would_move_start_time_us / US_PER_SEC,
                msg,
                &self
            );
            // so assign to this one but don't update any time related stats
            msg.lifecycle = self.id;
            self.nr_msgs += 1;
            return None;
        }

        // resume (e.g. from Android STR) detection:
        // - a gap of >MIN_RESUME_RECEPTION_TIME_GAP s in reception time
        // - msg.timestamp ~> last_timestamp
        // - a shift in the calc start time >MIN_RESUME_RECEPTION_TIME_GAP s (otherwise it was just e.g. a logger interuption)
        // - gap in reception time > gap in calc start time (as reception time consists of suspend_time + reconnect_time)
        //
        // note: with this we might identify a new lifecycle after a short lifecycle as a resume case. We handle this later and might "unresume" the lifecycle later.

        const MIN_RESUME_RECEPTION_TIME_GAP_US: u64 = US_PER_SEC * 10;
        let is_resume = (msg_reception_time_us
            >= self.last_reception_time + MIN_RESUME_RECEPTION_TIME_GAP_US)
            && (msg_timestamp_us >= self.max_timestamp_us)
            && (msg_lc_start >= self.start_time + MIN_RESUME_RECEPTION_TIME_GAP_US)
            && (msg_reception_time_us - self.last_reception_time > msg_lc_start - self.start_time);

        if !is_resume && is_part_of_cur_lc {
            // ok belongs to this lifecycle
            if self.min_timestamp_us > msg_timestamp_us {
                if let Some(resume_lc) = &self.resume_lc {
                    if msg_timestamp_us > resume_lc.max_timestamp_us {
                        // we ignore the buffered msgs from prev lc...
                        self.min_timestamp_us = msg_timestamp_us;
                    }
                } else {
                    self.min_timestamp_us = msg_timestamp_us;
                }
            }

            if self.max_timestamp_us < msg_timestamp_us {
                self.max_timestamp_us = msg_timestamp_us;
            } else if let Some(resume_lc) = &self.resume_lc {
                // we sometimes get in a resume case prev. msgs that had been buffered before the
                // suspend.
                // Best case we'd add those to the prev lc... (todo)
                // (those msgs will have a wrong calculated time in the resume lc...)
                // For now we consider them part of the resume lc as long as their timestamp
                // is >= half of the timestamp of prev lc:
                if msg_timestamp_us
                    < (resume_lc.max_timestamp_us - (resume_lc.max_timestamp_us / 8))
                {
                    // this was not a resume but a new lifecycle as condition 2 is not met any longer
                    /*println!(
                        "update: untagged resume lifecycle with msg with timestamp diff={}\n{:?}\nLC:{:?}",
                        resume_lc.max_timestamp_us - msg_timestamp_us,
                        msg, &self
                    );*/
                    self.resume_lc = None;
                    // afterwards we might be merged into prev lc as well
                }
            }

            /* if self.last_reception_time > msg_reception_time_us {
                // bug in dlt viewer: https://github.com/COVESA/dlt-viewer/issues/232
                // println!("msg.update reception time going backwards! LC:{:?} {:?} {}", self.last_reception_time, msg.reception_time_us, msg.index);
            } */
            self.last_reception_time = msg_reception_time_us;

            // does it move the start to earlier? (e.g. has a smaller buffering delay)
            // todo this can as well be caused by clock drift. Need to add clock_drift detection/compensation.
            // the clock drift is relative to the recording devices time clock.
            /* not needed as for buffered msgs the buffering delay is larger: if let Some(resume_lc) = &self.resume_lc {
                // for a resume case we take only msgs with timestamp > resume_lc.max_timestamp into account
                // so we do ignore the msgs that had been buffered before resume
                if msg_timestamp_us > resume_lc.max_timestamp_us && msg_lc_start < self.start_time {
                    self.start_time = msg_lc_start;
                }
            } else */
            if msg_lc_start < self.start_time {
                self.start_time = msg_lc_start;
            }
            msg.lifecycle = self.id;
            self.nr_msgs += 1;
            if msg.index > self.max_msg_index_update {
                self.max_msg_index_update = msg.index;
            }

            // sw-version contained?
            if self.sw_version.is_none() && msg.is_ctrl_response() {
                let mut args = msg.into_iter();
                let message_id_arg = args.next();
                let message_id = match message_id_arg {
                    Some(a) => {
                        if a.is_big_endian {
                            u32::from_be_bytes(a.payload_raw.get(0..4).unwrap().try_into().unwrap())
                        } else {
                            u32::from_le_bytes(a.payload_raw.get(0..4).unwrap().try_into().unwrap())
                        }
                    }
                    None => 0,
                };
                if message_id == SERVICE_ID_GET_SOFTWARE_VERSION {
                    let payload_arg = args.next();
                    let (payload, is_big_endian) = match payload_arg {
                        Some(a) => (a.payload_raw, a.is_big_endian),
                        None => (&[] as &[u8], false),
                    };
                    if payload.len() >= 5 {
                        if let Some(sw_vers) =
                            parse_ctrl_sw_version_payload(is_big_endian, &payload[1..])
                        {
                            self.sw_version = Some(sw_vers);
                        }
                    }
                }
            }

            None
        } else {
            /* if is_resume && is_part_of_cur_lc
            {
                println!(
                    "update: new resume lifecycle created by\n{:?}\ntimestamp_diff={}\nlc_start_diff= {}\nrecp_time_diff={}\nLC:{:?}",
                    msg, msg_timestamp_us - self.max_timestamp_us, msg_lc_start - self.start_time,
                    msg_reception_time_us - self.last_reception_time, &self
                );
                // assert!(false, "is_resume!");
            } */
            // new lifecycle:
            let mut lc = Lifecycle::new(msg);
            if is_resume {
                lc.resume_lc = Some(ResumeLcInfo {
                    id: self.id,
                    start_time: self.start_time,
                    max_timestamp_us: self.max_timestamp_us,
                });
            }
            Some(lc)
        }
    }
}

/// Calculate lifecycles from a stream of DltMessages.
/// # Assumptions:
/// * the stream is per ecu in the order as generated by the ecu. So messages are not in random order.
/// * if the origin are multiple files they are sorted by reception time already before sending to here
///
/// The messages are passed via a stream and will be forwarded to one after processing.
/// Messages might be buffered internally and are only forwarded as soon as the lifecycle is determined.
/// Messages are not sorted and output in same order as incoming.
///
/// # Examples
/// ````
/// let (tx, rx) = std::sync::mpsc::channel();
/// let (tx2, _rx2) = std::sync::mpsc::channel();
/// // add msgs here to the tx side
/// // tx.send(msg);
/// drop(tx); // close the channel tx to indicate last msg otherwise the function wont end
/// let (_lcs_r, lcs_w) = evmap::new::<adlt::lifecycle::LifecycleId, adlt::lifecycle::LifecycleItem>();
/// let lcs_w = adlt::lifecycle::parse_lifecycles_buffered_from_stream(lcs_w, rx, &|m|tx2.send(m));
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
/// let t = std::thread::spawn(move || adlt::lifecycle::parse_lifecycles_buffered_from_stream(lcs_w, rx, &|m|tx2.send(m)));
/// let lcs_w = t.join().unwrap();
/// // now lcs_r still contains valid data!
/// ````
/// ## Implementation details
/// ### Lifecycle information passing
/// To pass information about the detected lifecycles to the caller or other threads an evmap is used.
/// The lc.id is used as key and the LifecycleInfo as value.
/// As these are not globally shared the evmap needs to be "refreshed" to make the info available to other threads.
/// There are two rules to follow:
///
/// #1 for any message passed to the outflow the info should be available. So that the for any message returned a
/// lifecycle info is available. (so update whenever msgs for a new lifecycle are passed to the outflow)
///
/// #2 the lifecycle info should be updated from time to time (e.g. every 100k msgs) and at the end reflect
/// the final state. This is to e.g. have increasing number of msgs in an UI shown while parsing.
pub fn parse_lifecycles_buffered_from_stream<M, S, F: Fn(DltMessage) -> SendMsgFnReturnType>(
    mut lcs_w: evmap::WriteHandle<LifecycleId, LifecycleItem, M, S>,
    inflow: Receiver<DltMessage>,
    outflow: &F,
) -> evmap::WriteHandle<LifecycleId, LifecycleItem, M, S>
where
    S: std::hash::BuildHasher + Clone,
    M: 'static + Clone,
{
    let max_buffering_delay_us: u64 = 60_000_000; // 60s

    // create a map of ecu:vec<lifecycle.id>
    // we can maintain that here as we're the only one modifying the lcs_ evmap
    let mut ecu_map = std::collections::HashMap::with_capacity_and_hasher(
        64,
        nohash_hasher::BuildNoHashHasher::<DltChar4>::default(),
    );

    if let Some(lci) = lcs_w.read() {
        for (_id, b) in &lci {
            let lc = b.get_one().unwrap();
            match ecu_map.get_mut(&lc.ecu) {
                None => {
                    //ecu_map.insert(lc.ecu.clone(), [lc.id].to_vec());
                    ecu_map.insert(lc.ecu, [lc.clone()].to_vec());
                }
                Some(v) => v.push(lc.clone()),
            }
        }
    }

    /*
    println!("parse_lifecycles_buffered_from_stream. Have ecu_map.len={}", ecu_map.len());
    for (k, v) in &ecu_map {
        println!("Have for ecu {:?} {:?}", &k, &v);
    } */

    // we buffer all messages until we do treat the lifecycles as stable (e.g. likelhood of being merged with prev one low)
    // we buffer all messages in the same order as they arrive. So not e.g per ECU as we want to output them in the same order.
    let mut buffered_msgs: std::collections::VecDeque<DltMessage> =
        std::collections::VecDeque::with_capacity(10_000_000); // todo what is a good value to buffer at least 60s?
                                                               // the lifecycles that have a likelyhood of being merged with prev or changing start times are kept here:
    let mut buffered_lcs =
        std::collections::HashSet::with_hasher(BuildNoHashHasher::<LifecycleId>::default());

    // todo add check that msg.received times increase monotonically! (ignoring the dlt viewer bug)
    let mut next_buffer_check_time: u64 = 0;
    let mut last_msg_index: DltMessageIndexType = 0;

    let mut lcs_to_refresh = Vec::<LifecycleId>::with_capacity(128);

    let mark_lc_id_to_refresh = |id: LifecycleId, lcs_to_refresh: &mut Vec<LifecycleId>| {
        if !lcs_to_refresh.contains(&id) {
            // reverse contains might be faster
            lcs_to_refresh.push(id);
        }
    };

    let mut last_regular_refresh_index: DltMessageIndexType = 0;

    let mut check_regular_refresh =
        |last_msg_index: u32,
         force_refresh: bool,
         lcs_to_refresh: &mut Vec<LifecycleId>,
         lcs_w: &mut evmap::WriteHandle<LifecycleId, LifecycleItem, M, S>,
         ecu_map: &std::collections::HashMap<
            DltChar4,
            Vec<Lifecycle>,
            std::hash::BuildHasherDefault<nohash_hasher::NoHashHasher<DltChar4>>,
        >| {
            if force_refresh || last_regular_refresh_index + 100_000 < last_msg_index {
                // update all marked lifecycles:
                let mut nr_lcs_to_update = lcs_to_refresh.len();
                for vs in ecu_map.values() {
                    if nr_lcs_to_update == 0 {
                        break;
                    }
                    for lc in vs.iter().rev() {
                        if lcs_to_refresh.contains(&lc.id) {
                            lcs_w.update(lc.id, new_lifecycle_item(lc, last_msg_index));
                            nr_lcs_to_update -= 1;
                            if nr_lcs_to_update == 0 {
                                break;
                            }
                        }
                    }
                }
                lcs_w.refresh();
                last_regular_refresh_index = last_msg_index;
                lcs_to_refresh.clear();
            }
        };

    for mut msg in inflow {
        /* if msg.ecu == DltChar4::from_str("ECU").unwrap() && msg.timestamp_dms > 0 {
            println!(
                "got msg:{} {:?}:{:?} {} {}",
                msg.index,
                msg.apid(),
                msg.ctid(),
                msg.reception_time_us,
                msg.timestamp_dms
            );
        }*/
        // get the lifecycles for the ecu from that msg:
        last_msg_index = msg.index;
        let msg_reception_time_us = msg.reception_time_us;

        let msg_timestamp_us = msg.timestamp_us();

        let ecu_lcs = ecu_map.entry(msg.ecu).or_default();

        let ecu_lcs_len = ecu_lcs.len();
        if ecu_lcs_len > 0 {
            // get LC with that id:
            let (last_lc, rest_lcs) = ecu_lcs.as_mut_slice().split_last_mut().unwrap();
            let lc2 = last_lc;
            let mut remove_last_lc = false;
            match lc2.update(&mut msg, max_buffering_delay_us) {
                None => {
                    // lc2 was updated
                    // now we have to check whether it overlaps with the prev. one and needs to be merged:
                    if ecu_lcs_len > 1 {
                        let prev_lc = rest_lcs.last_mut().unwrap(); // : &mut Lifecycle = &mut last_lcs[ecu_lcs_len - 2];

                        // todo same logic from .update needed with !slightly overlapping...

                        if lc2.start_time <= prev_lc.end_time() && !lc2.is_resume() {
                            // todo consider clock skew here. the earliest start time needs to be close to the prev start time and not just within...
                            /*println!(
                                "merge needed after msg#{}:\n {:?}\n {:?}",
                                msg.index, prev_lc, lc2
                            );*/
                            // we merge into the prev. one (so use the prev.one only)
                            let is_buffered = buffered_lcs.contains(&prev_lc.id);
                            if is_buffered {
                                // the buffered lcs shall be merged again (so lc2 is invalid afterwards)
                                // todo this is cpu intensive/expensive. try to reduce the likelyhood.
                                // this is easy now:
                                prev_lc.merge(lc2);
                                msg.lifecycle = prev_lc.id;
                                // and now update the buffered msgs:
                                {
                                    buffered_msgs.iter_mut().for_each(|m| {
                                        /*println!(
                                            "modifying lifecycle from {} to {} for {:?}",
                                            lc2.id, prev_lc.id, m
                                        );*/
                                        if m.lifecycle == lc2.id {
                                            m.lifecycle = prev_lc.id;
                                        }
                                    });
                                };
                                // we can delete the buffered_lcs elem now:
                                assert!(
                                    buffered_lcs.contains(&lc2.id),
                                    "buffered_lcs does not contain {} msg:{:?}",
                                    lc2.id,
                                    msg
                                ); // logical error otherwise (prev lc still buffered but the newer one that is to be merged into the prev one not?)
                                buffered_lcs.remove(&lc2.id);
                                remove_last_lc = true;
                                // if we have no more yet, send the other msgs: (not possible as prev_lc exists)
                            } else {
                                /*
                                #[allow(clippy::collapsible_else_if)]
                                if merged_needed_id != lc2.id {
                                    println!("merge needed but prev_lc not buffered anymore! (todo!):\n {:?}\n {:?} msg #{}", prev_lc, lc2, last_msg_index);
                                    merged_needed_id = lc2.id;
                                }*/

                                let lc2_msgs = lc2.nr_msgs as usize;

                                // check first whether all msgs are buffered. If not, dont merge but keep it:
                                let nr_buffered_msgs = buffered_msgs
                                    .iter()
                                    .filter(|m| m.lifecycle == lc2.id)
                                    .count()
                                    + 1;
                                if nr_buffered_msgs == lc2_msgs {
                                    prev_lc.merge(lc2);
                                    msg.lifecycle = prev_lc.id;
                                    let mut moved_msgs = 1;
                                    // and now update the buffered msgs:
                                    {
                                        buffered_msgs.iter_mut().for_each(|m| {
                                            /*println!(
                                                "modifying lifecycle from {} to {} for {:?}",
                                                lc2.id, prev_lc.id, m
                                            );*/
                                            if m.lifecycle == lc2.id {
                                                m.lifecycle = prev_lc.id;
                                                moved_msgs += 1;
                                            }
                                        });
                                    };
                                    if !buffered_lcs.remove(&lc2.id) && moved_msgs != lc2_msgs {
                                        println!("merged lc was not in buffered_lcs or its msgs not buffered anymore!\n {:?}\n {:?} msg #{}, moved_msgs={} vs {}", prev_lc, lc2, last_msg_index, moved_msgs, lc2_msgs);
                                    }
                                    remove_last_lc = true;
                                } else {
                                    println!("merge needed but not all msgs buffered anymore! (todo!):\n {:?}\n {:?} msg #{}", prev_lc, lc2, last_msg_index);
                                    // we keep the lc2 for now and buffer the msgs
                                    // todo, needed? buffered_lcs.insert(lc2.id);
                                }
                                // we can simply merge with prev one, i.e. assign the prev_lc.id to the msgs from the cur one!
                                // (as those still need to buffered according to rule #b1)
                            }
                        }
                    }
                    // here lc2.id is not valid anylonger is remove_last_lc is set! Then it was merged in the buffered prev_lc
                }
                Some(new_lc) => {
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
                    buffered_lcs.insert(new_lc.id);
                    ecu_lcs.push(new_lc);
                }
            }
            if remove_last_lc {
                let _removed = ecu_lcs.remove(ecu_lcs_len - 1);
                // assert!(!buffered_lcs.contains(&removed.id));
            }
        } else {
            // msg.ecu not known yet:
            let lc = Lifecycle::new(&mut msg);
            // even though the first lifecycle per ecu cannot disappear it still has to be buffered
            // as the 2nd lifecycle might want to merge into that one
            buffered_lcs.insert(lc.id);
            ecu_lcs.push(lc);
        }

        // if we have buffered lifecycles check whether we can stop buffering them and mark as valid ones:
        // once the lifecycle start even including a max buffering delay can not fit into the prev one any longer:
        // The evaluation needs to be per ecu!

        // a lifecycle (or msgs of a lifecycle) need to be buffered for:
        // #b1. the current lifecycle (last one per ECU) might still be merged into the prev. one
        // #b2. ? (the prev one?) do we need to keep it? partly? for how long and why?
        //   There could be "cascaded" merges. E.g. lc2 merged with lc1 merged with lc0?
        //   Is this the same check as for #b1 but with "last lc"?
        //    So when can we assume a lifecycle will not need to be merged with prev. one?
        //     if its reasonable long enough: i.e. by amount of msgs... -> more and more unlikely (as the buffering delay tends to 0 then)
        //  ! ->  so if the lifecycle contains msgs with a timestamp distance > max_buffering_delay_us (e.g. min timestamp 10s, max timestamp 70s -> unlikely that msgs with timestamp <10 do arrive)
        //    this should be if: lc.max_timestamp_us - lc.min_timestamp_us > max_buffering_delay_us
        // or (if e.g. there are no more msgs for this lifecycle from ecu A but only from other LCs from ECU B): TODO

        //     (not) if the start time is not close to the prev. one even if a msg with max buffering delay would arrive (no, max buffering delay moves the calc start time to later)

        // Need to use a way that doesn't rely on the next lifecycle (so can only evaluate prev lc as the current test below)
        // with long lifecycles the buffer delay will be small so:
        //   msg.reception_time_us - msg_timestamp_us will converge towards lc.start_time
        //   so min_lc_start_time = msg.reception_time_us - msg_timestamp_us - max_buffering_delay_us will roughly be max_buffering_delay_us smaller than lc.start_time

        // we do this only once per sec
        if next_buffer_check_time < msg_reception_time_us {
            if msg_reception_time_us > (msg_timestamp_us + max_buffering_delay_us) {
                let min_lc_start_time =
                    msg_reception_time_us - (msg_timestamp_us + max_buffering_delay_us);
                for ecu_lcs in ecu_map.values() {
                    /*println!(
                        "ecu_lcs.len()={}, buffered_lcs.len()={} buffered_msgs.len()={}",
                        ecu_lcs.len(),
                        buffered_lcs.len(),
                        buffered_msgs.len()
                    );*/
                    for lc in ecu_lcs.iter().rev() {
                        if buffered_lcs.is_empty() {
                            break;
                        } else {
                            if !buffered_lcs.contains(&lc.id) {
                                continue;
                            }
                            // this lc is still buffered:
                            if (lc.start_time < min_lc_start_time && lc.ecu==msg.ecu)
                            || lc.max_timestamp_us - lc.min_timestamp_us > max_buffering_delay_us
                            // or if any message recvd would have a too high max_buffering_delay to impact this lifecycle
                            // the situation is a short (so the upper check doesn't fire) lifecycle close to start of a long next one
                            || msg_reception_time_us - max_buffering_delay_us > lc.end_time()
                            {
                                if lc.start_time < min_lc_start_time {
                                    println!(
                                    "confirmed buffered lc as min_lc_start_time {} > lc.start_time {}, confirmed lc={:?}",
                                    min_lc_start_time, lc.start_time, lc
                                );
                                } else {
                                    println!("confirmed buffered lc as >max_buffering_delay, confirmed lc={:?}", lc);
                                }
                                buffered_lcs.remove(&lc.id);
                                /*println!("remaining buffered_lcs={}", buffered_lcs.len());
                                for lc in &buffered_lcs {
                                    println!(" buffered_lc={}", lc);
                                }*/
                                // lc update due to rule #1:
                                lcs_w.update(lc.id, new_lifecycle_item(lc, last_msg_index));
                                lcs_w.refresh();

                                // if the first msg in buffered_msgs belongs to this confirmed lc
                                // then send all msgs until one msgs belongs to a buffered_lcs
                                let mut prune_lc_id = lc.id;
                                while !buffered_msgs.is_empty() {
                                    let msg_lc = buffered_msgs[0].lifecycle;
                                    if msg_lc == prune_lc_id {
                                        let msg = buffered_msgs.pop_front().unwrap(); // .remove(0);
                                        if let Err(e) = outflow(msg) {
                                            println!("parse_lifecycles_buffered_from_stream .send 1 got err={}", e);
                                            break; // exit. the receiver has stopped
                                        }
                                    } else if !buffered_lcs.contains(&msg_lc) {
                                        prune_lc_id = msg_lc;
                                        // todo: this would be a perfect time to update the lc from that msg due to rule #2
                                        // the lc info might have been significantly updated after being removed from buffered_lcs.
                                        // the updated lc.ids would need to be cached here to avoid double redundant updates.
                                        // for now mark only here as "needs refresh"
                                        mark_lc_id_to_refresh(msg_lc, &mut lcs_to_refresh);

                                        // send that msg right away: (code duplication, might as well just wait one iteration)
                                        let msg = buffered_msgs.pop_front().unwrap(); // .remove(0);
                                        if let Err(e) = outflow(msg) {
                                            println!("parse_lifecycles_buffered_from_stream .send 2 got err={}", e);
                                            break;
                                        }
                                    } else {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            next_buffer_check_time = msg_reception_time_us + US_PER_SEC;
            // in 1s again
        }

        // pass msg to outflow only if we dont have buffered lcs:
        // we cannot treat this per ecu as we need to keep the msg.index order
        // or for cases where we later on want to sort by timestamp even then we do need to keep the order somewhat
        // as we want a "streaming" search where we sort within a time window only...

        if !buffered_lcs.is_empty() {
            buffered_msgs.push_back(msg);
        } else {
            // check for lc update rule #2 here.
            mark_lc_id_to_refresh(msg.lifecycle, &mut lcs_to_refresh);
            check_regular_refresh(
                last_msg_index,
                false,
                &mut lcs_to_refresh,
                &mut lcs_w,
                &ecu_map,
            );
            if let Err(e) = outflow(msg) {
                println!(
                    "parse_lifecycles_buffered_from_stream .send 3 got err={}",
                    e
                );
                break;
            }
        }
    }

    // if we have still buffered lcs we have to make them valid now: (rule#1)
    let mut nr_lcs_to_update = buffered_lcs.len();
    for vs in ecu_map.values() {
        if nr_lcs_to_update == 0 {
            break;
        }
        for lc in vs.iter().rev() {
            if buffered_lcs.contains(&lc.id) {
                lcs_w.update(lc.id, new_lifecycle_item(lc, last_msg_index));
                nr_lcs_to_update -= 1;
                if nr_lcs_to_update == 0 {
                    break;
                }
            }
        }
    }
    lcs_w.refresh();

    // if we have buffered msgs we have to output them now:
    for m in buffered_msgs.into_iter() {
        mark_lc_id_to_refresh(m.lifecycle, &mut lcs_to_refresh);
        if let Err(e) = outflow(m) {
            println!(
                "parse_lifecycles_buffered_from_stream .send 4 got err={}",
                e
            );
            break;
        }
    }

    // todo check for rule #2 and do the final update
    check_regular_refresh(
        last_msg_index,
        true,
        &mut lcs_to_refresh,
        &mut lcs_w,
        &ecu_map,
    );

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
    /*let duration = start.elapsed();
    if duration > std::time::Duration::from_millis(1) {
        // println!("parse_lifecycles_buffered_from_stream took {:?}", duration);
    }*/
    lcs_w
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
    sorted_lcs.sort_by(|a, b| {
        if let Some(b_resume_lc) = &b.resume_lc {
            if b_resume_lc.id == a.id {
                // b is a resume of a so a must be earlier
                return std::cmp::Ordering::Less;
            }
        }
        if let Some(a_resume_lc) = &a.resume_lc {
            if a_resume_lc.id == b.id {
                // a is a resume of b so b must be earlier
                return std::cmp::Ordering::Greater;
            }
        }
        a.start_time.cmp(&b.start_time)
    });
    sorted_lcs
}

#[cfg(test)]
mod tests {
    //use super::*;
    use crate::dlt::*;
    use crate::lifecycle::*;
    use crate::utils::get_dlt_message_iterator;
    use crate::utils::get_new_namespace;
    use crate::utils::sorting_multi_readeriterator::SequentialMultiIterator;
    use crate::utils::LowMarkBufReader;
    use ntest::timeout;
    use std::fs::File;
    use std::str::FromStr;
    use std::sync::mpsc::{channel, sync_channel};
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
        let (tx2, rx2) = sync_channel(NUMBER_ITERATIONS);
        drop(tx);
        let (lcs_r, lcs_w) = evmap::Options::default()
            .with_hasher(nohash_hasher::BuildNoHashHasher::<LifecycleId>::default())
            .construct::<LifecycleId, LifecycleItem>();
        let start = Instant::now();
        let t = std::thread::spawn(move || {
            parse_lifecycles_buffered_from_stream(lcs_w, rx, &|m| tx2.send(m))
        });
        if let Some(a) = lcs_r.read() {
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
            assert!(read_handle.is_some());
            let read_handle = read_handle.unwrap();
            for i in 0..NUMBER_ITERATIONS {
                // check whether all msgs have a lifecycle:
                let m = rx2.recv();
                assert!(m.is_ok(), "{}th message missing", i + 1);
                let msg = m.unwrap();
                assert_ne!(msg.lifecycle, 0, "{}th message without lifecycle", i + 1);
                // check that the lifecycle is known as well: (this seems time consuming! around if omitted 90ms instead of 180ms)
                //let l = lcs_r.get_one(&msg.lifecycle);
                // using the read_handle its a lot faster: 106ms instead of 180ms/90ms
                let l = read_handle.get_one(&msg.lifecycle);
                assert!(l.is_some());
            }
        }
        let duration = start.elapsed();
        println!(
            "Time elapsed reading/verifying {}msgs is: {:?}",
            NUMBER_ITERATIONS, duration
        );
        assert!(rx2.recv().is_err());
        // and lifecycle info be available
        if let Some(a) = lcs_r.read() {
            println!("lcs_r content {:?}", a);
        }
        if let Some(a) = lcs_w.read() {
            for (id, b) in &a {
                println!("lcs_w2 content id={:?} lc={:?}", id, b);
            }
        }
        assert!(!lcs_r.is_empty(), "empty lcs!");
        assert_eq!(lcs_r.len(), 1, "wrong number of lcs!");
    }
    #[test]
    fn basics() {
        let (tx, rx) = channel();
        let (tx2, rx2) = sync_channel(2048);
        drop(tx);
        let (_lcs_r, lcs_w) = evmap::new::<LifecycleId, LifecycleItem>();
        parse_lifecycles_buffered_from_stream(lcs_w, rx, &|m| tx2.send(m));
        assert!(rx2.try_recv().is_err());
    }
    #[test]
    fn basics_read_in_different_thread() {
        let (tx, rx) = channel();
        let (tx2, rx2) = sync_channel(2048);
        drop(tx);
        let (lcs_r, lcs_w) = evmap::new::<LifecycleId, LifecycleItem>();
        parse_lifecycles_buffered_from_stream(lcs_w, rx, &|m| tx2.send(m));
        assert!(rx2.try_recv().is_err());
        let r = lcs_r;
        let t = std::thread::spawn(move || {
            if let Some(a) = r.read() {
                println!("r content {:?}", a);
            }
            assert_eq!(r.len(), 0);
        });
        t.join().unwrap();
    }

    #[test]
    fn lc_invalid_msg_timestamps() {
        // lifecycle use case 1:
        // one long lifecycle but with timestamp_dms all 0 (e.g. from Dlt-Viewer SER/ASC)
        let (tx, parse_lc_in) = channel();
        // 3 lifecycle messages:
        let mut m1 = crate::dlt::DltMessage::for_test();
        m1.timestamp_dms += 40_000 * 10; // that should now be invalid!
        assert!(m1.timestamp_us() > m1.reception_time_us);

        tx.send(m1).unwrap();
        drop(tx);
        let (parse_lc_out, _rx) = sync_channel(2048);
        let (lcs_r, lcs_w) = evmap::new::<LifecycleId, LifecycleItem>();
        let _lcs_w =
            parse_lifecycles_buffered_from_stream(lcs_w, parse_lc_in, &|m| parse_lc_out.send(m));
        assert_eq!(1, lcs_r.len(), "wrong number of lcs!");
        // todo
    }

    #[test]
    fn lc_uc_1() {
        // lifecycle use case 1:
        // one long lifecycle but with timestamp_dms all 0 (e.g. from Dlt-Viewer SER/ASC)
        // todo
    }

    #[test]
    fn lc_uc_2() {
        // lifecycle use case 2:
        // one lc but first message is with higher timestamp, then smaller ones
        // todo
    }

    #[test]
    fn lc_uc_3() {
        // lifecycle use case 3:
        // two lc with each first message is with higher timestamp, then smaller ones
        // todo
    }

    #[test]
    fn lc_uc_4() {
        // lifecycle use case 4:
        // three small lifecycles each 40s (<60s max_buffering_delay_us) long
        let (tx, parse_lc_in) = channel();
        // 3 lifecycle messages:
        let mut m1 = crate::dlt::DltMessage::for_test();
        m1.timestamp_dms = 40_000 * 10; // 40s
        m1.reception_time_us = m1.timestamp_us() + 1_000_000_000;

        let mut m2 = crate::dlt::DltMessage::for_test();
        m2.timestamp_dms = 40_000 * 10;
        m2.reception_time_us = m2.timestamp_us() + m1.reception_time_us + m1.timestamp_us() + 1;

        let mut m3 = crate::dlt::DltMessage::for_test();
        m3.timestamp_dms = 40_000 * 10;
        m3.reception_time_us = m3.timestamp_us() + m2.reception_time_us + m2.timestamp_us() + 1;

        tx.send(m1).unwrap();
        tx.send(m2).unwrap();
        tx.send(m3).unwrap();
        drop(tx);
        let (parse_lc_out, _rx) = sync_channel(2048);
        let (lcs_r, lcs_w) = evmap::new::<LifecycleId, LifecycleItem>();
        let _lcs_w =
            parse_lifecycles_buffered_from_stream(lcs_w, parse_lc_in, &|m| parse_lc_out.send(m));
        assert_eq!(3, lcs_r.len(), "wrong number of lcs!");
    }

    #[test]
    #[timeout(1000)]
    fn lc_uc_4_buf_delay_easy() {
        // lifecycle use case 4:
        // three small lifecycles each 70s (>60s max_buffering_delay_us) long, 1 one needs to be streamed from parse_lifecycles_buffered_from_stream while stream is not done
        let (tx, parse_lc_in) = channel();
        // 3 lifecycle messages:

        let m1 = crate::dlt::DltMessage::for_test_rcv_tms_ms(70_000, 50_000); // 20s buf delay
        tx.send(m1).unwrap();
        let m1 = crate::dlt::DltMessage::for_test_rcv_tms_ms(70_000, 70_000); // 0s buf delay
        tx.send(m1).unwrap();

        // next lifecycle starts 1ms after end of prev one (so at timestamp 70.001s)
        let m1 = crate::dlt::DltMessage::for_test_rcv_tms_ms(70_000 + 70_001, 50_000); // 20s buf delay
        tx.send(m1).unwrap();
        let m1 = crate::dlt::DltMessage::for_test_rcv_tms_ms(140_001, 70_000); // 0s buf delay
        tx.send(m1).unwrap();

        let m1 = crate::dlt::DltMessage::for_test_rcv_tms_ms(140_001 + 70_001, 50_000); // 20s buf delay
        tx.send(m1).unwrap();
        let m1 = crate::dlt::DltMessage::for_test_rcv_tms_ms(210_002, 70_000); // 0s buf delay
        tx.send(m1).unwrap();

        let (parse_lc_out, rx) = sync_channel(2048);
        let (lcs_r, lcs_w) = evmap::new::<LifecycleId, LifecycleItem>();

        let t = std::thread::spawn(move || {
            for _ in 0..4 {
                // 4 messages can be received. two from first and the two from second lc
                assert!(rx.recv().is_ok()); // one msg can be received
            }
            drop(tx);
            rx
        });

        let _lcs_w =
            parse_lifecycles_buffered_from_stream(lcs_w, parse_lc_in, &|m| parse_lc_out.send(m));
        // wait until one message could be received
        let _rx = t.join().unwrap(); // need result to avoid channel being closed too early!

        assert_eq!(3, lcs_r.len(), "wrong number of lcs!");
    }
    #[test]
    #[timeout(1000)]
    fn lc_uc_4_buf_delay_easy2() {
        // lifecycle use case 4:
        // three small lifecycles each 70s (>60s max_buffering_delay_us) long, 1 one needs to be streamed from parse_lifecycles_buffered_from_stream while stream is not done
        let (tx, parse_lc_in) = channel();
        // 3 lifecycle messages:

        let m1 = crate::dlt::DltMessage::for_test_rcv_tms_ms(70_000, 70_000); // 0s buf delay
        tx.send(m1).unwrap();

        // next lifecycle starts 1ms after end of prev one (so at timestamp 70.001s)
        let m1 = crate::dlt::DltMessage::for_test_rcv_tms_ms(140_001, 70_000); // 0s buf delay
        tx.send(m1).unwrap();

        let m1 = crate::dlt::DltMessage::for_test_rcv_tms_ms(210_002, 70_000); // 0s buf delay
        tx.send(m1).unwrap();

        let (parse_lc_out, rx) = sync_channel(2048);
        let (lcs_r, lcs_w) = evmap::new::<LifecycleId, LifecycleItem>();

        let t = std::thread::spawn(move || {
            for _ in 0..2 {
                // 2 messages can be received. one from first and one from second lc
                assert!(rx.recv().is_ok()); // one msg can be received
            }
            drop(tx);
            rx
        });

        let _lcs_w =
            parse_lifecycles_buffered_from_stream(lcs_w, parse_lc_in, &|m| parse_lc_out.send(m));
        // wait until one message could be received
        let _rx = t.join().unwrap(); // need result to avoid channel being closed too early!

        assert_eq!(3, lcs_r.len(), "wrong number of lcs!");
    }

    #[test]
    #[timeout(1000)]
    fn lc_uc_4_buf_delay_small() {
        // lifecycle use case 4:
        // four small lifecycles each 40s (<60s max_buffering_delay_us) long, 1 one needs to be streamed from parse_lifecycles_buffered_from_stream while stream is not done
        // this is a bit trickier than the lc_uc_4_buf_delay_easy as the lifecycles itself are not confirmed directly
        // 4 lifecycle messages:
        let (tx, parse_lc_in) = channel();

        let m1 = crate::dlt::DltMessage::for_test_rcv_tms_ms(40_000, 20_000); // 20s buf delay
        tx.send(m1).unwrap();
        let m1 = crate::dlt::DltMessage::for_test_rcv_tms_ms(40_000, 40_000); // 0s buf delay
        tx.send(m1).unwrap();

        // next lifecycle starts 1ms after end of prev one (so at timestamp 40.001s)
        let m1 = crate::dlt::DltMessage::for_test_rcv_tms_ms(40_000 + 40_001, 20_000); // 20s buf delay
        tx.send(m1).unwrap();
        let m1 = crate::dlt::DltMessage::for_test_rcv_tms_ms(80_001, 40_000); // 0s buf delay
        tx.send(m1).unwrap();

        let m1 = crate::dlt::DltMessage::for_test_rcv_tms_ms(80_001 + 40_001, 20_000); // 20s buf delay
        tx.send(m1).unwrap();
        let m1 = crate::dlt::DltMessage::for_test_rcv_tms_ms(120_002, 40_000); // 0s buf delay
        tx.send(m1).unwrap();

        let m1 = crate::dlt::DltMessage::for_test_rcv_tms_ms(120_002 + 40_001, 20_000); // 20s buf delay
        tx.send(m1).unwrap();
        let m1 = crate::dlt::DltMessage::for_test_rcv_tms_ms(160_003, 40_000); // 0s buf delay
        tx.send(m1).unwrap();

        let (parse_lc_out, rx) = sync_channel(2048);
        let (lcs_r, lcs_w) = evmap::new::<LifecycleId, LifecycleItem>();

        let t = std::thread::spawn(move || {
            for _ in 0..6 {
                // 4 messages can be received. two from first LC and two from 2nd lc and two from 3rd
                assert!(rx.recv().is_ok()); // one msg can be received
            }
            assert!(rx
                .recv_timeout(std::time::Duration::from_millis(10))
                .is_err());
            drop(tx);
            rx
        });

        let _lcs_w =
            parse_lifecycles_buffered_from_stream(lcs_w, parse_lc_in, &|m| parse_lc_out.send(m));
        // wait until one message could be received
        let rx = t.join().unwrap(); // need result to avoid channel being closed too early!
        assert!(rx.try_recv().is_ok()); // now msgs can be recvd
        assert_eq!(4, lcs_r.len(), "wrong number of lcs!");
    }
    #[test]
    #[timeout(1000)]
    fn lc_uc_4_buf_delay_small2() {
        // lifecycle use case 4:
        // four small lifecycles each 40s (<60s max_buffering_delay_us) long, 1 one needs to be streamed from parse_lifecycles_buffered_from_stream while stream is not done
        // this is a bit trickier than the lc_uc_4_buf_delay_easy as the lifecycles itself are not confirmed directly
        // 4 lifecycle messages:
        let (tx, parse_lc_in) = channel();

        let m1 = crate::dlt::DltMessage::for_test_rcv_tms_ms(40_000, 40_000); // 0s buf delay
        tx.send(m1).unwrap();

        // next lifecycle starts 1ms after end of prev one (so at timestamp 40.001s)
        let m1 = crate::dlt::DltMessage::for_test_rcv_tms_ms(80_001, 40_000); // 0s buf delay
        tx.send(m1).unwrap();

        let m1 = crate::dlt::DltMessage::for_test_rcv_tms_ms(120_002, 40_000); // 0s buf delay
        tx.send(m1).unwrap();

        let m1 = crate::dlt::DltMessage::for_test_rcv_tms_ms(160_003, 40_000); // 0s buf delay
        tx.send(m1).unwrap();

        let (parse_lc_out, rx) = sync_channel(2048);
        let (lcs_r, lcs_w) = evmap::new::<LifecycleId, LifecycleItem>();

        let t = std::thread::spawn(move || {
            for _ in 0..2 {
                // 2 messages can be received. one from first LC and one from 2nd lc
                assert!(rx.recv().is_ok()); // one msg can be received
            }
            assert!(rx
                .recv_timeout(std::time::Duration::from_millis(10))
                .is_err());
            drop(tx);
            rx
        });

        let _lcs_w =
            parse_lifecycles_buffered_from_stream(lcs_w, parse_lc_in, &|m| parse_lc_out.send(m));
        // wait until one message could be received
        let rx = t.join().unwrap(); // need result to avoid channel being closed too early!
        assert!(rx.try_recv().is_ok());

        assert_eq!(4, lcs_r.len(), "wrong number of lcs!");
    }

    #[test]
    fn lc_merge_1() {
        // test where 2nd lc gets merged into first
        let (tx, parse_lc_in) = channel();
        // 0s buffering delay assumed, lc start at 0
        tx.send(DltMessage::for_test_rcv_tms_ms(1_000, 1_000))
            .unwrap();
        // 1.5s buffering delay  -> but could be a new lifecycle as well with lc start at 1.5
        tx.send(DltMessage::for_test_rcv_tms_ms(2_000, 500))
            .unwrap();
        // 1s buffering delay
        tx.send(DltMessage::for_test_rcv_tms_ms(2_500, 1_500))
            .unwrap();

        drop(tx);
        let (parse_lc_out, _rx) = sync_channel(2048);
        let (lcs_r, lcs_w) = evmap::new::<LifecycleId, LifecycleItem>();
        let _lcs_w =
            parse_lifecycles_buffered_from_stream(lcs_w, parse_lc_in, &|m| parse_lc_out.send(m));
        assert_eq!(1, lcs_r.len(), "wrong number of lcs: {:?}", lcs_r.read());
    }

    #[test]
    fn lc_merge_2() {
        // test where 3rd lc gets merged into 2nd lc
        let (tx, parse_lc_in) = channel();
        // 0s buffering delay assumed, lc start at 0
        tx.send(DltMessage::for_test_rcv_tms_ms(1_000, 1_000))
            .unwrap();

        // new lc with 0s buf delay assumed, lc start at 2_000
        tx.send(DltMessage::for_test_rcv_tms_ms(3_000, 1_000))
            .unwrap();

        // 1.5s buffering delay  -> but could be a new lifecycle as well with lc start at 3.5
        tx.send(DltMessage::for_test_rcv_tms_ms(4_000, 500))
            .unwrap();
        // 1s buffering delay
        tx.send(DltMessage::for_test_rcv_tms_ms(4_500, 1_500))
            .unwrap();

        drop(tx);
        let (parse_lc_out, _rx) = sync_channel(2048);
        let (lcs_r, lcs_w) = evmap::new::<LifecycleId, LifecycleItem>();
        let _lcs_w =
            parse_lifecycles_buffered_from_stream(lcs_w, parse_lc_in, &|m| parse_lc_out.send(m));
        assert_eq!(2, lcs_r.len(), "wrong number of lcs!");
    }

    #[test]
    fn lc_merge_3() {
        // test where 3rd lc gets merged into 2nd lc and then into 1st lc
        let (tx, parse_lc_in) = channel();
        // 0s buffering delay assumed, lc start at 0
        tx.send(DltMessage::for_test_rcv_tms_ms(1_000, 1_000))
            .unwrap();

        // 2s buffering delay  -> but could be a new lifecycle as well with lc start at 2
        tx.send(DltMessage::for_test_rcv_tms_ms(3_000, 1_000))
            .unwrap();

        // 2s buffering delay  -> but could be a new lifecycle as well with lc start at 4
        tx.send(DltMessage::for_test_rcv_tms_ms(5_000, 1_00))
            .unwrap();
        // 1s buffering delay -> now we should have just one lifecycle
        tx.send(DltMessage::for_test_rcv_tms_ms(5_500, 4_500))
            .unwrap();
        // todo bug: but we currently need a 2nd message to trigger next merge
        tx.send(DltMessage::for_test_rcv_tms_ms(5_501, 4_501))
            .unwrap();

        drop(tx);
        let (parse_lc_out, _rx) = sync_channel(2048);
        let (lcs_r, lcs_w) = evmap::new::<LifecycleId, LifecycleItem>();
        let _lcs_w =
            parse_lifecycles_buffered_from_stream(lcs_w, parse_lc_in, &|m| parse_lc_out.send(m));
        assert_eq!(1, lcs_r.len(), "wrong number of lcs!");
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
                            htyp: DLT_STD_HDR_HAS_TIMESTAMP,
                            len: 0,
                            mcnt: 0,
                        },
                        extended_header: None,
                        payload: [].to_vec(),
                        payload_text: None,
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
            if !self.msgs.is_empty() {
                Some(self.msgs.remove(0))
            } else {
                None
            }
        }
    }

    #[test]
    fn gen_two_lcs() {
        let (tx, rx) = channel();
        let (tx2, rx2) = sync_channel(2048);
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
        let _lcs_w = parse_lifecycles_buffered_from_stream(lcs_w, rx, &|m| tx2.send(m));
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

            // now check whether each message has a valid lifecycle in mapped_lcs:
            // the msg has only an interims lifecycle id which might point to a
            // lifecycle that has been merged into a different one later on
            // or will be merged later on.
            // We could modify the msg as well to point to the final lc.id but
            // for streaming that doesn't really work as the ids might change later
            // so using the mapped lifecycles gives the current view
            for _i in 0..NUMBER_MSGS {
                let rm = rx2.recv();
                assert!(rm.is_ok());
                let m = rm.unwrap();
                assert!(m.lifecycle != 0);
                assert!(
                    final_lcs.iter().any(|x| x.id == m.lifecycle),
                    "no mapped_lcs for lc id {}",
                    &m.lifecycle
                );
                assert!(final_lcs
                    .iter()
                    .find(|x| x.id == m.lifecycle)
                    .unwrap()
                    .was_merged()
                    .is_none());
                //println!("got msg:{:?}", rm.unwrap());
            }
            assert!(rx2.try_recv().is_err());
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
        let _lcs_w = parse_lifecycles_buffered_from_stream(lcs_w, rx, &|m| tx2.send(m));
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

            // now check whether each message has a valid lifecycle in mapped_lcs:
            // the msg has only an interims lifecycle id which might point to a
            // lifecycle that has been merged into a different one later on
            // or will be merged later on.
            // We could modify the msg as well to point to the final lc.id but
            // for streaming that doesn't really work as the ids might change later
            // so using the mapped lifecycles gives the current view
            for _i in 0..2 * NUMBER_MSGS {
                let rm = rx2.recv();
                assert!(rm.is_ok());
                let m = rm.unwrap();
                assert!(m.lifecycle != 0);
                assert!(
                    final_lcs.iter().any(|x| x.id == m.lifecycle),
                    "no mapped_lcs for lc id {}",
                    &m.lifecycle
                );
                assert!(final_lcs
                    .iter()
                    .find(|x| x.id == m.lifecycle)
                    .unwrap()
                    .was_merged()
                    .is_none());
            }
            assert!(rx2.try_recv().is_err());
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
        let (tx2, rx2) = sync_channel(2048);
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
        let t2 = std::thread::spawn(move || {
            parse_lifecycles_buffered_from_stream(lcs_w, rx, &|m| tx2.send(m))
        });
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
                let interims_lcs = read.get_one(&m.lifecycle);
                let lc_start_time = interims_lcs.unwrap().start_time;
                let s_m = SortedDltMessage { m, lc_start_time };
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
            while !buffer.is_empty() {
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

    /// return a control message
    fn get_testmsg_control(big_endian: bool, noar: u8, payload_buf: &[u8]) -> DltMessage {
        let sh = DltStorageHeader {
            secs: 0,
            micros: 0,
            ecu: DltChar4::from_str("ECU1").unwrap(),
        };
        let exth = DltExtendedHeader {
            verb_mstp_mtin: 0x3 << 1 | (0x02 << 4),
            noar,
            apid: DltChar4::from_buf(b"DA1\0"),
            ctid: DltChar4::from_buf(b"DC1\0"),
        };
        let stdh = DltStandardHeader {
            htyp: 0x21
                | (if big_endian {
                    DLT_STD_HDR_BIG_ENDIAN
                } else {
                    0
                }),
            mcnt: 0,
            len: (DLT_MIN_STD_HEADER_SIZE + DLT_EXT_HEADER_SIZE + payload_buf.len()) as u16,
        };
        let mut add_header_buf = Vec::new();
        exth.to_write(&mut add_header_buf).unwrap();

        DltMessage::from_headers(1, sh, stdh, &add_header_buf, payload_buf.to_vec())
    }

    #[test]
    fn sw_version() {
        let mut m = get_testmsg_control(
            false,
            1,
            &[19, 0, 0, 0, 0, 4, 0, 0, 0, b'S', b'W', b' ', b'1'],
        );
        let mut m2 = get_testmsg_control(
            false,
            1,
            &[19, 0, 0, 0, 0, 4, 0, 0, 0, b'S', b'W', b' ', b'2'],
        );
        let mut lc = Lifecycle::new(&mut m);
        assert!(lc.sw_version.is_none()); // this is weird but currently accepted impl.
        lc.update(&mut m2, 60 * US_PER_SEC);
        assert!(lc.sw_version.is_some());
        assert_eq!(lc.sw_version.unwrap(), "SW 2");
    }

    fn get_file_iterator(file_name: &str, namespace: u32) -> Box<dyn Iterator<Item = DltMessage>> {
        let fi = File::open(file_name).unwrap();
        const BUFREADER_CAPACITY: usize = 512 * 1024;
        let buf_reader = LowMarkBufReader::new(fi, BUFREADER_CAPACITY, DLT_MAX_STORAGE_MSG_SIZE);
        let it = get_dlt_message_iterator(
            std::path::Path::new(file_name)
                .extension()
                .and_then(|s| s.to_str())
                .unwrap_or(""),
            0,
            buf_reader,
            namespace,
            None,
            None,
            None,
        );
        it
    }

    fn lcs_for_files(file_names: &[&str]) -> (DltMessageIndexType, Vec<Lifecycle>) {
        let (tx_for_parse_thread, rx_from_parse_thread) = channel();
        let (lcs_r, lcs_w) = evmap::new::<LifecycleId, LifecycleItem>();

        let (tx_for_lc_thread, rx_from_lc_thread) = sync_channel(2048);
        let lc_thread = std::thread::spawn(move || {
            parse_lifecycles_buffered_from_stream(lcs_w, rx_from_parse_thread, &|m| {
                tx_for_lc_thread.send(m)
            })
        });
        let junk_thread = std::thread::spawn(move || for _msg in rx_from_lc_thread {});

        let namespace = get_new_namespace();
        let its = file_names
            .iter()
            .map(|file_name| get_file_iterator(file_name, namespace));
        let mut it = SequentialMultiIterator::new_or_single_it(0, its);
        let mut messages_processed: DltMessageIndexType = 0;
        for msg in it.by_ref() {
            messages_processed += 1;
            tx_for_parse_thread.send(msg).unwrap(); // todo handle error
        }
        drop(tx_for_parse_thread);

        // wait for the threads
        junk_thread.join().unwrap();
        let _lcs_w = lc_thread.join().unwrap();
        let lcs = if let Some(a) = lcs_r.read() {
            let sorted_lcs = get_sorted_lifecycles_as_vec(&a);
            sorted_lcs.iter().map(|&l| l.clone()).collect()
        } else {
            [].to_vec()
        };

        (messages_processed, lcs)
    }

    fn nr_lcs_for_file(file_name: &str) -> (DltMessageIndexType, usize) {
        let (messages_processed, nr_lcs) = lcs_for_files(&[file_name]);
        (messages_processed, nr_lcs.len())
    }

    fn nr_lcs_for_files(file_names: &[&str]) -> (DltMessageIndexType, usize) {
        let (messages_processed, nr_lcs) = lcs_for_files(file_names);
        (messages_processed, nr_lcs.len())
    }

    fn get_tests_filename(file_name: &str) -> std::path::PathBuf {
        let mut test_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_dir.push("tests");
        test_dir.push(file_name);
        test_dir
    }

    #[test]
    fn lc_ex001() {
        // lc_ex001 should have 426464 msgs and 26 lifecycles:
        let ex001 = get_tests_filename("lc_ex001.dlt");
        if ex001.exists() {
            assert_eq!(nr_lcs_for_file(&ex001.to_string_lossy()), (426464, 26));
        } else {
            // consider adding to github...
            println!("skipped test lc_ex001 as file not available!");
        }
    }

    #[test]
    fn lc_ex002() {
        // very short lifecycle that start with timestamp 0
        assert_eq!(
            nr_lcs_for_file(&get_tests_filename("lc_ex002.dlt").to_string_lossy()),
            (11696, 4)
        );
    }
    #[test]
    fn lc_ex003() {
        // timestamp not available on all msgs -> 1 LC
        assert_eq!(
            nr_lcs_for_file(&get_tests_filename("lc_ex003.dlt").to_string_lossy()),
            (8045, 1)
        );
    }

    #[test]
    fn lc_ex004() {
        // an example with a RESUME detected even though it seems just to be a stuck output
        // so the RESUME lifecycle later one even gets an earlier start time_stamp.
        // check that get_get_sorted_lifecycles_as_vec sorts the resumed after the resumed from
        let (messages_processed, lcs) =
            lcs_for_files(&[&get_tests_filename("lc_ex004.dlt").to_string_lossy()]);
        assert_eq!(messages_processed, 52451);
        assert_eq!(lcs.len(), 2);
        assert!(!lcs[0].is_resume());
        // we dont enforce that! assert!(nr_lcs[1].is_resume());
        // that's not the case! assert!(nr_lcs[0].start_time < nr_lcs[1].start_time);
        assert!(lcs[0].resume_start_time() < lcs[1].resume_start_time());
    }

    #[test]
    fn lc_ex005() {
        // an example from the ECU internally recording its own logs.
        // Here the problem is that is has no realtime clock. So it persists the "realtime" at shutdown
        // and loads that value at startup as new realtime. This leads to the realtime clock slightly
        // getting stuck (i.e. the new lifecycle starts a bit before the old one ends)
        assert_eq!(
            nr_lcs_for_files(&[&get_tests_filename("lc_ex005.dlt").to_string_lossy()]),
            (40285, 2)
        );
    }

    #[test]
    fn lc_ex006() {
        // another example from the ECU internally recording its own logs.
        // Here the problem is that is has no realtime clock. So it persists the "realtime" at shutdown
        // and loads that value at startup as new realtime.
        // If then messages get assigned to the prev. lifecycle there was a weird behaviour that the
        // calculated lc end time was far lower than the reception time. But the new lifecycle start time was earlier
        // than the last reception time thus the messages were assigned to the prev lifecycle as well.
        assert_eq!(
            nr_lcs_for_files(&[&get_tests_filename("lc_ex006.dlt").to_string_lossy()]),
            (4226 + 5775, 2)
        );
    }

    // todo add tests and workaround for the regression introduced with the above
    //  lc_ex006 fix. Regressions seem to be in lifecycles with corrupts/inplausible (most of them too high) timestamps
    //  from an ecu with serial recording  (logs/tecmp around index 19413 and following)
}
