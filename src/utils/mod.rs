use crate::{
    dlt::{
        DltArg, DltChar4, DltMessage, DltMessageIndexType, DLT_TYPE_INFO_RAWD, DLT_TYPE_INFO_STRG,
    },
    SendMsgFnReturnType,
};
use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    io::{BufRead, BufReader, Read, Seek},
    path::{Path, PathBuf},
    str::FromStr,
    sync::{
        atomic::AtomicU32,
        mpsc::{Receiver, SendError, Sender, SyncSender, TrySendError},
        RwLock,
    },
};
mod lowmarkbufreader;
pub use self::lowmarkbufreader::LowMarkBufReader;
mod asc2dltmsgiterator;
pub use self::asc2dltmsgiterator::Asc2DltMsgIterator;
mod blf2dltmsgiterator;
pub use self::blf2dltmsgiterator::BLF2DltMsgIterator;
mod dltmessageiterator;
pub mod sorting_multi_readeriterator;
pub use self::dltmessageiterator::DltMessageIterator;
pub mod eac_stats;
mod logcat2dltmsgiterator;
pub mod remote_types;
pub use self::logcat2dltmsgiterator::LogCat2DltMsgIterator;
mod genlog2dltmsgiterator;
pub mod remote_utils;
pub use self::genlog2dltmsgiterator::GenLog2DltMsgIterator;

pub mod cloneable_seekable_reader;
pub mod seekablechain;
pub mod unzip;

use lazy_static::lazy_static;

static GLOBAL_NEXT_NAMESPACE: AtomicU32 = AtomicU32::new(0);

lazy_static! {
    // map by namespace to a map for tag to apid:
    static ref GLOBAL_TAG_APID_MAP: RwLock<HashMap<u32, HashMap<String, DltChar4>>> = RwLock::new(HashMap::new());
}

/// return a new namespace
///
/// A namespace is used to provide a grouping for a set of files that are opened
/// simultaneously. The main purpose is for CAN .asc files that are from different
/// CAN channels but that all use e.g. the BusMapping CAN 1 = ... identifier 1.
/// If those files are opened with the same namespace different channels will get
/// a different ECU id (CAN1, CAN2). If opened with different namespaces they might
/// both end up in CAN1 ECU id.
///
pub fn get_new_namespace() -> u32 {
    GLOBAL_NEXT_NAMESPACE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// return a 4 digit string with the prefix and the iteration number
///
/// for iteration 0 the input string is returned.
/// For other iterations the prefix is shortened to fit with the iteration number.
///
/// e.g. "abcd", 42 -> "ab42"
fn get_4digit_str(a_str: &str, iteration: u16) -> Cow<'_, str> {
    match iteration {
        0 => Cow::from(a_str),
        _ => {
            let len_str = a_str.len();
            let number_str = iteration.to_string();
            let len_number = number_str.len();
            let needed_str = if len_number > 3 { 0 } else { 4 - len_number };
            if needed_str > len_str {
                Cow::Owned(format!("{}{:0len$}", a_str, iteration, len = 4 - len_str))
            } else {
                Cow::Owned(format!("{}{}", &a_str[0..needed_str], iteration))
            }
        }
    }
}

/// generate a new apid for a tag for a namespace.
///
/// Per namespace a map is maintained that maps a tag to an apid.
/// If the tag exists already the existing apid is returned.
/// If the tag does not exist a new apid is generated.
///
/// todo: describe the algorithm for the name selection/abbrevation
pub fn get_apid_for_tag(namespace: u32, tag: &str) -> DltChar4 {
    let mut namespace_map = GLOBAL_TAG_APID_MAP.write().unwrap();
    let map = namespace_map.entry(namespace).or_default();
    match map.get(tag) {
        Some(e) => e.to_owned(),
        None => {
            let trimmed_tag = tag.trim();
            // try to find a good apid as tag abbrevation
            //
            let mut iteration = 0u16;
            loop {
                let apid = match trimmed_tag.len() {
                    0 => DltChar4::from_str(" ").unwrap(),
                    1..=4 => DltChar4::from_str(&get_4digit_str(trimmed_tag, iteration))
                        .unwrap_or(DltChar4::from_str(&get_4digit_str("NoAs", iteration)).unwrap()),
                    _ => {
                        let has_underscores = trimmed_tag.contains('_');
                        if has_underscores {
                            // assume snake case
                            let nr_underscore = trimmed_tag.chars().fold(0u32, |acc, c| {
                                if c == '_' {
                                    acc + 1
                                } else {
                                    acc
                                }
                            });
                            let mut needed_other = if nr_underscore < 3 {
                                3 - nr_underscore
                            } else {
                                0
                            };
                            let mut abbrev = String::with_capacity(4);
                            let mut take_next = true;
                            for c in trimmed_tag.chars() {
                                if c == '_' {
                                    take_next = true;
                                } else if c.is_ascii() {
                                    if take_next || needed_other > 0 {
                                        abbrev.push(c);
                                        if !take_next {
                                            needed_other -= 1;
                                        }
                                    }
                                    take_next = false;
                                }
                                if abbrev.len() >= 4 {
                                    break;
                                }
                            }

                            DltChar4::from_str(&get_4digit_str(&abbrev, iteration))
                        } else {
                            // assume camel case
                            let nr_capital = trimmed_tag.chars().fold(0u32, |acc, c| {
                                if c.is_ascii_uppercase() {
                                    acc + 1
                                } else {
                                    acc
                                }
                            });
                            let mut needed_lowercase =
                                if nr_capital < 4 { 4 - nr_capital } else { 0 };
                            let mut abbrev = String::with_capacity(4);
                            for c in trimmed_tag.chars() {
                                if c.is_ascii_uppercase() {
                                    abbrev.push(c);
                                } else if needed_lowercase > 0 && c.is_ascii() {
                                    abbrev.push(c);
                                    needed_lowercase -= 1;
                                }
                                if abbrev.len() >= 4 {
                                    break;
                                }
                            }

                            DltChar4::from_str(&get_4digit_str(&abbrev, iteration))
                        }
                    }
                    .unwrap_or(DltChar4::from_str(&get_4digit_str("NoAs", iteration)).unwrap()),
                };

                // does apid exist already?
                if let Some((_k, _v)) = map.iter().find(|(_k, v)| v == &&apid) {
                    /* println!(
                        "get_apid_for_tag iteration {} apid {} for tag {} exists already for tag {}",
                        iteration, apid, tag, k
                    ); */
                    iteration += 1;
                } else {
                    map.insert(tag.to_owned(), apid.to_owned());
                    return apid;
                }
            } // todo abort after >100 iterations with a default?
        }
    }
}

/// return the proper dlt message iterator for a file type/extension
///
/// Does this currently by extension:
///  - `asc` uses the Asc2DltMsgIterator
///  - `blf` uses the Blf2DltMsgIterator
///  - `txt` uses the LogCat2DltMsgIterator
///  - `log` uses the GenLog2DltMsgIterator
///  - others use the DltMessageIterator
///
/// ### Arguments
/// * `file_ext` - the file extension used to determine the iterator
/// * `start_index` - the start_index to use for the messages generated
/// * `reader` - the reader providing the byte stream to parse
/// * `` - the namespace to use. Used for CAN files. Different channels in the same
///   namespace will use a different CANx ecu id.
/// * `first_reception_time_us` - used to provide a time used as reference
///   for the timestamps for CAN files. Should be from the first file opened.
///   Not needed/ignored for DLT files.
/// * `modified_time_us` - the time from the files last created/modified time in us.
///   Used when e.g. the format supports only relative timestamps.
pub fn get_dlt_message_iterator<'a, R: 'a + BufRead + Seek>(
    file_ext: &str,
    start_index: DltMessageIndexType,
    reader: R,
    namespace: u32,
    first_reception_time_us: Option<u64>,
    modified_time_us: Option<u64>,
    log: Option<&'a slog::Logger>,
) -> Box<dyn Iterator<Item = DltMessage> + 'a> {
    match file_ext.to_lowercase().as_str() {
        "asc" => Box::new(Asc2DltMsgIterator::new(
            start_index,
            reader,
            namespace,
            first_reception_time_us,
            log,
        )),
        "blf" => Box::new(BLF2DltMsgIterator::new(
            start_index,
            reader,
            namespace,
            first_reception_time_us,
            log,
        )),
        "txt" => Box::new(LogCat2DltMsgIterator::new(
            start_index,
            reader,
            namespace,
            first_reception_time_us,
            modified_time_us,
            log,
        )),
        "log" => Box::new(GenLog2DltMsgIterator::new(
            start_index,
            reader,
            namespace,
            first_reception_time_us,
            modified_time_us,
            log,
        )),
        _ => Box::new({
            let mut it = DltMessageIterator::new(start_index, reader);
            it.log = log;
            it
        }),
    }
}

#[derive(PartialEq, Clone, Debug)]
pub struct DltFileInfos {
    pub modified_time_us: Option<u64>, // last modified date of the file in us since 1.1.1970
    pub file_len: Option<u64>,         // length of the file
    pub read_size: usize,              // number of bytes that have been tried to read/parse
    pub first_msg: Option<DltMessage>, // the first DLT message
    pub namespace: u32,                // namespace (for the ECU names)
    pub ecus_seen: HashSet<DltChar4>,  // the ECU ids within the read_size range
}

/// Returns infos of a partial parsing from a DLT supported file
///
/// Returned info contain e.g. the ECU ids encountered in the DLT messages within the first read_size number of bytes.
///
/// **Note:** consumes up to read_size bytes from the file!
///
/// # Examples
///
/// ```
/// use std::fs::File;
/// use adlt::dlt::DltChar4;
/// use adlt::utils::get_dlt_infos_from_file;
/// let dfi = get_dlt_infos_from_file("asc", &mut File::open("./tests/can_example1.asc").unwrap(), 512*1024, 0).unwrap();
/// assert!(dfi.first_msg.is_some());
/// assert!(dfi.ecus_seen.contains(&DltChar4::from_buf(b"CAN1")));
/// ```

pub fn get_dlt_infos_from_file(
    file_ext: &str,
    file: &mut std::fs::File,
    read_size: usize,
    namespace: u32,
) -> std::io::Result<DltFileInfos> {
    let (file_len, modified_time_us) = file.metadata().map_or((None, None), |m| {
        (
            Some(m.len()),
            m.modified()
                .map(|t| {
                    t.duration_since(std::time::SystemTime::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_micros() as u64
                })
                .ok(),
        )
    });
    get_dlt_infos_from_read(
        file_ext,
        file,
        file_len,
        modified_time_us,
        read_size,
        namespace,
    )
}

pub fn get_dlt_infos_from_read<R: Read>(
    file_ext: &str,
    read: &mut R,
    file_len: Option<u64>,
    modified_time_us: Option<u64>,
    read_size: usize,
    namespace: u32,
) -> std::io::Result<DltFileInfos> {
    let mut buf = vec![0u8; read_size];
    let res = read.read(&mut buf); // todo replace by helper function that tries to read full buf size!
    match res {
        Ok(res) => {
            let mut it = get_dlt_message_iterator(
                file_ext,
                0,
                BufReader::with_capacity(read_size, std::io::Cursor::new(&buf[0..res])),
                namespace,
                None,
                modified_time_us,
                None,
            );
            let first_msg = it.next();
            let mut ecus_seen = HashSet::with_capacity(8);
            if let Some(first_m) = &first_msg {
                ecus_seen.insert(first_m.ecu);
                // scan other msgs as well:
                for m in it {
                    ecus_seen.insert(m.ecu);
                }
            }

            Ok(DltFileInfos {
                modified_time_us,
                file_len,
                read_size,
                first_msg,
                namespace,
                ecus_seen,
            })
        }
        Err(e) => Err(e),
    }
}

// const MS_PER_SEC:u32 = 1_000;

/// const for micro-secs (us) per second
pub const US_PER_SEC: u64 = 1_000_000;

pub fn utc_time_from_us(time_us: u64) -> chrono::NaiveDateTime {
    chrono::NaiveDateTime::from_timestamp_opt(
        // todo get rid of all those mult/%...
        (time_us / US_PER_SEC) as i64,
        1_000u32 * (time_us % 1_000_000) as u32,
    )
    .unwrap_or_else(|| chrono::NaiveDateTime::from_timestamp_opt(0, 0).unwrap())
}

/// Checks if a string contains any regular expression special characters.
///
/// # Arguments
///
/// * `s` - A string slice to check for regex special characters.
///
/// # Returns
///
/// A boolean value indicating whether the string contains any regex special characters ^$*+?()[]{}|.-\=!<,
///
/// # Example
///
/// ```
/// use adlt::utils::contains_regex_chars;
///
/// let has_special_chars = contains_regex_chars("hello.*");
/// assert_eq!(has_special_chars, true);
/// ```
pub fn contains_regex_chars(s: &str) -> bool {
    s.contains(|c| {
        c == '^'
            || c == '$'
            || c == '*'
            || c == '+'
            || c == '?'
            || c == '('
            || c == ')'
            || c == '['
            || c == ']'
            || c == '{'
            || c == '}'
            || c == '|'
            || c == '.'
            || c == '-'
            || c == '\\'
            || c == '='
            || c == '!'
            || c == '<'
            || c == '>'
            || c == ','
    })
}

static U8_HEX_LOW: [u8; 16] = *b"0123456789abcdef";

#[inline(always)]
pub fn is_printable_char(c: &u8) -> bool {
    *c >= 0x20 && *c <= 0x7e
}

#[inline(always)]
pub fn is_non_printable_char_wo_rnt(c: &u8) -> bool {
    !is_printable_char(c) && *c != b'\r' && *c != b'\n' && *c != b'\t'
}

/// output as buffer as printable ascii to a (char) writer.
/// Each byte between [0x20...=0x7e] is printed. Others are replaced by the replacement_char.
///
/// Returns how often the replacement char was used except for whitespace chars like \r\n\t.
pub fn buf_as_printable_ascii_to_write(
    writer: &mut impl std::fmt::Write,
    buf: &[u8],
    replacement_char: char,
) -> Result<u32, std::fmt::Error> {
    let mut times_replaced = 0;
    for item in buf.iter() {
        if is_printable_char(item) {
            writer.write_char(*item as char)?;
        } else {
            writer.write_char(replacement_char)?;
            match *item {
                b'\r' | b'\n' | b'\t' => {}
                _ => times_replaced += 1,
            };
        }
    }
    Ok(times_replaced)
}

/// output a buffer as hex dump to a (char) writer.
/// Each byte is output as two lower-case digits.
/// A space is output between each byte.
/// e.g. "0f 00"
pub fn buf_as_hex_to_write(
    writer: &mut impl std::fmt::Write,
    buf: &[u8],
) -> Result<(), std::fmt::Error> {
    for (i, item) in buf.iter().enumerate() {
        let c1 = U8_HEX_LOW[(item >> 4) as usize];
        let c2 = U8_HEX_LOW[(item & 0x0f) as usize];
        if i > 0 {
            // SAFETY: we know that the slice is valid UTF8
            writer.write_str(unsafe { std::str::from_utf8_unchecked(&[b' ', c1, c2]) })?;
        } else {
            // SAFETY: we know that the slice is valid UTF8
            writer.write_str(unsafe { std::str::from_utf8_unchecked(&[c1, c2]) })?;
        }
    }

    Ok(())
}

/// same as buf_as_hex_to_write but with a
/// std::io::Write as a byte stream.
///
/// Each byte is output as two lower-case digits.
/// A space is output between each byte.
/// e.g. "0f 00"
pub fn buf_as_hex_to_io_write(
    writer: &mut impl std::io::Write,
    buf: &[u8],
) -> Result<(), std::io::Error> {
    for (i, item) in buf.iter().enumerate() {
        let c1 = U8_HEX_LOW[(item >> 4) as usize];
        let c2 = U8_HEX_LOW[(item & 0x0f) as usize];
        if i > 0 {
            writer.write_all(&[b' ', c1, c2])?
        } else {
            writer.write_all(&[c1, c2])?
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
        // we can alloc the Vec size upfront:
        let mut v: Vec<u8> = Vec::with_capacity((s.len() + 1) / 3);

        for i in (0..s.len()).step_by(3) {
            let s = u8::from_str_radix(&s[i..i + 2], 16);
            if let Ok(s) = s {
                v.push(s);
            } else {
                return None;
            }
        }
        Some(v)
    }
}

/// convert a type that supports to_be/le_bytes into a vec
/// first param is the type to be output as vec
/// 2nd param indicates whether big_endianess is to be used.
#[macro_export]
macro_rules! to_endian_vec {
    ($x:expr, $i:expr) => {
        if $i {
            $x.to_be_bytes().to_vec()
        } else {
            $x.to_le_bytes().to_vec()
        }
    };
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
        self.calculated_time_us == other.calculated_time_us && self.m.index == other.m.index
    }
}
impl std::cmp::Ord for SortedDltMessage {
    #[inline(always)]
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // have to use the calculated time and not the own time
        if self.calculated_time_us == other.calculated_time_us {
            self.m.index.cmp(&other.m.index) // keep the initial order on same timestamp
        } else {
            self.calculated_time_us.cmp(&other.calculated_time_us)
        }
    }
}
impl std::cmp::PartialOrd for SortedDltMessage {
    #[inline(always)]
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
pub fn buffer_sort_messages<M, S, F: Fn(DltMessage) -> SendMsgFnReturnType>(
    inflow: Receiver<DltMessage>,
    outflow: &F,
    lcs_r: &evmap::ReadHandle<crate::lifecycle::LifecycleId, crate::lifecycle::LifecycleItem, M, S>,
    windows_size_secs: u8,
    min_buffer_delay_us: u64,
) -> Result<(), SendError<DltMessage>>
where
    S: std::hash::BuildHasher + Clone,
    M: 'static + Clone,
{
    // we need a data structure that supports fast search (partition_point) and fast insert. VecDeque's insert is quite slow (needs memmove)
    // BinaryHeap seems faster. Use as min_heap

    let mut buffer = std::collections::binary_heap::BinaryHeap::with_capacity(1024 * 1024);
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
                // println!("added lc_map {} {}", x, start_time);
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
            let entry = max_buffering_delays.entry(*ecu).or_insert_with(|| {
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
                /* if new_max_buffer_time_us != max_buffer_time_us
                    && new_max_buffer_time_us > min_buffer_delay_us * 2
                {
                    println!("max_buffer_time_us={}", new_max_buffer_time_us);
                } */
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
        buffer.push(std::cmp::Reverse(sm));

        // remove all messages from buffer that have a time more than max_buffer_time_us earlier

        while let Some(sm) = buffer.peek() {
            if sm.0.calculated_time_us + max_buffer_time_us < msg_reception_time_us {
                let sm2 = buffer.pop().unwrap();
                outflow(sm2.0.m)?;
            } else {
                break; // msgs are sorted so we stop here and check after next msg
            }
        }
    }
    while let Some(sm) = buffer.pop() {
        outflow(sm.0.m)?;
    }
    Ok(())
}

/// convert DltArg array into raw payload
///
/// Endianess from the first DltArg is used for the payload.
/// Mainly used for testing.
pub fn payload_from_args<'a>(args: &'a [DltArg<'a>]) -> Vec<u8> {
    if !args.is_empty() {
        let mut payload = Vec::new();

        // use endianess from first one:
        let big_endian = args[0].is_big_endian;
        // serialize the args
        // type_info, len and payload
        for arg in args {
            let persist_len_u16 = if arg.type_info & (DLT_TYPE_INFO_STRG | DLT_TYPE_INFO_RAWD) != 0
            {
                arg.payload_raw.len() as u16
            } else {
                0u16
            };

            let type_info = if big_endian {
                arg.type_info.to_be_bytes()
            } else {
                arg.type_info.to_le_bytes()
            };
            payload.extend_from_slice(&type_info);
            if persist_len_u16 > 0 {
                payload.extend_from_slice(&if big_endian {
                    persist_len_u16.to_be_bytes()
                } else {
                    persist_len_u16.to_le_bytes()
                })
            };
            payload.extend_from_slice(arg.payload_raw);
        }

        payload
    } else {
        vec![]
    }
}

/// get all files with a given extension in a directory
///
/// # Arguments
/// * `dir` - the directory to search in
/// * `extensions` - the extensions to search for
/// * `recursive` - whether to recurse into sub directories
///
/// # Returns
/// A vector with all the files found
///
/// todo refactor get_all_fibex_in_dir by this function call
pub fn get_all_files_with_ext_in_dir(
    dir: &Path,
    extensions: &[&str],
    recursive: bool,
) -> Result<Vec<PathBuf>, std::io::Error> {
    let entries = dir.read_dir()?;
    let mut res = Vec::new();
    for entry in entries.flatten() {
        if entry.path().is_dir() {
            if recursive && !entry.path().is_symlink() {
                // dont recurse into symlinks
                let sub = get_all_files_with_ext_in_dir(&entry.path(), extensions, true);
                if let Ok(sub) = sub {
                    for p in sub {
                        res.push(p);
                    }
                } // we ignore errs from sub dirs.
            }
        } else if entry.path().is_file() {
            if let Some(ext) = entry.path().extension() {
                for e in extensions {
                    if ext.eq_ignore_ascii_case(e) {
                        res.push(entry.path().clone());
                        break;
                    }
                }
            }
        }
    }
    Ok(res)
}

/// Sends a value to the (bounded) channel, delaying 10ms if the channel is full.
///
/// This function sends a value to the synchronous channel represented by `sender`. If the channel is full,
/// it waits for a 10ms duration and tries then blocking(!) via .send(...).
///
/// # Arguments
///
/// * `value` - The value to send to the channel.
/// * `sender` - A `sync::Sender<T>` representing the synchronous channel to send the value to.
///
/// # Returns
///
/// * A `Result<(), SendError<T>>` representing the result of the send operation. If the value was sent successfully,
///   it returns `Ok(())`. If the receiver has disconnected and the value could not be sent, it returns `Err(SendError(T))`.
///
/// # Example
///
/// ```
/// use std::sync::mpsc;
/// use adlt::utils::sync_sender_send_delay_if_full;
///
/// let (sender, receiver) = mpsc::sync_channel(1);
/// let send_result = sync_sender_send_delay_if_full(42, &sender);
///
/// match send_result {
///     Ok(_) => println!("Value sent successfully"),
///     Err(error) => println!("Failed to send value: {}", error),
/// }
/// ```
#[inline(always)]
pub fn sync_sender_send_delay_if_full<T>(m: T, tx: &SyncSender<T>) -> Result<(), SendError<T>> {
    match tx.try_send(m) {
        Ok(_) => Ok(()),
        Err(TrySendError::Full(m)) => {
            std::thread::sleep(std::time::Duration::from_millis(10));
            tx.send(m)
        }
        Err(TrySendError::Disconnected(m)) => Err(SendError(m)),
    }
}

#[cfg(test)]
mod tests {
    use crate::dlt::{DltMessage, DltStandardHeader, DltStorageHeader};
    use crate::lifecycle::*;
    use crate::utils::*;
    use std::fs::File;
    use std::io::Write;
    use std::sync::mpsc::{channel, sync_channel};
    //    use std::time::Instant;
    use chrono::{Datelike, Timelike};
    use tempfile::NamedTempFile;

    #[test]
    fn get_4digit_str_1() {
        assert_eq!(get_4digit_str("", 0), "");
        assert_eq!(get_4digit_str("", 1), "0001");
        assert_eq!(get_4digit_str("a", 0), "a");
        assert_eq!(get_4digit_str("a", 1), "a001");
        assert_eq!(get_4digit_str("a", 99), "a099");
        assert_eq!(get_4digit_str("a", 1000), "1000");
        assert_eq!(get_4digit_str("abc", 9), "abc9");
        assert_eq!(get_4digit_str("abc", 99), "ab99");
        assert_eq!(get_4digit_str("abcd", 0), "abcd");
        assert_eq!(get_4digit_str("abcd", 1), "abc1");
        assert_eq!(get_4digit_str("abcd", 9), "abc9");
        assert_eq!(get_4digit_str("abcd", 10), "ab10");
        assert_eq!(get_4digit_str("abcd", 99), "ab99");
        assert_eq!(get_4digit_str("abcd", 100), "a100");
        assert_eq!(get_4digit_str("abcd", 999), "a999");
        assert_eq!(get_4digit_str("abcd", 1000), "1000");
    }

    #[test]
    fn get_apid_for_tag_1() {
        assert_eq!(
            get_apid_for_tag(0, "snake_case"),
            DltChar4::from_buf(b"snac")
        );
        assert_eq!(
            get_apid_for_tag(0, "snake_case2"),
            DltChar4::from_buf(b"sna1") // snac -> exists -> add numbers...
        );
        assert_eq!(
            get_apid_for_tag(1, "snake_case3"),
            DltChar4::from_buf(b"snac") // different namespace
        );

        assert_eq!(
            get_apid_for_tag(0, "CamelBaseAllGood"),
            DltChar4::from_buf(b"CBAG")
        );
        assert_eq!(
            get_apid_for_tag(0, "CamelBaseAll"),
            DltChar4::from_buf(b"CaBA")
        );
    }

    pub fn get_first_message(
        file_ext: &str,
        reader: impl BufRead + Seek,
        namespace: u32,
    ) -> Option<DltMessage> {
        let mut it = get_dlt_message_iterator(file_ext, 0, reader, namespace, None, None, None);
        it.next()
    }

    /// return the first DltMessage from the first read_size bytes in the file provided
    ///
    /// Reads read_size bytes into a buf and searches for the first DltMessage there
    pub fn get_first_message_from_file(
        file_ext: &str,
        file: &mut std::fs::File,
        read_size: usize,
        namespace: u32,
    ) -> Option<DltMessage> {
        let mut buf = vec![0u8; read_size];
        let res = file.read(&mut buf);
        match res {
            Ok(res) => get_first_message(
                file_ext,
                BufReader::with_capacity(read_size, std::io::Cursor::new(&buf[0..res])),
                namespace,
            ),
            _ => None,
        }
    }

    #[test]
    fn get_dlt_message_it() {
        // todo provide some real test data to see whether proper it is returned!
        let mut it_asc = get_dlt_message_iterator(
            "asc",
            0,
            std::io::Cursor::new(&[] as &[u8]),
            get_new_namespace(),
            None,
            None,
            None,
        );
        assert!(it_asc.next().is_none());

        let mut it_dlt = get_dlt_message_iterator(
            "dlt",
            0,
            std::io::Cursor::new(&[] as &[u8]),
            get_new_namespace(),
            None,
            None,
            None,
        );
        assert!(it_dlt.next().is_none());
    }

    #[test]
    fn get_first_message_tests() {
        // create a test file with 1M DLT messages:
        let mut file = NamedTempFile::new().unwrap();
        let file_path = String::from(file.path().to_str().unwrap());

        let persisted_msgs: DltMessageIndexType = 10;
        let ecus = [
            DltChar4::from_buf(b"ECU1"),
            DltChar4::from_buf(b"ECU2"),
            DltChar4::from_buf(b"ECU3"),
        ];
        for i in 0..persisted_msgs {
            let sh = DltStorageHeader {
                secs: (1640995200000000 / US_PER_SEC) as u32, // 1.1.22, 00:00:00 as GMT
                micros: 0,
                ecu: ecus[i as usize % ecus.len()],
            };
            let standard_header = DltStandardHeader {
                htyp: 1 << 5, // vers 1
                mcnt: (i % 256) as u8,
                len: 4,
            };

            let m = DltMessage::from_headers(i, sh, standard_header, &[], vec![]);
            m.to_write(&mut file).unwrap(); // will persist with timestamp
        }
        file.flush().unwrap();
        let file_len = std::fs::metadata(&file_path).unwrap().len();

        let namespace = get_new_namespace();

        let m1 = get_first_message(
            "dlt",
            BufReader::with_capacity(512 * 1024, File::open(&file_path).unwrap()),
            namespace,
        );
        assert!(m1.is_some());
        assert_eq!(m1.unwrap().mcnt(), 0);

        let m1 = get_first_message_from_file(
            "dlt",
            &mut File::open(&file_path).unwrap(),
            512 * 1024,
            namespace,
        );
        assert!(m1.is_some());
        assert_eq!(m1.unwrap().mcnt(), 0);

        let dfi = get_dlt_infos_from_file(
            "dlt",
            &mut File::open(&file_path).unwrap(),
            512 * 1024,
            namespace,
        )
        .unwrap();
        assert_eq!(dfi.read_size, 512 * 1024);
        assert_eq!(dfi.namespace, namespace);
        assert!(dfi.first_msg.is_some());
        assert!(dfi.file_len.is_some());
        assert_eq!(dfi.file_len.unwrap(), file_len);
        assert!(dfi
            .ecus_seen
            .symmetric_difference(&HashSet::from_iter(ecus.iter().cloned()))
            .collect::<HashSet<_>>()
            .is_empty());
    }

    #[test]
    fn sync_sender_send_delay_if_full_1() {
        let (tx, rx) = sync_channel(1);
        let send_result = sync_sender_send_delay_if_full(42, &tx);
        assert!(send_result.is_ok());
        assert_eq!(rx.recv().unwrap(), 42);

        drop(rx);
        // now the send should fail even if the channel is empty
        let send_result = sync_sender_send_delay_if_full(43, &tx);
        assert!(send_result.is_err());

        let (tx, rx) = sync_channel(1);
        let send_result = sync_sender_send_delay_if_full(42, &tx);
        assert!(send_result.is_ok());
        drop(rx);
        // now the send should fail and not block/delay
        let send_result = sync_sender_send_delay_if_full(43, &tx);
        assert!(send_result.is_err());

        // difficult to test the case where the channel is full.
        // would need to spawn a thread to read from the channel but even then the
        // detection whether a sleep did occur is not easy.
    }

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
    fn test_contains_regex_chars() {
        assert!(!contains_regex_chars("ecu"));
        assert!(contains_regex_chars("ecu.*"));
        assert!(contains_regex_chars("ecu\\d+"));
        assert!(contains_regex_chars("ecu1|ecu2"));
        assert!(!contains_regex_chars("123"));
        assert!(contains_regex_chars("[]"));
        assert!(contains_regex_chars("()"));
        assert!(contains_regex_chars("\\\\"));
        assert!(contains_regex_chars("!="));
        assert!(contains_regex_chars("<>"));
        assert!(contains_regex_chars(","));
    }

    #[test]
    fn is_non_printable_char_wo_rnt_1() {
        assert!(!is_non_printable_char_wo_rnt(&b'A'));
        assert!(!is_non_printable_char_wo_rnt(&b'z'));
        assert!(!is_non_printable_char_wo_rnt(&b' '));
        assert!(!is_non_printable_char_wo_rnt(&0x7e));
        assert!(is_non_printable_char_wo_rnt(&0x1f));
        assert!(is_non_printable_char_wo_rnt(&0x7f));
        assert!(is_non_printable_char_wo_rnt(&0x00));
        assert!(!is_non_printable_char_wo_rnt(&b'\r'));
        assert!(!is_non_printable_char_wo_rnt(&b'\n'));
        assert!(!is_non_printable_char_wo_rnt(&b'\t'));
    }

    #[test]
    fn buf_as_ascii() {
        let mut s = String::new();
        let times_replaced = buf_as_printable_ascii_to_write(&mut s, &[], '-').unwrap();
        assert_eq!(s.len(), 0);
        assert_eq!(times_replaced, 0);

        let times_replaced = buf_as_printable_ascii_to_write(
            &mut s,
            &[
                0x00_u8, 0x1f, 0x20, 0x40, 0x7c, 0x7e, 0x7f, 0xff, b'\t', b'\r', b'\n', b' ',
            ],
            '-',
        )
        .unwrap();
        assert_eq!(s, "-- @|~----- ");
        assert_eq!(times_replaced, 4);
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

        let mut v = Vec::<u8>::new();
        buf_as_hex_to_io_write(&mut v, &[0x0f_u8, 0x00_u8, 0xff_u8]).unwrap();
        assert_eq!(std::str::from_utf8(v.as_slice()).unwrap(), "0f 00 ff");
    }

    #[test]
    fn hex_to_bytes1() {
        assert!(hex_to_bytes("").is_none());
        assert!(hex_to_bytes("1").is_none());
        assert_eq!(hex_to_bytes("02").unwrap(), vec![0x2]);
        assert_eq!(hex_to_bytes("12").unwrap(), vec![0x12]);
        assert!(hex_to_bytes("123").is_none());
        assert!(hex_to_bytes("12 ").is_none());
        assert!(hex_to_bytes("12 3").is_none());
        assert_eq!(hex_to_bytes("12 34").unwrap(), vec![0x12, 0x34]);
        assert!(hex_to_bytes("12 34 ").is_none());
        assert!(hex_to_bytes("12 34 5").is_none());
        assert_eq!(hex_to_bytes("ff dd").unwrap(), vec![0xff, 0xdd]);
        assert_eq!(hex_to_bytes("fF Dd").unwrap(), vec![0xff, 0xdd]);
        assert!(hex_to_bytes("gh").is_none());
        assert!(hex_to_bytes("gh 10 23 ij").is_none());
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

        let (parse_lc_out, sort_in) = sync_channel(2048);
        let (sort_out, rx) = channel();

        let (lcs_r, lcs_w) = evmap::new::<LifecycleId, LifecycleItem>();

        let _lcs_w =
            parse_lifecycles_buffered_from_stream(lcs_w, parse_lc_in, &|m| parse_lc_out.send(m));
        assert_eq!(1, lcs_r.len(), "wrong number of lcs!");
        drop(parse_lc_out);

        let res = buffer_sort_messages(sort_in, &|m| sort_out.send(m), &lcs_r, 3, 2_000_000);
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

        let res = buffer_sort_messages(sort_in, &|m| sort_out.send(m), &lcs_r, 3, 2_000_000);
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
        assert!(lc.update(&mut m2, 60 * US_PER_SEC).is_none());

        tx.send(m2).unwrap();
        drop(tx);

        let (sort_out, rx) = channel();

        let (lcs_r, mut lcs_w) = evmap::new::<LifecycleId, LifecycleItem>();
        lcs_w.insert(lc.id(), lc);
        lcs_w.refresh();

        let res = buffer_sort_messages(sort_in, &|m| sort_out.send(m), &lcs_r, 3, 2_000_000);
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
