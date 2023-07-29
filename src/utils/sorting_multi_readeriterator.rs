use std::{cmp::Ordering, collections::BinaryHeap};

use crate::dlt::{DltMessage, DltMessageIndexType};

struct MinHeapEntry<'a> {
    m: DltMessage,
    it: Box<dyn Iterator<Item = DltMessage> + 'a>,
}

impl<'a> Ord for MinHeapEntry<'a> {
    fn cmp(&self, other: &Self) -> Ordering {
        // self.m.reception_time_us.cmp(&other.m.reception_time_us) // regular, we do need reverse
        other.m.reception_time_us.cmp(&self.m.reception_time_us) // reversed
    }
}

impl<'a> PartialOrd for MinHeapEntry<'a> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl<'a> PartialEq for MinHeapEntry<'a> {
    fn eq(&self, other: &Self) -> bool {
        self.m.reception_time_us == other.m.reception_time_us
    }
}
impl<'a> Eq for MinHeapEntry<'a> {}

/// Iterator that processes other iterators in "parallel"
/// i.e. it merges the msgs by reception time.
/// Every single iterator needs to provide a sorted stream of DltMessages
/// but they can be recorded "in parallel". The main use case is the merge
/// of e.g. multiple CAN or DLT channels from different ECUs.
///
/// *Note:* This iterator is significantly slower than a regular single iterator.
/// It uses a min-heap to read from all parallel channels one message each and returns
/// the oldest (smallest) one first.
pub struct SortingMultiReaderIterator<'a> {
    // its: Vec<Box<dyn Iterator<Item = DltMessage> + 'a>>,
    pub index: DltMessageIndexType,
    min_heap: BinaryHeap<MinHeapEntry<'a>>,
}

impl<'a> SortingMultiReaderIterator<'a> {
    pub fn new(
        start_index: DltMessageIndexType,
        its: Vec<Box<dyn Iterator<Item = DltMessage> + 'a>>,
    ) -> SortingMultiReaderIterator<'a> {
        let mut min_heap = BinaryHeap::with_capacity(its.len());
        for mut it in its.into_iter() {
            if let Some(m) = it.next() {
                min_heap.push(MinHeapEntry { m, it });
            }
        }
        SortingMultiReaderIterator {
            index: start_index,
            min_heap,
        }
    }
    /// return a new SortingMultiReaderIterator or a single iterator if just
    /// one iterator is passed.
    ///
    /// This is to avoid any runtime overhead for single iterator case.
    /// **Note:** Take care that the start_index is ignored for the single iterator case!
    pub fn new_or_single_it(
        start_index: DltMessageIndexType,
        its: Vec<Box<dyn Iterator<Item = DltMessage> + 'a>>,
    ) -> Box<dyn Iterator<Item = DltMessage> + 'a> {
        if its.len() == 1 {
            Box::new(its.into_iter().next().unwrap())
        } else {
            Box::new(SortingMultiReaderIterator::new(start_index, its))
        }
    }
}

impl<'a> Iterator for SortingMultiReaderIterator<'a> {
    type Item = DltMessage;
    fn next(&mut self) -> Option<Self::Item> {
        let heap_entry = self.min_heap.pop();
        if let Some(heap_entry) = heap_entry {
            let mut m = heap_entry.m;
            m.index = self.index;
            self.index += 1;
            let mut it = heap_entry.it;
            if let Some(m) = it.next() {
                self.min_heap.push(MinHeapEntry { m, it })
            }
            Some(m)
        } else {
            None
        }
    }
}

/// Iterator that sequentially chains other iterators of DltMessages
///
/// Similar like iter::chain or chain! but updates the msg.index as well
///
/// It doesn't take a vec of iterators to avoid the need to e.g. open all files in parallel.
///
/// *Note:* This is roughly 10% slower than the single iterator (run dlt_benches for details).
/// Use: `new_or_single_it` to avoid the overhead for a single iterator case.
pub struct SequentialMultiIterator<'a, O> {
    pub index: DltMessageIndexType,
    its: O,
    cur_it: Option<Box<dyn Iterator<Item = DltMessage> + 'a>>,
}
impl<'a, O: Iterator + 'a> SequentialMultiIterator<'a, O> {
    pub fn new(start_index: DltMessageIndexType, mut its: O) -> SequentialMultiIterator<'a, O>
    where
        O: Iterator<Item = Box<dyn Iterator<Item = DltMessage> + 'a>>,
    {
        let cur_it = its.next();
        SequentialMultiIterator {
            index: start_index,
            its,
            cur_it,
        }
    }

    /// return a new SequentialMultiIterator or a single iterator if the
    /// size_hint of the passed its is (1, Some(1)).
    ///
    /// This is to avoid any runtime overhead for single iterator case.
    /// **Note:** Take care that the start_index is ignored for the single iterator case!
    pub fn new_or_single_it(
        start_index: DltMessageIndexType,
        mut its: O,
    ) -> Box<dyn Iterator<Item = DltMessage> + 'a>
    where
        O: Iterator<Item = Box<dyn Iterator<Item = DltMessage> + 'a>>,
    {
        if its.size_hint() == (1, Some(1)) {
            if let Some(it) = its.next() {
                return Box::new(it);
            }
        }
        Box::new(SequentialMultiIterator::new(start_index, its))
    }
}

impl<'a, O: Iterator<Item = Box<dyn Iterator<Item = DltMessage> + 'a>>> Iterator
    for SequentialMultiIterator<'a, O>
{
    type Item = DltMessage;
    fn next(&mut self) -> Option<Self::Item> {
        if let Some(cur_it) = self.cur_it.as_mut() {
            let m = cur_it.next();
            if let Some(mut msg) = m {
                msg.index = self.index;
                self.index += 1;
                Some(msg)
            } else {
                self.cur_it = self.its.next();
                self.next()
            }
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dlt::DLT_MAX_STORAGE_MSG_SIZE;
    use crate::utils::asc2dltmsgiterator::asc_parse_date;
    use crate::utils::{get_dlt_message_iterator, get_new_namespace, LowMarkBufReader};
    use std::fs::File;

    #[test]
    fn test_single_it() {
        let buf_reader = LowMarkBufReader::new(
            File::open("./tests/can_example1.asc").unwrap(),
            512 * 1024usize,
            DLT_MAX_STORAGE_MSG_SIZE,
        );
        let it1 =
            get_dlt_message_iterator("asc", 0, buf_reader, get_new_namespace(), None, None, None);
        let mit = SortingMultiReaderIterator::new(0, vec![it1]);
        let mut iterated_msgs = 0;
        for m in mit {
            assert_eq!(m.index, iterated_msgs);
            iterated_msgs += 1;
        }
        assert_eq!(101, iterated_msgs);
    }

    #[test]
    fn test_par_multiple_it() {
        let buf_reader1 = LowMarkBufReader::new(
            File::open("./tests/can_example1.asc").unwrap(),
            512 * 1024usize,
            DLT_MAX_STORAGE_MSG_SIZE,
        );
        let namespace = get_new_namespace();
        let it1 = get_dlt_message_iterator("asc", 0, buf_reader1, namespace, None, None, None);

        let buf_reader2 = LowMarkBufReader::new(
            File::open("./tests/can_example1c.asc").unwrap(),
            512 * 1024usize,
            DLT_MAX_STORAGE_MSG_SIZE,
        );
        let it2 = get_dlt_message_iterator("asc", 0, buf_reader2, namespace, None, None, None);

        let mit = SortingMultiReaderIterator::new(0, vec![it2, it1]);
        let mut iterated_msgs = 0;
        let mut last_reception_time_us = 0;
        for m in mit {
            // println!("#{} {} {}", m.index, m.ecu, m.reception_time_us);
            assert_eq!(m.index, iterated_msgs);
            iterated_msgs += 1;
            assert!(m.reception_time_us >= last_reception_time_us);
            last_reception_time_us = m.reception_time_us;
        }
        assert_eq!(101 + 3, iterated_msgs);
    }

    #[test]
    fn test_ser_multiple_it_optimized() {
        let files = vec!["./tests/can_example1.asc"];
        let namespace = get_new_namespace();
        let its = files.into_iter().map(|file_name| {
            let buf_reader = LowMarkBufReader::new(
                File::open(file_name).unwrap(),
                512 * 1024usize,
                DLT_MAX_STORAGE_MSG_SIZE,
            );
            get_dlt_message_iterator("asc", 0, buf_reader, namespace, None, None, None)
        });

        assert_eq!((1, Some(1)), its.size_hint());

        let mit = SequentialMultiIterator::new_or_single_it(0, its);
        let mut iterated_msgs = 0;
        for m in mit {
            assert_eq!(m.index, iterated_msgs);
            iterated_msgs += 1;
        }
        assert_eq!(101, iterated_msgs);
    }

    #[test]
    fn test_ser_multiple_it() {
        let buf_reader1 = LowMarkBufReader::new(
            File::open("./tests/can_example1.asc").unwrap(),
            512 * 1024usize,
            DLT_MAX_STORAGE_MSG_SIZE,
        );
        let namespace = get_new_namespace();
        let it1 = get_dlt_message_iterator("asc", 0, buf_reader1, namespace, None, None, None);

        let buf_reader2 = LowMarkBufReader::new(
            File::open("./tests/can_example1c.asc").unwrap(),
            512 * 1024usize,
            DLT_MAX_STORAGE_MSG_SIZE,
        );
        let it2 = get_dlt_message_iterator("asc", 0, buf_reader2, namespace, None, None, None);

        let mit = SequentialMultiIterator::new(0, vec![it2, it1].into_iter());
        let mut iterated_msgs = 0;
        for m in mit {
            assert_eq!(m.index, iterated_msgs);
            iterated_msgs += 1;
        }
        assert_eq!(101 + 3, iterated_msgs);
    }

    #[test]
    fn test_ser_multiple_it2() {
        let files = vec!["./tests/can_example1.asc", "./tests/can_example1c.asc"];
        let namespace = get_new_namespace();
        let its = files.into_iter().map(|file_name| {
            let buf_reader = LowMarkBufReader::new(
                File::open(file_name).unwrap(),
                512 * 1024usize,
                DLT_MAX_STORAGE_MSG_SIZE,
            );
            get_dlt_message_iterator("asc", 0, buf_reader, namespace, None, None, None)
        });

        let mit = SequentialMultiIterator::new(0, its);
        let mut iterated_msgs = 0;
        for m in mit {
            assert_eq!(m.index, iterated_msgs);
            iterated_msgs += 1;
        }
        assert_eq!(101 + 3, iterated_msgs);
    }

    #[test]
    fn test_ser_multiple_it_non_overlap() {
        let files = vec!["./tests/can_example2a.asc"];
        let namespace = get_new_namespace();
        let first_reception_time_us = asc_parse_date("Thu Apr 20 10:25:26 AM 2023")
            .ok()
            .map(|a| a.timestamp_micros() as u64);

        let its = files.into_iter().map(|file_name| {
            let buf_reader = LowMarkBufReader::new(
                File::open(file_name).unwrap(),
                512 * 1024usize,
                DLT_MAX_STORAGE_MSG_SIZE,
            );
            get_dlt_message_iterator(
                "asc",
                0,
                buf_reader,
                namespace,
                first_reception_time_us,
                None,
                None,
            )
        });
        let mit_2a = SequentialMultiIterator::new(0, its);

        let files = vec!["./tests/can_example2b.asc"];
        let namespace = get_new_namespace();
        let its = files.into_iter().map(|file_name| {
            let buf_reader = LowMarkBufReader::new(
                File::open(file_name).unwrap(),
                512 * 1024usize,
                DLT_MAX_STORAGE_MSG_SIZE,
            );
            get_dlt_message_iterator(
                "asc",
                0,
                buf_reader,
                namespace,
                first_reception_time_us,
                None,
                None,
            )
        });
        let mit_2b = SequentialMultiIterator::new(0, its);

        let mut mit_2concat = mit_2a.chain(mit_2b);

        // those files don't overlap. so we expect them to have the same times as if read as single files
        let files = vec!["./tests/can_example2a.asc", "./tests/can_example2b.asc"];
        let namespace = get_new_namespace();
        let first_reception_time_us = asc_parse_date("Thu Apr 20 10:25:26 AM 2023")
            .ok()
            .map(|a| a.timestamp_micros() as u64);
        let its = files.into_iter().map(|file_name| {
            let buf_reader = LowMarkBufReader::new(
                File::open(file_name).unwrap(),
                512 * 1024usize,
                DLT_MAX_STORAGE_MSG_SIZE,
            );
            get_dlt_message_iterator(
                "asc",
                0,
                buf_reader,
                namespace,
                first_reception_time_us,
                None,
                None,
            )
        });

        let mit = SequentialMultiIterator::new(0, its);
        let mut iterated_msgs = 0;
        let mut expected_timestamps = [
            0_u32,
            6466,
            777746, /* 10:25:26+77,7746 */
            770000,
            777770, /* 10:26:43 + 0.777 = 10:25:26 + 1:17 + 0.777 = 10:25:26 + 77.7770  */
            770000 + 2266406,
        ]
        .into_iter();
        for m in mit {
            assert_eq!(m.index, iterated_msgs);
            iterated_msgs += 1;

            assert_eq!(
                m.timestamp_dms,
                expected_timestamps.next().unwrap(),
                "timestamp mismatch for msg {:?}",
                m
            );
            // reception time should be equal to as if read as single files (they are absolute)
            let m2 = mit_2concat.next().unwrap();
            assert_eq!(m.reception_time_us, m2.reception_time_us);
        }
        assert_eq!(6, iterated_msgs);
    }
}
