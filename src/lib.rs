pub mod lifecycle;
pub mod utils;

pub fn name() -> &'static str {
    "adlt"
}
pub fn version() -> (u32, u32, u32) {
    (0, 0, 1)
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Copy)]
pub struct DltChar4 {
    char4: [u8; 4],
}

#[derive(Debug)]
pub struct DltMessage {
    time_stamp: u64,    // us
    received_time: u64, // us since 1970
    ecu: DltChar4,
    lifecycle: u32, // 0 = none, otherwise the id of an interims(!) lifecycle
}

static NEXT_TEST_TIMESTAMP: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

impl DltMessage {
    pub fn for_test() -> DltMessage {
        let time_stamp = NEXT_TEST_TIMESTAMP.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        DltMessage {
            time_stamp,
            received_time: 100_000 + time_stamp,
            ecu: DltChar4 {
                char4: [0x41, 0x42, 0x43, 0x44],
            },
            lifecycle: 0,
        }
    }
    pub fn interims_lifecycle_id(&self) -> u32 {
        self.lifecycle
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn mut_vec_elems() {
        let mut buffer = vec![1, 2, 3, 5, 8];
        let parts = buffer.as_mut_slice();
        parts[3] = 4;
        parts[4] = 5;
        let p0: &mut i32 = &mut parts[0];
        *p0 = 0;
        assert_eq!(buffer, vec![0, 2, 3, 4, 5], "buffer={:?}", buffer);
    }
    #[test]
    fn mut_two_vec_elems() {
        let mut buffer = vec![1, 2, 3, 5, 8];
        let (last, rest) = buffer.as_mut_slice().split_last_mut().unwrap();
        *last = 5;
        *rest.last_mut().unwrap() = 4;
        assert_eq!(buffer, vec![1, 2, 3, 4, 5], "buffer={:?}", buffer);
    }
}
