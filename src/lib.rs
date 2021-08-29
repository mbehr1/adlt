pub mod dlt;
pub mod filter;
pub mod lifecycle;
pub mod utils;

pub fn name() -> &'static str {
    "adlt"
}
pub fn version() -> (u32, u32, u32) {
    (0, 0, 1)
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
