extern crate lazy_static;

pub mod dlt;
pub mod filter;
pub mod lifecycle;
pub mod plugins;
pub mod utils;

pub fn name() -> &'static str {
    "adlt"
}
pub fn version() -> (u32, u32, u32) {
    const VERSION_MAJOR: &str = env!("CARGO_PKG_VERSION_MAJOR");
    const VERSION_MINOR: &str = env!("CARGO_PKG_VERSION_MINOR");
    const VERSION_PATCH: &str = env!("CARGO_PKG_VERSION_PATCH");
    (
        VERSION_MAJOR.parse::<u32>().unwrap_or(0),
        VERSION_MINOR.parse::<u32>().unwrap_or(0),
        VERSION_PATCH.parse::<u32>().unwrap_or(0),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lib_name_version() {
        const NAME: &str = env!("CARGO_PKG_NAME");
        assert_eq!(NAME, name());
        const VERSION: &str = env!("CARGO_PKG_VERSION");
        let (major, minor, patch) = version();
        assert_eq!(VERSION, format!("{}.{}.{}", major, minor, patch));
    }

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
