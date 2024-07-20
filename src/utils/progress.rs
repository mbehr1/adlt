use std::{
    fmt::Debug,
    sync::{
        atomic::{AtomicBool, AtomicU64},
        Arc,
    },
};

pub enum ProgressPoll<T> {
    Progress((u32, u32)), // cur/max
    Done(T),
    Err(()),
}

pub struct ProgressNonAsyncFuture<T> {
    progress: Arc<AtomicU64>,
    shall_cancel: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<T>>,
}

impl<T> Debug for ProgressNonAsyncFuture<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProgressNonAsyncFuture")
            .field("progress", &self.cur_progress())
            .finish()
    }
}

impl<T> ProgressNonAsyncFuture<T> {
    pub fn spawn<F>(f: F) -> ProgressNonAsyncFuture<T>
    where
        F: FnOnce(&dyn Fn(u32, u32), Arc<AtomicBool>) -> T + Send + 'static,
        T: Send + 'static,
    {
        let progress = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let progress_clone = progress.clone();
        let shall_cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let shall_cancel_clone = shall_cancel.clone();
        ProgressNonAsyncFuture {
            progress,
            shall_cancel,
            thread: Some(std::thread::spawn(move || {
                let progress_cb = |cur, max| Self::update_progress(cur, max, &progress_clone);
                f(&progress_cb, shall_cancel_clone)
            })),
        }
    }

    pub fn poll(&mut self) -> ProgressPoll<T> {
        // todo what if thread is already removed from last poll?
        let finished = if let Some(thread) = &self.thread {
            thread.is_finished()
        } else {
            false
        };
        if finished {
            let thread = self.thread.take().unwrap();
            match thread.join() {
                Ok(r) => ProgressPoll::Done(r),
                Err(_e) => ProgressPoll::Err(()),
            }
        } else {
            let cur_prog = self.progress.load(std::sync::atomic::Ordering::Relaxed);
            ProgressPoll::Progress(Self::u64_to_progress(cur_prog))
        }
    }

    /// indicate the async task to cancel
    ///
    /// Afterwards you can wait until poll returns Done or Err
    pub fn cancel(&self) {
        self.shall_cancel
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn cur_progress(&self) -> (u32, u32) {
        Self::u64_to_progress(self.progress.load(std::sync::atomic::Ordering::Relaxed))
    }

    fn update_progress(cur: u32, max: u32, progress: &AtomicU64) {
        progress.store(
            Self::progress_to_u64((cur, max)),
            std::sync::atomic::Ordering::Relaxed,
        )
    }

    fn progress_to_u64(progress: (u32, u32)) -> u64 {
        (progress.0 as u64) | ((progress.1 as u64) << 32)
    }

    fn u64_to_progress(p_u64: u64) -> (u32, u32) {
        ((p_u64 & 0xffff_ffff) as u32, (p_u64 >> 32) as u32)
    }
}

#[cfg(test)]
mod tests {
    use std::time;

    use super::*;

    #[test]
    fn progress_non_async_future() {
        let mut pnaf = ProgressNonAsyncFuture::spawn(|upd_progress, _shall_cancel| {
            upd_progress(0, 100);
            std::thread::sleep(time::Duration::from_millis(10));
            upd_progress(100, 100);
            42
        });
        loop {
            match pnaf.poll() {
                ProgressPoll::Progress((cur, max)) => {
                    println!("progress {}/{}", cur, max);
                    std::thread::sleep(time::Duration::from_millis(1));
                }
                ProgressPoll::Done(r) => {
                    println!("result: {:?}, last progress:{:?}", r, pnaf.cur_progress());
                    break;
                }
                _ => {
                    break;
                }
            }
        }
    }

    #[test]
    fn progress_non_async_future_cancel() {
        let mut pnaf = ProgressNonAsyncFuture::spawn(|upd_progress, shall_cancel| {
            upd_progress(0, 100);
            while !shall_cancel.load(std::sync::atomic::Ordering::Relaxed) {
                std::thread::sleep(time::Duration::from_millis(10));
            }
            upd_progress(99, 100);
            42
        });
        loop {
            match pnaf.poll() {
                ProgressPoll::Progress((cur, max)) => {
                    println!("progress {}/{}", cur, max);
                    std::thread::sleep(time::Duration::from_millis(1));
                    pnaf.cancel();
                }
                ProgressPoll::Done(r) => {
                    println!("result: {:?}, last progress:{:?}", r, pnaf.cur_progress());
                    break;
                }
                _ => {
                    break;
                }
            }
        }
    }
}
