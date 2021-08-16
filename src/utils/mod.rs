use crate::{lifecycle::Lifecycle, DltMessage};
use std::sync::mpsc::{Receiver, Sender};

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

#[cfg(test)]
mod tests {
    use crate::utils::*;
    use std::sync::mpsc::channel;
    //    use std::time::Instant;
    #[test]
    fn buffer_messages() {
        let (tx, rx) = channel();
        const NUMBER_MSGS: usize = 1_000;
        for _ in 0..NUMBER_MSGS {
            tx.send(crate::DltMessage::for_test()).unwrap();
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
            tx.send(crate::DltMessage::for_test()).unwrap();
        }
        // now the first messages should arrive:
        let mut last_time_stamp = 0;
        for i in 0..NUMBER_MSGS {
            let mr = rx2.recv_timeout(std::time::Duration::from_millis(50));
            assert!(mr.is_ok(), "failed to get msg#{}", i);
            let m = mr.unwrap();
            assert!(
                m.time_stamp > last_time_stamp,
                "msg#{} has wrong order/time_stamp! {} vs. exp. > {}",
                i,
                m.time_stamp,
                last_time_stamp
            );
            last_time_stamp = m.time_stamp;
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
                m.time_stamp > last_time_stamp,
                "msg#{} has wrong order/time_stamp! {} vs. exp. > {}",
                NUMBER_MSGS + i,
                m.time_stamp,
                last_time_stamp
            );
            last_time_stamp = m.time_stamp;
        }
        assert!(rx2
            .recv_timeout(std::time::Duration::from_millis(50))
            .is_err());
    }
}
