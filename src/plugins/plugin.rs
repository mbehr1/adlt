use std::fmt;

use crate::dlt::DltMessage;

pub trait Plugin {
    fn name(&self) -> &str;
    fn enabled(&self) -> bool;

    /// process a single msg
    /// this can modify the msg (and is expected for most plugins)
    ///
    /// a plugin can modify e.g.
    /// - msg.timestamp_dms
    /// - msg.reception_time_us
    /// - payload: msg.set_payload_text(...)
    ///
    /// returns false if the msg should be droppped (i.e. not forwarded) and true in all other cases
    fn process_msg(&mut self, msg: &mut DltMessage) -> bool;
}

impl fmt::Debug for dyn Plugin + Send {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Plugin")
            .field("name", &self.name())
            .field("enabled", &self.enabled())
            .finish()
    }
}
