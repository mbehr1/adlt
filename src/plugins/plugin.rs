use std::{fmt, sync::Arc};

use crate::dlt::DltMessage;

pub trait Plugin {
    fn name(&self) -> &str;
    fn enabled(&self) -> bool;

    fn state(&self) -> Arc<PluginState>;

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

/// status/state from a plugin. Can be updated and be shared across threads
///
/// The state consists of a json object (value) with at least the members:
/// - name: <name of the plugin>
/// optional:
/// - treeItems: Array of objects with
///  - label:String
///  - children -> json objects with similar structure
///  optional members:
///  - tooltip:String
///  - description:String
///  - iconPath:String (see https://code.visualstudio.com/api/references/icons-in-labels#icon-listing)
///  to ease presentation in a treeview (https://code.visualstudio.com/api/references/vscode-api#TreeItem)
#[derive(Debug)]
pub struct PluginState {
    pub generation: u32, // 0 initial, 1 = 1st,...
    pub value: serde_json::Value,
}

impl Default for PluginState {
    fn default() -> Self {
        PluginState {
            generation: 0,
            value: serde_json::Value::Null,
        }
    }
}
