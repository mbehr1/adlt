use std::{
    any::Any,
    fmt,
    sync::{Arc, RwLock},
};

use crate::dlt::DltMessage;

pub trait Plugin {
    fn name(&self) -> &str;
    fn enabled(&self) -> bool;

    fn state(&self) -> Arc<RwLock<PluginState>>;

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

type ApplyCommandFn = fn(
    internal_data: &Option<Box<dyn Any + Send + Sync>>,
    cmd: &str,
    params: Option<&serde_json::Map<String, serde_json::Value>>,
    cmdCtx: Option<&serde_json::Map<String, serde_json::Value>>,
) -> bool;

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
///
/// Two other members are used to interact with a plugin:
/// - apply_command : optional fn that will be called e.g. from remote plugin_cmd. Current use-case: FileTransferPlugin "save"
/// - internal_data: optional data that the apply_command function can access.
pub struct PluginState {
    pub generation: u32, // 0 initial, 1 = 1st,...
    pub value: serde_json::Value,
    pub apply_command: Option<ApplyCommandFn>,
    pub internal_data: Option<Box<dyn Any + Send + Sync>>,
}

impl fmt::Debug for PluginState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PluginState")
            .field("generation", &self.generation)
            .field("value", &self.value)
            .field("apply_command", &self.apply_command.is_some())
            .field("internal_data", &self.internal_data.is_some())
            .finish()
    }
}

impl Default for PluginState {
    fn default() -> Self {
        PluginState {
            generation: 0,
            value: serde_json::Value::Null,
            apply_command: None,
            internal_data: None,
        }
    }
}
