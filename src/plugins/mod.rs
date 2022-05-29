pub mod anonymize;
pub mod can;
pub mod factory;
pub mod file_transfer;
pub mod non_verbose;
pub mod plugin;
pub mod rewrite;
pub mod someip;

use crate::dlt::DltMessage;
use plugin::Plugin;

/// read all msgs from inflow, have all plugins process the msg.
/// if any plugin returns false processing of that msg is stopped and the msg
/// is not forwarded to outflow. Otherwise msg is forwarded to outflow.
pub fn plugins_process_msgs(
    inflow: std::sync::mpsc::Receiver<DltMessage>,
    outflow: std::sync::mpsc::Sender<DltMessage>,
    mut plugins_active: Vec<Box<dyn Plugin + Send>>,
) -> Result<Vec<Box<dyn Plugin + Send>>, std::sync::mpsc::SendError<DltMessage>> {
    for mut msg in inflow {
        // pass the message through the plugins (sequentially, not parallel)
        let mut forward_msg = true;
        for plugin in &mut plugins_active {
            let plugin = plugin.as_mut();
            if !plugin.process_msg(&mut msg) {
                forward_msg = false;
                break;
            }
        }
        if forward_msg {
            outflow.send(msg)?;
        }
    }
    Ok(plugins_active)
}
