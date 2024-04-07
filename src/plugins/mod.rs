pub mod anonymize;
pub mod can;
pub mod export;
pub mod factory;
pub mod file_transfer;
pub mod muniic;
pub mod non_verbose;
pub mod plugin;
pub mod rewrite;
pub mod someip;

use crate::{dlt::DltMessage, SendMsgFnReturnType};
use plugin::Plugin;

use std::sync::mpsc::{Receiver, SendError};

/// read all msgs from inflow, have all plugins process the msg.
/// if any plugin returns false processing of that msg is stopped and the msg
/// is not forwarded to outflow. Otherwise msg is forwarded to outflow.
pub fn plugins_process_msgs<F: Fn(DltMessage) -> SendMsgFnReturnType>(
    inflow: Receiver<DltMessage>,
    outflow: &F,
    mut plugins_active: Vec<Box<dyn Plugin + Send>>,
) -> Result<Vec<Box<dyn Plugin + Send>>, SendError<DltMessage>> {
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
            outflow(msg)?;
        }
    }
    Ok(plugins_active)
}

#[cfg(test)]
mod tests {
    use crate::utils::eac_stats::EacStats;

    use super::{factory::get_plugin, *};
    use serde_json::json;
    use std::sync::mpsc::channel;

    #[test]
    fn end_and_return_plugins() {
        let mut eac_stats = EacStats::default();
        let plugin = get_plugin(
            json!({"name":"FileTransfer"}).as_object().unwrap(),
            &mut eac_stats,
        )
        .unwrap();

        let plugins_active = vec![plugin];

        let (to_fn, inflow) = channel();
        let (outflow, _from_fn) = channel();

        let t1 = std::thread::spawn(move || {
            plugins_process_msgs(inflow, &|m| outflow.send(m), plugins_active)
        });
        drop(to_fn);
        let plugins_returned = t1.join().unwrap().unwrap();

        assert_eq!(plugins_returned.len(), 1);
    }
}
