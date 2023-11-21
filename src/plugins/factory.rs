use crate::utils::eac_stats::EacStats;

use super::{
    can::CanPlugin, file_transfer::FileTransferPlugin, muniic::MuniicPlugin,
    non_verbose::NonVerbosePlugin, plugin::Plugin, rewrite::RewritePlugin, someip::SomeipPlugin,
};

pub fn get_plugin(
    config: &serde_json::Map<String, serde_json::Value>,
    eac_stats: &mut EacStats,
) -> Option<Box<dyn Plugin + Send>> {
    let name = match &config.get("name") {
        Some(serde_json::Value::String(s)) => Some(s),
        _ => None,
    };
    let enabled = match &config.get("enabled") {
        Some(serde_json::Value::Bool(b)) => *b,
        None | Some(serde_json::Value::Null) => true,
        _ => false,
    };

    if enabled {
        if let Some(name) = name {
            let name = name.as_str();

            return match name {
                "SomeIp" => {
                    let plugin = SomeipPlugin::from_json(config);
                    if let Ok(plugin) = plugin {
                        Some(Box::new(plugin))
                    } else {
                        // todo log error properly
                        println!("plugin:{} got err {:?}", name, plugin.unwrap_err());
                        None
                    }
                }
                "Rewrite" => {
                    let plugin = RewritePlugin::from_json(config);
                    if let Ok(plugin) = plugin {
                        Some(Box::new(plugin))
                    } else {
                        println!("plugin:{} got err {:?}", name, plugin.unwrap_err());
                        None
                    }
                }
                "NonVerbose" => {
                    let plugin = NonVerbosePlugin::from_json(config, eac_stats);
                    if let Ok(plugin) = plugin {
                        Some(Box::new(plugin))
                    } else {
                        println!("plugin:{} got err {:?}", name, plugin.unwrap_err());
                        None
                    }
                }
                "CAN" => {
                    let plugin = CanPlugin::from_json(config);
                    if let Ok(plugin) = plugin {
                        Some(Box::new(plugin))
                    } else {
                        // todo log error properly
                        println!("plugin:{} got err {:?}", name, plugin.unwrap_err());
                        None
                    }
                }
                "FileTransfer" => {
                    let plugin = FileTransferPlugin::from_json(config);
                    if let Ok(plugin) = plugin {
                        Some(Box::new(plugin))
                    } else {
                        // todo log error properly
                        println!("plugin:{} got err {:?}", name, plugin.unwrap_err());
                        None
                    }
                }
                "Muniic" => {
                    let plugin = MuniicPlugin::from_json(config);
                    if let Ok(plugin) = plugin {
                        Some(Box::new(plugin))
                    } else {
                        // todo log error properly
                        println!("plugin:{} got err {:?}", name, plugin.unwrap_err());
                        None
                    }
                }
                _ => {
                    println!(
                        "got enabled not supported/unknown plugin with name:{}",
                        name
                    );
                    None
                }
            };
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn valid() {
        let mut eac_stats = EacStats::default();
        let plugin = get_plugin(
            json!({"name":"FileTransfer"}).as_object().unwrap(),
            &mut eac_stats,
        )
        .unwrap();
        // default enabled
        assert!(plugin.enabled());
    }

    #[test]
    fn valid2() {
        let mut eac_stats = EacStats::default();
        let plugin = get_plugin(
            json!({"name":"FileTransfer", "enabled":false})
                .as_object()
                .unwrap(),
            &mut eac_stats,
        );
        // disabled plugins are not loaded/provided
        assert!(plugin.is_none());
    }

    #[test]
    fn invalid() {
        let mut eac_stats = EacStats::default();
        assert!(get_plugin(json!({}).as_object().unwrap(), &mut eac_stats).is_none());

        assert!(get_plugin(json!({"name":false}).as_object().unwrap(), &mut eac_stats).is_none());
    }
}
