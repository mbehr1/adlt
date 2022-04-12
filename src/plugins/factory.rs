use super::{plugin::Plugin, rewrite::RewritePlugin, someip::SomeipPlugin};

pub fn get_plugin(
    config: &serde_json::Map<String, serde_json::Value>,
) -> Option<Box<dyn Plugin + Send>> {
    let name = match &config["name"] {
        serde_json::Value::String(s) => Some(s),
        _ => None,
    };
    let enabled = match &config["enabled"] {
        serde_json::Value::Bool(b) => *b,
        serde_json::Value::Null => true,
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
