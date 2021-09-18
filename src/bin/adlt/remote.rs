use slog::{info}; // crit, debug, info, warn, error};

/// provide remote server functionalities
pub fn remote(log: slog::Logger, sub_m: &clap::ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    // we do use log only if for local websocket related issues
    // for the remote part we do use an own logger logging to the websocket itself todo
    let port = sub_m.value_of("port").unwrap().parse::<u16>()?;
    info!(log, "remote starting"; "port" => port);

    info!(log, "remote stopped"; "port" => port);
    Ok(())
}