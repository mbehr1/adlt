use chrono::{Local, TimeZone};
use clap::{Arg, Command};
use glob::{glob_with, MatchOptions};
use slog::{debug, error, info, warn, Drain};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fs::File,
    io::{prelude::*, BufWriter},
    sync::mpsc::sync_channel,
    time::Instant,
};
use tempfile::TempDir;

use adlt::{
    dlt::{DltChar4, DLT_MAX_STORAGE_MSG_SIZE},
    filter::{
        functions::{filters_from_convert_format, filters_from_dlf},
        Char4OrRegex, Filter,
    },
    plugins::{
        anonymize::AnonymizePlugin, can::CanPlugin, file_transfer::FileTransferPlugin,
        muniic::MuniicPlugin, non_verbose::NonVerbosePlugin, plugin::Plugin, plugins_process_msgs,
        rewrite::RewritePlugin, someip::SomeipPlugin,
    },
    utils::{
        buf_as_hex_to_io_write, contains_regex_chars,
        eac_stats::EacStats,
        get_dlt_message_iterator, get_new_namespace,
        seekablechain::SeekableChain,
        sorting_multi_readeriterator::{SequentialMultiIterator, SortingMultiReaderIterator},
        sync_sender_send_delay_if_full,
        unzip::{
            archive_get_path_and_glob, extract_to_dir, is_part_of_multi_volume_archive,
            list_archive_contents, search_dir_for_multi_volume_archive,
        },
        DltFileInfos, LowMarkBufReader,
    },
};

#[derive(Clone, Copy)]
enum OutputStyle {
    Hex,
    Ascii,
    //Mixed,
    HeaderOnly,
    None,
}

#[derive(Debug, Clone)]
struct EacFilter {
    filter: Filter,
}

impl EacFilter {
    /// Parse a filter in the format: "ECU:APID:CTID"
    /// All 3 parts can be regex.
    /// Empty parts are ignored.
    /// e.g. filter for CTID 'TC': "::TC"
    fn from_str(s: &str) -> Result<Self, String> {
        if s.is_empty() {
            return Err("filter condition is missing".to_string());
        }
        let mut parts = s.split(':');
        let ecu = parts.next().unwrap_or_default();
        let apid = parts.next().unwrap_or_default();
        let ctid = parts.next().unwrap_or_default();
        let mut filter = Filter::new(adlt::filter::FilterKind::Positive);
        if !ecu.is_empty() {
            let is_regex = contains_regex_chars(ecu);
            let c4 = Char4OrRegex::from_str(ecu, is_regex);
            match c4 {
                Ok(c4) => {
                    filter.ecu = Some(c4);
                }
                Err(e) => {
                    return Err(format!("failed to parse ecu '{}': {}", ecu, e));
                }
            }
        }
        if !apid.is_empty() {
            let is_regex = contains_regex_chars(apid);
            let c4 = Char4OrRegex::from_str(apid, is_regex);
            match c4 {
                Ok(c4) => {
                    filter.apid = Some(c4);
                }
                Err(e) => {
                    return Err(format!("failed to parse apid '{}': {}", apid, e));
                }
            }
        }
        if !ctid.is_empty() {
            let is_regex = contains_regex_chars(ctid);
            let c4 = Char4OrRegex::from_str(ctid, is_regex);
            match c4 {
                Ok(c4) => {
                    filter.ctid = Some(c4);
                }
                Err(e) => {
                    return Err(format!("failed to parse ctid '{}': {}", ctid, e));
                }
            }
        }
        Ok(EacFilter { filter })
    }
}

pub fn add_subcommand(app: Command) -> Command {
    app.subcommand(
        Command::new("convert").about("Open DLT files and show on console or export to DLT file")
             .arg(
                Arg::new("hex")
                    .short('x')
                    .action(clap::ArgAction::SetTrue)
                    .group("style")
                    .display_order(2)
                    .help("Print DLT file; payload as hex"),
            )
            .arg(
                Arg::new("ascii")
                    .short('a')
                    .action(clap::ArgAction::SetTrue)
                    .group("style")
                    .display_order(1)
                    .help("Print DLT file; payload as ASCII"),
            )
            /* .arg(
                Arg::with_name("mixed")
                    .short("m")
                    .group("style")
                    .display_order(1)
                    .help("print DLT file; payload as ASCII and hex"),
            )*/
            .arg(
                Arg::new("headers")
                    .short('s')
                    .action(clap::ArgAction::SetTrue)
                    .group("style")
                    .display_order(1)
                    .help("Print DLT file; only headers"),
            )
            .arg(
                Arg::new("filter_file")
                .short('f')
                .num_args(1)
                .help("File with filters to apply. Can be in dlt-convert format or dlt-viewer dlf format.")
            )
            .arg(
                Arg::new("filter_eac")
                .short('F')
                .long("eac")
                .action(clap::ArgAction::Set)
                .require_equals(true)
                .num_args(1..)
                .value_parser(EacFilter::from_str)
                .value_delimiter(',')
                .help(r#"Filter for the specified ECU:APID:CTIDs. E.g. --eac=ECU:APID:CTID,ECU2,:APID2 . Ecu, apid, ctid are separated by ':'. Empty ones are ignored. E.g. ':apid' filters for apid only not for ecu. Entries can contain regex chars e.g. --eac=ECU1|ECU2:TC to filter for ecu=ECU1|ECU2 with APID TC. Seperate multiple filter by ','. Warning: powershell needs escaping ("-F=ECU1,ECU2,ECU3:APID3") or the long arg --eac=ECU1,ECU2,ECU3:APID3"#)
            )
            .arg(
                Arg::new("file")
                    .required(true)
                    .num_args(1..)
                    .help("Input DLT files to process. If multiple files are provided they are sorted by their first DLT message reception time. Can contain glob patterns like **/*.dlt"),
            ).arg(
                Arg::new("index_first")
                .short('b')
                .num_args(1)
                .value_parser(clap::value_parser!(adlt::dlt::DltMessageIndexType))
                .help("First message (index) to be handled. Index is from the original file before any filters are applied.")
            ).arg(
                Arg::new("index_last")
                .short('e')
                .num_args(1)
                .value_parser(clap::value_parser!(adlt::dlt::DltMessageIndexType))
                .help("Last message (index) to be handled")
            ).arg(
                Arg::new("filter_lc_ids")
                .short('l')
                .long("lcs")
                .action(clap::ArgAction::Set)
                .require_equals(true)
                .num_args(1..)
                .value_parser(clap::value_parser!(u32))
                .value_delimiter(',')
                .help(r#"Filter for the specified lifecycle ids. E.g. --lcs=1,2,3 . Seperate multiple lifecycles by ','. Warning: powershell needs escaping ("-l=1,2,3") or the long arg --lcs=1,2,3"#)
            ).arg(
                Arg::new("output_file")
                .short('o')
                .num_args(1)
                .help("Output messages in new DLT file")
            ).arg(
                Arg::new("sort")
                .long("sort")
                .num_args(0)
                .help("Sort by timestamp. Sorts by timestamp per lifecycle.")
            )
            .arg(
                Arg::new("anon")
                .long("anon")
                .num_args(0)
                .help("Anonymize the output. Rewrite APID, CTIDs,sw_versions and payload. Useful only for lifecycle detection tests.")
            )
            .arg(
                Arg::new("file_transfer")
                .long("file_transfer")
                .value_name("glob pattern")
                .require_equals(true)
                .num_args(1)
                .help("Pattern to export files included in logs that match the given glob pattern. e.g. ='*.bin'. Existing files are not overwritten!")
            )
            .arg(
                Arg::new("file_transfer_path")
                .long("file_transfer_path")
                .num_args(1)
                .help("Path where to store exported files. Defaults to current dir. Directory will be created if it doesn't exist.")
            )
            .arg(
                Arg::new("file_transfer_apid")
                .long("file_transfer_apid")
                .num_args(1)
                .help("APID used for file transfers. E.g. SYS. Providing an apid speeds up the file transfer extraction significantly!")
            ).arg(
                Arg::new("file_transfer_ctid")
                .long("file_transfer_ctid")
                .num_args(1)
                .help("CTID used for file transfers. E.g. FILE. Providing a ctid speeds up the file transfer extraction significantly!")
            ).arg(
                Arg::new("nonverbose_path")
                .long("nonverbose_path")
                .num_args(1)
                .help("Path to directory with the FIBEX files for the Non-Verbose plugin. If not provided the Non-Verbose plugin is deactivated.")
            ).arg(
                Arg::new("someip_path")
                .long("someip_path")
                .num_args(1)
                .help("Path to directory with the FIBEX files for the SOME/IP plugin. If not provided the SOME/IP plugin is deactivated.")
            ).arg(
                Arg::new("rewrite_path")
                .long("rewrite_path")
                .num_args(1)
                .help("Path to json config with the Rewrite plugin config with '{name, rewrites:[...]}'. If not provided the Rewrite plugin is deactivated.")
            ).arg(
                Arg::new("can_path")
                .long("can_path")
                .num_args(1)
                .help("Path to directory with the FIBEX files for the CAN plugin. If not provided the CAN plugin is deactivated.")
            ).arg(
                Arg::new("muniic_path")
                .long("muniic_path")
                .num_args(1)
                .help("Path to directory with the json files for the Muniic plugin. If not provided the Muniic plugin is deactivated.")
            )
            .arg(
                Arg::new("debug_verify_sort")
                .long("debug_verify_sort")
                .num_args(0)
                .help("Verify the sort order in the output (for --sort) per ECU and per ECU/APID. This is slow! Use it only for debugging!")
            ).arg(
                Arg::new("debug_verify_lcs")
                .long("debug_verify_lcs")
                .num_args(0)
                .help("Verify that within each lifecycle the timestamps for msgs from an apid/ctid are ascending (+/-0.1s). This is slow! Use it only for debugging!")
            ),
    )
}

#[allow(dead_code)] // we currently use it only for test
pub struct ConvertResult<W: std::io::Write + Send + 'static> {
    messages_processed: adlt::dlt::DltMessageIndexType,
    messages_output: adlt::dlt::DltMessageIndexType,
    writer_screen: Option<W>,
}

/// same as genivi dlt dlt-convert binary
///
/// log the files to console
///
/// supports additional lifecycle detection and sort by timestamp
pub fn convert<W: std::io::Write + Send + 'static>(
    log: &slog::Logger,
    sub_m: &clap::ArgMatches,
    mut writer_screen: W,
) -> std::io::Result<ConvertResult<W>> {
    let input_file_names: Vec<String> = sub_m
        .get_many::<String>("file")
        .unwrap()
        .map(|a| a.to_owned())
        .collect();

    let output_style: OutputStyle = if sub_m.get_flag("hex") {
        OutputStyle::Hex
    } else if sub_m.get_flag("ascii") {
        OutputStyle::Ascii
    } else if sub_m.get_flag("headers") {
        OutputStyle::HeaderOnly
    } else {
        OutputStyle::None
    };

    let sort_by_time = sub_m.get_flag("sort");
    let debug_verify_sort = sub_m.get_flag("debug_verify_sort");
    let debug_verify_lcs = sub_m.get_flag("debug_verify_lcs");

    let do_anonimize = sub_m.get_flag("anon");

    let do_file_transfer = sub_m.get_many::<String>("file_transfer").is_some();

    let someip_path = sub_m.get_one::<String>("someip_path").map(|s| s.to_owned());
    let nonverbose_path = sub_m
        .get_one::<String>("nonverbose_path")
        .map(|s| s.to_owned());
    let rewrite_path = sub_m
        .get_one::<String>("rewrite_path")
        .map(|s| s.to_owned());
    let can_path = sub_m.get_one::<String>("can_path").map(|s| s.to_owned());
    let muniic_path = sub_m.get_one::<String>("muniic_path").map(|s| s.to_owned());

    let index_first: adlt::dlt::DltMessageIndexType =
        match sub_m.get_one::<adlt::dlt::DltMessageIndexType>("index_first") {
            None => 0,
            Some(s) => *s,
        };
    let index_last: adlt::dlt::DltMessageIndexType =
        match sub_m.get_one::<adlt::dlt::DltMessageIndexType>("index_last") {
            None => adlt::dlt::DltMessageIndexType::MAX,
            Some(s) => *s,
        };

    let filter_lc_ids: std::collections::BTreeSet<u32> =
        match sub_m.get_many::<u32>("filter_lc_ids") {
            None => std::collections::BTreeSet::new(),
            Some(s) => s.copied().collect(),
        };

    // parse filter file if provided:
    let filter_file = sub_m.get_one::<String>("filter_file");
    let mut filters = if let Some(filter_file) = filter_file {
        // try to open the file in either dlf/xml format or dlt-convert "APID CTID " format.
        let file = File::open(filter_file)?;
        let reader = std::io::BufReader::new(file);
        let filters = filters_from_dlf(reader);
        if let Ok(filters) = filters {
            info!(log, "parsed dlf format file with {} filters", filters.len());
            filters
        } else {
            // parse as dlt-convert format
            let file = File::open(filter_file)?;
            let reader = std::io::BufReader::new(file);

            let filters = filters_from_convert_format(reader)?;
            info!(
                log,
                "parsed dlt-convert format file with {:?} filters", filters
            );
            filters
        }
    } else {
        vec![]
    };

    let filter_eac: Vec<&EacFilter> = match sub_m.get_many::<EacFilter>("filter_eac") {
        None => vec![],
        Some(s) => s.collect(),
    };

    if !filter_eac.is_empty() {
        info!(
            log,
            "filter_eac: {:?}",
            filter_eac.iter().map(|f| &f.filter).collect::<Vec<_>>()
        );
        for eac_f in &filter_eac {
            filters.push(eac_f.filter.clone());
        }
    }

    let output_file = sub_m.get_one::<String>("output_file").map(|s| s.to_owned());
    info!(log, "convert have {} input files", input_file_names.len(); "index_first"=>index_first, "index_last"=>index_last);
    debug!(log, "convert "; "input_file_names" => format!("{:?}",&input_file_names), "filter_lc_ids" => format!("{:?}",filter_lc_ids), "sort_by_time" => sort_by_time, "output_file" => &output_file, "filter_file" => &filter_file, "filters" =>  format!("{:?}",&filters) );

    // if we have multiple files we do need to sort them first by the first log reception_time!
    // we follow this path even if there is just one paramater as it might be a glob expression

    // check whether some input files are zip files or zipfiles with glob patterns (...*.zip/** )
    let mut temp_dirs: Vec<(String, TempDir)> = vec![]; // need to keep them till the end. Pair of path/file_name and corresp. temp dir where we extracted to

    let prev_len = input_file_names.len();
    let input_file_names: Vec<String> = input_file_names
        .into_iter()
        .flat_map(|file_name| extract_archives(file_name, &mut temp_dirs, log))
        .collect();
    if input_file_names.len() != prev_len || !temp_dirs.is_empty() {
        info!(
            log,
            "have {} input files after archive check and {} tempdirs",
            input_file_names.len(),
            temp_dirs.len()
        );
    }

    // map input_file_names to name/first msg
    let namespace = get_new_namespace();
    let file_msgs = input_file_names
        .iter()
        .flat_map(|f_name| resolve_input_filename(f_name, namespace, log));

    let (files_ok, _files_err): (Vec<_>, Vec<_>) = file_msgs.partition(|(_, b)| b.is_ok());

    if files_ok.is_empty() {
        return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
    }
    let max_files = files_ok.len();

    // collect from all existing files the ones with at least one DltMessage:
    let file_msgs = files_ok
        .into_iter()
        .map(|(a, b)| (a, b.unwrap()))
        .filter(|(_a, b)| b.first_msg.is_some());

    // now we do need to "partition" into non-overlapping streams. "non-overlapping" = ranges [reception_time.start..reception_time.end] do
    // not overlap.
    // We do so by the following indirect way:
    // if they are from the same ecu(s) -> assumed to be recorded in the same way -> sort by reception_time.start
    // if from different ecu(s) -> use a different "bucket" and later on process them using the SortingMultiReaderIterator in "parallel".
    // So we do determine the files per ecus.
    // Example: 3 files: (ecu1, ecu2, ecu1+2) -> will be parsed as 3 parallel streams
    // The ecu1+2 case is a bit weird but seems a common pattern where e.g. ecu2 gets tunneled via ecu1

    // as the amount of files is usually limited/small we use a naive approach:
    type SetOfEcuIds = HashSet<DltChar4>;
    type StreamEntry = (SetOfEcuIds, Vec<(u64, String, DltFileInfos)>);

    let mut input_file_streams: Vec<StreamEntry> = Vec::with_capacity(max_files);
    for fm in file_msgs {
        let stream = input_file_streams
            .iter_mut()
            .find(|e| e.0 == fm.1.ecus_seen);
        match stream {
            Some((_, l)) => {
                l.push((
                    fm.1.first_msg.as_ref().unwrap().reception_time_us,
                    fm.0,
                    fm.1,
                ));
            }
            None => {
                input_file_streams.push((
                    fm.1.ecus_seen.clone(),
                    vec![(
                        fm.1.first_msg.as_ref().unwrap().reception_time_us,
                        fm.0,
                        fm.1,
                    )],
                ));
            }
        }
    }

    // now we do need to sort and dedup each stream only:
    let input_file_streams: Vec<StreamEntry> = input_file_streams
        .into_iter()
        .map(|(hashset, mut time_files)| {
            time_files.sort_by(|a, b| a.0.cmp(&b.0));
            time_files.dedup(); // remove duplicates
            (hashset, time_files)
        })
        .collect();
    if log.is_debug_enabled() {
        for (ecus, files) in &input_file_streams {
            info!(log, "ecus {:?} have {} files:", ecus, files.len());
            for (time, file, _dfi) in files {
                info!(log, " file {} has first msg at {}", file, time);
            }
        }
    }

    // determine plugins
    let mut plugins_active: Vec<Box<dyn Plugin + Send>> = vec![];
    if do_anonimize {
        plugins_active.push(Box::new(AnonymizePlugin::new("anon")));
    }
    if do_file_transfer {
        if let Some(ft_config) = serde_json::json!({"name":"file_transfer","allowSave":false, "keepFLDA":true,"autoSavePath":sub_m.get_one::<String>("file_transfer_path").map_or("./", |s|s), "autoSaveGlob":sub_m.get_one::<String>("file_transfer").unwrap()}).as_object_mut(){
            if let Some(apid) = sub_m.get_one::<String>("file_transfer_apid") {
                // e.g. "SYS"
                ft_config.insert(
                    "apid".to_owned(),
                    serde_json::Value::String(apid.to_string()),
                );
            }
            if let Some(ctid) = sub_m.get_one::<String>("file_transfer_ctid") {
                // e.g. "FILE"
                ft_config.insert(
                    "ctid".to_owned(),
                    serde_json::Value::String(ctid.to_string()),
                );
            }

            match FileTransferPlugin::from_json(ft_config) {
                Ok(plugin) => {
                    debug!(log, "file_transfer plugin used: {:?}", plugin);
                    plugins_active.push(Box::new(plugin));
                }
                Err(e) => warn!(log, "file_transfer plugin failed with err: {:?}", e),
            }
        }else{
            warn!(log, "file_transfer failed to parse config");
        }
    }
    if let Some(nonverbose_path) = &nonverbose_path {
        if let Some(np_config) =
            serde_json::json!({"name":"NonVerbose","fibexDir":nonverbose_path}).as_object()
        {
            let mut eac_stats = EacStats::new(); // we dont use them now. todo!
            match NonVerbosePlugin::from_json(np_config, &mut eac_stats) {
                Ok(plugin) => {
                    debug!(log, "Non-Verbose plugin used: {}", plugin.name());
                    plugins_active.push(Box::new(plugin));
                }
                Err(e) => warn!(log, "Non-Verbose plugin failed with err: {:?}", e),
            }
        }
    }
    if let Some(someip_path) = &someip_path {
        if let Some(sp_config) =
            serde_json::json!({"name":"SomeIp","fibexDir":someip_path}).as_object()
        {
            match SomeipPlugin::from_json(sp_config) {
                Ok(plugin) => {
                    debug!(log, "SomeIp plugin used: {}", plugin.name());
                    plugins_active.push(Box::new(plugin));
                }
                Err(e) => warn!(log, "SomeIp plugin failed with err: {:?}", e),
            }
        }
    }
    if let Some(rewrite_path) = &rewrite_path {
        match std::fs::read_to_string(rewrite_path) {
            Ok(rewrite_config_str) => {
                match serde_json::from_str::<serde_json::Value>(&rewrite_config_str) {
                    Ok(json) => {
                        if let Some(sp_config) = json.as_object() {
                            match RewritePlugin::from_json(sp_config) {
                                Ok(plugin) => {
                                    debug!(log, "Rewrite plugin used: {}", plugin.name());
                                    plugins_active.push(Box::new(plugin));
                                }
                                Err(e) => warn!(log, "Rewrite plugin failed with err: {:?}", e),
                            }
                        }
                    }
                    Err(e) => warn!(
                        log,
                        "Failed to parse config file {} for Rewrite plugin with err: {:?}",
                        rewrite_path,
                        e
                    ),
                }
            }
            Err(e) => warn!(
                log,
                "Failed to to read config file {} for Rewrite plugin with err: {:?}",
                rewrite_path,
                e
            ),
        }
    }

    if let Some(can_path) = &can_path {
        if let Some(sp_config) = serde_json::json!({"name":"CAN","fibexDir":can_path}).as_object() {
            match CanPlugin::from_json(sp_config) {
                Ok(plugin) => {
                    debug!(log, "CAN plugin used: {}", plugin.name());
                    plugins_active.push(Box::new(plugin));
                }
                Err(e) => warn!(log, "CAN plugin failed with err: {:?}", e),
            }
        }
    }
    if let Some(muniic_path) = &muniic_path {
        if let Some(sp_config) =
            serde_json::json!({"name":"Muniic","jsonDir":muniic_path}).as_object()
        {
            match MuniicPlugin::from_json(sp_config) {
                Ok(plugin) => {
                    debug!(log, "Muniic plugin used: {}", plugin.name());
                    plugins_active.push(Box::new(plugin));
                }
                Err(e) => warn!(log, "Muniic plugin failed with err: {:?}", e),
            }
        }
    }

    // We use bounded channels to reduce the memory/alloc pressure. The bounded channels can allocate once.
    // The channel sizes start with 1mio msgs and then decrease following the logic that each stage should always have enough data to work on.
    // If sending to a channel fails with "full" we artificially wait 10ms to avoid that from that time one the process is constantly woken up.
    // The 10ms time is a bit arbitrary and we might need to find an algorithm to calculate the optimal time (e.g. 1/4 of the time it took to fill the buffer).

    // setup (thread) filter chain:
    let (tx_for_parse_thread, rx_from_parse_thread) = sync_channel(1024 * 1024); // msg -> parse_lifecycles (t2)
    let (tx_for_lc_thread, rx_from_lc_thread) = sync_channel(512 * 1024); // parse_lifecycles -> buffer_sort_messages (t3)
    let (lcs_r, lcs_w) = evmap::Options::default()
        .with_hasher(nohash_hasher::BuildNoHashHasher::<
            adlt::lifecycle::LifecycleId,
        >::default())
        .construct::<adlt::lifecycle::LifecycleId, adlt::lifecycle::LifecycleItem>();
    let lc_thread = std::thread::spawn(move || {
        adlt::lifecycle::parse_lifecycles_buffered_from_stream(lcs_w, rx_from_parse_thread, &|m| {
            sync_sender_send_delay_if_full(m, &tx_for_lc_thread)
        })
    });

    let (plugin_thread, rx_from_plugin_thread) = if !plugins_active.is_empty() {
        let (tx_for_plugin_thread, rx_from_plugin_thread) = sync_channel(512 * 1024);
        (
            Some(std::thread::spawn(move || {
                plugins_process_msgs(
                    rx_from_lc_thread,
                    &|m| sync_sender_send_delay_if_full(m, &tx_for_plugin_thread),
                    plugins_active,
                )
            })),
            rx_from_plugin_thread,
        )
    } else {
        (None, rx_from_lc_thread)
    };

    let sort_thread_lcs_r = lcs_r.clone();
    let (sort_thread, rx_final) = if sort_by_time {
        let (tx_for_sort_thread, rx_from_sort_thread) = sync_channel(512 * 1024);
        (
            Some(std::thread::spawn(move || {
                adlt::utils::buffer_sort_messages(
                    rx_from_plugin_thread,
                    &|m| sync_sender_send_delay_if_full(m, &tx_for_sort_thread),
                    &sort_thread_lcs_r,
                    3,                            // windows_size_secs for the buffer_delay_calc
                    20 * adlt::utils::US_PER_SEC, // min_buffer_delay_us:  // todo target 2s. (to allow live tracing) but some big ECUs have a much weirder delay. Need to improve the algorithm to detect those.
                )
            })),
            rx_from_sort_thread,
        )
    } else {
        (None, rx_from_plugin_thread)
    };

    // if we have filters we use a filter thread:
    let (thread_filter, t4_input) = if !filters.is_empty() {
        let (tx_filter, rx_filter) = sync_channel(256 * 1024);
        (
            Some(std::thread::spawn(move || {
                adlt::filter::functions::filter_as_streams(&filters, &rx_final, &|m| {
                    sync_sender_send_delay_if_full(m, &tx_filter)
                })
            })),
            rx_filter,
        )
    } else {
        (None, rx_final)
    };

    let t4_log = log.clone();
    let t4 = std::thread::spawn(
        move || -> Result<(adlt::dlt::DltMessageIndexType, W), Box<dyn std::error::Error + Send + Sync>> {
            let log = t4_log;
            let mut output_file = if let Some(s) = output_file {
                match std::fs::File::create(s) {
                    Ok(f) => Ok(BufWriter::new(f)),
                    Err(e) => Err(e),
                }
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "no output_file param",
                ))
            };

            let mut output : adlt::dlt::DltMessageIndexType= 0;
            let mut writer_screen_flush_pending = false;

            // debug function: verify sort order
            let mut last_timestamp_by_lc_map= BTreeMap::<adlt::lifecycle::LifecycleId, (u32, HashMap::<DltChar4,(u32,adlt::dlt::DltMessageIndexType)>)>::new();
            // debug function: verify lcs timestamp
            let mut last_lc_timestamp_by_ecu_apid_ctid_map = BTreeMap::<(u32, u32, u32), (u32, u32)>::new();

            for msg in t4_input {

                // from time to time (all ~0.5mio msgs) we flush the writer_screen to get a fast output 
                // and not at the end only the last chunk:
                if writer_screen_flush_pending && (msg.index & 0x7ffff == 0) {
                    writer_screen.flush()?;
                    writer_screen_flush_pending = false;
                }

                // lifecycle filtered?
                if !filter_lc_ids.is_empty() && !filter_lc_ids.contains(&msg.lifecycle) {
                    continue;
                }
                // start with a simple dump of the msgs similar to dlt_message_header
                if msg.index >= index_first && msg.index <= index_last {
                    // debug function: verify sort order
                    if debug_verify_sort {
                        // verify that msg.calculated_time is monotonicaly ascending per lc:
                        if !msg.is_ctrl_request() {
                            let last_timestamp = last_timestamp_by_lc_map.entry(msg.lifecycle).or_insert_with(|| (msg.timestamp_dms, std::collections::HashMap::new()));
                            if msg.timestamp_dms < last_timestamp.0 {
                                warn!(log, "sort order check: wrong timestamp order for ecu {} at idx {} {:?}:{:?} lc {} got {} prev {}",msg.ecu, msg.index, msg.apid() , msg.ctid(), msg.lifecycle, msg.timestamp_dms, last_timestamp.0);
                            }
                            last_timestamp.0  = msg.timestamp_dms;
                            // check for the apid as well:
                            if let Some(apid)=msg.apid() {
                                let last_apid_tmsp = last_timestamp.1.entry(*apid).or_insert((msg.timestamp_dms,msg.index));
                                if msg.timestamp_dms < last_apid_tmsp.0 {
                                    if msg.is_ctrl_response() {
                                        info!(log, "sort order check: wrong timestamp order for apid {}/{}:{:?} at idx {} lc {} got {} prev {} at idx {}", msg.ecu, apid, msg.ctid(), msg.index, msg.lifecycle, msg.timestamp_dms, last_apid_tmsp.0, last_apid_tmsp.1 );
                                    }else{
                                        warn!(log, "sort order check: wrong timestamp order for apid {}/{}:{:?} at idx {} lc {} got {} prev {} at idx {}", msg.ecu, apid, msg.ctid(), msg.index, msg.lifecycle, msg.timestamp_dms, last_apid_tmsp.0, last_apid_tmsp.1 );
                                    }
                                }
                                *last_apid_tmsp = (msg.timestamp_dms, msg.index);
                            }
                        }
                    }
                    if debug_verify_lcs {
                        // we can verify only per apid/ctid so we do need msgs with ext header
                        if let Some(ext_header) = &msg.extended_header {
                            if !msg.is_ctrl_request() && !msg.is_ctrl_response() {
                                let last_lc_timestamp = last_lc_timestamp_by_ecu_apid_ctid_map.entry((msg.ecu.as_u32le(), ext_header.apid.as_u32le(), ext_header.ctid.as_u32le())).or_insert((msg.lifecycle, msg.timestamp_dms));
                                if msg.lifecycle == last_lc_timestamp.0 && msg.timestamp_dms < last_lc_timestamp.1 && last_lc_timestamp.1 - msg.timestamp_dms > 1000 {
                                    // we warn only for >0.1s and no control responses (requests neither)
                                    warn!(log, "lifecycle check: wrong timestamp order (>0.1s) for ecu {} at idx {} {:?}:{:?} lc {} got {} prev {}",msg.ecu, msg.index, msg.apid() , msg.ctid(), msg.lifecycle, msg.timestamp_dms, last_lc_timestamp.1);
                                }
                                *last_lc_timestamp = (msg.lifecycle, msg.timestamp_dms);
                            }
                        }
                    }
                    // if print header, ascii, hex or mixed: todo
                    let mut did_output = false;
                    match output_style {
                        OutputStyle::HeaderOnly => {
                            msg.header_as_text_to_write( &mut writer_screen)?;
                            writer_screen.write_all(&[b'\n'])?;
                            did_output = true;
                        }
                        OutputStyle::Ascii => {
                            msg.header_as_text_to_write(&mut writer_screen)?;
                            writeln!(writer_screen, " [{}]", msg.payload_as_text()?)?;
                            did_output = true;
                        }
                        OutputStyle::Hex => {
                            msg.header_as_text_to_write(&mut writer_screen)?;
                            writer_screen.write_all(&[b' ',b'['])?;
                            buf_as_hex_to_io_write(&mut writer_screen, &msg.payload)?;
                            writer_screen.write_all(&[b']',b'\n'])?;
                            did_output = true;
                        }
                        _ => {
                            // todo... mixed? (the dlt-convert output is not nicely readable...)
                        }
                    }
                     if did_output {
                        writer_screen_flush_pending = true;
                    }
                    // if output to file:
                    if let Ok(ref mut file) = output_file {
                        msg.to_write(file)?;
                        did_output = true;
                    }
                    if did_output{ output += 1;}
                }
            }
            if let Ok(mut writer) = output_file {
                writer.flush()?;
                drop(writer); // close, happens anyhow autom...
            }

            Ok((output, writer_screen))
        },
    );
    const BUFREADER_CAPACITY: usize = 512 * 1024;
    // we use a relatively small 512kb chunk size as we're processing
    // the data multithreaded reader in bigger chunks slows is in total slower

    //assert!(BUFREADER_CAPACITY > DLT_MAX_STORAGE_MSG_SIZE);

    let mut messages_processed: adlt::dlt::DltMessageIndexType = 0;
    let mut messages_output: adlt::dlt::DltMessageIndexType = 0;

    let get_single_it =
        |input_file_name: &str,
         start_index: adlt::dlt::DltMessageIndexType,
         first_reception_time_us: Option<u64>,
         modified_time_us: Option<u64>| match File::open(input_file_name) {
            Ok(fi) => {
                info!(log, "opened file {} {:?}", &input_file_name, &fi);
                let buf_reader =
                    LowMarkBufReader::new(fi, BUFREADER_CAPACITY, DLT_MAX_STORAGE_MSG_SIZE);
                get_dlt_message_iterator(
                    std::path::Path::new(&input_file_name)
                        .extension()
                        .and_then(|s| s.to_str())
                        .unwrap_or(""),
                    start_index,
                    buf_reader,
                    namespace,
                    first_reception_time_us,
                    modified_time_us,
                    Some(log),
                )
            }
            Err(e) => {
                error!(
                    log,
                    "failed to open file {} due to {}!", &input_file_name, e
                );
                Box::new(std::iter::empty())
            }
        };

    let mut dlt_msg_iterator = SortingMultiReaderIterator::new_or_single_it(
        0,
        input_file_streams
            .into_iter()
            .map(|(_, files)| {
                let first_reception_time_us = if files.is_empty() {
                    None
                } else {
                    Some(files[0].0)
                };
                SequentialMultiIterator::new_or_single_it(
                    0,
                    files.into_iter().map(move |(_, file, dfi)| {
                        get_single_it(&file, 0, first_reception_time_us, dfi.modified_time_us)
                    }),
                )
            })
            .collect(),
    );
    loop {
        match dlt_msg_iterator.next() {
            Some(msg) => {
                messages_processed += 1;
                match sync_sender_send_delay_if_full(msg, &tx_for_parse_thread) {
                    Ok(()) => {}
                    Err(e) => {
                        error!(log, "failed to send msg to parse_thread due to {:?}", e);
                        break;
                    }
                }
            }
            None => {
                debug!(log, "finished processing all msgs";"messages_processed"=>messages_processed);
                break;
            }
        }
    }

    drop(tx_for_parse_thread);
    let _lcs_w = lc_thread.join().unwrap();

    plugins_active = if let Some(t) = plugin_thread {
        match t.join() {
            Err(s) => {
                error!(log, "plugin_thread join got Err {:?}", s);
                Vec::new()
            }
            Ok(s) => {
                if let Ok(plugins) = s {
                    plugins
                } else {
                    Vec::new()
                }
            }
        }
    } else {
        Vec::new()
    };

    if let Some(t) = sort_thread {
        match t.join() {
            Err(s) => error!(log, "sort_thread join got Error {:?}", s),
            Ok(s) => debug!(log, "sort_thread join was Ok {:?}", s),
        };
    }

    if let Some(t) = thread_filter {
        match t.join() {
            Err(s) => error!(log, "thread_filter join got Error {:?}", s),
            Ok(s) => debug!(log, "thread_filter join was Ok {:?}", s),
        };
    }

    let mut writer_screen = match t4.join() {
        Err(s) => {
            error!(log, "t4 join got Error {:?}", s);
            None
        }
        Ok(s) => {
            if let Ok(s) = s {
                debug!(log, "t4 join was Ok {:?}", s.0);
                messages_output += s.0;
                Some(s.1)
            } else {
                None
            }
        }
    };

    info!(log, "finished processing"; "messages_processed"=>messages_processed);

    // print lifecycles:
    if let OutputStyle::None = output_style {
        const EMPTY_STR: String = String::new();
        const EMPTY_STR_R: &String = &EMPTY_STR;
        if let Some(writer_screen) = writer_screen.as_mut() {
            if let Some(a) = lcs_r.read() {
                let sorted_lcs = adlt::lifecycle::get_sorted_lifecycles_as_vec(&a);
                writeln!(writer_screen, "have {} lifecycles:", sorted_lcs.len(),)?;
                // todo to output_screen!
                // output lifecycles
                for lc in sorted_lcs {
                    writeln!(
                        writer_screen,
                        "LC#{:3}: {:4} {} - {} #{:8}{} {}",
                        lc.id(),
                        lc.ecu,
                        if lc.is_resume() {
                            Local
                                .from_utc_datetime(&adlt::utils::utc_time_from_us(lc.resume_time()))
                                .format("%Y/%m/%d %H:%M:%S RESUME")
                        } else {
                            Local
                                .from_utc_datetime(&adlt::utils::utc_time_from_us(lc.start_time))
                                .format("%Y/%m/%d %H:%M:%S%.6f")
                        },
                        Local
                            .from_utc_datetime(&adlt::utils::utc_time_from_us(lc.end_time()))
                            .format("%H:%M:%S"),
                        lc.nr_msgs,
                        if lc.only_control_requests() {
                            " CTRL_REQUESTS_ONLY"
                        } else {
                            ""
                        },
                        if let Some(sw_vers) = &lc.sw_version {
                            sw_vers
                        } else {
                            EMPTY_STR_R
                        }
                    )?;
                }
            }
            for plugin in plugins_active {
                let plugin_state = plugin.state();
                let state = plugin_state.read().unwrap();
                // output any warnings
                if let Some(warnings) = state.value["warnings"].as_array() {
                    if !warnings.is_empty() {
                        writeln!(
                            writer_screen,
                            "Plugin {} generated {} warning{}:",
                            plugin.name(),
                            warnings.len(),
                            if warnings.len() > 1 { "s" } else { "" }
                        )?;
                    }
                    for warning in warnings {
                        writeln!(
                            writer_screen,
                            " {}",
                            if let Some(warn) = warning.as_str() {
                                warn
                            } else {
                                "<unknown type of warning!>"
                            }
                        )?;
                    }
                }

                if plugin.name() == "file_transfer" {
                    debug!(log, "file_transfer.state.value={:?}", state.value);
                    // output the files detected:
                    if let Some(tree_items) = state.value["treeItems"].as_array() {
                        if !tree_items.is_empty() {
                            writeln!(
                                writer_screen,
                                "have {} file transfers:",
                                tree_items.len() - 1 // need to remove the Sorted...
                            )?;
                        }

                        for item in tree_items {
                            if let Some(label) = item["label"].as_str() {
                                if let Some(meta) = item["meta"].as_object() {
                                    writeln!(
                                        writer_screen,
                                        "LC# {}: {} {}",
                                        meta["lc"],
                                        label,
                                        if let Some(path) = meta["autoSavedTo"].as_str() {
                                            format!(", saved as: '{}'", path)
                                        } else {
                                            EMPTY_STR
                                        }
                                    )?;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(ConvertResult {
        messages_processed,
        messages_output,
        writer_screen,
    })
}

/// check whether a file name is a supported archive and if so extract it to a temp dir
///
/// Supports globs for archives as well like "...zip/**/*.dlt"
/// Checks whether the archive has been extracted to the temp_dirs already and reuses it if so.
/// If not it extracts the archive to a temp dir, returns the list of extracted files and adds the
/// temp dir to the temp_dirs list.
///
/// Multi-volume archives are supported and only the first part should be used (e.g. .zip.001).
fn extract_archives(
    file_name: String,
    temp_dirs: &mut Vec<(String, TempDir)>,
    log: &slog::Logger,
) -> Vec<String> {
    // check whether its a archive file or whether it's a non existing file with a glob pattern
    let path = std::path::Path::new(&file_name);
    if let Some((archive_path, glob_pattern)) = archive_get_path_and_glob(path) {
        let start_time = Instant::now();
        let (mut archive, can_path) = if is_part_of_multi_volume_archive(&archive_path) {
            let all_parts = search_dir_for_multi_volume_archive(&archive_path);
            info!(
                log,
                "search for other parts for multi volume archive file got: '{:?}'.", all_parts
            );
            let can_path: String = all_parts
                .first()
                .unwrap_or(&archive_path)
                .canonicalize()
                .map_or_else(
                    |_| file_name.clone(),
                    |f| f.to_str().unwrap_or_default().to_owned(),
                );
            let all_files: Vec<_> = all_parts.iter().flat_map(File::open).collect();
            (SeekableChain::new(all_files), can_path)
        } else {
            let can_path: String = archive_path.canonicalize().map_or_else(
                |_| file_name.clone(),
                |f| f.to_str().unwrap_or_default().to_owned(),
            );
            if let Ok(archive_file) = File::open(&archive_path) {
                (SeekableChain::new(vec![archive_file]), can_path)
            } else {
                warn!(
                    log,
                    "failed to open archive file '{}'",
                    archive_path.display()
                );
                return vec![file_name];
            }
        };
        // todo could optimize for glob **/*
        // and/or extract only supported file extensions...

        match list_archive_contents(&mut archive) {
            Ok(archive_contents) => {
                archive
                    .seek(std::io::SeekFrom::Start(0))
                    .expect("failed to seek");
                let mut matching_files = vec![];
                for entry in archive_contents {
                    if glob_pattern.matches(&entry) {
                        matching_files.push(entry);
                    }
                }
                info!(
                    log,
                    "found {} matching files in {}:{:?} took {:?}",
                    matching_files.len(),
                    archive_path.display(),
                    matching_files,
                    start_time.elapsed()
                );
                if !matching_files.is_empty() {
                    // do we have this tempdir yet?
                    if let Some((_p, d)) = temp_dirs.iter().find(|(p, _d)| p == &can_path) {
                        info!(
                            log,
                            "reuse extracted archive file '{}' in '{}'",
                            file_name,
                            d.path().display()
                        );
                        matching_files
                            .iter()
                            .map(|s| format!("{}/{}", d.path().display(), s))
                            .collect()
                    } else {
                        let temp_dir = TempDir::new().expect("failed to create temp dir");
                        info!(
                            log,
                            "extracting archive file '{}' to '{}'",
                            file_name,
                            temp_dir.path().display()
                        );
                        let temp_dir_path = temp_dir.path().to_owned();
                        match extract_to_dir(
                            &mut archive,
                            &temp_dir_path,
                            Some(matching_files.clone()),
                        ) {
                            Ok(nr_extracted) => {
                                info!(
                                    log,
                                    "extracted {}/{} matching files took {:?}",
                                    nr_extracted,
                                    matching_files.len(),
                                    start_time.elapsed()
                                );
                                temp_dirs.push((can_path, temp_dir));
                                matching_files
                                    .iter()
                                    .map(|s| format!("{}/{}", temp_dir_path.display(), s))
                                    .collect()
                            }
                            Err(e) => {
                                warn!(
                                    log,
                                    "failed to extract archive file '{}' due to {:?}", file_name, e
                                );
                                vec![file_name]
                            }
                        }
                    }
                } else {
                    vec![]
                }
            }
            Err(e) => {
                warn!(
                    log,
                    "failed to list archive contents of '{}' due to {:?}",
                    archive_path.display(),
                    e
                );
                vec![]
            }
        }
    } else {
        // not a supported archive
        vec![file_name]
    }
}

/// try to resolve a provide filename to a vec of pair of filename and DltFileInfos
///
/// handles glob expressions thus from one input filename multiple output filenames can be generated
///
fn resolve_input_filename(
    f_name: &String,
    namespace: u32,
    log: &slog::Logger,
) -> Vec<(String, Result<DltFileInfos, std::io::Error>)> {
    info!(log, "resolving input filename {}", f_name; "namespace"=>namespace);
    let path = std::path::Path::new(f_name);
    let fi = File::open(path);
    match fi {
        Ok(mut f) => {
            let file_ext = std::path::Path::new(&f_name)
                .extension()
                .and_then(|s| s.to_str())
                .unwrap_or_default();
            let dfi = adlt::utils::get_dlt_infos_from_file(file_ext, &mut f, 512 * 1024, namespace);
            match dfi {
                Ok(dfi) => {
                    let m1 = &dfi.first_msg;
                    if m1.is_none() {
                        warn!(log, "file {} ({}) (ext: '{}') doesn't contain a DLT message in first 0.5MB. Skipping!", f_name, path.canonicalize().unwrap_or_else(|_|std::path::PathBuf::from(f_name)).display(), file_ext;);
                    }
                    vec![(
                        path.canonicalize()
                            .unwrap_or_else(|_| std::path::PathBuf::from(f_name))
                            .to_string_lossy()
                            .to_string(),
                        Ok(dfi),
                    )]
                }
                Err(e) => {
                    warn!(log, "file {} ({}) (ext: '{}') had io error '{}'. Skipping!", f_name, path.canonicalize().unwrap_or_else(|_|std::path::PathBuf::from(f_name)).display(), file_ext, e;);
                    vec![(
                        path.canonicalize()
                            .unwrap_or_else(|_| std::path::PathBuf::from(f_name))
                            .to_string_lossy()
                            .to_string(),
                        Err(e),
                    )]
                }
            }
        }
        _ => {
            // file does not exist. Let's check whether its a glob expression (as windows doesn't support glob on cmd)
            let options = MatchOptions {
                case_sensitive: false,
                require_literal_separator: false,
                require_literal_leading_dot: false,
            };
            let mut globbed_names = vec![];
            if let Ok(paths) = glob_with(f_name, options) {
                for glob_name in paths.flatten() {
                    debug!(log, "found '{}' via glob '{}'", glob_name.display(), f_name;);
                    globbed_names.push(glob_name);
                }
            }
            if !globbed_names.is_empty() {
                globbed_names.iter().map(|glob_name|{
                        let fi = File::open(glob_name);
                        if let Ok(mut f)=fi {
                            let file_ext = std::path::Path::new(glob_name).extension().and_then(|s|s.to_str()).unwrap_or_default();

                            let dfi = adlt::utils::get_dlt_infos_from_file(file_ext, &mut f, 512*1024, namespace);
                            match dfi {
                                Ok(dfi) => {
                                    let m1 = &dfi.first_msg;
                                    if m1.is_none() {
                                        warn!(log, "globbed file '{}' (ext: '{}') doesn't contain a DLT message in first 0.5MB. Skipping!", f_name, file_ext;);
                                    }
                                    let path_glob = std::path::Path::new(glob_name);
                                    (path_glob.canonicalize().unwrap_or_else(|_|glob_name.to_path_buf()).to_string_lossy().to_string(), Ok(dfi))
                                },
                                Err(e) => {
                                    warn!(log, "file {} ({}) (ext: '{}') had io error '{}'. Skipping!", f_name, path.canonicalize().unwrap_or_else(|_|std::path::PathBuf::from(f_name)).display(), file_ext, e;);
                                    (glob_name.to_string_lossy().to_string(), Err(e))
                                }
                            }
                        }else{
                            (glob_name.to_string_lossy().to_string(), Err(std::io::Error::from(std::io::ErrorKind::NotFound)))
                        }
                    }).collect::<Vec<_>>()
            } else {
                warn!(log, "couldn't open '{}'. Skipping!", f_name;);
                vec![(
                    f_name.to_owned(),
                    Err(std::io::Error::from(std::io::ErrorKind::NotFound)),
                )]
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use adlt::dlt::{DltMessage, DLT_TYPE_INFO_RAWD, DLT_TYPE_INFO_SINT};
    use adlt::*;
    use adlt::{
        dlt::{DltArg, DLT_TYLE_32BIT, DLT_TYPE_INFO_STRG, DLT_TYPE_INFO_UINT},
        utils::payload_from_args,
    };

    use slog::{o, Drain, Logger};
    use tempfile::NamedTempFile;

    fn new_logger() -> Logger {
        let decorator = slog_term::PlainSyncDecorator::new(slog_term::TestStdoutWriter);
        let drain = slog_term::FullFormat::new(decorator).build().fuse();
        Logger::root(drain, o!())
    }

    #[test]
    fn params_file_non_existent() {
        let logger = new_logger();
        let arg_vec = vec!["t", "convert", "foo.dlt"];
        let sub_c = add_subcommand(Command::new("t")).get_matches_from(arg_vec);
        let (c, sub_m) = sub_c.subcommand().unwrap();
        assert_eq!("convert", c);
        assert!(sub_m.get_many::<String>("file").is_some());
        let r = convert(&logger, sub_m, std::io::stdout());
        assert!(r.is_err());
    }

    #[test]
    fn params_file_glob() {
        let logger = new_logger();
        let arg_vec = vec!["t", "convert", "tests/lc_ex00[2-3].dlt"];
        let sub_c = add_subcommand(Command::new("t")).get_matches_from(arg_vec);
        let (_, sub_m) = sub_c.subcommand().unwrap();
        let r = convert(&logger, sub_m, std::io::stdout()).unwrap();
        assert_eq!(19741, r.messages_processed);
    }

    #[test]
    fn params_file_glob_autoremove_dup() {
        let logger = new_logger();
        let arg_vec = vec![
            "t",
            "convert",
            "tests/lc_ex00[2-3].dlt",
            "tests/lc_ex002.dlt",
            "tests/../tests/lc_ex00[2-3].dlt",
        ];
        let sub_c = add_subcommand(Command::new("t")).get_matches_from(arg_vec);
        let (_, sub_m) = sub_c.subcommand().unwrap();
        let r = convert(&logger, sub_m, std::io::stdout()).unwrap();
        assert_eq!(19741, r.messages_processed);
    }

    #[test]
    fn empty1() {
        let logger = new_logger();

        let file = NamedTempFile::new().unwrap();
        let file_path = file.path().to_str().unwrap();

        let arg_vec = vec!["t", "convert", file_path];
        let sub_c = add_subcommand(Command::new("t")).get_matches_from(arg_vec);
        let (c, sub_m) = sub_c.subcommand().unwrap();
        assert_eq!("convert", c);
        assert!(sub_m.get_many::<String>("file").is_some());

        let r = convert(&logger, sub_m, std::io::stdout()).unwrap();
        assert_eq!(0, r.messages_output);
        assert_eq!(0, r.messages_processed);
        assert!(file.close().is_ok());
    }

    #[test]
    fn non_empty1() {
        let logger = new_logger();

        let mut file = NamedTempFile::new().unwrap();
        let file_path = String::from(file.path().to_str().unwrap());

        // persist some messages (more than the 512kb chunk size -> 20 byte per msg)
        let persisted_msgs: adlt::dlt::DltMessageIndexType = 1024 * 1024 / 20;
        let ecu = dlt::DltChar4::from_buf(b"ECU1");
        for i in 0..persisted_msgs {
            let sh = adlt::dlt::DltStorageHeader {
                secs: (1640995200000000 / utils::US_PER_SEC) as u32, // 1.1.22, 00:00:00 as GMT
                micros: 0,
                ecu,
            };
            let standard_header = adlt::dlt::DltStandardHeader {
                htyp: 1 << 5, // vers 1
                mcnt: (i % 256) as u8,
                len: 4,
            };

            let m = adlt::dlt::DltMessage::from_headers(i, sh, standard_header, &[], vec![]);
            m.to_write(&mut file).unwrap(); // will persist with timestamp
        }
        file.flush().unwrap();

        let arg_vec = vec!["t", "convert", file_path.as_str()];
        let sub_c = add_subcommand(Command::new("t")).get_matches_from(arg_vec);
        let (c, sub_m) = sub_c.subcommand().unwrap();
        assert_eq!("convert", c);
        assert!(!sub_m.get_flag("hex"));
        assert!(sub_m.get_many::<String>("file").is_some());

        let r = convert(&logger, sub_m, std::io::stdout()).unwrap();
        assert_eq!(0, r.messages_output);
        assert_eq!(persisted_msgs, r.messages_processed);
        assert!(file.close().is_ok());
    }

    #[test]
    fn non_empty_invalid_bytes() {
        let logger = new_logger();

        let mut file = NamedTempFile::new().unwrap();
        let file_path = String::from(file.path().to_str().unwrap());

        // persist some messages
        let persisted_msgs: adlt::dlt::DltMessageIndexType = 10;
        let ecu = dlt::DltChar4::from_buf(b"ECU1");

        // random bytes buffer:
        // todo needs better parsing heuristics let invalid_data = [b'D', b'L', b'T', 0x1];
        let invalid_data = [b'D', b'L', b'T', 0x2];

        for i in 0..persisted_msgs {
            // put some random bytes between (in front) of messages:
            file.write_all(&invalid_data[0..i as usize % (invalid_data.len() + 1)])
                .unwrap();

            let sh = adlt::dlt::DltStorageHeader {
                secs: (1640995200000000 / utils::US_PER_SEC) as u32, // 1.1.22, 00:00:00 as GMT
                micros: 0,
                ecu,
            };
            let standard_header = adlt::dlt::DltStandardHeader {
                htyp: 1 << 5, // vers 1
                mcnt: (i % 256) as u8,
                len: 4,
            };

            let m = adlt::dlt::DltMessage::from_headers(i, sh, standard_header, &[], vec![]);
            m.to_write(&mut file).unwrap(); // will persist with timestamp
        }
        file.flush().unwrap();

        let arg_vec = vec!["t", "convert", "-s", "-b2", "-e5", file_path.as_str()];
        let sub_c = add_subcommand(Command::new("t")).get_matches_from(arg_vec);
        let (c, sub_m) = sub_c.subcommand().unwrap();
        assert_eq!("convert", c);
        assert!(sub_m.get_flag("headers"));
        assert!(sub_m.get_many::<String>("file").is_some());

        let r = convert(&logger, sub_m, std::io::stdout()).unwrap();
        assert_eq!(5 - 2 + 1, r.messages_output);
        assert_eq!(persisted_msgs, r.messages_processed);
        assert!(file.close().is_ok());
    }

    #[test]
    fn hex_output() {
        let logger = new_logger();

        let mut file = NamedTempFile::new().unwrap();
        let file_path = String::from(file.path().to_str().unwrap());

        // persist some messages
        let persisted_msgs: adlt::dlt::DltMessageIndexType = 2;
        let ecu = dlt::DltChar4::from_buf(b"ECU1");

        for i in 0..persisted_msgs {
            let sh = adlt::dlt::DltStorageHeader {
                secs: i + (1640995200000000 / utils::US_PER_SEC) as u32, // 1.1.22, 00:00:00 as GMT
                micros: 0,
                ecu,
            };
            let standard_header = adlt::dlt::DltStandardHeader {
                htyp: 1 << 5, // vers 1
                mcnt: (i % 256) as u8,
                len: 4,
            };

            let m = adlt::dlt::DltMessage::from_headers(
                i,
                sh,
                standard_header,
                &[],
                vec![(i % 256) as u8, ((i + 1) % 256) as u8],
            );
            m.to_write(&mut file).unwrap(); // will persist with timestamp
        }
        file.flush().unwrap();

        let arg_vec = vec!["t", "convert", "-x", "-e2", file_path.as_str()];
        let sub_c = add_subcommand(Command::new("t")).get_matches_from(arg_vec);
        let (_c, sub_m) = sub_c.subcommand().unwrap();

        let output_buf = Vec::new();
        let output = std::io::BufWriter::new(output_buf);
        let r = convert(&logger, sub_m, output).unwrap();
        assert_eq!(2, r.messages_output);
        assert_eq!(persisted_msgs, r.messages_processed);
        file.close().unwrap();
        assert!(r.writer_screen.is_some());
        let output_buf = r.writer_screen.unwrap().into_inner().unwrap();
        assert!(!output_buf.is_empty());
        let s = String::from_utf8(output_buf).unwrap();
        //println!("{}", s);
        let lines: Vec<&str> = s.lines().collect();
        assert_eq!(persisted_msgs as usize, lines.len());
        assert_eq!(
            ":00.000000          0 000 ECU1 ---- ---- --- --- N - 0 [00 01]",
            &lines[0][18..] // time is in local format. so ignore here
        );
        assert_eq!(
            ":01.000000          0 001 ECU1 ---- ---- --- --- N - 0 [01 02]",
            &lines[1][18..]
        );
    }

    #[test]
    fn non_empty_sort_sorted_check_mcnt() {
        let logger = new_logger();

        let mut file = NamedTempFile::new().unwrap();
        let file_path = String::from(file.path().to_str().unwrap());

        // persist some messages
        let persisted_msgs: adlt::dlt::DltMessageIndexType = 10;
        let ecu = dlt::DltChar4::from_buf(b"ECU1");
        for i in 0..persisted_msgs {
            let sh = adlt::dlt::DltStorageHeader {
                secs: (1640995200000000 / utils::US_PER_SEC) as u32, // 1.1.22, 00:00:00 as GMT
                micros: 0,
                ecu,
            };
            let standard_header = adlt::dlt::DltStandardHeader {
                htyp: 1 << 5, // vers 1
                mcnt: (i % 256) as u8,
                len: 4,
            };

            let m = adlt::dlt::DltMessage::from_headers(i, sh, standard_header, &[], vec![]);
            m.to_write(&mut file).unwrap(); // will persist with timestamp
        }
        file.flush().unwrap();

        let arg_vec = vec!["t", "convert", "-a", "--sort", file_path.as_str()];
        let sub_c = add_subcommand(Command::new("t")).get_matches_from(arg_vec);
        let (c, sub_m) = sub_c.subcommand().unwrap();
        assert_eq!("convert", c);
        assert!(sub_m.get_many::<String>("file").is_some());

        let output_buf = Vec::new();
        let output = std::io::BufWriter::new(output_buf);

        let r = convert(&logger, sub_m, output).unwrap();
        assert_eq!(persisted_msgs, r.messages_output);
        assert_eq!(persisted_msgs, r.messages_processed);
        assert!(file.close().is_ok());
        // check output but we get the output only in the integration tests...
        assert!(r.writer_screen.is_some());
        let output_buf = r.writer_screen.unwrap().into_inner().unwrap();
        assert!(!output_buf.is_empty());
        let s = String::from_utf8(output_buf).unwrap();
        //println!("{}", s);
        let lines: Vec<&str> = s.lines().collect();
        assert_eq!(persisted_msgs as usize, lines.len());
        for (i, line) in lines.iter().enumerate() {
            // in this case the output should be sorted with mcnt from 0 to 9 (as all have timestamp 0 -> stable order)
            // mcnt is the 4th " " splitted
            let parts: Vec<&str> = line.split_ascii_whitespace().collect();
            assert_eq!(parts[4].parse::<u8>().unwrap(), (i % 256) as u8);
        }
    }

    #[test]
    fn non_empty_sort_sorted_check_mcnt_multiple() {
        // create two files and provide them in wrong order:

        let logger = new_logger();

        let mut file1 = NamedTempFile::new().unwrap();
        let file1_path = String::from(file1.path().to_str().unwrap());
        let mut file2 = NamedTempFile::new().unwrap();
        let file2_path = String::from(file2.path().to_str().unwrap());

        // provide a 3rd existing file that contains no dlt
        let mut file3 = NamedTempFile::new().unwrap();
        let file3_path = String::from(file3.path().to_str().unwrap());
        file3.write_all(b"this is a text only file").unwrap();
        file3.flush().unwrap();

        let file4_path = file3_path.clone() + "invalid";

        // persist some messages (15 each per file)
        let persisted_msgs: adlt::dlt::DltMessageIndexType = 30;
        let ecu = dlt::DltChar4::from_buf(b"ECU1");
        for i in 0..persisted_msgs {
            let sh = adlt::dlt::DltStorageHeader {
                secs: i + (1640995200000000 / utils::US_PER_SEC) as u32, // 1.1.22, 00:00:00 as GMT
                micros: 0,
                ecu,
            };
            let standard_header = adlt::dlt::DltStandardHeader {
                htyp: 1 << 5, // vers 1
                mcnt: (i % 256) as u8,
                len: 4,
            };

            let m = adlt::dlt::DltMessage::from_headers(i, sh, standard_header, &[], vec![]);
            m.to_write(if i < persisted_msgs / 2 {
                &mut file1
            } else {
                &mut file2
            })
            .unwrap(); // will persist with timestamp
        }
        file1.flush().unwrap();
        file2.flush().unwrap();

        let arg_vec = vec![
            "t",
            "convert",
            "-a",
            "--sort",
            file2_path.as_str(),
            file4_path.as_str(),
            file3_path.as_str(),
            file1_path.as_str(),
        ];
        let sub_c = add_subcommand(Command::new("t")).get_matches_from(arg_vec);
        let (_c, sub_m) = sub_c.subcommand().unwrap();

        let output_buf = Vec::new();
        let output = std::io::BufWriter::new(output_buf);

        let r = convert(&logger, sub_m, output).unwrap();
        assert_eq!(persisted_msgs, r.messages_output);
        assert_eq!(persisted_msgs, r.messages_processed);
        assert!(file1.close().is_ok());
        assert!(file2.close().is_ok());

        // check output but we get the output only in the integration tests...
        assert!(r.writer_screen.is_some());
        let output_buf = r.writer_screen.unwrap().into_inner().unwrap();
        assert!(!output_buf.is_empty());
        let s = String::from_utf8(output_buf).unwrap();
        //println!("{}", s);
        let lines: Vec<&str> = s.lines().collect();
        assert_eq!(persisted_msgs as usize, lines.len());
        for (i, line) in lines.iter().enumerate() {
            // in this case the output should be sorted with mcnt from 0 to 9 (as all have timestamp 0 -> stable order)
            // mcnt is the 4th " " splitted
            let parts: Vec<&str> = line.split_ascii_whitespace().collect();
            assert_eq!(parts[4].parse::<u8>().unwrap(), (i % 256) as u8);
        }
    }

    #[test]
    fn output_to_file() {
        let logger = new_logger();

        let mut file = NamedTempFile::new().unwrap();
        let file_path = String::from(file.path().to_str().unwrap());

        // persist some messages
        let persisted_msgs: adlt::dlt::DltMessageIndexType = 10;
        let ecu = dlt::DltChar4::from_buf(b"ECU1");
        for i in 0..persisted_msgs {
            let sh = adlt::dlt::DltStorageHeader {
                secs: (1640995200000000 / utils::US_PER_SEC) as u32, // 1.1.22, 00:00:00 as GMT
                micros: 0,
                ecu,
            };
            let standard_header = adlt::dlt::DltStandardHeader {
                htyp: 1 << 5, // vers 1
                mcnt: (i % 256) as u8,
                len: 4,
            };

            let m = adlt::dlt::DltMessage::from_headers(i, sh, standard_header, &[], vec![]);
            m.to_write(&mut file).unwrap(); // will persist with timestamp
        }
        file.flush().unwrap();

        let output_file = NamedTempFile::new().unwrap();
        let output_file_path = String::from(output_file.path().to_str().unwrap());

        let arg_vec = vec![
            "t",
            "convert",
            "-b2",
            "-e5",
            file_path.as_str(),
            "-o",
            &output_file_path,
        ];
        let sub_c = add_subcommand(Command::new("t")).get_matches_from(arg_vec);
        let (_, sub_m) = sub_c.subcommand().unwrap();

        let r = convert(&logger, sub_m, std::io::stdout()).unwrap();
        assert_eq!(5 - 2 + 1, r.messages_output);
        assert_eq!(persisted_msgs, r.messages_processed);
        assert!(file.close().is_ok());

        // check that output file has now the expected (number of) msgs:
        let arg_vec = vec!["t", "convert", &output_file_path];
        let sub_c = add_subcommand(Command::new("t")).get_matches_from(arg_vec);
        let (_, sub_m) = sub_c.subcommand().unwrap();
        let r = convert(&logger, sub_m, std::io::stdout()).unwrap();
        assert_eq!(5 - 2 + 1, r.messages_processed);
        assert!(output_file.close().is_ok());
    }

    #[test]
    fn eacfilter_fromstr() {
        assert!(EacFilter::from_str("").is_err());
        assert!(EacFilter::from_str("ecuŊ").is_err()); // non ascii
        assert!(EacFilter::from_str("ecu:a(").is_err()); // ctid invalid regex
        assert!(EacFilter::from_str("ecu::c|\\").is_err()); // ctid invalid regex

        // TODO not working! assert!(EacFilter::from_str("e|uŊ").is_err()); // apid non ascii regex...
        let f = EacFilter::from_str("ECU1:APID:CTID").unwrap().filter;
        assert_eq!(f.ecu, Some(Char4OrRegex::from_str("ECU1", false).unwrap()));
        assert_eq!(f.apid, Some(Char4OrRegex::from_str("APID", false).unwrap()));
        assert_eq!(f.ctid, Some(Char4OrRegex::from_str("CTID", false).unwrap()));

        let f = EacFilter::from_str("ECU1:APID|API2").unwrap().filter;
        assert_eq!(f.ecu, Some(Char4OrRegex::from_str("ECU1", false).unwrap()));
        assert_eq!(
            f.apid,
            Some(Char4OrRegex::from_str("APID|API2", true).unwrap())
        );
        assert_eq!(f.ctid, None);

        let f = EacFilter::from_str("ECU1|ECU2::CTID|CT").unwrap().filter;
        assert_eq!(
            f.ecu,
            Some(Char4OrRegex::from_str("ECU1|ECU2", true).unwrap())
        );
        assert_eq!(f.apid, None);
        assert_eq!(
            f.ctid,
            Some(Char4OrRegex::from_str("CTID|CT", true).unwrap())
        );
    }

    #[test]
    fn filter_eac() {
        let logger = new_logger();

        let mut file = NamedTempFile::new().unwrap();
        let file_path = String::from(file.path().to_str().unwrap());

        // persist some messages
        let persisted_msgs: adlt::dlt::DltMessageIndexType = 5;
        let ecu = dlt::DltChar4::from_buf(b"ECU1");
        for i in 0..persisted_msgs {
            let sh = adlt::dlt::DltStorageHeader {
                secs: (1640995200000000 / utils::US_PER_SEC) as u32, // 1.1.22, 00:00:00 as GMT
                micros: 0,
                ecu,
            };
            let standard_header = adlt::dlt::DltStandardHeader {
                htyp: 1 << 5, // vers 1
                mcnt: (i % 256) as u8,
                len: 4,
            };

            let m = adlt::dlt::DltMessage::from_headers(i, sh, standard_header, &[], vec![]);
            m.to_write(&mut file).unwrap(); // will persist with timestamp
        }
        file.flush().unwrap();

        let arg_vec = vec!["t", "convert", "-a", "-F=ECU1,ECU2", file_path.as_str()];
        let sub_c = add_subcommand(Command::new("t")).get_matches_from(arg_vec);
        let (c, sub_m) = sub_c.subcommand().unwrap();
        assert_eq!("convert", c);
        assert_eq!(sub_m.get_many::<EacFilter>("filter_eac").unwrap().len(), 2);

        let r = convert(&logger, sub_m, std::io::stdout()).unwrap();
        assert_eq!(persisted_msgs, r.messages_output);
        assert_eq!(persisted_msgs, r.messages_processed);

        let arg_vec = vec![
            "t",
            "convert",
            "-a",
            "-F=ECU2:AP2:CT2,ECU3::CT3,ECU4::",
            file_path.as_str(),
        ];
        let sub_c = add_subcommand(Command::new("t")).get_matches_from(arg_vec);
        let (c, sub_m) = sub_c.subcommand().unwrap();
        assert_eq!("convert", c);
        assert_eq!(sub_m.get_many::<EacFilter>("filter_eac").unwrap().len(), 3);

        let r = convert(&logger, sub_m, std::io::stdout()).unwrap();
        assert_eq!(0, r.messages_output);
        assert_eq!(persisted_msgs, r.messages_processed);

        assert!(file.close().is_ok());
    }

    #[test]
    fn filter_file() {
        let logger = new_logger();

        let mut file = NamedTempFile::new().unwrap();
        let file_path = String::from(file.path().to_str().unwrap());

        let persisted_msgs: adlt::dlt::DltMessageIndexType = 100;
        let ecu = dlt::DltChar4::from_buf(b"ECU1");
        for i in 0..persisted_msgs {
            let sh = adlt::dlt::DltStorageHeader {
                secs: (1640995200000000 / utils::US_PER_SEC) as u32, // 1.1.22, 00:00:00 as GMT
                micros: 0,
                ecu,
            };
            let standard_header = adlt::dlt::DltStandardHeader {
                htyp: 1 << 5, // vers 1
                mcnt: (i % 256) as u8,
                len: 4,
            };

            let m = adlt::dlt::DltMessage::from_headers(i, sh, standard_header, &[], vec![]);
            m.to_write(&mut file).unwrap(); // will persist with timestamp
        }
        file.flush().unwrap();

        // create a filter file with dlt-convert format:
        let mut filter_file = NamedTempFile::new().unwrap();
        let filter_file_path = String::from(filter_file.path().to_str().unwrap());
        filter_file.write_all(b"APID CTID ").unwrap();

        let arg_vec = vec![
            "t",
            "convert",
            "-a",
            "-f",
            filter_file_path.as_str(),
            file_path.as_str(),
        ];
        let sub_c = add_subcommand(Command::new("t")).get_matches_from(arg_vec);
        let (_c, sub_m) = sub_c.subcommand().unwrap();

        let r = convert(&logger, sub_m, std::io::stdout()).unwrap();
        assert_eq!(0, r.messages_output);
        assert_eq!(persisted_msgs, r.messages_processed);
        filter_file.close().unwrap();

        // create a filter file with dlf format:
        let mut filter_file = NamedTempFile::new().unwrap();
        let filter_file_path = String::from(filter_file.path().to_str().unwrap());
        filter_file
            .write_all(b"<dltfilter><filter><type>1</type><ecuid>ECU1</ecuid><enableecuid>1</enableecuid><enablefilter>1</enablefilter></filter></dltfilter>")
            .unwrap();

        let arg_vec = vec![
            "t",
            "convert",
            "-a",
            "-f",
            filter_file_path.as_str(),
            file_path.as_str(),
        ];
        let sub_c = add_subcommand(Command::new("t")).get_matches_from(arg_vec);
        let (_c, sub_m) = sub_c.subcommand().unwrap();

        let r = convert(&logger, sub_m, std::io::stdout()).unwrap();
        assert_eq!(0, r.messages_output);
        assert_eq!(persisted_msgs, r.messages_processed);
        assert!(file.close().is_ok());
        filter_file.close().unwrap();
    }

    #[test]
    fn file_transfer1() {
        // test single file transfer via console and
        //  that the file transfer is automatically detected at last FLDA package (and not only on FLFI)
        let logger = new_logger();

        let mut file = NamedTempFile::new().unwrap();
        let file_path = String::from(file.path().to_str().unwrap());

        let payload = payload_from_args(
            &[
                (DLT_TYPE_INFO_STRG, b"FLST\0" as &[u8]),
                (
                    DLT_TYPE_INFO_UINT | DLT_TYLE_32BIT as u32,
                    &17u32.to_le_bytes(), // serial
                ),
                (DLT_TYPE_INFO_STRG, b"test_file.bin\0" as &[u8]), // file name
                (
                    DLT_TYPE_INFO_UINT | DLT_TYLE_32BIT as u32,
                    &4u32.to_le_bytes(), // filesize
                ),
                (DLT_TYPE_INFO_STRG, b"2022-06-02 21:54:00\0"), // creation date
                (
                    DLT_TYPE_INFO_UINT | DLT_TYLE_32BIT as u32,
                    &1u32.to_le_bytes(), // nr packages
                ),
                (
                    DLT_TYPE_INFO_UINT | DLT_TYLE_32BIT as u32,
                    &512u32.to_le_bytes(), // buffer size
                ),
                (DLT_TYPE_INFO_STRG, b"FLST\0"),
            ]
            .iter()
            .map(|a| DltArg {
                type_info: a.0,
                is_big_endian: false,
                payload_raw: a.1,
            })
            .collect::<Vec<DltArg>>(),
        );
        let persisted_msgs = 2;

        let m_flst = DltMessage::get_testmsg_with_payload(false, 8, &payload);

        m_flst.to_write(&mut file).unwrap();
        let payload = payload_from_args(
            &[
                (DLT_TYPE_INFO_STRG, b"FLDA\0" as &[u8]),
                (
                    DLT_TYPE_INFO_UINT | DLT_TYLE_32BIT as u32,
                    &17u32.to_le_bytes(),
                ),
                (
                    DLT_TYPE_INFO_SINT | DLT_TYLE_32BIT as u32,
                    &1i32.to_le_bytes(),
                ),
                (DLT_TYPE_INFO_RAWD, b"data"),
                (DLT_TYPE_INFO_STRG, b"FLDA\0" as &[u8]),
            ]
            .iter()
            .map(|a| DltArg {
                type_info: a.0,
                is_big_endian: false,
                payload_raw: a.1,
            })
            .collect::<Vec<DltArg>>(),
        );
        let m_flda = DltMessage::get_testmsg_with_payload(false, 5, &payload);
        m_flda.to_write(&mut file).unwrap();
        file.flush().unwrap();

        let arg_vec = vec![
            "t",
            "convert",
            "--file_transfer=true",
            "--file_transfer_ctid",
            "CTID",
            file_path.as_str(),
        ];
        let sub_c = add_subcommand(Command::new("t")).get_matches_from(arg_vec);
        let (_c, sub_m) = sub_c.subcommand().unwrap();

        let output_buf = Vec::new();
        let output = std::io::BufWriter::new(output_buf);

        let r = convert(&logger, sub_m, output).unwrap();
        assert_eq!(0, r.messages_output);
        assert_eq!(persisted_msgs, r.messages_processed);

        let output_buf = r.writer_screen.unwrap().into_inner().unwrap();
        assert!(!output_buf.is_empty());
        let s = String::from_utf8(output_buf).unwrap();
        assert!(s.contains("have 1 file transfer"));

        assert!(file.close().is_ok());
    }

    /// A Writer based on a Vec<u8> that can be used to log to and compare output
    #[derive(Clone)]
    struct TestWriter {
        storage: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    }

    impl TestWriter {
        fn new() -> Self {
            TestWriter {
                storage: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            }
        }

        fn into_string(self) -> String {
            String::from_utf8(self.storage.lock().unwrap().to_vec()).unwrap()
        }
    }
    impl Write for TestWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.storage.lock().unwrap().write(buf)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.storage.lock().unwrap().flush()
        }
    }

    #[test]
    fn file_plugins() {
        let log_output = TestWriter::new();
        {
            let decorator = slog_term::PlainSyncDecorator::new(log_output.clone());
            let drain = slog_term::FullFormat::new(decorator).build().fuse();
            let logger = Logger::root(drain, o!());

            let arg_vec = vec![
                "t",
                "convert",
                "--nonverbose_path",
                "tests/",
                "--someip_path",
                "./",
                "--rewrite_path",
                "tests/rewrite.cfg",
                "--can_path",
                "tests/",
                "tests/lc_ex002.dlt",
            ];
            let sub_c = add_subcommand(Command::new("t")).get_matches_from(arg_vec);
            let (_c, sub_m) = sub_c.subcommand().unwrap();

            let output_buf = Vec::new();
            let output = std::io::BufWriter::new(output_buf);

            let r = convert(&logger, sub_m, output).unwrap();
            assert_eq!(0, r.messages_output);

            let output_buf = r.writer_screen.unwrap().into_inner().unwrap();
            assert!(!output_buf.is_empty());
            let s = String::from_utf8(output_buf).unwrap();
            assert!(
                s.contains("Plugin SomeIp generated 1 warning:"),
                "s='\n{}\n'",
                s
            );
        }
        let s = log_output.into_string();
        assert!(s.contains("Non-Verbose plugin used:"), "{}", s);
        assert!(s.contains("SomeIp plugin used:"), "{}", s);
        assert!(s.contains("Rewrite plugin used:"), "{}", s);
        assert!(s.contains("CAN plugin used:"), "{}", s);
    }
}
