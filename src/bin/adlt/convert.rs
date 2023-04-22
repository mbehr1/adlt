use chrono::{Local, TimeZone};
use clap::{Arg, Command};
use glob::{glob_with, MatchOptions};
use slog::{debug, error, info, warn};
use std::{
    fs::File,
    io::{prelude::*, BufWriter},
    sync::mpsc::channel,
};

use adlt::{
    dlt::{DltChar4, DLT_MAX_STORAGE_MSG_SIZE},
    filter::functions::{filters_from_convert_format, filters_from_dlf},
    plugins::{
        anonymize::AnonymizePlugin, file_transfer::FileTransferPlugin, plugin::Plugin,
        plugins_process_msgs,
    },
    utils::{
        buf_as_hex_to_io_write, get_dlt_message_iterator, get_new_namespace, LowMarkBufReader,
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
                .help("Anonymize the output. Rewrite APID, CTIDs,sw_versiona and payload. Useful only for lifecycle detection tests.")
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
                Arg::new("debug_verify_sort")
                .long("debug_verify_sort")
                .num_args(0)
                .help("Verify the sort order in the output (for --sort) per ECU and per ECU/APID. This is slow! Use it only for debugging!")
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
    let mut input_file_names: Vec<String> = sub_m
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

    let do_anonimize = sub_m.get_flag("anon");

    let do_file_transfer = sub_m.get_many::<String>("file_transfer").is_some();

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
    let filters = if let Some(filter_file) = filter_file {
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

    let output_file = sub_m.get_one::<String>("output_file").map(|s| s.to_owned());
    info!(log, "convert have {} input files", input_file_names.len(); "index_first"=>index_first, "index_last"=>index_last);
    debug!(log, "convert "; "input_file_names" => format!("{:?}",&input_file_names), "filter_lc_ids" => format!("{:?}",filter_lc_ids), "sort_by_time" => sort_by_time, "output_file" => &output_file, "filter_file" => &filter_file, "filters" =>  format!("{:?}",&filters) );

    // if we have multiple files we do need to sort them first by the first log reception_time!
    // we follow this path even if there is just one paramater as it might be a glob expression

    // map input_file_names to name/first msg
    let namespace = get_new_namespace();
    let file_msgs = input_file_names.iter().flat_map(|f_name| {
            let path = std::path::Path::new(f_name);
            let fi = File::open(path);
            match fi {
                Ok(mut f) => {
                    let file_ext = std::path::Path::new(&f_name).extension().and_then(|s|s.to_str()).unwrap_or_default();
                    let m1 = adlt::utils::get_first_message_from_file(file_ext, &mut f, 512 * 1024, namespace);
                    if m1.is_none() {
                        warn!(log, "file {} ({}) (ext: '{}') doesn't contain a DLT message in first 0.5MB. Skipping!", f_name, path.canonicalize().unwrap_or_else(|_|std::path::PathBuf::from(f_name)).display(), file_ext;);
                    }
                    vec![(path.canonicalize().unwrap_or_else(|_|std::path::PathBuf::from(f_name)).to_string_lossy().to_string(), Ok(m1))]
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
                                let m1 = adlt::utils::get_first_message_from_file(file_ext, &mut f, 512 * 1024, namespace);
                                if m1.is_none() {
                                    warn!(log, "globbed file '{}' (ext: '{}') doesn't contain a DLT message in first 0.5MB. Skipping!", f_name, file_ext;);
                                }
                                let path_glob = std::path::Path::new(glob_name);
                                (path_glob.canonicalize().unwrap_or_else(|_|glob_name.to_path_buf()).to_string_lossy().to_string(), Ok(m1))
                            }else{
                                (glob_name.to_string_lossy().to_string(), Err(std::io::Error::from(std::io::ErrorKind::NotFound)))
                            }
                        }).collect::<Vec<_>>()
                    }else{
                        warn!(log, "couldn't open '{}'. Skipping!", f_name;);
                        vec![(f_name.to_owned(), Err(std::io::Error::from(std::io::ErrorKind::NotFound)))]
                    }
                }
            }
        });

    let (files_ok, _files_err): (Vec<_>, Vec<_>) = file_msgs.partition(|(_, b)| b.is_ok());

    if files_ok.is_empty() {
        return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
    }

    let mut file_msgs: Vec<_> = files_ok
        .into_iter()
        .map(|(a, b)| (a, b.unwrap()))
        .filter(|(_a, b)| b.is_some())
        .map(|(a, b)| (a, b.unwrap()))
        .collect();
    file_msgs.sort_by(|a, b| a.1.reception_time_us.cmp(&b.1.reception_time_us));
    // todo if the reception time is similar for duplicates the ones with same name might not be consecutive! (will need additional sorting)

    input_file_names = file_msgs.iter().map(|(a, _b)| a.clone()).collect();
    input_file_names.dedup(); // remove duplicates now that they are sorted/consecutive
    debug!(log, "sorted input_files by first message reception time:"; "input_file_names" => format!("{:?}",&input_file_names));

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

    // setup (thread) filter chain:
    let (tx_for_parse_thread, rx_from_parse_thread) = channel(); // msg -> parse_lifecycles (t2)
    let (tx_for_lc_thread, rx_from_lc_thread) = channel(); // parse_lifecycles -> buffer_sort_messages (t3)
    let (lcs_r, lcs_w) =
        evmap::new::<adlt::lifecycle::LifecycleId, adlt::lifecycle::LifecycleItem>();
    let lc_thread = std::thread::spawn(move || {
        adlt::lifecycle::parse_lifecycles_buffered_from_stream(
            lcs_w,
            rx_from_parse_thread,
            tx_for_lc_thread,
        )
    });

    let (plugin_thread, rx_from_plugin_thread) = if !plugins_active.is_empty() {
        let (tx_for_plugin_thread, rx_from_plugin_thread) = std::sync::mpsc::channel();
        (
            Some(std::thread::spawn(move || {
                plugins_process_msgs(rx_from_lc_thread, tx_for_plugin_thread, plugins_active)
            })),
            rx_from_plugin_thread,
        )
    } else {
        (None, rx_from_lc_thread)
    };

    let sort_thread_lcs_r = lcs_r.clone();
    let (sort_thread, rx_final) = if sort_by_time {
        let (tx_for_sort_thread, rx_from_sort_thread) = channel();
        (
            Some(std::thread::spawn(move || {
                adlt::utils::buffer_sort_messages(
                    rx_from_plugin_thread,
                    tx_for_sort_thread,
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
        let (tx_filter, rx_filter) = channel();
        (
            Some(std::thread::spawn(move || {
                adlt::filter::functions::filter_as_streams(&filters, &rx_final, &tx_filter)
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
            let mut last_timestamp_by_lc_map= std::collections::BTreeMap::<adlt::lifecycle::LifecycleId, (u32, std::collections::HashMap::<DltChar4,(u32,adlt::dlt::DltMessageIndexType)>)>::new();

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

    for input_file_name in &input_file_names {
        let fi = File::open(input_file_name)?;
        info!(log, "opened file {} {:?}", &input_file_name, &fi);
        let buf_reader = LowMarkBufReader::new(fi, BUFREADER_CAPACITY, DLT_MAX_STORAGE_MSG_SIZE);
        let mut it = get_dlt_message_iterator(
            std::path::Path::new(&input_file_name)
                .extension()
                .and_then(|s| s.to_str())
                .unwrap_or(""),
            messages_processed,
            buf_reader,
            namespace,
            Some(log),
        );
        loop {
            match it.next() {
                Some(msg) => {
                    messages_processed += 1;
                    tx_for_parse_thread.send(msg).unwrap(); // todo handle error
                }
                None => {
                    debug!(log, "finished processing a file";"messages_processed"=>messages_processed);
                    break;
                }
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
        if let Some(..) = writer_screen {
            let writer_screen = writer_screen.as_mut().unwrap();
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
                if plugin.name() == "file_transfer" {
                    let plugin_state = plugin.state();
                    let state = plugin_state.read().unwrap();
                    debug!(log, "file_transfer.state.value={:?}", state.value);
                    // output the files detected:
                    if let Some(tree_items) = state.value["treeItems"].as_array() {
                        if !tree_items.is_empty() {
                            writeln!(writer_screen, "have {} file transfers:", tree_items.len())?;
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
            &vec![
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
            &vec![
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
}
