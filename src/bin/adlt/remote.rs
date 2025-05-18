// todos
// [ ] sort by time is only per lifecycle. could interleave lifecycles from different ecus as well (eg bugs-41250)

use adlt::{
    dlt::{DltChar4, DltMessageIndexType, DLT_MAX_STORAGE_MSG_SIZE},
    lifecycle::LifecycleId,
    plugins::{
        factory::get_plugin,
        plugin::{Plugin, PluginState},
        plugins_process_msgs,
    },
    utils::{
        eac_stats::EacStats,
        get_dlt_infos_from_file, get_dlt_message_iterator, get_new_namespace,
        progress::{ProgressNonAsyncFuture, ProgressPoll},
        remote_types,
        remote_utils::{match_filters, process_stream_new_msgs, StreamContext},
        seekablechain::SeekableChain,
        sorting_multi_readeriterator::{SequentialMultiIterator, SortingMultiReaderIterator},
        sync_sender_send_delay_if_full,
        unzip::{
            archive_contents_metadata, archive_contents_read_dir, archive_get_path_and_glob,
            archive_is_supported_filename, archive_supported_fileexts, extract_archives,
            is_part_of_multi_volume_archive, list_archive_contents_cached,
            search_dir_for_multi_volume_archive,
        },
        DltFileInfos, LowMarkBufReader,
    },
};
use clap::{value_parser, Arg, Command};
use nohash_hasher::NoHashHasher;
use slog::{debug, error, info, warn};
use std::{
    collections::{BTreeMap, HashSet},
    fs::File,
    hash::BuildHasherDefault,
    io::prelude::*,
    net::TcpListener,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{sync_channel, Receiver, SendError},
        Arc, RwLock,
    },
    time::Instant,
};
use tempfile::TempDir;
use tungstenite::{
    accept_hdr_with_config,
    handshake::server::{Request, Response},
    Message, WebSocket,
};

use adlt::filter::{Filter, FilterKind, FilterKindContainer};

use bincode::config;

const BINCODE_CONFIG: config::Configuration<config::LittleEndian, config::Fixint, config::NoLimit> =
    config::legacy(); // todo choose local endianess

pub fn add_subcommand(app: Command) -> Command {
    app.subcommand(
        Command::new("remote")
            .about("Provide remote server functionalities")
            .arg(
                Arg::new("port")
                    .short('p')
                    .num_args(1)
                    .help("websocket port to use")
                    .default_value("6665")
                    .value_parser(clap::value_parser!(u16)),
            )
            .arg(
                Arg::new("listen_address")
                    .long("listen_address")
                    .num_args(1)
                    .help("websocket ipv4 address to listen/bind to")
                    .default_value("127.0.0.1")
                    .value_parser(value_parser!(std::net::Ipv4Addr)),
            ),
    )
}

/// provide remote server functionalities
pub fn remote(
    log: &slog::Logger,
    sub_m: &clap::ArgMatches,
    just_one_connection: bool, // only used for testing
) -> Result<(), Box<dyn std::error::Error>> {
    // we do use log only if for local websocket related issues
    // for the remote part we do use an own logger logging to the websocket itself todo
    let ip_addr = sub_m
        .get_one::<std::net::Ipv4Addr>("listen_address")
        .unwrap();
    let port = sub_m.get_one::<u16>("port").unwrap();
    info!(log, "remote starting"; "port" => port);

    let server_addr = format!("{}:{}", ip_addr, port); // todo ipv6???
    let server = TcpListener::bind(server_addr)?;
    // server.set_nonblocking(true).expect("Cannot set non-blocking");
    info!(log, "remote server listening on {}:{}", ip_addr, port; "port" => port);
    // output on stdout as well to help identify a proper startup even with verbose options:
    println!("remote server listening on {}:{}", ip_addr, port); // todo use server.local_addr() and exist in case of failure?

    let mut spawned_servers = vec![];
    let no_more_incoming_cons = just_one_connection;

    for stream in server.incoming() {
        let logc = log.clone();
        spawned_servers.push(
            std::thread::Builder::new()
                .name("server".to_string())
                .spawn(move || {
                    let log = logc;
                    let callback = |req: &Request, mut response: Response| {
                        info!(log, "Received a new ws handshake");
                        info!(log, "The request's path is: {}", req.uri().path());
                        info!(log, "The request's headers are:");
                        for (ref header, value) in req.headers() {
                            info!(log, "* {}:{:?}", header, value);
                        }

                        // Let's add an additional header to our response to the client.
                        let headers = response.headers_mut();
                        headers.append("adlt-version", clap::crate_version!().parse().unwrap());
                        headers.append(
                            "adlt-archives-supported",
                            archive_supported_fileexts().join(",").parse().unwrap(),
                        );
                        Ok(response)
                    };

                    let web_socket_config = tungstenite::protocol::WebSocketConfig {
                        max_message_size: Some(1_000_000_000),
                        max_send_queue: None,
                        max_frame_size: None,
                        accept_unmasked_frames: false,
                    };

                    let a_stream = stream.unwrap();
                    // we set a larger initial timeout as e.g. on vscode restart the accept fail often with read timeouts
                    a_stream
                        .set_read_timeout(Some(std::time::Duration::from_millis(5000)))
                        .expect("failed to set_read_timeout"); // panic on failure
                    a_stream
                        .set_write_timeout(None)
                        .expect("failed to set_write_timeout");
                    let websocket_res =
                        accept_hdr_with_config(a_stream, callback, Some(web_socket_config));
                    if websocket_res.is_err() {
                        warn!(log, "websocket accept failed. thread done");
                        return;
                    }
                    let mut websocket = websocket_res.unwrap();

                    // now reduce read timeout to 100ms
                    websocket
                        .get_ref()
                        .set_read_timeout(Some(std::time::Duration::from_millis(100)))
                        .expect("failed to set_read_timeout"); // panic on failure;

                    let mut file_context: Option<FileContext> = None;

                    // we do a kind of event loop here
                    // 1st check for any new DltMessages from any started threads and process those
                    // 2nd check for new websocket messages from the client
                    // the socket is configured with a read timeout so that reading doesn't block for long
                    // todo change to event/poll alike solution

                    let mut last_all_msgs_len = usize::MAX;
                    loop {
                        // 1st step any new messages to process
                        if let Some(ref mut fc) = file_context {
                            let r = process_file_context(&log, fc, &mut websocket);
                            if r.is_err() {
                                warn!(log, "ws process_file_context returned err {:?}", r);
                                break;
                            }
                        }

                        let msg = websocket.read_message();
                        if let Err(err) = msg {
                            match err {
                                tungstenite::Error::Io(ref e)
                                    if e.kind() == std::io::ErrorKind::WouldBlock
                                        || e.kind() == std::io::ErrorKind::TimedOut =>
                                {
                                    let all_msgs_len = if let Some(ctx) = &file_context {
                                        ctx.all_msgs.len()
                                    } else {
                                        0
                                    };
                                    if all_msgs_len != last_all_msgs_len {
                                        last_all_msgs_len = all_msgs_len;
                                        info!(
                                    log,
                                    "ws read_message returned WouldBlock. all_msgs.len()={}",
                                    all_msgs_len
                                );
                                    }
                                    continue;
                                }
                                _ => {
                                    warn!(log, "ws read_message returned err {:?}", err);
                                    break;
                                }
                            }
                        }
                        let msg = msg.unwrap();
                        match msg {
                            Message::Text(t) => process_incoming_text_message(
                                &log,
                                t,
                                &mut file_context,
                                &mut websocket,
                            ),
                            Message::Binary(b) => {
                                info!(log, "got binary message with len {}", b.len());
                            }
                            Message::Frame(b) => {
                                info!(log, "got frame message with len {}", b.len());
                            }
                            Message::Close(cf) => {
                                warn!(log, "got close message with {:?}", cf);
                                break;
                            }
                            Message::Ping(_) | Message::Pong(_) => {}
                        }
                    }
                    let _ = websocket.write_pending(); // ignore error
                    warn!(log, "websocket thread done");
                })
                .unwrap(),
        );
        if no_more_incoming_cons {
            break;
        }
    }

    info!(
        log,
        "waiting for {:?} servers to join/finish",
        spawned_servers.len()
    );
    // join all spawned servers here:
    for server in spawned_servers {
        let _ = server.join(); // ignore any errors
    }

    info!(log, "remote stopped"; "port" => port);
    Ok(())
}

type SetOfEcuIds = HashSet<DltChar4>;
type StreamEntry = (SetOfEcuIds, Vec<(u64, String, DltFileInfos)>);
type ProgressPendingExtract = ProgressNonAsyncFuture<(Vec<StreamEntry>, Vec<(String, TempDir)>)>;

#[derive(Debug, PartialEq)]
enum CollectMode {
    All,
    OnePassStreams,
    None,
}

#[derive(Debug)]
struct FileContext {
    pending_extract: Option<ProgressPendingExtract>,
    file_streams: Vec<StreamEntry>, // set of files that need to be processed as parallel streams
    temp_dirs: Vec<(String, TempDir)>, // set of temp dirs for extracted archives content
    namespace: u32,
    sort_by_time: bool,                          // sort by timestamp
    plugins_active: Vec<Box<dyn Plugin + Send>>, // will be moved to parsing_thread
    plugin_states: Vec<(u32, Arc<RwLock<PluginState>>)>,
    parsing_thread: Option<ParserThreadType>,
    collect_mode: CollectMode,
    all_msgs: Vec<adlt::dlt::DltMessage>,
    /// drained/removed from the start of all_msgs.. Used for collect_mode=OnePassStreams
    drained_all_msgs: usize,
    streams: Vec<StreamContext>,
    paused: bool,
    /// we did send lifecycles with that lcs_w_refresh_idx
    last_lcs_w_refresh_index: u32,

    /// stats like ecu, apid, ctid:
    eac_stats: EacStats,
    eac_next_send_time: Instant,
    eac_last_nr_msgs: DltMessageIndexType,
    did_inform_parser_processing_finished: bool,
}

impl FileContext {
    /// create a file context from a json string
    ///
    /// supported json keys:
    /// - `files`: array of strings with file names
    /// - `sort`: bool (default false) do sort by calculated time/ lc & timestamp (or by file index/order)
    /// - `collect`: bool (default true) determines whether msgs should be collected into all_msgs
    /// - `plugins`: array of objects with plugin specific settings
    ///
    fn from(
        log: &slog::Logger,
        command: &str,
        json_str: &str,
    ) -> Result<FileContext, std::io::Error> {
        let mut file_names: Vec<String> = vec![];

        let v = serde_json::from_str::<serde_json::Value>(json_str)?;
        debug!(log, "FileContext::from({}:{}) = {:?}", command, json_str, v);

        let mut eac_stats = EacStats::new();

        match &v["files"] {
            serde_json::Value::Array(a) => {
                for file in a {
                    if file.is_string() {
                        let file_str = file.as_str().unwrap();
                        info!(log, "FileContext files got '{}'", file_str);
                        file_names.push(file_str.to_string());
                    } else {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "wrong type for 'files'",
                        ));
                    }
                }
            }
            serde_json::Value::Null => {} // no file (leads to an error later)
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "wrong type for 'files'",
                ));
            }
        }

        let sort_by_time = match &v["sort"] {
            serde_json::Value::Bool(b) => *b,
            _ => false, // we default to non sorted
        };

        let collect_mode: CollectMode = match &v["collect"] {
            serde_json::Value::Bool(b) => {
                if *b {
                    CollectMode::All
                } else {
                    CollectMode::None
                }
            }
            serde_json::Value::String(s) => match s.as_str() {
                "all" | "true" => CollectMode::All,
                "one_pass_streams" => CollectMode::OnePassStreams,
                "none" | "false" => CollectMode::None,
                s => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("invalid value ({s}) for 'collect'. Use 'all', 'one_pass_streams' or 'none'."),
                    ))
                }
            },
            _ => CollectMode::All, // we default to "do collect"
        };
        // we default to not paused except for OnePassStreams
        let paused = match collect_mode {
            CollectMode::All => false,
            CollectMode::OnePassStreams => true,
            CollectMode::None => false,
        };

        if file_names.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "at least one file name needed",
            ));
        }
        let namespace = get_new_namespace();

        // archive support:
        let have_archives = file_names
            .iter()
            .any(|f| archive_get_path_and_glob(std::path::Path::new(f)).is_some());
        let (pending_extract, all_msgs, input_file_streams) = if have_archives {
            let log = log.clone();
            let pending_extract =
                ProgressNonAsyncFuture::spawn(move |upd_progress, shall_cancel| {
                    let mut temp_dirs: Vec<(String, TempDir)> = vec![]; // need to keep them till the end. Pair of path/file_name and corresp. temp dir where we extracted to
                    let initial_file_names_len = file_names.len() as u32;
                    upd_progress(0, initial_file_names_len);
                    let mut did_process = 0;
                    let prev_len = file_names.len();
                    let file_names: Vec<String> = file_names
                        .into_iter() // todo might benefit from par_iter...
                        .flat_map(|file_name| {
                            if !shall_cancel.load(Ordering::Relaxed) {
                                let v = extract_archives(
                                    file_name,
                                    &mut temp_dirs,
                                    &shall_cancel,
                                    &log,
                                );
                                did_process += 1;
                                upd_progress(did_process, initial_file_names_len);
                                v
                            } else {
                                vec![]
                            }
                        })
                        .collect();
                    if file_names.len() != prev_len || !temp_dirs.is_empty() {
                        info!(
                            log,
                            "have {} files after archive check and {} tempdirs",
                            file_names.len(),
                            temp_dirs.len()
                        );
                    }
                    // map input_file_names to name/first msg
                    let (_sum_file_len, input_file_streams) =
                        file_names_to_file_streams(file_names, namespace, &log);

                    // todo: return error here if no files found
                    // todo: allocate all_msgs with size estimate?

                    // Vec<StreamEntry>, Vec<(String, TempDir)>)
                    (input_file_streams, temp_dirs)
                });
            (Some(pending_extract), Vec::new(), Vec::new())
        } else {
            // map input_file_names to name/first msg
            let (sum_file_len, input_file_streams) =
                file_names_to_file_streams(file_names, namespace, log);
            if input_file_streams.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "cannot open files or files contain no DLT messages",
                ));
            }

            let all_msgs_len_estimate = sum_file_len / 128; // todo better heuristics? e.g. 20gb dlt -> 117mio msgs
            info!(
                log,
                "FileContext sum_file_len={} -> estimated #msgs = {}",
                sum_file_len,
                all_msgs_len_estimate
            );
            let all_msgs = Vec::with_capacity(match collect_mode {
                CollectMode::All => {
                    std::cmp::min(all_msgs_len_estimate as usize, u32::MAX as usize)
                }
                CollectMode::OnePassStreams => 1024 * 1024, // todo better heuristics?
                CollectMode::None => 0,
            });
            (None, all_msgs, input_file_streams)
        };

        // plugins
        let mut plugins_active: Vec<Box<dyn Plugin + Send>> = vec![];
        match &v["plugins"] {
            serde_json::Value::Array(a) => {
                for plugin in a {
                    if plugin.is_object() {
                        info!(log, "FileContext plugins got '{:?}'", plugin.as_object());
                        let p = get_plugin(plugin.as_object().unwrap(), &mut eac_stats);
                        if let Some(p) = p {
                            plugins_active.push(p);
                        }
                    } else {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "wrong type for 'plugins'",
                        ));
                    }
                }
            }
            serde_json::Value::Null => {} // no file (leads to an error later)
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "wrong type for 'plugins'",
                ));
            }
        }

        let plugin_states = plugins_active.iter().map(|p| (0u32, p.state())).collect();

        Ok(FileContext {
            pending_extract,
            file_streams: input_file_streams,
            temp_dirs: vec![],
            namespace,
            sort_by_time,
            plugins_active,
            plugin_states,
            parsing_thread: None,
            collect_mode,
            all_msgs,
            drained_all_msgs: 0,
            streams: Vec::new(),
            paused,
            last_lcs_w_refresh_index: 0,
            eac_stats,
            eac_next_send_time: std::time::Instant::now() + std::time::Duration::from_secs(2), // after 2 secs the first update
            eac_last_nr_msgs: 0,
            did_inform_parser_processing_finished: false,
        })
    }

    fn create_parser_thread(&mut self, log: &slog::Logger) {
        let plugins_active = std::mem::take(&mut self.plugins_active);
        self.parsing_thread = Some(create_parser_thread(
            log.clone(),
            self.file_streams.clone(),
            self.namespace,
            self.sort_by_time,
            plugins_active,
        ));
    }
}

type InputFileStream = (u64, String, DltFileInfos);
type TupleSumFileLenInputFileStreams = (u64, Vec<(HashSet<DltChar4>, Vec<InputFileStream>)>);

fn file_names_to_file_streams(
    file_names: Vec<String>,
    namespace: u32,
    log: &slog::Logger,
) -> TupleSumFileLenInputFileStreams {
    let file_msgs = file_names.iter().map(|f_name| {
        let fi = File::open(f_name);
        match fi {
            Ok(mut f) => {
                let file_ext = std::path::Path::new(f_name).extension().and_then(|s|s.to_str()).unwrap_or_default();

                let dfi = get_dlt_infos_from_file(file_ext, &mut f, 512*1024, namespace);
                match dfi {
                    Ok(dfi) =>{
                        let m1 = &dfi.first_msg;
                        if m1.is_none() {
                            warn!(log, "file {} (ext: '{}') doesn't contain a DLT message in first 0.5MB. Skipping!", f_name, file_ext;);
                        }
                        let file_len = dfi.file_len.unwrap_or(0);
                        (f_name, Some(dfi), file_len)
                    }
                    Err(e)=>{
                        warn!(log, "reading {} got io error '{}'. Skipping!", f_name, e;);
                        (f_name, None, 0)
                    }
                }
            }
            _ => {
                warn!(log, "couldn't open {}. Skipping!", f_name;);
                (f_name, None, 0)
            }
        }
    });
    // filter/remove the files that dont have a first DLT message:
    let file_msgs = file_msgs
        .filter(|(_a, b, _c)| b.is_some() && b.as_ref().unwrap().first_msg.is_some())
        .map(|(a, b, c)| (a, b.unwrap(), c));

    let mut input_file_streams: Vec<StreamEntry> = Vec::with_capacity(file_names.len());
    let mut sum_file_len: u64 = 0;
    for (file_name, dfi, file_len) in file_msgs {
        sum_file_len += file_len;
        let stream = input_file_streams.iter_mut().find(|e| e.0 == dfi.ecus_seen);
        match stream {
            Some((_, l)) => {
                l.push((
                    dfi.first_msg.as_ref().unwrap().reception_time_us,
                    file_name.to_owned(),
                    dfi,
                ));
            }
            None => {
                input_file_streams.push((
                    dfi.ecus_seen.clone(),
                    vec![(
                        dfi.first_msg.as_ref().unwrap().reception_time_us,
                        file_name.to_owned(),
                        dfi,
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
            // time_files.dedup(); // remove duplicates (not needed here)
            (hashset, time_files)
        })
        .collect();
    info!(log, "sorted input_files by first message reception time and ecus_seen:"; "input_file_streams" => format!("{:?}",&input_file_streams));
    (sum_file_len, input_file_streams)
}

/// process incoming text message sent from the client
///
/// We do support:
/// - `open` <filename> [filename2 ...]
///   - Opens the files as DLT files.
///   - Waits for `stream` commands before sending any DLT messages to the client.
/// - `stream` params_as_json_text
///   - Starts streaming messages. The params is a json object that should contain:
///     - `filters`: Array with filters to use
///     - `sort`: "index" (default) or "time"
///     - `type`: "snapshot" (dont update on new incoming dlt messages) or "stream" (default, stream new messages to client on any incoming new DLT messages parsed )
///     - `window`: Array as pair of start_idx (incl.) end_idx (non-incl.) todo add command to update window for a stream. Default [0...usize::MAX]
///       Returns a stream_id. And guarantues that no msg is streamed before the answer is send with that stream_id.
/// - `stop` stream_id
///   - Stop streaming from the requested stream_id.
/// - `close`
///   - Closes the file and releases any resources associated. Afterwards new files can be opened.
/// - `query`
///   - Similar as stream but stops automatically.
/// - `stream_binary_search`
///   - binary search e.g. with time within the msgs returning closest index of a msg of the stream
/// - `stream_window`
///   - change the window for an existing stream
/// - `plugin_cmd`
///   - execute a command for a plugin (e.g. FileTransfer save file)
fn process_incoming_text_message<T: Read + Write>(
    log: &slog::Logger,
    t: String,
    file_context: &mut Option<FileContext>,
    websocket: &mut WebSocket<T>,
) {
    //info!(log, "got text message {:?}", t);
    let cmd_params: Vec<&str> = t.splitn(2, ' ').collect();
    let command = if !cmd_params.is_empty() {
        cmd_params[0]
    } else {
        ""
    };
    let params = if cmd_params.len() >= 2 {
        cmd_params[1]
    } else {
        ""
    };
    info!(log, "got command '{}' params:'{}'", command, params);

    match command {
        "open" => {
            if file_context.is_some() {
                websocket
                    .write_message(Message::Text(format!(
                        "err: open '{}' failed as file(s) '{:?}' is open. close first!",
                        params,
                        file_context.as_ref().unwrap().file_streams
                    )))
                    .unwrap(); // todo
            } else {
                match FileContext::from(log, command, params) {
                    Ok(mut fc) => {
                        let plugins_active_str = serde_json::json!(fc
                            .plugins_active
                            .iter()
                            .map(|p| p.name())
                            .collect::<Vec<&str>>());

                        if fc.pending_extract.is_none() {
                            // setup parsing thread
                            // todo think about it. we do need to move the plugins now out as we pass them to a different thread
                            // and they are not + Sync (but only +Send)
                            fc.create_parser_thread(log);
                        } // else we do it once the extract is done in ... todo

                        file_context.replace(fc);

                        // lifecycle detection thread
                        // sorting thread (if wanted by prev. set options or default options)
                        // and send the messages via mpsc back to here (FileContext.all_msgs)

                        websocket
                            .write_message(Message::Text(format!(
                                "ok: open {{\"plugins_active\":{}}}",
                                plugins_active_str
                            )))
                            .unwrap(); // todo
                    }
                    Err(e) => {
                        websocket
                            .write_message(Message::Text(format!(
                                "err: open '{}' failed with '{:?}'!",
                                params, e
                            )))
                            .unwrap(); // todo
                    }
                }
            }
        }
        "pause" | "resume" => {
            if let Some(fc) = file_context {
                fc.paused = command == "pause";
                websocket
                    .write_message(Message::Text(format!(
                        "ok: {} {{\"paused\":{}}}",
                        command, fc.paused
                    )))
                    .unwrap(); // todo
            } else {
                websocket
                    .write_message(Message::Text(format!(
                        "err: {} failed as no file open. open first!",
                        command
                    )))
                    .unwrap(); // todo
            }
        }
        "close" => {
            if file_context.is_some() {
                let old_fc = file_context.take().unwrap();
                if let Some(pending_extract) = old_fc.pending_extract {
                    info!(log, "close: cancelling pending extract");
                    pending_extract.cancel();
                }
                if let Some(parsing_thread) = old_fc.parsing_thread {
                    parsing_thread
                        .shall_stop
                        .store(true, std::sync::atomic::Ordering::Relaxed);
                    // now we try to read msgs from the rx as any thread might be stuck in bounded channel send
                    //while !parsing_thread.parse_thread.is_finished() {
                    loop {
                        // waiting just for parse_thread is not enough, last thread (sort or lc_thread) could block as well
                        match parsing_thread.rx.try_recv() {
                            Ok(_msg) => {} // throw away
                            Err(std::sync::mpsc::TryRecvError::Empty) => {
                                std::thread::sleep(std::time::Duration::from_millis(10));
                            }
                            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                                break;
                            }
                        }
                    }
                    if parsing_thread.parse_thread.join().is_err() {
                        error!(log, "close: joining parse_thread failed!");
                    }
                    if parsing_thread.lc_thread.join().is_err() {
                        error!(log, "close: joining lc_thread failed!");
                    }
                    if let Some(sort_thread) = parsing_thread.sort_thread {
                        if sort_thread.join().is_err() {
                            error!(log, "close: joining sort_thread failed!");
                        }
                    }
                    info!(log, "close: all threads joined");
                }

                websocket
                    .write_message(Message::Text(format!("ok: '{}'!", command)))
                    .unwrap(); // todo
                               // todo send info with 0 msgs
            } else {
                websocket
                    .write_message(Message::Text(
                        "err: close failed as no file open. open first!".to_string(),
                    ))
                    .unwrap(); // todo
                info!(log, "err: close failed as no file open. open first!");
            }
        }
        "stream" | "query" => {
            match file_context {
                Some(fc) => {
                    match fc.collect_mode {
                        CollectMode::All | CollectMode::OnePassStreams => {
                            // todo additional checks for 1pass streams like: need to be paused, no msgs skipped yet,...
                            let stream = StreamContext::from(log, command, params);
                            match stream {
                                Ok(stream) => {
                                    if !stream.one_pass
                                        && fc.collect_mode == CollectMode::OnePassStreams
                                    {
                                        websocket
                                            .write_message(Message::Text(format!(
                                                "err: {} failed as open option 'collect:'one_pass_streams'' was used. Only one_pass streams supported.",
                                                command
                                            )))
                                            .unwrap(); // todo
                                    } else {
                                        websocket
                                            .write_message(Message::Text(format!(
                                            "ok: {} {{\"id\":{}, \"number_filters\":[{},{},{}]}}",
                                            command,
                                            stream.id,
                                            stream.filters[FilterKind::Positive].len(),
                                            stream.filters[FilterKind::Negative].len(),
                                            stream.filters[FilterKind::Event].len()
                                        )))
                                            .unwrap(); // todo
                                        fc.streams.push(stream);
                                    }
                                }
                                Err(e) => {
                                    websocket
                                        .write_message(Message::Text(format!(
                                            "err: {} failed with err '{}' from '{}'!",
                                            command, e, params
                                        )))
                                        .unwrap(); // todo
                                }
                            }
                        }
                        CollectMode::None => {
                            websocket
                        .write_message(Message::Text(format!(
                            "err: {} failed as open option 'collect:false' was used. Stream not supported then.",
                            command
                        )))
                        .unwrap(); // todo
                        }
                    }
                }
                None => {
                    websocket
                        .write_message(Message::Text(format!(
                            "err: {} failed as no file open. open first!",
                            command
                        )))
                        .unwrap(); // todo
                }
            }
        }
        "stop" | "stream_binary_search" | "stream_change_window" | "stream_search" => {
            let params_splitted = params.split(' ').collect::<Vec<_>>();
            let param0 = params_splitted[0];
            match param0.parse::<u32>() {
                Ok(id) => {
                    match file_context {
                        Some(fc) => {
                            // todo add check for !stream.one_pass
                            if let Some(pos) = fc.streams.iter().position(|x| x.id == id) {
                                match command {
                                    "stream_search" => {
                                        // search within the stream for all messages matching the filters:
                                        let stream = &fc.streams[pos];
                                        if let Err(e) = process_stream_search_params(
                                            log,
                                            websocket,
                                            &fc.all_msgs,
                                            stream,
                                            command,
                                            params.split_once(' ').unwrap().1,
                                        ) {
                                            websocket
                                                .write_message(Message::Text(format!(
                                                    "err: {} failed with err '{}' from '{}'!",
                                                    command, e, params
                                                )))
                                                .unwrap(); // todo
                                        }
                                    }
                                    "stream_binary_search" => {
                                        // binary search, i.e. return the first info for a search expr
                                        let stream = &fc.streams[pos];

                                        // for now two supported search: ~time_ms=... index=...
                                        // that returns the index of the filtered_msgs that is closest to the time/msg.index:
                                        if params_splitted.len() > 1 {
                                            let search_text = params_splitted[1];
                                            let search = search_text.split_once('=');
                                            match search {
                                                Some(("index", what)) => {
                                                    match binary_search_by_msg_index(
                                                        what.parse::<DltMessageIndexType>()
                                                            .unwrap_or_default(),
                                                        fc,
                                                        stream,
                                                    ) {
                                                        Ok(filtered_msg_index) => {
                                                            websocket
                                                                .write_message(Message::Text(
                                                                    format!(
                                                        "ok: {} {}={{\"filtered_msg_index\":{}}}",
                                                        command, id, filtered_msg_index,
                                                    ),
                                                                ))
                                                                .unwrap(); // todo
                                                        }
                                                        Err(err_reason) => {
                                                            websocket
                                                        .write_message(Message::Text(format!(
                                                            "err: {} failed. stream_id {}: all_msgs#={}, search='{:?}', reason={}",
                                                            command,
                                                            id,
                                                            fc.all_msgs.len(),
                                                            search,
                                                            err_reason
                                                        )))
                                                        .unwrap(); // todo
                                                        }
                                                    }
                                                }
                                                Some(("time_ms", what)) => {
                                                    let filtered_msg_index =
                                                        binary_search_by_time_us(
                                                            1000u64
                                                                * what
                                                                    .parse::<u64>()
                                                                    .unwrap_or_default(),
                                                            fc,
                                                            stream,
                                                        );
                                                    websocket
                                                        .write_message(Message::Text(format!(
                                                        "ok: {} {}={{\"filtered_msg_index\":{}}}",
                                                        command, id, filtered_msg_index,
                                                    )))
                                                        .unwrap();
                                                }
                                                _ => {
                                                    websocket
                                                    .write_message(Message::Text(format!(
                                                        "err: {} failed. stream_id {}:filtered_msgs={}: search '{:?}' unknown! params_splitted={:?}",
                                                        command, id, stream.filtered_msgs.len(), search, params_splitted
                                                    )))
                                                    .unwrap(); // todo
                                                }
                                            }
                                        } else {
                                            websocket
                                            .write_message(Message::Text(format!(
                                                "err: {} failed. stream_id {}, filtered_msgs={}: too few params_splitted={:?}",
                                                command, id, stream.filtered_msgs.len(), params_splitted
                                            )))
                                            .unwrap(); // todo
                                        }
                                    }
                                    "stream_change_window" => {
                                        if params_splitted.len() > 1 {
                                            let stream = &mut fc.streams[pos];
                                            // we expect one parameter with "<start>,<end>"
                                            let window_text = params_splitted[1];
                                            let window =
                                                window_text.split_once(',').map(|(s, e)| {
                                                    (
                                                        s.parse::<usize>().unwrap_or(0),
                                                        e.parse::<usize>().unwrap_or(0),
                                                    )
                                                });
                                            match window {
                                                Some((start_idx, end_idx)) => {
                                                    stream.msgs_to_send = std::ops::Range {
                                                        start: start_idx,
                                                        end: end_idx,
                                                    };
                                                    stream.msgs_sent = std::ops::Range {
                                                        start: start_idx,
                                                        end: start_idx,
                                                    };
                                                    // we do assigne a new stream id to ease identifying binmsgs sent already
                                                    stream.new_id();
                                                    websocket
                                                        .write_message(Message::Text(format!(
                                                            "ok: {} {}={{\"id\":{},\"window\":[{},{}]}}",
                                                            command, id, stream.id, start_idx, end_idx
                                                        )))
                                                        .unwrap(); // todo
                                                }
                                                _ => {
                                                    websocket
                                            .write_message(Message::Text(format!(
                                                "err: {} failed. stream_id {}: failure parsing={:?}",
                                                command, id, window_text
                                            )))
                                            .unwrap(); // todo
                                                }
                                            }
                                        } else {
                                            websocket
                                            .write_message(Message::Text(format!(
                                                "err: {} failed. stream_id {}: too few params_splitted={:?}",
                                                command, id, params_splitted
                                            )))
                                            .unwrap(); // todo
                                        }
                                    }
                                    "stop" => {
                                        fc.streams.remove(pos);
                                        websocket
                                            .write_message(Message::Text(format!(
                                                "ok: {} stream stream_id {}",
                                                command, id
                                            )))
                                            .unwrap(); // todo
                                    }
                                    _ => {
                                        websocket
                                            .write_message(Message::Text(format!(
                                                "err: {} failed. stream_id {} not found!",
                                                command, id
                                            )))
                                            .unwrap(); // todo
                                    }
                                }
                            } else {
                                websocket
                                    .write_message(Message::Text(format!(
                                        "err: {} stream failed. stream_id {} not found!",
                                        command, id
                                    )))
                                    .unwrap(); // todo
                            }
                        }
                        None => {
                            websocket
                                .write_message(Message::Text(format!(
                                    "err: {} stream failed. No file opened!",
                                    command
                                )))
                                .unwrap(); // todo
                        }
                    }
                }
                Err(e) => {
                    websocket
                        .write_message(Message::Text(format!(
                            "err: {} stream failed. param {} is no valid stream_id! Err={}",
                            command, params, e
                        )))
                        .unwrap(); // todo
                }
            }
        }
        "plugin_cmd" => {
            match file_context {
                Some(fc) => {
                    let params = serde_json::from_str::<serde_json::Value>(params);
                    if let Ok(params) = params {
                        if let Some(params) = params.as_object() {
                            if let (Some(cmd), Some(plugin_name)) = (
                                params.get("cmd").and_then(serde_json::Value::as_str),
                                params.get("name").and_then(serde_json::Value::as_str),
                            ) {
                                let mut found_plugin = false;
                                for plugin_state in &fc.plugin_states {
                                    // find the plugin with the matching name:
                                    let plugin_state = plugin_state.1.read().unwrap();
                                    if let Some(name) = plugin_state
                                        .value
                                        .as_object()
                                        .and_then(|s| s.get("name"))
                                        .and_then(serde_json::Value::as_str)
                                    {
                                        if name.eq(plugin_name) {
                                            // got it
                                            if let Some(apply_command) = plugin_state.apply_command
                                            {
                                                let r = apply_command(
                                                    &plugin_state.internal_data,
                                                    cmd,
                                                    params
                                                        .get("params")
                                                        .and_then(serde_json::Value::as_object),
                                                    params
                                                        .get("cmdCtx")
                                                        .and_then(serde_json::Value::as_object),
                                                );
                                                websocket
                                                    .write_message(Message::Text(format!(
                                                        "ok: {} {}",
                                                        command, r
                                                    )))
                                                    .unwrap(); // todo
                                            } else {
                                                websocket
                                                                .write_message(Message::Text(
                                                                    format!(
                                                                        "err: {} plugin '{}' does not support commands",
                                                                        command, plugin_name
                                                                    ),
                                                                ))
                                                                .unwrap(); // todo
                                            }
                                            found_plugin = true;
                                            break;
                                        }
                                    }
                                }
                                if !found_plugin {
                                    websocket
                                        .write_message(Message::Text(format!(
                                            "err: {} plugin '{}' not found!",
                                            command, plugin_name
                                        )))
                                        .unwrap(); // todo
                                }
                            } else {
                                websocket
                                    .write_message(Message::Text(format!(
                                        "err: {} params misses cmd or name!",
                                        command,
                                    )))
                                    .unwrap(); // todo
                            }
                        } else {
                            websocket
                                .write_message(Message::Text(format!(
                                    "err: {} params not an object!",
                                    command,
                                )))
                                .unwrap(); // todo
                        }
                    } else {
                        websocket
                            .write_message(Message::Text(format!(
                                "err: {} failed parsing params with '{}'!",
                                command,
                                params.err().unwrap()
                            )))
                            .unwrap(); // todo
                    }
                }
                None => {
                    websocket
                        .write_message(Message::Text(format!(
                            "err: {} failed as no file open. open first!",
                            command
                        )))
                        .unwrap(); // todo
                }
            }
        }
        "fs" => {
            let params = serde_json::from_str::<serde_json::Value>(params);
            if let Ok(params) = params {
                if let Some(params) = params.as_object() {
                    match process_fs_cmd(log, params) {
                        Ok(res) => {
                            websocket
                                .write_message(Message::Text(format!("ok: {}:{}", command, res)))
                                .unwrap(); // todo
                        }
                        Err(err_reason) => {
                            websocket
                                .write_message(Message::Text(format!(
                                    "err: {} {}",
                                    command, err_reason
                                )))
                                .unwrap(); // todo
                        }
                    }
                } else {
                    websocket
                        .write_message(Message::Text(format!(
                            "err: {} params not an object!",
                            command,
                        )))
                        .unwrap(); // todo
                }
            } else {
                websocket
                    .write_message(Message::Text(format!(
                        "err: {} failed parsing params with '{}'!",
                        command,
                        params.err().unwrap()
                    )))
                    .unwrap(); // todo
            }
        }
        _ => {
            websocket
                .write_message(Message::Text(format!("unknown command '{}'!", t)))
                .unwrap(); // todo
        }
    }
}

/// Determines the type of a file based on its `FileType`.
///
/// # Arguments
///
/// * `file_type` - A `std::fs::FileType` instance representing the type of the file.
/// * `path` - A `std::path::PathBuf` instance representing the path to the file.
///
/// # Returns
///
/// * A `&str` representing the type of the file. Possible values are "dir", "file", "symlink_dir", "symlink_file", "symlink" and "unknown".
///   For symlinks the type of the target is returned (symlink_dir, symlink_file or symlink).
///
/// # Example
///
/// ```
/// use std::fs;
///
/// let file_path:PathBuf = "/path/to/file".into();
/// let file_type = fs::symlink_metadata(file_path).unwrap().file_type();
/// let file_type_str = type_for_filetype(file_type);
///
/// println!("The file type is: {}", file_type_str);
/// assert_eq!(file_type_str, "unknown");
/// ```
fn type_for_filetype(filetype: &std::fs::FileType, path: &std::path::PathBuf) -> &'static str {
    if filetype.is_dir() {
        "dir"
    } else if filetype.is_file() {
        "file"
    } else if filetype.is_symlink() {
        let sl_metadata = std::fs::metadata(path);
        match sl_metadata {
            Ok(sl_metadata) => {
                if sl_metadata.file_type().is_dir() {
                    "symlink_dir"
                } else if sl_metadata.file_type().is_file() {
                    "symlink_file"
                } else {
                    "symlink"
                }
            }
            Err(_) => {
                // e.g. for links to unmounted volumes...
                "symlink"
            }
        }
    } else {
        "unknown"
    }
}

/// process "fs" command
///
/// # Arguments
/// * `log` - A reference to a `slog::Logger` instance for logging.
/// * `params` - A reference to a `serde_json::Map<String, serde_json::Value>` instance representing the parameters of the command.
///
/// The params expects an object with the following keys:
/// * `cmd` - A string representing the command to execute. Possible values are "stat" and "readDirectory".
/// * `path` - A string representing the path to the file or directory to execute the command on.
///
/// # Returns
/// For cmd "stat":
/// * A `serde_json::Value` object with keys:
///     * `type` - A string representing the type of the file. Possible values are "dir", "file", "symlink_dir", "symlink_file", "symlink" and "unknown".
///     * `size` - A u64 representing the size of the file in bytes.
///     * `mtime` - A u64 representing the modification time of the file in milliseconds since the UNIX epoch.
///     * `ctime` - A u64 representing the creation time of the file in milliseconds since the UNIX epoch.
///
/// For cmd "readDirectory":
/// * A `serde_json::Value` object representing an array of objects with keys:
///   * `name` - A string representing the name of the file or directory.
///   * `type` - A string representing the type of the file. Possible values are "dir", "file", "symlink_dir", "symlink_file", "symlink" and "unknown".
///
fn process_fs_cmd(
    log: &slog::Logger,
    params: &serde_json::Map<String, serde_json::Value>,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    if let (Some(cmd), Some(path)) = (
        params.get("cmd").and_then(serde_json::Value::as_str),
        params.get("path").and_then(serde_json::Value::as_str),
    ) {
        info!(log, "process_fs_cmd(cmd:'{}', path:'{}')", cmd, path,);
        match cmd {
            "stat" => {
                match std::fs::symlink_metadata(path) {
                    // todo size/mtime/ctime for the traversed dest?)
                    Ok(attr) => Ok(serde_json::json!({"stat":{
                        "type":type_for_filetype(&attr.file_type(), &path.into()),
                        "size":attr.len(),
                        "mtime":attr.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH).duration_since(std::time::SystemTime::UNIX_EPOCH).unwrap_or(std::time::Duration::from_secs(0)).as_millis() as u64, // to u64 as json windows cannot convert u128
                        "ctime":attr.created().unwrap_or(std::time::SystemTime::UNIX_EPOCH).duration_since(std::time::SystemTime::UNIX_EPOCH).unwrap_or(std::time::Duration::from_secs(0)).as_millis() as u64,
                    }})),
                    Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => {
                        let r = fs_cmd_archive(path, log, cmd);
                        info!(log, "fs_cmd_archive(cmd:'{}')={:?}", cmd, r);
                        r
                    }
                    Err(e) => Ok(serde_json::json!({"err":format!("stat failed with '{}'", e)})),
                }
            }
            "readDirectory" => {
                match std::fs::read_dir(path) {
                    Ok(entries) => Ok(entries
                        .filter_map(|e| {
                            e.ok().and_then(|e| {
                            if let Some(file_name) = e.path().file_name() {
                                let file_type = e.file_type().ok(); // Convert the Result to an Option
                                Some(serde_json::json!({
                                    "name": file_name.to_str().unwrap_or_default(),
                                    "type": match file_type {
                                        Some(file_type) => type_for_filetype(&file_type, &e.path()),
                                        _ => "unknown",
                                    },
                                }))
                            } else {
                                None
                            }
                        })
                        })
                        .collect()),
                    Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => {
                        // see whether its an archive path...
                        let r = fs_cmd_archive(path, log, cmd);
                        info!(log, "fs_cmd_archive(cmd:'{}')={:?}", cmd, r);
                        r
                    }
                    Err(e) => {
                        Ok(serde_json::json!({"err":format!("readDirectory failed with '{}'", e)}))
                    }
                }
            }
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("cmd '{}' unknown", cmd),
            )
            .into()),
        }
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "params misses cmd or path",
        )
        .into())
    }
}

fn fs_cmd_archive(
    full_path: &str,
    log: &slog::Logger,
    cmd: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    // we expect "path/to.archive!/path/within/archive"
    // file path can be any uri/url
    // as separator the first !/ is used...

    let uri = full_path.splitn(2, "!/").collect::<Vec<&str>>();
    if uri.len() != 2 && !full_path.ends_with('!') {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "path '{}' not in expected format 'path/to.archive!/path/within/archive'",
                full_path
            ),
        )
        .into());
    }
    let (archive_path, path_within) = match uri.len() {
        2 => (uri[0], uri[1]),
        1 => (&uri[0][..uri[0].len() - 1], ""),
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("path '{}' not in expected format", full_path),
            )
            .into())
        }
    };
    //let url = Url::parse(uri[0]);
    info!(
        log,
        "fs_cmd_archive(cmd:'{}', archive_path:'{}', within:'{}')", cmd, archive_path, path_within
    );
    let archive_path = PathBuf::from(archive_path);
    if archive_path.exists() {
        if archive_is_supported_filename(&archive_path) {
            let mut source = if is_part_of_multi_volume_archive(&archive_path) {
                let paths = search_dir_for_multi_volume_archive(&archive_path);
                let sources = paths.into_iter().flat_map(std::fs::File::open).collect();
                SeekableChain::new(sources)
            } else {
                SeekableChain::new(vec![std::fs::File::open(&archive_path)?])
            };
            return match cmd {
                "readDirectory" => {
                    let files =
                        list_archive_contents_cached(&mut source, &archive_path.to_string_lossy())
                            .unwrap();
                    // info!(log, "got files:{:?}", files);

                    // special handling for e.g. bz2, .gz... where a single file is within the archive with "unknown" name ("data"):
                    if files.len() == 1 && files[0] == "data" {
                        let archive_name = archive_path
                            .file_stem()
                            .map(|f| f.to_string_lossy())
                            .unwrap_or("data".into());
                        return Ok(serde_json::json!([{"name": archive_name ,"type":"file"}]));
                    }

                    let entries: Vec<_> = archive_contents_read_dir(&files, path_within)
                        .map(|(name, entry_type)| {
                            serde_json::json!({
                                "name": name,
                                "type": entry_type,
                            })
                        })
                        .collect();
                    Ok(serde_json::json!(entries))
                }
                "stat" => {
                    let files =
                        list_archive_contents_cached(&mut source, &archive_path.to_string_lossy())
                            .unwrap();
                    // special handling for e.g. bz2, .gz... where a single file is within the archive with "unknown" name ("data"):
                    if files.len() == 1 && files[0] == "data" {
                        return Ok(
                            serde_json::json!({"stat":{"size": 42 ,"type":"file", "mtime":0, "ctime":0}}),
                        );
                    }
                    match archive_contents_metadata(&files, path_within) {
                        Ok((meta_type, meta_size)) => {
                            Ok(serde_json::json!({"stat":{
                                "type":meta_type,
                                "size":meta_size,
                                "mtime":std::time::SystemTime::UNIX_EPOCH.duration_since(std::time::SystemTime::UNIX_EPOCH).unwrap_or(std::time::Duration::from_secs(0)).as_millis() as u64, // to u64 as json windows cannot convert u128
                                "ctime":std::time::SystemTime::UNIX_EPOCH.duration_since(std::time::SystemTime::UNIX_EPOCH).unwrap_or(std::time::Duration::from_secs(0)).as_millis() as u64,
                            }}))
                        }
                        Err(e) => {
                            Ok(serde_json::json!({"err":format!("stat failed with '{}'", e)}))
                        }
                    }
                }
                _ => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("cmd '{}' not supported", cmd),
                )
                .into()),
            };
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("path '{}' not a supported archive", archive_path.display()),
        )
        .into())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("path '{}' does not exist", archive_path.display()),
        )
        .into())
    }
}

/// find the index of the msg within the stream that is closest/next to the time given
///
fn binary_search_by_time_us(time_us: u64, fc: &FileContext, stream: &StreamContext) -> usize {
    let lc_id_map = if let Some(pt) = &fc.parsing_thread {
        let lcs_r = &pt.lcs_r;
        let mut lc_map = BTreeMap::<LifecycleId, u64>::new(); // todo could opt with capacity
        if let Some(map_read_ref) = lcs_r.read() {
            map_read_ref.iter().for_each(|(k, l)| {
                if let Some(l) = l.get_one() {
                    lc_map.insert(*k, l.start_time);
                }
            });
        };
        lc_map
    } else {
        BTreeMap::<LifecycleId, u64>::new()
    };
    let all_msgs_idx = fc
        .all_msgs
        .binary_search_by(|m| {
            let m_time = if let Some(lc_start_time) = lc_id_map.get(&m.lifecycle) {
                lc_start_time + m.timestamp_us()
            } else {
                m.reception_time_us
            };
            m_time.cmp(&time_us)
        })
        .unwrap_or_else(|e| e);
    if stream.filters_active {
        // return the index that fits to that:
        // binary_search is ok as the filtered_msgs are sorted by all_msgs index! (not by msg index)
        stream
            .filtered_msgs
            .binary_search(&all_msgs_idx)
            .unwrap_or_else(|e| e)
    } else {
        all_msgs_idx
    }
}

/// find the index of the msg within the stream that is closest/next to the msg.index given
///
/// Handles both the sort_by_time and sort_by_index case.
/// For sort_by_time it does have O(n=number of all_msgs) complexity. (todo: think about optimizations!)
/// For sort_by_index it does have O(log(n)) complexity.
///
fn binary_search_by_msg_index(
    wanted_msg_idx: DltMessageIndexType,
    fc: &FileContext,
    stream: &StreamContext,
) -> Result<usize, String> {
    if fc.sort_by_time {
        // find the msg with that index in all_msgs.
        // start with naive (O(n) approach)
        // todo think about optimizations!
        let wanted_msg = fc
            .all_msgs
            .iter()
            .enumerate()
            .find(|(_all_msgs_idx, m)| m.index == wanted_msg_idx);

        if let Some((all_msgs_idx, msg)) = wanted_msg {
            let filtered_msg_index = if stream.filters_active {
                // map of all lc.id/lifecycle_start_times:
                let lc_id_map = if let Some(pt) = &fc.parsing_thread {
                    let lcs_r = &pt.lcs_r;
                    let mut lc_map = BTreeMap::<LifecycleId, u64>::new(); // todo could opt with capacity
                    if let Some(map_read_ref) = lcs_r.read() {
                        map_read_ref.iter().for_each(|(k, l)| {
                            if let Some(l) = l.get_one() {
                                lc_map.insert(*k, l.start_time);
                            }
                        });
                    };
                    lc_map
                } else {
                    BTreeMap::<LifecycleId, u64>::new()
                };

                // search in the filtered msgs for the time:
                // todo: think whether as a first step a search whether the msg is directly included
                // makes sense. but binary_search cannot be used as the filtered_msgs are not sorted by index!
                let wanted_msg_time_us = if let Some(lc_start_time) = lc_id_map.get(&msg.lifecycle)
                {
                    lc_start_time + msg.timestamp_us()
                } else {
                    msg.reception_time_us
                };
                stream
                    .filtered_msgs
                    .binary_search_by(|f_idx| {
                        let msg = fc.all_msgs.get(*f_idx).unwrap();
                        let m_time = if let Some(lc_start_time) = lc_id_map.get(&msg.lifecycle) {
                            lc_start_time + msg.timestamp_us()
                        } else {
                            msg.reception_time_us
                        };
                        m_time.cmp(&wanted_msg_time_us)
                    })
                    .unwrap_or_else(|e| e)
            } else {
                // !filters_active
                all_msgs_idx
            };
            Ok(filtered_msg_index)
        } else {
            Err(format!("sort_by_time, index={} unknown", wanted_msg_idx))
        }
    } else {
        // sort by index
        // anyhow the assumption that msg.index === index within all_msgs is wrong
        // as e.g. plugins (file_transfer, etc.) can remove msgs from all_msgs!
        // but we can do a fast binary search:
        let all_msgs_idx = fc
            .all_msgs
            .binary_search_by(|m| m.index.cmp(&wanted_msg_idx));
        if let Ok(all_msgs_idx) = all_msgs_idx {
            let filtered_msg_index = stream
                .filtered_msgs
                .binary_search(&all_msgs_idx)
                .unwrap_or_else(|e| e);
            Ok(filtered_msg_index)
        } else {
            Err(format!(
                "sort_by_index, index={} not in all_msgs",
                wanted_msg_idx
            ))
        }
    }
}

/// process a "stream_search" command
///
/// executes a filter search within the stream
/// and returns the relative indices of the messages matching
///
/// Input params:
/// filters: (similar to stream command)
/// start_idx: idx of the stream msgs to start, defaults to 0
/// max_results: max. number of msgs to return, defaults to 100
///
/// Returns:
/// A json message to the websocket with:
/// search_idxs:[...] - array of indices
/// nextSearchIdx: relative idx of the stream msgs where to start next search. Omitted if search is finished.
///
fn process_stream_search_params<T: Read + Write>(
    log: &slog::Logger,
    websocket: &mut WebSocket<T>,
    all_msgs: &[adlt::dlt::DltMessage],
    stream: &StreamContext,
    command: &str,
    params_json: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // parse json
    let v = serde_json::from_str::<serde_json::Value>(params_json)?;
    debug!(
        log,
        "process_stream_search_params({}:{}) = {:?}", command, params_json, v
    );
    let start_idx = match &v["start_idx"] {
        serde_json::Value::Number(i) => i.as_u64().unwrap_or(0) as usize,
        serde_json::Value::Null => 0, // keep defaults
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "wrong type for 'start_idx'",
            )
            .into());
        }
    };
    let max_results = match &v["max_results"] {
        serde_json::Value::Number(i) => i.as_u64().unwrap_or(0) as usize,
        serde_json::Value::Null => 100, // keep defaults
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "wrong type for 'start_idx'",
            )
            .into());
        }
    };
    let mut filters: FilterKindContainer<Vec<Filter>> = Default::default();

    match &v["filters"] {
        serde_json::Value::Array(a) => {
            for filter in a {
                debug!(
                    log,
                    "process_stream_search_params filters got '{}'",
                    filter.to_string()
                );
                let filter_struct = Filter::from_json(&filter.to_string())?;
                debug!(
                    log,
                    "process_stream_search_params filters parsed as '{:?}'", filter_struct
                );
                if filter_struct.enabled {
                    // otherwise the no pos filter -> ... logic doesnt work
                    filters[filter_struct.kind].push(filter_struct);
                }
            }
        }
        serde_json::Value::Null => {} // no filters
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "wrong type for 'filters'",
            )
            .into());
        }
    }

    // perform the search now synchronous/blocking:
    let mut search_idxs: Vec<DltMessageIndexType> = Vec::with_capacity(max_results);

    // check msgs from _processed_len to all_msgs_len
    // todo use parallel iterator
    // todo break after some max time/max amount of messages to improve reaction time
    let mut i = start_idx;
    let stream_msgs_len = stream.filtered_msgs.len();
    while i < stream_msgs_len {
        let msg: &adlt::dlt::DltMessage = &all_msgs[stream.filtered_msgs[i]];
        let matches = match_filters(msg, &filters);

        if matches {
            search_idxs.push(i as u32);
            if search_idxs.len() >= max_results {
                i += 1;
                break;
            }
        }
        i += 1;
    }
    let next_search_idx = if i < stream_msgs_len {
        Some(i + 1)
    } else {
        None
    };

    debug!(
        log,
        "process_stream_search_params: start_idx={}, max_results={} filters= pos #{} returning #{}, i={}/{}",
        start_idx,
        max_results,
        filters[FilterKind::Positive].len(),
        search_idxs.len(), i, stream_msgs_len
    );

    websocket
        .write_message(Message::Text(format!(
            "ok: {} {}={}",
            command,
            stream.id,
            serde_json::json!({"search_idxs":search_idxs, "next_search_idx":next_search_idx}),
        )))
        .unwrap(); // todo
    Ok(())
}

/// process any messages to be send to the client
///
/// This function should not block longer than e.g. 100ms as otherwise
/// incoming messages wont be processed.
fn process_file_context<T: Read + Write>(
    log: &slog::Logger,
    fc: &mut FileContext,
    websocket: &mut WebSocket<T>,
) -> Result<(), Box<tungstenite::Error>> {
    let mut got_new_msgs = false;
    let mut parser_thread_finished = false;
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(50);

    if let Some(progress) = &mut fc.pending_extract {
        match progress.poll() {
            ProgressPoll::Progress((cur, max)) => {
                debug!(
                    log,
                    "process_file_context: extract_progress: {}/{}", cur, max
                );
                websocket.write_message(Message::Binary(
                    bincode::encode_to_vec(
                        remote_types::BinType::Progress(remote_types::BinProgress {
                            cur_progress: cur,
                            max_progress: max,
                            action: std::borrow::Cow::Borrowed("extracting archives"),
                        }),
                        BINCODE_CONFIG,
                    )
                    .unwrap(), // todo
                ))?;
                std::thread::sleep(std::time::Duration::from_millis(50));
                return Ok(());
            }
            ProgressPoll::Done((file_streams, mut temp_dirs)) => {
                let (cur, max) = progress.cur_progress();
                info!(
                    log,
                    "process_file_context: pending_extract done. #file_streams={} last progress: {}/{}", file_streams.len(), cur, max
                );
                websocket.write_message(Message::Binary(
                    bincode::encode_to_vec(
                        remote_types::BinType::Progress(remote_types::BinProgress {
                            cur_progress: cur,
                            max_progress: max,
                            action: std::borrow::Cow::Borrowed("extracting archives"),
                        }),
                        BINCODE_CONFIG,
                    )
                    .unwrap(), // todo
                ))?;
                fc.pending_extract = None;
                assert!(fc.file_streams.is_empty());
                assert!(fc.parsing_thread.is_none());

                fc.file_streams = file_streams;
                fc.temp_dirs.append(&mut temp_dirs);
                fc.create_parser_thread(log);
            }
            ProgressPoll::Err(_) => {
                fc.pending_extract = None;
                // todo will never have a parser thread... is the error below enough?
                //websocket
                //    .write_message(Message::Text(format!("err: extract_failed {}", e)))?;
                return Err(Box::new(tungstenite::Error::Io(std::io::Error::other(
                    "extract_failed",
                ))));
            }
        }
    };

    if fc.paused {
        return Ok(());
    }
    if let Some(pt) = &fc.parsing_thread {
        let rx = &pt.rx;
        loop {
            // todo use rx.try_recv first???
            let rm = rx.recv_timeout(std::time::Duration::from_millis(10));
            match rm {
                Ok(msg) => {
                    fc.eac_stats.add_msg(&msg);
                    match fc.collect_mode {
                        CollectMode::All | CollectMode::OnePassStreams => {
                            fc.all_msgs.push(msg);
                        }
                        _ => {}
                    }
                    got_new_msgs = true;
                }
                Err(e) => match e {
                    std::sync::mpsc::RecvTimeoutError::Timeout => {
                        break;
                    }
                    std::sync::mpsc::RecvTimeoutError::Disconnected => {
                        parser_thread_finished = true;
                        break;
                    }
                },
            };
            if std::time::Instant::now() > deadline {
                break;
            }
        }
    }
    // inform about new msgs
    if got_new_msgs && websocket.can_write() {
        // todo debounce this a bit? (eg with eac stats?)
        let nr_msgs = match fc.collect_mode {
            CollectMode::All => fc.all_msgs.len() as u32,
            CollectMode::OnePassStreams => (fc.all_msgs.len() + fc.drained_all_msgs) as u32,
            CollectMode::None => fc.eac_stats.nr_msgs(),
        };
        // send on new msgs or once if finished
        websocket.write_message(Message::Binary(
            bincode::encode_to_vec(
                remote_types::BinType::FileInfo(remote_types::BinFileInfo { nr_msgs }),
                BINCODE_CONFIG,
            )
            .unwrap(), // todo
        ))?;
    }
    // lc infos:
    // we send updates only on the ones that did change
    if let Some(pt) = &fc.parsing_thread {
        let lcs_r = &pt.lcs_r;
        if let Some(lc_map) = lcs_r.read() {
            let mut lcs: Vec<remote_types::BinLifecycle> = vec![];
            let mut new_lcs_w_refresh_index = fc.last_lcs_w_refresh_index;
            for lc in lc_map.iter().map(|(_id, b)| b.get_one().unwrap()) {
                if lc.lcs_w_refresh_idx > fc.last_lcs_w_refresh_index {
                    new_lcs_w_refresh_index =
                        std::cmp::max(new_lcs_w_refresh_index, lc.lcs_w_refresh_idx);
                    if !lc.only_control_requests() {
                        // send this one
                        lcs.push(remote_types::BinLifecycle {
                            id: lc.id(),
                            ecu: lc.ecu.as_u32le(),
                            nr_msgs: lc.nr_msgs,
                            start_time: lc.resume_start_time(), // we use the resume start time here as this is never earlier than from the lifecycle it resumed
                            resume_time: if lc.is_resume() {
                                Some(lc.resume_time())
                            } else {
                                None
                            },
                            end_time: lc.end_time(),
                            sw_version: lc.sw_version.to_owned(),
                        })
                    }
                }
            }
            fc.last_lcs_w_refresh_index = new_lcs_w_refresh_index;
            if !lcs.is_empty() {
                // we do send them sorted (even in case only updates are sent)
                lcs.sort_unstable_by(|a, b| a.start_time.cmp(&b.start_time));
                let encoded: Vec<u8> =
                    bincode::encode_to_vec(remote_types::BinType::Lifecycles(lcs), BINCODE_CONFIG)
                        .unwrap(); // todo
                websocket.write_message(Message::Binary(encoded))?;
            }
        }
    }

    // send eac stats? if deadline expired and nr_msgs have increased
    // so if only desc have been updated this wont trigger a resend
    if fc.eac_next_send_time < deadline
        || (parser_thread_finished && !fc.did_inform_parser_processing_finished)
    {
        // deadline is slightly off (~40ms), but we dont care
        fc.eac_next_send_time = std::time::Instant::now() + std::time::Duration::from_secs(3); // every 3s
        let eac_nr_msgs = fc.eac_stats.nr_msgs();
        if fc.eac_last_nr_msgs < eac_nr_msgs {
            fc.eac_last_nr_msgs = eac_nr_msgs;
            // yes, resend:
            websocket.write_message(Message::Binary(
                bincode::encode_to_vec(
                    remote_types::BinType::EacInfo(
                        fc.eac_stats
                            .ecu_map
                            .iter()
                            .map(remote_types::BinEcuStats::from)
                            .collect(),
                    ),
                    BINCODE_CONFIG,
                )
                .unwrap(), // todo
            ))?;
        }

        // check plugin states with same frequency:
        let mut plugin_states: Vec<String> = vec![];
        for (last_gen, state) in &mut fc.plugin_states {
            let state = state.read().unwrap();
            if state.generation != *last_gen {
                *last_gen = state.generation;
                let state_value = state.value.to_string();
                plugin_states.push(state_value);
            }
        }
        if !plugin_states.is_empty() {
            websocket.write_message(Message::Binary(
                bincode::encode_to_vec(
                    remote_types::BinType::PluginState(plugin_states),
                    BINCODE_CONFIG,
                )
                .unwrap(), // todo
            ))?;
        }
    }

    let mut stream_marked_as_done = false;
    // in any stream any messages to send?
    let all_msgs_len = fc.all_msgs.len() + fc.drained_all_msgs;
    for stream in &mut fc.streams {
        let last_all_msgs_last_processed_len =
            std::cmp::min(stream.all_msgs_last_processed_len, all_msgs_len);
        // assert!(last_all_msgs_last_processed_len >= fc.drained_all_msgs);
        process_stream_new_msgs(
            stream,
            last_all_msgs_last_processed_len,
            &fc.all_msgs[last_all_msgs_last_processed_len - fc.drained_all_msgs..],
            3_000_000,
        );

        // any new msgs for this stream to send to the remote side?
        let stream_msgs_len = if stream.filters_active {
            stream.filtered_msgs.len()
        } else {
            all_msgs_len
        };

        if stream.all_msgs_last_processed_len != last_all_msgs_last_processed_len {
            // or kind of keep-alive from the stream every sec? (todo debounce?)
            // post info amount of filtered msgs vs all_msgs
            let encoded: Vec<u8> = bincode::encode_to_vec(
                remote_types::BinType::StreamInfo(remote_types::BinStreamInfo {
                    stream_id: stream.id,
                    nr_stream_msgs: stream_msgs_len as u32,
                    nr_file_msgs_processed: stream.all_msgs_last_processed_len as u32,
                    nr_file_msgs_total: all_msgs_len as u32,
                }),
                BINCODE_CONFIG,
            )
            .unwrap(); // todo
                       //info!(log, "encoded: #{:?}", &encoded);
            websocket.write_message(Message::Binary(encoded))?;
        }

        // any new msgs for this stream to send to the remote side?
        if stream.msgs_sent.end < stream.msgs_to_send.end && stream.msgs_sent.end < stream_msgs_len
        {
            // send some more...
            let new_end = std::cmp::min(stream_msgs_len, stream.msgs_to_send.end);
            debug!(
                log,
                "sending {}..{} (stream_msgs_len={})",
                stream.msgs_sent.end,
                new_end,
                stream_msgs_len
            );
            if stream.binary {
                if new_end > stream.msgs_sent.end {
                    let mut bin_msgs = Vec::with_capacity(new_end - stream.msgs_sent.end);
                    for i in stream.msgs_sent.end..new_end {
                        let msg_idx = if stream.filters_active {
                            stream.filtered_msgs[i]
                        } else {
                            i
                        };
                        // assert!(msg_idx >= fc.drained_all_msgs);
                        let msg = &fc.all_msgs[msg_idx - fc.drained_all_msgs];
                        let payload_as_text = msg.payload_as_text().unwrap_or_default();
                        let bin_msg = remote_types::BinDltMsg {
                            index: msg.index,
                            reception_time: msg.reception_time_us,
                            timestamp_dms: msg.timestamp_dms,
                            ecu: msg.ecu.as_u32le(),
                            apid: if let Some(a) = msg.apid() {
                                a.as_u32le()
                            } else {
                                0
                            },
                            ctid: if let Some(a) = msg.ctid() {
                                a.as_u32le()
                            } else {
                                0
                            },
                            lifecycle_id: msg.lifecycle,
                            htyp: msg.standard_header.htyp,
                            mcnt: msg.standard_header.mcnt,
                            verb_mstp_mtin: if let Some(e) = &msg.extended_header {
                                e.verb_mstp_mtin
                            } else {
                                0
                            },
                            noar: msg.noar(),
                            payload_as_text,
                        };
                        bin_msgs.push(bin_msg);
                    }
                    info!(
                        log,
                        "stream #{} sending {} bin_msgs",
                        stream.id,
                        bin_msgs.len()
                    );
                    let encoded: Vec<u8> = bincode::encode_to_vec(
                        remote_types::BinType::DltMsgs((stream.id, bin_msgs)),
                        BINCODE_CONFIG,
                    )
                    .unwrap(); // todo
                               //info!(log, "encoded: #{:?}", &encoded);
                    websocket.write_message(Message::Binary(encoded))?;
                }
            } else {
                for i in stream.msgs_sent.end..new_end {
                    let data = Vec::<u8>::with_capacity(65000);
                    let mut writer = std::io::BufWriter::new(data);
                    let msg_idx = if stream.filters_active {
                        stream.filtered_msgs[i]
                    } else {
                        i
                    };
                    fc.all_msgs[msg_idx - fc.drained_all_msgs]
                        .header_as_text_to_write(&mut writer)
                        .unwrap();
                    let data = writer.into_inner().unwrap();
                    websocket.write_message(Message::Text(format!(
                        "stream:{} msg({}):{}",
                        stream.id,
                        i, // or msg_idx or both? rethink with binary stream format
                        String::from_utf8(data).unwrap()
                    )))?;
                }
            }
            stream.msgs_sent.end = new_end;
            // todo for one_pass streams drain the filtered_msgs as well!

            //info!(log, "stream #{} did send {:?}", stream.id, stream.msgs_sent);
        }
        // for queries (not streams), check whether query is done:
        if ((
            ((!got_new_msgs && !(fc.collect_mode==CollectMode::OnePassStreams))
                ||(parser_thread_finished && fc.collect_mode == CollectMode::OnePassStreams))
            && (stream.all_msgs_last_processed_len >= all_msgs_len)) // no new msgs and all processed
            || (stream.msgs_sent.end >= stream.msgs_to_send.end)) // or window size achieved
            && !stream.is_stream
        {
            stream_marked_as_done = true; // will be removed later from the list
            stream.is_done = true;
            // we send an empty list to indicate the end:
            let encoded: Vec<u8> = bincode::encode_to_vec(
                remote_types::BinType::DltMsgs((stream.id, vec![])),
                BINCODE_CONFIG,
            )
            .unwrap(); // todo
            websocket.write_message(Message::Binary(encoded))?;
        }
    }
    if stream_marked_as_done {
        fc.streams.retain(|stream| !stream.is_done);
    }

    if fc.collect_mode == CollectMode::OnePassStreams {
        // drain messages that are not needed any longer
        // from active streams determine min of all_msgs_last_processed_len
        let min_all_msgs_last_processed_len = fc
            .streams
            .iter()
            .map(|s| s.all_msgs_last_processed_len)
            .min()
            .unwrap_or(all_msgs_len);
        // we do assume that the streams dont need to send that msgs later on...
        // todo add assert

        // assert!(min_all_msgs_last_processed_len >= fc.drained_all_msgs);
        let amount_to_drain = min_all_msgs_last_processed_len.saturating_sub(fc.drained_all_msgs);
        if amount_to_drain > 0 {
            debug!(log, "draining {} msgs", amount_to_drain);
            fc.drained_all_msgs += amount_to_drain;
            fc.all_msgs.drain(0..amount_to_drain);
        }
    }

    if parser_thread_finished && !fc.did_inform_parser_processing_finished {
        // we want this to be the last msg (so once lifecycle and eac are sent)
        let nr_msgs = match fc.collect_mode {
            CollectMode::All => fc.all_msgs.len() as u32,
            CollectMode::OnePassStreams => (fc.all_msgs.len() + fc.drained_all_msgs) as u32,
            CollectMode::None => fc.eac_stats.nr_msgs(),
        };
        // send on new msgs or once if finished
        websocket.write_message(Message::Binary(
            bincode::encode_to_vec(
                // todo add info here to indicate that the parser_thread has finished (extend BinFileInfo or introduce new type)
                remote_types::BinType::FileInfo(remote_types::BinFileInfo { nr_msgs }),
                BINCODE_CONFIG,
            )
            .unwrap(), // todo
        ))?;
        fc.did_inform_parser_processing_finished = true;

        // we release the tmpdirs as well:
        fc.temp_dirs.clear();
    }
    Ok(())
}

#[derive(Debug)]
struct ParserThreadType {
    shall_stop: Arc<AtomicBool>,
    parse_thread: std::thread::JoinHandle<Result<(), Box<dyn std::error::Error + Send + Sync>>>,
    lc_thread: std::thread::JoinHandle<
        evmap::WriteHandle<
            adlt::lifecycle::LifecycleId,
            adlt::lifecycle::LifecycleItem,
            (),
            BuildHasherDefault<NoHashHasher<u32>>,
        >,
    >,
    sort_thread: Option<std::thread::JoinHandle<Result<(), SendError<adlt::dlt::DltMessage>>>>,
    lcs_r: evmap::ReadHandle<
        adlt::lifecycle::LifecycleId,
        adlt::lifecycle::Lifecycle,
        (),
        BuildHasherDefault<NoHashHasher<u32>>,
    >,
    rx: Receiver<adlt::dlt::DltMessage>,
}

/// create a parser thread including a channel
///
/// The thread reads data from the BufReader, parses the DLT messages via `parse_dlt_with_storage_header`
/// and forwards the DLT messages to the mpsc channel.
/// Returns the thread handle and the channel receiver where the parsed messages will be send to.
fn create_parser_thread(
    log: slog::Logger,
    input_file_streams: Vec<StreamEntry>,
    namespace: u32,
    sort_by_time: bool,
    mut plugins_active: Vec<Box<dyn Plugin + Send>>,
) -> ParserThreadType {
    let (tx_for_parse_thread, rx_from_parse_thread) = sync_channel(1024 * 1024);
    let (tx_for_lc_thread, rx_from_lc_thread) = sync_channel(512 * 1024);
    let (lcs_r, lcs_w) = evmap::Options::default()
        .with_hasher(nohash_hasher::BuildNoHashHasher::<
            adlt::lifecycle::LifecycleId,
        >::default())
        .construct::<adlt::lifecycle::LifecycleId, adlt::lifecycle::LifecycleItem>();

    // the message flow is:
    // generated by parser_thread  -> lc_thread -> plugin_thread (if plugins_active) -> sort_thread

    let lc_thread = std::thread::Builder::new()
        .name("lc_thread".to_string())
        .spawn(move || {
            adlt::lifecycle::parse_lifecycles_buffered_from_stream(
                lcs_w,
                rx_from_parse_thread,
                &|m| sync_sender_send_delay_if_full(m, &tx_for_lc_thread),
            )
        })
        .unwrap();

    let lcs_r_for_plugins = lcs_r.clone();
    let (_plugin_thread, rx_from_plugin_thread) = if !plugins_active.is_empty() {
        let (tx_for_plugin_thread, rx_from_plugin_thread) = sync_channel(512 * 1024);
        (
            Some(
                std::thread::Builder::new()
                    .name("plugin_thread".to_string())
                    .spawn(move || {
                        plugins_active.iter_mut().for_each(|p| {
                            p.set_lifecycle_read_handle(&lcs_r_for_plugins);
                        });
                        match plugins_process_msgs(
                            rx_from_lc_thread,
                            &|m| sync_sender_send_delay_if_full(m, &tx_for_plugin_thread),
                            plugins_active,
                        ) {
                            Ok(mut plugins_active) => {
                                plugins_active.iter_mut().for_each(|p| p.sync_all());
                                Ok(plugins_active)
                            }
                            Err(e) => Err(e),
                        }
                    })
                    .unwrap(),
            ),
            rx_from_plugin_thread,
        )
    } else {
        (None, rx_from_lc_thread)
    };

    let sort_thread_lcs_r = lcs_r.clone();
    let (sort_thread, rx_final) = if sort_by_time {
        let (tx_for_sort_thread, rx_from_sort_thread) = sync_channel(512 * 1024);
        (
            Some(
                std::thread::Builder::new()
                    .name("sort_thread".to_string())
                    .spawn(move || {
                        adlt::utils::buffer_sort_messages(
                            rx_from_plugin_thread,
                            &|m| sync_sender_send_delay_if_full(m, &tx_for_sort_thread),
                            &sort_thread_lcs_r,
                            3,
                            20 * adlt::utils::US_PER_SEC, // todo target 2s. (to allow live tracing) but some big ECUs have a much weirder delay. Need to improve the algorithm to detect those.
                        )
                    })
                    .unwrap(),
            ),
            rx_from_sort_thread,
        )
    } else {
        (None, rx_from_plugin_thread)
    };

    let shall_stop = Arc::new(AtomicBool::new(false));
    let pt_shall_stop = shall_stop.clone();

    ParserThreadType {
        shall_stop,
        sort_thread,
        parse_thread: std::thread::Builder::new()
                    .name("parse_thread".to_string()).spawn(
            move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                info!(log, "parse_thread started");
                let shall_stop = pt_shall_stop.as_ref();
                let mut messages_processed: adlt::dlt::DltMessageIndexType = 0;

                const BUFREADER_CAPACITY: usize = 512 * 1024;
                // we use a relatively small 512kb chunk size as we're processing
                // the data multithreaded. reading in bigger chunks is in total slower

                let get_single_it =
                    |input_file_name: &str,
                     start_index: adlt::dlt::DltMessageIndexType,
                     first_reception_time_us: Option<u64>,
                     modified_time_us: Option<u64>| {
                        match File::open(input_file_name) {
                            Ok(fi) => {
                                let file_ext = std::path::Path::new(input_file_name)
                                    .extension()
                                    .and_then(|s| s.to_str())
                                    .unwrap_or_default();
                                info!(log, "opened file {} {:?}", input_file_name, &fi);
                                let buf_reader = LowMarkBufReader::new(
                                    fi,
                                    BUFREADER_CAPACITY,
                                    DLT_MAX_STORAGE_MSG_SIZE,
                                );
                                get_dlt_message_iterator(
                                    file_ext,
                                    start_index,
                                    buf_reader,
                                    namespace,
                                    first_reception_time_us,
                                    modified_time_us,
                                    Some(&log),
                                )
                            }
                            Err(e) => {
                                error!(
                                    log,
                                    "failed to open file {} due to {}!", &input_file_name, e
                                );
                                Box::new(std::iter::empty())
                            }
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
                                    get_single_it(
                                        &file,
                                        0,
                                        first_reception_time_us,
                                        dfi.modified_time_us,
                                    )
                                }),
                            )
                        })
                        .collect(),
                );

                loop {
                    match dlt_msg_iterator.next() {
                        Some(msg) => {
                            messages_processed += 1;
                            if let Err(e) =
                                sync_sender_send_delay_if_full(msg, &tx_for_parse_thread)
                            // might block!
                            {
                                info!(log, "parser_thread aborted on err={}", e; "messages_processed" => messages_processed);
                                return Err(Box::new(e));
                            }
                            if shall_stop.load(std::sync::atomic::Ordering::Relaxed) {
                                // todo check how expensive this check is (compared to e.g. doing it only every 1k msgs)
                                info!(log, "parser_thread stopped by shall_stop"; "messages_processed"=>messages_processed);
                                break;
                            }
                        }
                        None => {
                            debug!(log, "finished processing all msgs"; "messages_processed"=>messages_processed);
                            break;
                        }
                    }
                }
                drop(tx_for_parse_thread);
                info!(log, "parser_thread stopped");
                Ok(())
            },
        ).unwrap(),
        lc_thread,
        lcs_r,
        rx: rx_final,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use adlt::{utils::remote_types::BinLifecycle, *};

    // use serde_json::ser::to_string;
    use portpicker::pick_unused_port;
    use slog::{o, Drain, Logger};
    use tempfile::NamedTempFile;

    fn new_logger() -> Logger {
        let decorator = slog_term::PlainSyncDecorator::new(slog_term::TestStdoutWriter);
        let drain = slog_term::FullFormat::new(decorator).build().fuse();
        Logger::root(drain, o!())
    }

    fn write_msgs(
        file: &mut impl std::io::Write,
        nr_msgs: dlt::DltMessageIndexType,
        start_index: u32,
    ) {
        let ecu = dlt::DltChar4::from_buf(b"ECUR");
        for i in start_index..start_index + nr_msgs {
            let sh = dlt::DltStorageHeader {
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
            m.to_write(file).unwrap(); // will persist with timestamp
        }
        file.flush().unwrap();
    }

    #[test]
    fn file_context_1() {
        let log = new_logger();
        assert!(FileContext::from(&log, "open", r#""#).is_err());

        let mut file = NamedTempFile::new().unwrap();
        let file_path = file.path().to_str().unwrap().to_owned();
        let invalid_file_path = file_path.clone() + "foo";

        // empty file -> err as well
        assert!(FileContext::from(
            &log,
            "open",
            format!(r#"{{"files":[{}]}}"#, serde_json::json!(file_path)).as_str()
        )
        .is_err());
        // invalid file -> err
        assert!(FileContext::from(
            &log,
            "open",
            format!(r#"{{"files":[{}]}}"#, serde_json::json!(invalid_file_path)).as_str()
        )
        .is_err());

        // now write one messsage into file_path (and check sort as well)
        write_msgs(&mut file, 1, 0);
        let fc = FileContext::from(
            &log,
            "open",
            format!(
                r#"{{"sort": true, "files":[{}]}}"#,
                serde_json::json!(file_path)
            )
            .as_str(),
        )
        .unwrap();
        assert!(fc.sort_by_time);

        // now two files:
        let mut file2 = NamedTempFile::new().unwrap();
        write_msgs(&mut file2, 1, 1);

        let fc = FileContext::from(
            &log,
            "open",
            format!(
                r#"{{"files":[{},{}]}}"#,
                serde_json::json!(file2.path().to_str().unwrap()),
                serde_json::json!(file_path)
            )
            .as_str(),
        );
        assert!(fc.is_ok());
        let fc = fc.unwrap();
        assert!(!fc.sort_by_time); // defaults to false
        assert_eq!(fc.file_streams.len(), 1);
        assert_eq!(fc.file_streams[0].1.len(), 2);
        // files should be sorted now!
        assert_eq!(
            fc.file_streams[0]
                .1
                .iter()
                .map(|(_, b, _)| b.clone())
                .collect::<Vec<String>>(),
            vec![file_path, file2.path().to_str().unwrap().to_owned()]
        );
        println!("fc with 2 files sorted={:?}", fc); // we can debug print it
    }

    use std::{collections::HashMap, time::Duration};

    #[test]
    fn create_parser_thread_empty() {
        let log = new_logger();
        let input_file_streams: Vec<StreamEntry> = vec![];
        let ptt = create_parser_thread(log, input_file_streams, 42, true, vec![]);
        let pt_pt = ptt.parse_thread.join().unwrap();
        assert!(pt_pt.is_ok());
        let lc_pt = ptt.lc_thread.join().unwrap();
        assert_eq!(lc_pt.len(), 0);
        assert!(ptt.sort_thread.is_some());
        if let Some(st) = ptt.sort_thread {
            let st_pt = st.join().unwrap();
            assert!(st_pt.is_ok());
        }
        // now without sort_by_time:
        let log = new_logger();
        let input_file_streams: Vec<StreamEntry> = vec![];
        let ptt = create_parser_thread(log, input_file_streams, 42, false, vec![]);
        let pt_pt = ptt.parse_thread.join().unwrap();
        assert!(pt_pt.is_ok());
        let lc_pt = ptt.lc_thread.join().unwrap();
        assert_eq!(lc_pt.len(), 0);
        assert!(ptt.sort_thread.is_none());
    }
    #[test]
    fn create_parser_thread_2() {
        let log = new_logger();
        let test_file = std::path::PathBuf::new().join("tests").join("lc_ex002.dlt");
        let fc = FileContext::from(
            &log.clone(),
            "open",
            format!(
                r#"{{"sort":false, "files":[{}]}}"#,
                serde_json::json!(test_file.to_str().unwrap())
            )
            .as_str(),
        )
        .unwrap();
        let mut all_msgs = Vec::with_capacity(52 * 1024 * 1024);
        let start = std::time::Instant::now();
        let ptt =
            create_parser_thread(log, fc.file_streams, 42, fc.sort_by_time, fc.plugins_active);
        let rx_thread = std::thread::spawn(move || {
            for m in ptt.rx {
                all_msgs.push(m);
            }
            all_msgs
        });
        let pt_pt = ptt.parse_thread.join().unwrap();
        let pt_dur = start.elapsed();
        println!("parse_thread took {:?}", pt_dur);
        assert!(pt_pt.is_ok());
        let lc_pt = ptt.lc_thread.join().unwrap();
        let lc_dur = start.elapsed();
        println!("lc_thread took {:?}", lc_dur);
        assert!(!lc_pt.is_empty());
        if let Some(st) = ptt.sort_thread {
            let st_pt = st.join().unwrap();
            let st_dur = start.elapsed();
            println!("sort_thread took {:?}", st_dur);
            assert!(st_pt.is_ok());
        }
        let all_msgs = rx_thread.join().unwrap();
        let rx_dur = start.elapsed();
        println!("rx_thread took {:?}", rx_dur);
        println!("got_msgs={}", all_msgs.len());
    }

    #[test]
    fn create_parser_thread_3() {
        let log = new_logger();
        let test_file = std::path::PathBuf::new().join("tests").join("lc_ex002.dlt");

        let fc = FileContext::from(
            &log.clone(),
            "open",
            format!(
                r#"{{"sort":true, "plugins":[{{"name":"FileTransfer"}}], "files":[{}]}}"#,
                serde_json::json!(test_file.to_str().unwrap())
            )
            .as_str(),
        )
        .unwrap();
        let mut all_msgs = Vec::with_capacity(52 * 1024 * 1024);
        let start = std::time::Instant::now();
        let ptt =
            create_parser_thread(log, fc.file_streams, 42, fc.sort_by_time, fc.plugins_active);
        let rx_thread = std::thread::spawn(move || {
            for m in ptt.rx {
                all_msgs.push(m);
            }
            all_msgs
        });
        let pt_pt = ptt.parse_thread.join().unwrap();
        let pt_dur = start.elapsed();
        println!("parse_thread took {:?}", pt_dur);
        assert!(pt_pt.is_ok());
        let lc_pt = ptt.lc_thread.join().unwrap();
        let lc_dur = start.elapsed();
        println!("lc_thread took {:?}", lc_dur);
        assert!(!lc_pt.is_empty());
        if let Some(st) = ptt.sort_thread {
            let st_pt = st.join().unwrap();
            let st_dur = start.elapsed();
            println!("sort_thread took {:?}", st_dur);
            assert!(st_pt.is_ok());
        }
        let all_msgs = rx_thread.join().unwrap();
        let rx_dur = start.elapsed();
        println!("rx_thread took {:?}", rx_dur);
        println!("got_msgs={}", all_msgs.len());
    }

    #[test]
    /// test a remote "open" command with "collect:false" that can be used to
    /// get all file infos like lifecycles, eac stats, nr_msgs but no msgs
    fn process_file_context_no_collect() {
        let log = new_logger();
        let port = pick_unused_port().expect("no ports free");
        let server = TcpListener::bind(format!("127.0.0.1:{}", port)).unwrap();

        // spawn a thread to connect to the server
        let t = std::thread::spawn(move || {
            let mut ws = tungstenite::client::connect(format!("ws://127.0.0.1:{}", port))
                .unwrap()
                .0;
            println!("got client websocket");
            if let tungstenite::stream::MaybeTlsStream::<std::net::TcpStream>::Plain(stream) =
                ws.get_mut()
            {
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
            }
            let mut file_info_nr_msgs = 0;
            let mut last_eac = None;
            let mut last_lcs: Option<Vec<BinLifecycle>> = None;
            let mut text_msgs: Vec<String> = vec![];
            while let Ok(msg) = ws.read_message() {
                match msg {
                    Message::Binary(d) => {
                        if let Ok((btype, _)) = bincode::decode_from_slice::<remote_types::BinType, _>(
                            &d,
                            BINCODE_CONFIG,
                        ) {
                            match btype {
                                BinType::Progress(p) => {
                                    println!(
                                        "got progress: {} {}/{}",
                                        p.action, p.cur_progress, p.max_progress
                                    );
                                }
                                BinType::FileInfo(s) => {
                                    println!("got file info: nr_msgs={}", s.nr_msgs);
                                    file_info_nr_msgs = s.nr_msgs;
                                }
                                BinType::Lifecycles(lcs) => {
                                    println!(
                                        "got {} lifecycles: {:? }",
                                        lcs.len(),
                                        lcs.iter()
                                            .map(|lc| format!(
                                                "{}:{} #msgs={}",
                                                lc.id, lc.ecu, lc.nr_msgs
                                            ))
                                            .collect::<Vec<String>>()
                                    );
                                    if let Some(last_lcs) = &mut last_lcs {
                                        // merge
                                        for lc in lcs {
                                            if let Some(last_lc) = last_lcs
                                                .iter_mut()
                                                .find(|last_lc| last_lc.id == lc.id)
                                            {
                                                last_lc.nr_msgs = lc.nr_msgs;
                                            } else {
                                                last_lcs.push(lc);
                                            }
                                        }
                                    } else {
                                        last_lcs = Some(lcs);
                                    }
                                }
                                BinType::EacInfo(eac) => {
                                    println!("got eac: {:?}", eac.len());
                                    last_eac = Some(eac);
                                }
                                BinType::PluginState(ps) => {
                                    println!("got plugin state: {:?}", ps);
                                }
                                BinType::StreamInfo(si) => {
                                    println!(
                                        "got stream info: nr_file_msgs_total={}",
                                        si.nr_file_msgs_total
                                    );
                                }
                                BinType::DltMsgs((stream_id, msgs)) => {
                                    println!(
                                        "got dlt msgs: stream_id={} msgs={}",
                                        stream_id,
                                        msgs.len()
                                    );
                                }
                            }
                        }
                    }
                    Message::Text(s) => {
                        println!("got text msg: {}", s);
                        text_msgs.push(s);
                    }
                    _ => {
                        println!("got other msg: {:?}", msg);
                    }
                }
            }
            ws.write_message(tungstenite::protocol::Message::Text("quit".to_string()))
                .unwrap();
            println!("closed client websocket");
            (file_info_nr_msgs, last_eac, last_lcs, text_msgs)
        });

        let stream = server.incoming().next().unwrap().unwrap();
        println!("got incoming stream");
        let mut ws = tungstenite::accept(stream).unwrap();
        println!("got incoming websocket");

        let mut fc = None;
        process_incoming_text_message(
            &log, // lc_ex002 changes later to merged lifecycles... (so use _ex004)
            r#"open {"sort":true, "collect":false, "files":["tests/lc_ex004.dlt"]}"#.to_string(),
            &mut fc,
            &mut ws,
        );
        assert!(fc.is_some());

        // check that streams/queries are rejected:
        process_incoming_text_message(&log, r#"stream {}"#.to_string(), &mut fc, &mut ws);
        process_incoming_text_message(&log, r#"query {}"#.to_string(), &mut fc, &mut ws);

        let mut fc = fc.unwrap();
        assert!(matches!(fc.collect_mode, CollectMode::None));

        let a = process_file_context(&log, &mut fc, &mut ws);
        assert!(a.is_ok(), "a={:?}", a);
        assert!(fc.all_msgs.is_empty());

        // wait >2s to send eac info to the client as well
        std::thread::sleep(Duration::from_millis(2010));
        loop {
            let a = process_file_context(&log, &mut fc, &mut ws);
            assert!(a.is_ok(), "a={:?}", a);
            assert!(fc.all_msgs.is_empty());

            // the example file is small so within >2s we expect all msgs to be processed:
            if fc.eac_stats.nr_msgs() >= 52451 {
                break;
            } else {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        assert_eq!(fc.eac_stats.nr_msgs(), 52451);
        let (remote_file_info_nr_msgs, remote_eac, remote_lcs, remote_text_msgs) =
            t.join().unwrap();
        assert!(remote_text_msgs.iter().any(|t| t.starts_with("ok: open ")));
        assert!(remote_text_msgs
            .iter()
            .any(|t| t.starts_with("err: stream failed")));
        assert!(remote_text_msgs
            .iter()
            .any(|t| t.starts_with("err: query failed")));

        assert_eq!(remote_file_info_nr_msgs, 52451);
        let remote_eac = remote_eac.unwrap();
        assert_eq!(remote_eac.len(), 1);
        assert_eq!(remote_eac.iter().map(|eac| eac.nr_msgs).sum::<u32>(), 52451);
        let remote_lcs = remote_lcs.unwrap();
        assert_eq!(remote_lcs.len(), 2);
        assert_eq!(remote_lcs.iter().map(|lc| lc.nr_msgs).sum::<u32>(), 52451);
    }

    #[test]
    /// test a remote "open" command with 'collect:"one_pass_streams"' that can be used to
    /// use streams that cannot be seeked, searched,... but no messages are collected
    /// so it has little memory usage and is used e.g. by fba-cli to execute once all fishbone queries
    fn process_file_context_one_pass_streams() {
        let log = new_logger();
        let port = pick_unused_port().expect("no ports free");
        let server = TcpListener::bind(format!("127.0.0.1:{}", port)).unwrap();

        // spawn a thread to connect to the server
        let t = std::thread::spawn(move || {
            let mut ws = tungstenite::client::connect(format!("ws://127.0.0.1:{}", port))
                .unwrap()
                .0;
            println!("got client websocket");
            if let tungstenite::stream::MaybeTlsStream::<std::net::TcpStream>::Plain(stream) =
                ws.get_mut()
            {
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
            }
            let mut file_info_nr_msgs = 0;
            let mut last_eac = None;
            let mut last_lcs: Option<Vec<BinLifecycle>> = None;
            let mut text_msgs: Vec<String> = vec![];
            while let Ok(msg) = ws.read_message() {
                match msg {
                    Message::Binary(d) => {
                        if let Ok((btype, _)) = bincode::decode_from_slice::<remote_types::BinType, _>(
                            &d,
                            BINCODE_CONFIG,
                        ) {
                            match btype {
                                BinType::Progress(p) => {
                                    println!(
                                        "got progress: {} {}/{}",
                                        p.action, p.cur_progress, p.max_progress
                                    );
                                }
                                BinType::FileInfo(s) => {
                                    println!("got file info: nr_msgs={}", s.nr_msgs);
                                    file_info_nr_msgs = s.nr_msgs;
                                }
                                BinType::Lifecycles(lcs) => {
                                    println!(
                                        "got {} lifecycles: {:? }",
                                        lcs.len(),
                                        lcs.iter()
                                            .map(|lc| format!(
                                                "{}:{} #msgs={}",
                                                lc.id, lc.ecu, lc.nr_msgs
                                            ))
                                            .collect::<Vec<String>>()
                                    );
                                    if let Some(last_lcs) = &mut last_lcs {
                                        // merge
                                        for lc in lcs {
                                            if let Some(last_lc) = last_lcs
                                                .iter_mut()
                                                .find(|last_lc| last_lc.id == lc.id)
                                            {
                                                last_lc.nr_msgs = lc.nr_msgs;
                                            } else {
                                                last_lcs.push(lc);
                                            }
                                        }
                                    } else {
                                        last_lcs = Some(lcs);
                                    }
                                }
                                BinType::EacInfo(eac) => {
                                    println!("got eac: {:?}", eac.len());
                                    last_eac = Some(eac);
                                }
                                BinType::PluginState(ps) => {
                                    println!("got plugin state: {:?}", ps);
                                }
                                BinType::StreamInfo(si) => {
                                    println!(
                                        "got stream info: nr_file_msgs_total={}",
                                        si.nr_file_msgs_total
                                    );
                                }
                                BinType::DltMsgs((stream_id, msgs)) => {
                                    println!(
                                        "got dlt msgs: stream_id={} msgs={}",
                                        stream_id,
                                        msgs.len()
                                    );
                                }
                            }
                        }
                    }
                    Message::Text(s) => {
                        println!("got text msg: {}", s);
                        text_msgs.push(s);
                    }
                    _ => {
                        println!("got other msg: {:?}", msg);
                    }
                }
            }
            ws.write_message(tungstenite::protocol::Message::Text("quit".to_string()))
                .unwrap();
            println!("closed client websocket");
            (file_info_nr_msgs, last_eac, last_lcs, text_msgs)
        });

        let stream = server.incoming().next().unwrap().unwrap();
        println!("got incoming stream");
        let mut ws = tungstenite::accept(stream).unwrap();
        println!("got incoming websocket");

        let mut fc = None;
        process_incoming_text_message(
            &log, // lc_ex002 changes later to merged lifecycles... (so use _ex004)
            r#"open {"sort":true, "collect":"one_pass_streams", "files":["tests/lc_ex004.dlt"]}"#
                .to_string(),
            &mut fc,
            &mut ws,
        );
        assert!(fc.is_some());

        if let Some(fc) = &mut fc {
            assert!(matches!(fc.collect_mode, CollectMode::OnePassStreams));
            assert!(fc.paused)
        }

        // check that generic streams/queries are rejected:
        process_incoming_text_message(&log, r#"stream {}"#.to_string(), &mut fc, &mut ws);
        process_incoming_text_message(&log, r#"query {}"#.to_string(), &mut fc, &mut ws);

        // as fc is paused it should be a no op
        if let Some(fc) = &mut fc {
            let a = process_file_context(&log, fc, &mut ws);
            assert!(a.is_ok(), "a={:?}", a);
            assert!(fc.all_msgs.is_empty());
        }

        // now add a stream and unpause:
        process_incoming_text_message(
            &log,
            r#"stream {"one_pass":true, "binary":true}"#.to_string(),
            &mut fc,
            &mut ws,
        );
        let mut fc = fc.unwrap();

        assert!(matches!(fc.collect_mode, CollectMode::OnePassStreams));
        fc.paused = false;

        // wait >2s to send eac info to the client as well
        std::thread::sleep(Duration::from_millis(2010));
        loop {
            let a = process_file_context(&log, &mut fc, &mut ws);
            assert!(a.is_ok(), "a={:?}", a);
            assert!(fc.all_msgs.is_empty());

            // the example file is small so within >2s we expect all msgs to be processed:
            if fc.eac_stats.nr_msgs() >= 52451 {
                break;
            } else {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        assert_eq!(fc.eac_stats.nr_msgs(), 52451);
        let (remote_file_info_nr_msgs, remote_eac, remote_lcs, remote_text_msgs) =
            t.join().unwrap();
        assert!(remote_text_msgs.iter().any(|t| t.starts_with("ok: open ")));
        assert!(remote_text_msgs
            .iter()
            .any(|t| t.starts_with("err: stream failed")));
        assert!(remote_text_msgs
            .iter()
            .any(|t| t.starts_with("err: query failed")));

        assert_eq!(remote_file_info_nr_msgs, 52451);
        let remote_eac = remote_eac.unwrap();
        assert_eq!(remote_eac.len(), 1);
        assert_eq!(remote_eac.iter().map(|eac| eac.nr_msgs).sum::<u32>(), 52451);
        let remote_lcs = remote_lcs.unwrap();
        assert_eq!(remote_lcs.len(), 2);
        assert_eq!(remote_lcs.iter().map(|lc| lc.nr_msgs).sum::<u32>(), 52451);
    }

    #[test]
    fn remote_basic() {
        let log = new_logger();
        let port: u16 = pick_unused_port().expect("no ports free");
        let port_str = format!("{}", port);
        let arg_vec = vec!["t", "remote", "-p", &port_str];
        let sub_c = add_subcommand(Command::new("t")).get_matches_from(arg_vec);
        let (_, sub_m) = sub_c.subcommand().unwrap();

        let t = std::thread::spawn(move || {
            let mut ws;
            let start_time = Instant::now();
            loop {
                match tungstenite::client::connect(format!("wss://127.0.0.1:{}", port)) {
                    Ok(p) => {
                        ws = p.0;
                        break;
                    }
                    Err(_e) => {
                        if start_time.elapsed() > Duration::from_secs(1) {
                            panic!("couldnt connect");
                        } else {
                            std::thread::sleep(Duration::from_millis(20));
                        }
                    }
                }
            }
            // simply close:
            ws.write_message(tungstenite::protocol::Message::Text("quit".to_string()))
                .unwrap();
            let answer = ws.read_message().unwrap();
            assert!(answer.is_text(), "answer={:?}", answer);
            assert_eq!(answer.into_text().unwrap(), "unknown command 'quit'!");
            ws.close(None).unwrap();
            std::thread::sleep(Duration::from_millis(20));
        });

        let r = remote(&log, sub_m, true);
        assert!(r.is_ok());
        t.join().unwrap(); // we have to use the result to handle panics from the thread as test error
    }

    use adlt::utils::remote_types::BinType;

    #[test]
    fn remote_open_close() {
        let log = new_logger();
        let port: u16 = pick_unused_port().expect("no ports free");
        let port_str = format!("{}", port);
        let arg_vec = vec!["t", "remote", "-p", &port_str];
        let sub_c = add_subcommand(Command::new("t")).get_matches_from(arg_vec);
        let (_, sub_m) = sub_c.subcommand().unwrap();

        let t = std::thread::spawn(move || {
            let mut ws;
            let start_time = Instant::now();
            let mut adlt_version = None;
            let mut adlt_archives_supported = None;
            loop {
                match tungstenite::client::connect(format!("wss://127.0.0.1:{}", port)) {
                    Ok(p) => {
                        ws = p.0;
                        for (ref header, value) in p.1.headers() {
                            println!("header: {:?}={:?}", header, value);
                            match header.as_str() {
                                "adlt-version" => {
                                    adlt_version = value.to_str().map(|v| v.to_owned()).ok()
                                }
                                "adlt-archives-supported" => {
                                    adlt_archives_supported =
                                        value.to_str().map(|v| v.to_owned()).ok()
                                }
                                _ => {
                                    println!(" ignored header: {:?}={:?}", header, value);
                                }
                            }
                        }
                        break;
                    }
                    Err(_e) => {
                        if start_time.elapsed() > Duration::from_secs(1) {
                            panic!("couldnt connect");
                        } else {
                            std::thread::sleep(Duration::from_millis(20));
                        }
                    }
                }
            }
            assert!(adlt_version.is_some());
            assert!(adlt_archives_supported.is_some());
            // open a file:
            let test_file = std::path::PathBuf::new()
                .join("tests")
                .join("lc_ex002.zip!/tests/lc_ex002.dlt");
            ws.write_message(tungstenite::protocol::Message::Text(format!(
                r#"open {{"files":[{}], "plugins":[{{"name":"Rewrite","rewrites":[]}}]}}"#,
                serde_json::json!(test_file.to_str().unwrap()),
            )))
            .unwrap();
            let answer = ws.read_message().unwrap();
            assert_eq!(
                answer.into_text().unwrap(),
                r#"ok: open {"plugins_active":["Rewrite"]}"#
            );

            let expected_msgs = 11696;
            let expected_lcs = 3;
            let mut got_lcs: HashMap<u32, u32> = HashMap::new();
            // now we'll get some infos:
            // we do expect:
            //  FileInfo with the nr_msgs up to 11696
            //  Lifecycle info for 3 lifecycles covering 11696-4 msgs (4 CTRL_REQUEST are part of a non transmitted LC)
            //  EACs info covering the 11696 msgs
            // PluginState

            let mut got_stream_ok = false;
            let mut got_msgs = 0usize;

            let mut got_lifecycles = false;
            let mut got_fileinfo = false; // set once 11696 msgs have been announced
            let mut got_eacinfo = false;
            let mut got_pluginstate = false;
            let mut got_streaminfo = false;

            let start_time = Instant::now();
            if let tungstenite::stream::MaybeTlsStream::<std::net::TcpStream>::Plain(stream) =
                ws.get_mut()
            {
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
            }
            loop {
                if let Ok(msg) = ws.read_message() {
                    match msg {
                        Message::Binary(d) => {
                            if let Ok((btype, _)) = bincode::decode_from_slice::<
                                remote_types::BinType,
                                _,
                            >(&d, BINCODE_CONFIG)
                            {
                                match btype {
                                    BinType::Progress(p) => {
                                        println!(
                                            "got binary msg Progress: {} {}/{}",
                                            p.action, p.cur_progress, p.max_progress
                                        );
                                    }
                                    BinType::FileInfo(s) => {
                                        println!("got binary msg FileInfo: {}", s.nr_msgs);
                                        got_fileinfo = s.nr_msgs == expected_msgs;
                                    }
                                    BinType::Lifecycles(lcs) => {
                                        println!("got binary msg with {} Lifecycles", lcs.len());
                                        for lc in &lcs {
                                            println!(
                                                "got binary msg Lifecycle: #{} {} msgs",
                                                lc.id, lc.nr_msgs
                                            );
                                            got_lcs.insert(lc.id, lc.nr_msgs);
                                        }
                                        got_lifecycles = got_lcs.iter().map(|lc| lc.1).sum::<u32>()
                                        == (expected_msgs-4) // 4 are CTRL_REQUESTS and not part of lc
                                        && got_lcs.len() == expected_lcs;
                                    }
                                    BinType::EacInfo(eacs) => {
                                        let sum_msgs: u32 =
                                            eacs.iter().map(|eac| eac.nr_msgs).sum();
                                        got_eacinfo = sum_msgs == expected_msgs;
                                        println!(
                                            "got binary msg EacInfo: {}, sum_msgs={}",
                                            eacs.len(),
                                            sum_msgs
                                        );
                                    }
                                    BinType::PluginState(p) => {
                                        println!("got binary msg PluginState: {}", p.len());
                                        got_pluginstate = true;
                                    }
                                    BinType::DltMsgs((_stream_id, msgs)) => {
                                        println!("got binary msg DltMsgs: #{}", msgs.len());
                                        got_msgs += msgs.len();
                                    } // _ => {}
                                    BinType::StreamInfo(_si) => {
                                        got_streaminfo = true;
                                        // todo add test where this is evaluated!
                                    }
                                }
                            }
                        }
                        Message::Text(s) => {
                            println!("got text msg: {}", s);
                            if s.starts_with("ok: stream") {
                                // todo check stream id {"id":x,...} and compare with DltMsgs stream_id
                                got_stream_ok = true;
                            }
                        }
                        _ => {} // ignore
                    }
                }
                if got_fileinfo && got_lifecycles && got_eacinfo && got_pluginstate {
                    break;
                }
                if start_time.elapsed() > Duration::from_secs(10) {
                    println!("timeout");
                    break;
                }
            }
            assert!(got_fileinfo);
            assert!(
                got_lifecycles,
                "expected lcs={}, got_lcs={:?}",
                expected_lcs, got_lcs
            );
            assert!(got_eacinfo);
            assert!(got_pluginstate);
            assert_eq!(got_msgs, 0); // no msgs expected as no stream requested
            assert!(!got_stream_ok);
            assert!(!got_streaminfo);

            // send a cmd to the plugin:
            ws.write_message(tungstenite::protocol::Message::Text(
                r#"plugin_cmd {"name":"Rewrite","cmd":"unknown_cmd"}"#.to_string(),
            ))
            .unwrap();
            // there might be binary messages as well, so we need to loop:
            loop {
                let answer = ws.read_message().unwrap();
                if answer.is_binary() {
                    continue;
                }
                assert!(answer.is_text(), "answer={:?}", answer);
                assert_eq!(
                    answer.into_text().unwrap(),
                    "err: plugin_cmd plugin 'Rewrite' does not support commands"
                );
                break;
            }

            // simply close it
            ws.write_message(tungstenite::protocol::Message::Text("close".to_string()))
                .unwrap();
            let answer = ws.read_message().unwrap();
            assert!(answer.is_text(), "answer={:?}", answer);
            assert_eq!(answer.into_text().unwrap(), "ok: 'close'!");
            ws.close(None).unwrap();
            std::thread::sleep(Duration::from_millis(20));
        });

        let r = remote(&log, sub_m, true);
        assert!(r.is_ok());
        t.join().unwrap(); // we have to use the result to handle panics from the thread as test error
    }

    #[test]
    fn type_for_filetype1() {
        let path = std::path::PathBuf::new().join("tests");
        let metadata = path.metadata().unwrap();
        assert_eq!(type_for_filetype(&metadata.file_type(), &path), "dir");

        let path = std::path::PathBuf::new().join("tests").join("lc_ex002.dlt");
        let metadata = path.metadata().unwrap();
        assert_eq!(type_for_filetype(&metadata.file_type(), &path), "file");
        // todo how to add locally a symlink? (could add to tests dir and then remove?)
    }

    #[test]
    fn test_process_fs_cmd_wrong_args() {
        let log = new_logger();
        let res = process_fs_cmd(
            &log,
            serde_json::json!({"path":"tests"}).as_object().unwrap(),
        );
        assert!(res.is_err()); // cmd missing
        let res = process_fs_cmd(
            &log,
            serde_json::json!({"cmd":"unknown"}).as_object().unwrap(),
        );
        assert!(res.is_err()); // path missing
        let res = process_fs_cmd(
            &log,
            serde_json::json!({"cmd":"unknown","path":"tests"})
                .as_object()
                .unwrap(),
        );
        assert!(res.is_err()); // unknown cmd
    }

    #[test]
    fn test_process_fs_cmd_stat() {
        let log = new_logger();
        let res = process_fs_cmd(
            &log,
            serde_json::json!({"cmd":"stat", "path":"tests"})
                .as_object()
                .unwrap(),
        );
        assert!(res.is_ok());
        let res = res.unwrap();
        //println!("res={}", serde_json::to_string_pretty(&res).unwrap());
        assert!(res.is_object());
        let res = res.as_object().unwrap();
        let stat = res.get("stat");
        assert!(stat.is_some());
        let stat = stat.unwrap();
        assert!(stat.is_object());
        let stat = stat.as_object().unwrap();
        assert_eq!(stat.get("type").unwrap(), "dir");
    }

    #[test]
    fn test_process_fs_cmd_read_dir() {
        let log = new_logger();
        let res = process_fs_cmd(
            &log,
            serde_json::json!({"cmd":"readDirectory", "path":"tests"})
                .as_object()
                .unwrap(),
        );
        assert!(res.is_ok());
        let res = res.unwrap();
        println!("res={}", serde_json::to_string_pretty(&res).unwrap());
        assert!(res.is_array());
        let res = res.as_array().unwrap();
        assert!(!res.is_empty());
        let first = res.first().unwrap();
        assert!(first.is_object());
        let first = first.as_object().unwrap();
        assert!(first.contains_key("name"));
        assert!(first.contains_key("type"));
        // check that all entries have a name and type
        for entry in res {
            assert!(entry.is_object());
            let entry = entry.as_object().unwrap();
            assert!(entry.contains_key("name"));
            assert!(entry.contains_key("type"));
        }
    }

    #[test]
    fn test_process_fs_cmd_read_dir_archive() {
        let log = new_logger();
        let res = process_fs_cmd(
            &log,
            serde_json::json!({"cmd":"readDirectory", "path":format!("{}/tests/lc_ex002.zip!/tests", std::env::current_dir().unwrap().to_str().unwrap())})
                .as_object()
                .unwrap(),
        );
        println!("res={:?}", res);
        assert!(res.is_ok());
        let res = res.unwrap();
        //println!("res={}", serde_json::to_string_pretty(&res).unwrap());
        assert!(res.is_array());
        let res = res.as_array().unwrap();
        assert!(!res.is_empty());
        // check that all entries have a name and type
        for entry in res {
            assert!(entry.is_object());
            let entry = entry.as_object().unwrap();
            assert!(entry.contains_key("name"));
            assert!(entry.contains_key("type"));
        }
    }

    #[test]
    fn test_process_fs_cmd_read_dir_archive_root() {
        let log = new_logger();
        let res = process_fs_cmd(
            &log,
            serde_json::json!({"cmd":"readDirectory", "path":format!("{}/tests/lc_ex002.zip!", std::env::current_dir().unwrap().to_str().unwrap())})
                .as_object()
                .unwrap(),
        );
        println!("res={:?}", res);
        assert!(res.is_ok());
        let res = res.unwrap();
        //println!("res={}", serde_json::to_string_pretty(&res).unwrap());
        assert!(res.is_array());
        let res = res.as_array().unwrap();
        assert!(!res.is_empty());
        // check that all entries have a name and type
        for entry in res {
            assert!(entry.is_object());
            let entry = entry.as_object().unwrap();
            assert!(entry.contains_key("name"));
            assert!(entry.contains_key("type"));
        }
    }
}
