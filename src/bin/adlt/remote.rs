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
        get_dlt_infos_from_file, get_dlt_message_iterator, get_new_namespace, remote_types,
        sorting_multi_readeriterator::{SequentialMultiIterator, SortingMultiReaderIterator},
        sync_sender_send_delay_if_full, DltFileInfos, LowMarkBufReader,
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
    sync::{
        mpsc::{sync_channel, Receiver, SendError},
        Arc, RwLock,
    },
    time::Instant,
};
use tungstenite::{
    accept_hdr_with_config,
    handshake::server::{Request, Response},
    Message, WebSocket,
};

use adlt::filter::{Filter, FilterKind, FilterKindContainer};

use bincode::config;

const BINCODE_CONFIG: config::Configuration<
    config::LittleEndian,
    config::Fixint,
    config::WriteFixedArrayLength,
    config::NoLimit,
> = config::legacy(); // todo choose local endianess

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
        spawned_servers.push(std::thread::spawn(move || {
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
            let websocket_res = accept_hdr_with_config(a_stream, callback, Some(web_socket_config));
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
                    Message::Text(t) => {
                        process_incoming_text_message(&log, t, &mut file_context, &mut websocket)
                    }
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
        }));
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

#[derive(Debug)]
struct StreamContext {
    id: u32,
    is_done: bool,   // stop message is sent
    is_stream: bool, // else one-time query
    binary: bool,
    filters_active: bool,
    filters: FilterKindContainer<Vec<Filter>>,
    filtered_msgs: Vec<usize>,            // indizes to all_msgs vec
    all_msgs_last_processed_len: usize,   // last len of all_msgs reflected in filtered_msgs
    msgs_to_send: std::ops::Range<usize>, // the requested window
    msgs_sent: std::ops::Range<usize>,
}

/// next stream id. Zero is used as "no lifecycle" so first one must start with 1
static NEXT_STREAM_ID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);

impl StreamContext {
    fn from(
        log: &slog::Logger,
        command: &str,
        json_str: &str,
    ) -> Result<StreamContext, Box<dyn std::error::Error>> {
        // parse json
        let v = serde_json::from_str::<serde_json::Value>(json_str)?;
        debug!(
            log,
            "StreamContext::from({}:{}) = {:?}", command, json_str, v
        );

        let is_stream = command == "stream";

        let mut start_idx = 0;
        let mut end_idx = 20; // todo
        let mut filters: FilterKindContainer<Vec<Filter>> = Default::default();

        match &v["window"] {
            serde_json::Value::Array(a) => {
                debug!(log, "StreamContext window={:?}", a);
                if a.len() != 2 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("'window' expects array with two elements. got {}", a.len()),
                    )
                    .into());
                } else {
                    start_idx = a[0].as_u64().unwrap_or(0) as usize; // todo better err and not ignore
                    end_idx = a[1].as_u64().unwrap_or(20) as usize; // todo better err and not default 20
                }
            }
            serde_json::Value::Null => {} // keep defaults
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "wrong type for 'window'",
                )
                .into());
            }
        }

        match &v["filters"] {
            serde_json::Value::Array(a) => {
                for filter in a {
                    debug!(log, "StreamContext filters got '{}'", filter.to_string());
                    let filter_struct = Filter::from_json(&filter.to_string())?;
                    debug!(log, "StreamContext filters parsed as '{:?}'", filter_struct);
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

        let binary = match &v["binary"] {
            serde_json::Value::Bool(b) => b,
            _ => {
                if is_stream {
                    &false
                } else {
                    &true
                }
            } // we default to binary for all but stream (yet)
        };

        // todo think about Marker, Event...
        let filters_active = filters[FilterKind::Positive].len()
            + filters[FilterKind::Negative].len()
            + filters[FilterKind::Event].len()
            > 0;

        Ok(StreamContext {
            id: NEXT_STREAM_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            is_done: false,
            is_stream,
            binary: *binary,
            filters,
            filters_active,
            filtered_msgs: Vec::new(),
            all_msgs_last_processed_len: 0,
            msgs_to_send: std::ops::Range {
                start: start_idx,
                end: end_idx,
            },
            msgs_sent: std::ops::Range {
                start: start_idx,
                end: start_idx,
            },
        })
    }
}

type SetOfEcuIds = HashSet<DltChar4>;
type StreamEntry = (SetOfEcuIds, Vec<(u64, String, DltFileInfos)>);

#[derive(Debug)]
struct FileContext {
    file_streams: Vec<StreamEntry>, // set of files that need to be processed as parallel streams
    namespace: u32,
    sort_by_time: bool,                          // sort by timestamp
    plugins_active: Vec<Box<dyn Plugin + Send>>, // will be moved to parsing_thread
    plugin_states: Vec<(u32, Arc<RwLock<PluginState>>)>,
    parsing_thread: Option<ParserThreadType>,
    all_msgs: Vec<adlt::dlt::DltMessage>,
    streams: Vec<StreamContext>,
    /// we did send lifecycles with that max_msg_index_update
    lcs_max_msg_index_update: DltMessageIndexType,

    /// stats like ecu, apid, ctid:
    eac_stats: EacStats,
    eac_next_send_time: Instant,
    eac_last_nr_msgs: DltMessageIndexType,
}

impl FileContext {
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

        // check whether at least the first file can be opened:
        if file_names.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "at least one file name needed",
            ));
        }
        let namespace = get_new_namespace();

        // map input_file_names to name/first msg
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

        let all_msgs_len_estimate = sum_file_len / 128; // todo better heuristics? e.g. 20gb dlt -> 117mio msgs
        info!(
            log,
            "FileContext sum_file_len={} -> estimated #msgs = {}",
            sum_file_len,
            all_msgs_len_estimate
        );

        if input_file_streams.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "cannot open files or files contain no DLT messages",
            ));
        }

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
            file_streams: input_file_streams,
            namespace,
            sort_by_time,
            plugins_active,
            plugin_states,
            parsing_thread: None,
            all_msgs: Vec::with_capacity(std::cmp::min(
                all_msgs_len_estimate as usize,
                u32::MAX as usize,
            )),
            streams: Vec::new(),
            lcs_max_msg_index_update: 0,
            eac_stats,
            eac_next_send_time: std::time::Instant::now() + std::time::Duration::from_secs(2), // after 2 secs the first update
            eac_last_nr_msgs: 0,
        })
    }
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
///     Returns a stream_id. And guarantues that no msg is streamed before the answer is send with that stream_id.
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
                    Ok(mut s) => {
                        let plugins_active_str = serde_json::json!(s
                            .plugins_active
                            .iter()
                            .map(|p| p.name())
                            .collect::<Vec<&str>>());

                        // setup parsing thread
                        // todo think about it. we do need to move the plugins now out as we pass them to a different thread
                        // and they are not + Sync (but only +Send)
                        let plugins_active = std::mem::take(&mut s.plugins_active);
                        s.parsing_thread = Some(create_parser_thread(
                            log.clone(),
                            s.file_streams.clone(),
                            s.namespace,
                            s.sort_by_time,
                            plugins_active,
                        ));

                        file_context.replace(s);

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
        "close" => {
            if file_context.is_some() {
                let old_fc = file_context.take().unwrap();
                // todo how to trigger end e.g. for streams?
                if let Some(parsing_thread) = old_fc.parsing_thread {
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
                    let stream = StreamContext::from(log, command, params);
                    match stream {
                        Ok(stream) => {
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
                            if let Some(pos) = fc.streams.iter().position(|x| x.id == id) {
                                match command {
                                    "stream_search" => {
                                        // search within the stram for all messages matching the filters:
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
                                                    stream.id = NEXT_STREAM_ID.fetch_add(
                                                        1,
                                                        std::sync::atomic::Ordering::Relaxed,
                                                    );
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
/// For symlinks the type of the target is returned (symlink_dir, symlink_file or symlink).
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
            "stat" => match std::fs::symlink_metadata(path) {
                // todo size/mtime/ctime for the traversed dest?)
                Ok(attr) => Ok(serde_json::json!({"stat":{
                    "type":type_for_filetype(&attr.file_type(), &path.into()),
                    "size":attr.len(),
                    "mtime":attr.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH).duration_since(std::time::SystemTime::UNIX_EPOCH).unwrap_or(std::time::Duration::from_secs(0)).as_millis() as u64, // to u64 as json windows cannot convert u128
                    "ctime":attr.created().unwrap_or(std::time::SystemTime::UNIX_EPOCH).duration_since(std::time::SystemTime::UNIX_EPOCH).unwrap_or(std::time::Duration::from_secs(0)).as_millis() as u64,
                }})),
                Err(e) => Ok(serde_json::json!({"err":format!("stat failed with '{}'", e)})),
            },
            "readDirectory" => match std::fs::read_dir(path) {
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
                Err(e) => {
                    Ok(serde_json::json!({"err":format!("readDirectory failed with '{}'", e)}))
                }
            },
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

    let have_pos_filters = !filters[FilterKind::Positive].is_empty();
    let have_event_filters = !filters[FilterKind::Event].is_empty();

    // check msgs from _processed_len to all_msgs_len
    // todo use parallel iterator
    // todo break after some max time/max amount of messages to improve reaction time
    let mut i = start_idx;
    let stream_msgs_len = stream.filtered_msgs.len();
    while i < stream_msgs_len {
        let msg: &adlt::dlt::DltMessage = &all_msgs[stream.filtered_msgs[i]];
        let matches = match_filters(msg, &filters, have_pos_filters, have_event_filters);

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
) -> Result<(), tungstenite::Error> {
    let mut got_new_msgs = false;
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(50);

    if let Some(pt) = &fc.parsing_thread {
        let rx = &pt.rx;
        loop {
            // todo use rx.try_recv first???
            let rm = rx.recv_timeout(std::time::Duration::from_millis(10));
            match rm {
                Ok(msg) => {
                    fc.eac_stats.add_msg(&msg);
                    fc.all_msgs.push(msg);
                    got_new_msgs = true;
                }
                _ => {
                    break;
                }
            };
            if std::time::Instant::now() > deadline {
                break;
            }
        }
    }
    // inform about new msgs
    if got_new_msgs && websocket.can_write() {
        // todo debounce this a bit? (eg with eac stats?)
        websocket.write_message(Message::Binary(
            bincode::encode_to_vec(
                remote_types::BinType::FileInfo(remote_types::BinFileInfo {
                    nr_msgs: fc.all_msgs.len() as u32,
                }),
                BINCODE_CONFIG,
            )
            .unwrap(), // todo
        ))?;

        // lc infos:
        // we send updates only on the ones that did change
        if let Some(pt) = &fc.parsing_thread {
            let lcs_r = &pt.lcs_r;
            if let Some(lc_map) = lcs_r.read() {
                let mut lcs: Vec<remote_types::BinLifecycle> = vec![];
                let mut new_max_msg_index_update = fc.lcs_max_msg_index_update;
                for lc in lc_map.iter().map(|(_id, b)| b.get_one().unwrap()) {
                    if lc.max_msg_index_update > fc.lcs_max_msg_index_update {
                        new_max_msg_index_update =
                            std::cmp::max(new_max_msg_index_update, lc.max_msg_index_update);
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
                fc.lcs_max_msg_index_update = new_max_msg_index_update;
                if !lcs.is_empty() {
                    // we do send them sorted (even in case only updates are sent)
                    lcs.sort_unstable_by(|a, b| a.start_time.cmp(&b.start_time));
                    let encoded: Vec<u8> = bincode::encode_to_vec(
                        remote_types::BinType::Lifecycles(lcs),
                        BINCODE_CONFIG,
                    )
                    .unwrap(); // todo
                               //info!(log, "encoded: #{:?}", &encoded);
                    websocket.write_message(Message::Binary(encoded))?;
                }
            }
        }
    }

    // send eac stats? if deadline expired and nr_msgs have increased
    // so if only desc have been updated this wont trigger a resend
    if fc.eac_next_send_time < deadline {
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
    let all_msgs_len = fc.all_msgs.len();
    for stream in &mut fc.streams {
        // more messages avail?
        let last_all_msgs_last_processed_len = stream.all_msgs_last_processed_len;
        if all_msgs_len > last_all_msgs_last_processed_len {
            if stream.filters_active {
                let have_pos_filters = !stream.filters[FilterKind::Positive].is_empty();
                let have_event_filters = !stream.filters[FilterKind::Event].is_empty();

                // check msgs from _processed_len to all_msgs_len
                // todo use parallel iterator
                // todo break after some max time/max amount of messages to improve reaction time
                let mut i = last_all_msgs_last_processed_len;
                while i < all_msgs_len {
                    let msg: &adlt::dlt::DltMessage = &fc.all_msgs[i];
                    let matches =
                        match_filters(msg, &stream.filters, have_pos_filters, have_event_filters);

                    if matches {
                        stream.filtered_msgs.push(i);
                        // for !is_stream end as soon as enough are filtered/found
                        if !stream.is_stream
                            && stream.filtered_msgs.len() >= stream.msgs_to_send.end
                        {
                            i += 1;
                            break;
                        }
                    }
                    i += 1;
                    if i % 1_000_000 == 0 {
                        // process 1mio msgs as a chunk
                        break;
                    }
                }
                stream.all_msgs_last_processed_len = i;
            } else {
                stream.all_msgs_last_processed_len = all_msgs_len;
            }
        }

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
                        let msg = &fc.all_msgs[msg_idx];
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
                            payload_as_text: msg.payload_as_text().unwrap_or_default(),
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
                    fc.all_msgs[msg_idx]
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
            //info!(log, "stream #{} did send {:?}", stream.id, stream.msgs_sent);
        }
        if ((!got_new_msgs && (stream.all_msgs_last_processed_len >= all_msgs_len)) // no new msgs and all processed
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
    Ok(())
}

fn match_filters(
    msg: &adlt::dlt::DltMessage,
    filters: &FilterKindContainer<Vec<Filter>>,
    have_pos_filters: bool,
    have_event_filters: bool,
) -> bool {
    let mut matches = !have_pos_filters;

    // for now do a simple support of pos. and neg. filters
    for filter in &filters[FilterKind::Positive] {
        if filter.matches(msg) {
            matches = true;
            // debug!(log, "stream {} got pos matching msg idx={}", stream.id, i);
            break;
        }
    }
    if matches {
        // and neg that removes the msg?
        for filter in &filters[FilterKind::Negative] {
            if filter.matches(msg) {
                matches = false;
                // debug!(log, "stream {} got neg matching msg idx={}", stream.id, i);
                break;
            }
        }
    }

    // report/event filter?
    // if any is set it has to match as well
    // so they are applied after the pos/neg filters
    // todo think about it... (could be treated as pos filter as well)
    if matches && have_event_filters {
        matches = false;
        for filter in &filters[FilterKind::Event] {
            if filter.matches(msg) {
                matches = true;
                /*debug!(
                    log,
                    "stream {} got pos matching event msg idx={}", stream.id, i
                );*/
                break;
            }
        }
    }
    matches
}

#[derive(Debug)]
struct ParserThreadType {
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
    plugins_active: Vec<Box<dyn Plugin + Send>>,
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

    let lc_thread = std::thread::spawn(move || {
        adlt::lifecycle::parse_lifecycles_buffered_from_stream(lcs_w, rx_from_parse_thread, &|m| {
            sync_sender_send_delay_if_full(m, &tx_for_lc_thread)
        })
    });

    let (_plugin_thread, rx_from_plugin_thread) = if !plugins_active.is_empty() {
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
                    3,
                    20 * adlt::utils::US_PER_SEC, // todo target 2s. (to allow live tracing) but some big ECUs have a much weirder delay. Need to improve the algorithm to detect those.
                )
            })),
            rx_from_sort_thread,
        )
    } else {
        (None, rx_from_plugin_thread)
    };

    ParserThreadType {
        sort_thread,
        parse_thread: std::thread::spawn(
            move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                info!(log, "parser_thread started");
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
                            {
                                info!(log, "parser_thread aborted on err={}", e; "msgs_processed" => messages_processed);
                                return Err(Box::new(e));
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
        ),
        lc_thread,
        lcs_r,
        rx: rx_final,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use adlt::*;
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

    #[test]
    fn stream_context_1() {
        let log = new_logger();
        let sc = StreamContext::from(&log, "stream", "");
        assert!(sc.is_err()); // not a json object
                              // valid one with defaults:
        let sc = StreamContext::from(&log, "stream", "{}").unwrap();
        assert!(!sc.filters_active);

        // with empty filters:
        let sc = StreamContext::from(&log, "stream", r#"{"filters":[]}"#).unwrap();
        assert!(!sc.filters_active);
        assert_eq!(sc.filters[FilterKind::Positive].len(), 0);
        assert_eq!(sc.filters[FilterKind::Negative].len(), 0);
        assert_eq!(sc.filters[FilterKind::Marker].len(), 0);
        assert_eq!(sc.filters[FilterKind::Event].len(), 0);

        // with a neg filters:
        let sc = StreamContext::from(&log, "stream", r#"{"filters":[{"type":1}]}"#).unwrap();
        assert!(sc.filters_active);
        assert_eq!(sc.filters[FilterKind::Positive].len(), 0);
        assert_eq!(sc.filters[FilterKind::Negative].len(), 1);
        assert_eq!(sc.filters[FilterKind::Marker].len(), 0);
        assert_eq!(sc.filters[FilterKind::Event].len(), 0);

        // with a window (but empty -> invalid)
        assert!(StreamContext::from(&log, "stream", r#"{"window":[]}"#).is_err());
        // with a window (but 1 value -> invalid)
        assert!(StreamContext::from(&log, "stream", r#"{"window":[1]}"#).is_err());
        // with a window (but 3 values -> invalid)
        assert!(StreamContext::from(&log, "stream", r#"{"window":[1,2,3]}"#).is_err());
        // with a valid window (todo order, wrong types.... to be added)
        let sc = StreamContext::from(&log, "stream", r#"{"window":[1,2]}"#).unwrap();
        println!("sc with windows={:?}", sc); // we can debug print it
        assert_eq!(sc.msgs_to_send.start, 1);
        assert_eq!(sc.msgs_to_send.end, 2);
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
        assert!(lc_pt.len() > 0);
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
        assert!(lc_pt.len() > 0);
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
            // open a file:
            let test_file = std::path::PathBuf::new().join("tests").join("lc_ex002.dlt");
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
            let answer = ws.read_message().unwrap();
            assert!(answer.is_text(), "answer={:?}", answer);
            assert_eq!(
                answer.into_text().unwrap(),
                "err: plugin_cmd plugin 'Rewrite' does not support commands"
            );

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
        //println!("res={}", serde_json::to_string_pretty(&res).unwrap());
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
}
