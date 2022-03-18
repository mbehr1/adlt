use adlt::dlt::DLT_MAX_STORAGE_MSG_SIZE;
use adlt::utils::{
    get_first_message_from_file, remote_types, DltMessageIterator, LowMarkBufReader,
};
use clap::{App, Arg, SubCommand};
use slog::{debug, error, info, warn}; // crit, debug, info
use std::fs::File;
use std::io::prelude::*;
use std::net::TcpListener;

use tungstenite::{
    accept_hdr,
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

pub fn add_subcommand<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
    app.subcommand(
        SubCommand::with_name("remote")
            .about("Provide remote server functionalities")
            .arg(
                Arg::with_name("port")
                    .short("p")
                    .takes_value(true)
                    .help("websocket port to use")
                    .default_value("6665"),
            ),
    )
}

/// provide remote server functionalities
pub fn remote(
    log: &slog::Logger,
    sub_m: &clap::ArgMatches,
) -> Result<(), Box<dyn std::error::Error>> {
    // we do use log only if for local websocket related issues
    // for the remote part we do use an own logger logging to the websocket itself todo
    let port = sub_m.value_of("port").unwrap().parse::<u16>()?;
    info!(log, "remote starting"; "port" => port);

    let server_addr = format!("127.0.0.1:{}", port); // todo ipv6???
    let server = TcpListener::bind(server_addr)?;
    // server.set_nonblocking(true).expect("Cannot set non-blocking");
    info!(log, "remote server listening on 127.0.0.1:{}", port; "port" => port);
    // output on stdout as well to help identify a proper startup even with verbose options:
    println!("remote server listening on 127.0.0.1:{}", port);

    for stream in server.incoming() {
        let logc = log.clone();
        std::thread::spawn(move || {
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
            let a_stream = stream.unwrap();
            a_stream
                .set_read_timeout(Some(std::time::Duration::from_millis(100)))
                .expect("failed to set_read_timeout"); // panic on failure
            let mut websocket = accept_hdr(a_stream, callback).unwrap();

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
                        info!(log, "ws process_file_context returned err {:?}", r);
                        break;
                    }
                }

                let msg = websocket.read_message();
                if let Err(err) = msg {
                    match err {
                        tungstenite::Error::Io(ref e)
                            if e.kind() == std::io::ErrorKind::WouldBlock =>
                        {
                            let all_msgs_len = if file_context.is_some() {
                                file_context.as_ref().unwrap().all_msgs.len()
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
                            info!(log, "ws read_message returned {:?}", err);
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
                    Message::Close(cf) => {
                        info!(log, "got close message with {:?}", cf);
                        break;
                    }
                    Message::Ping(_) | Message::Pong(_) => {}
                }
            }
            let _ = websocket.write_pending(); // ignore error
        });
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
                    info!(log, "StreamContext filters got '{}'", filter.to_string());
                    let filter_struct = Filter::from_json(&filter.to_string())?;
                    info!(log, "StreamContext filters parsed as '{:?}'", filter_struct);
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

#[derive(Debug)]
struct FileContext {
    file_names: Vec<String>,
    sort_by_time: bool, // sort by timestamp
    parsing_thread: Option<ParserThreadType>,
    all_msgs: Vec<adlt::dlt::DltMessage>,
    streams: Vec<StreamContext>,
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
        // map input_file_names to name/first msg
        let file_msgs = file_names.iter().map(|f_name| {
            let fi = File::open(f_name);
            match fi {
                Ok(mut f) => {
                    let m1 = get_first_message_from_file(&mut f, 512 * 1024);
                    if m1.is_none() {
                        warn!(log, "file {} doesn't contain a DLT message in first 0.5MB. Skipping!", f_name;);
                    }
                    (f_name, m1)
                }
                _ => {
                    warn!(log, "couldn't open {}. Skipping!", f_name;);
                    (f_name, None)
                }
            }
        });
        let mut file_msgs: Vec<_> = file_msgs.filter(|(_a, b)| b.is_some()).collect();
        file_msgs.sort_by(|a, b| {
            a.1.as_ref()
                .unwrap()
                .reception_time_us
                .cmp(&b.1.as_ref().unwrap().reception_time_us)
        });
        let file_names: Vec<_> = file_msgs.iter_mut().map(|(a, _b)| (*a).into()).collect();
        //debug!(log, "sorted input_files by first message reception time:"; "input_file_names" => format!("{:?}",&input_file_names));

        if file_names.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "cannot open files or files contain no DLT messages",
            ));
        }

        Ok(FileContext {
            file_names,
            sort_by_time,
            parsing_thread: None,
            all_msgs: Vec::new(),
            streams: Vec::new(),
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
                        file_context.as_ref().unwrap().file_names
                    )))
                    .unwrap();
            // todo
            } else {
                match FileContext::from(log, command, params) {
                    Ok(mut s) => {
                        // setup parsing thread
                        s.parsing_thread = Some(create_parser_thread(
                            log.clone(),
                            s.file_names.clone(),
                            s.sort_by_time,
                        ));
                        file_context.replace(s);

                        // lifecycle detection thread
                        // sorting thread (if wanted by prev. set options or default options)
                        // and send the messages via mpsc back to here (FileContext.all_msgs)

                        websocket
                            .write_message(Message::Text(format!("ok: open '{}'", params)))
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
        "stop" => {
            match params.parse::<u32>() {
                Ok(id) => {
                    match file_context {
                        Some(fc) => {
                            if let Some(pos) = fc.streams.iter().position(|x| x.id == id) {
                                fc.streams.remove(pos);
                                websocket
                                    .write_message(Message::Text(format!(
                                        "ok: stop stream stream_id {}",
                                        id
                                    )))
                                    .unwrap(); // todo
                            } else {
                                websocket
                                    .write_message(Message::Text(format!(
                                        "err: stop stream failed. stream_id {} not found!",
                                        id
                                    )))
                                    .unwrap(); // todo
                            }
                        }
                        None => {
                            websocket
                                .write_message(Message::Text(
                                    "err: stop stream failed. No file opened!".to_string(),
                                ))
                                .unwrap(); // todo
                        }
                    }
                }
                Err(e) => {
                    websocket
                        .write_message(Message::Text(format!(
                            "err: stop stream failed. param {} is no valid stream_id! Err={}",
                            params, e
                        )))
                        .unwrap(); // todo
                }
            }
        }
        _ => {
            websocket
                .write_message(Message::Text(format!("unknown command '{}'!", t)))
                .unwrap(); // todo
        }
    }
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
        if let Some(pt) = &fc.parsing_thread {
            let lcs_r = &pt.lcs_r;
            if let Some(lc_map) = lcs_r.read() {
                let sorted_lcs = adlt::lifecycle::get_sorted_lifecycles_as_vec(&lc_map);
                info!(log, "lcs: #{}", sorted_lcs.len());

                // encode the lifecycles:
                let lcs = sorted_lcs
                    .iter()
                    .map(|&l| remote_types::BinLifecycle {
                        id: l.id(),
                        ecu: l.ecu.as_u32le(),
                        nr_msgs: l.nr_msgs,
                        start_time: l.start_time,
                        end_time: l.end_time(),
                    })
                    .collect();
                let encoded: Vec<u8> =
                    bincode::encode_to_vec(remote_types::BinType::Lifecycles(lcs), BINCODE_CONFIG)
                        .unwrap(); // todo
                                   //info!(log, "encoded: #{:?}", &encoded);

                websocket.write_message(Message::Binary(encoded))?;
            }
        }
    }

    let mut stream_marked_as_done = false;
    // in any stream any messages to send?
    let all_msgs_len = fc.all_msgs.len();
    for mut stream in &mut fc.streams {
        let mut new_stream_msgs = false; // todo needed?
                                         // more messages avail?
        if all_msgs_len > stream.all_msgs_last_processed_len {
            let have_pos_filters = !stream.filters[FilterKind::Positive].is_empty();
            let have_event_filters = !stream.filters[FilterKind::Event].is_empty();

            if stream.filters_active {
                // check msgs from _processed_len to all_msgs_len
                // todo use parallel iterator
                for i in stream.all_msgs_last_processed_len..all_msgs_len {
                    let msg: &adlt::dlt::DltMessage = &fc.all_msgs[i];
                    let mut matches = !have_pos_filters;

                    // for now do a simple support of pos. and neg. filters
                    for filter in &stream.filters[FilterKind::Positive] {
                        if filter.matches(msg) {
                            matches = true;
                            debug!(log, "stream {} got pos matching msg idx={}", stream.id, i);
                            break;
                        }
                    }
                    if matches {
                        // and neg that removes the msg?
                        for filter in &stream.filters[FilterKind::Negative] {
                            if filter.matches(msg) {
                                matches = false;
                                debug!(log, "stream {} got neg matching msg idx={}", stream.id, i);
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
                        for filter in &stream.filters[FilterKind::Event] {
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

                    if matches {
                        stream.filtered_msgs.push(i);
                        new_stream_msgs = true;
                        // todo for !is_stream end as soon as enough (msgs.to_send.end) are filtered!
                    }
                }
            } else {
                new_stream_msgs = true;
            }
            stream.all_msgs_last_processed_len = all_msgs_len;
        }

        if got_new_msgs || new_stream_msgs { // todo or once at least?
             // or kind of keep-alive from the stream every sec?
             // todo post info amount of filtered msgs vs all_msgs?
             // so that the client can understand whether messages should arrive?
        }

        let stream_msgs_len = if stream.filters_active {
            stream.filtered_msgs.len()
        } else {
            fc.all_msgs.len()
        };

        if stream.msgs_sent.end < stream.msgs_to_send.end && stream.msgs_sent.end <= stream_msgs_len
        {
            // send some more...
            let new_end = std::cmp::min(stream_msgs_len, stream.msgs_to_send.end);
            debug!(log, "sending {}..{}", stream.msgs_sent.end, new_end);
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
        if (!got_new_msgs || (stream.msgs_sent.end >= stream.msgs_to_send.end)) && !stream.is_stream
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

#[derive(Debug)]
struct ParserThreadType {
    parse_thread: std::thread::JoinHandle<Result<(), Box<dyn std::error::Error + Send + Sync>>>,
    lc_thread: std::thread::JoinHandle<
        evmap::WriteHandle<adlt::lifecycle::LifecycleId, adlt::lifecycle::LifecycleItem>,
    >,
    sort_thread: Option<
        std::thread::JoinHandle<Result<(), std::sync::mpsc::SendError<adlt::dlt::DltMessage>>>,
    >,
    lcs_r: evmap::ReadHandle<adlt::lifecycle::LifecycleId, adlt::lifecycle::Lifecycle>,
    rx: std::sync::mpsc::Receiver<adlt::dlt::DltMessage>,
}

/// create a parser thread including a channel
///
/// The thread reads data from the BufReader, parses the DLT messages via `parse_dlt_with_storage_header`
/// and forwards the DLT messages to the mpsc channel.
/// Returns the thread handle and the channel receiver where the parsed messages will be send to.
fn create_parser_thread(
    log: slog::Logger,
    input_file_names: Vec<String>,
    sort_by_time: bool,
) -> ParserThreadType {
    let (tx, rx) = std::sync::mpsc::channel();
    let (tx2, rx2) = std::sync::mpsc::channel();
    let (lcs_r, lcs_w) =
        evmap::new::<adlt::lifecycle::LifecycleId, adlt::lifecycle::LifecycleItem>();
    let lc_thread = std::thread::spawn(move || {
        adlt::lifecycle::parse_lifecycles_buffered_from_stream(lcs_w, rx, tx2)
    });

    let sort_thread_lcs_r = lcs_r.clone();
    let (sort_thread, rx_final) = if sort_by_time {
        let (tx3, rx3) = std::sync::mpsc::channel();
        (
            Some(std::thread::spawn(move || {
                adlt::utils::buffer_sort_messages(
                    rx2,
                    tx3,
                    &sort_thread_lcs_r,
                    3,
                    2 * adlt::utils::US_PER_SEC,
                )
            })),
            rx3,
        )
    } else {
        (None, rx2)
    };

    ParserThreadType {
        sort_thread,
        parse_thread: std::thread::spawn(
            move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                info!(log, "parser_thread started");
                let mut bytes_processed: u64 = 0;
                let mut messages_processed: adlt::dlt::DltMessageIndexType = 0;

                const BUFREADER_CAPACITY: usize = 512 * 1024;
                // we use a relatively small 512kb chunk size as we're processing
                // the data multithreaded reader in bigger chunks slows is in total slower

                for ref input_file_name in input_file_names {
                    let fi = File::open(input_file_name)?;
                    info!(log, "opened file {} {:?}", input_file_name, &fi);
                    let buf_reader =
                        LowMarkBufReader::new(fi, BUFREADER_CAPACITY, DLT_MAX_STORAGE_MSG_SIZE);
                    let mut it = DltMessageIterator::new(messages_processed, buf_reader);
                    it.log = Some(&log);
                    loop {
                        match it.next() {
                            Some(msg) => {
                                if let Err(e) = tx.send(msg) {
                                    info!(log, "parser_thread aborted on err={}", e; "bytes_processed" => bytes_processed, "msgs_processed" => messages_processed);
                                    return Err(Box::new(e));
                                }
                            }
                            None => {
                                messages_processed = it.index;
                                debug!(log, "finished processing a file"; "bytes_processed"=>it.bytes_processed, "bytes_skipped"=>it.bytes_skipped, "messages_processed"=>messages_processed);
                                bytes_processed += (it.bytes_processed + it.bytes_skipped) as u64;
                                break;
                            }
                        }
                    }
                }
                drop(tx);
                info!(log, "parser_thread stopped"; "bytes_processed" => bytes_processed);
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
        assert_eq!(fc.file_names.len(), 2);
        // files should be sorted now!
        assert_eq!(
            fc.file_names,
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
}
