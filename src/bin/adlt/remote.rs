use slog::{debug, info}; // crit, debug, info, warn, error};
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::net::TcpListener;

use tungstenite::{
    accept_hdr,
    handshake::server::{Request, Response},
    Message, WebSocket,
};

use adlt::{
    filter::{Filter, FilterKind, FilterKindContainer},
};

/// provide remote server functionalities
pub fn remote(
    log: slog::Logger,
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
                headers.append("MyCustomHeader", ":)".parse().unwrap());
                headers.append("SOME_TUNGSTENITE_HEADER", "header_value".parse().unwrap());

                Ok(response)
            };
            let a_stream = stream.unwrap();
            a_stream.set_read_timeout(Some(std::time::Duration::from_millis(100)));
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
                match file_context {
                    Some(ref mut fc) => process_file_context(&log, fc, &mut websocket),
                    _ => {}
                };

                let msg = websocket.read_message();
                if msg.is_err() {
                    let err = msg.unwrap_err();
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
            match websocket.write_pending() {
                _ => {}
            }; // ignore any errors
        });
    }

    info!(log, "remote stopped"; "port" => port);
    Ok(())
}

#[derive(Debug)]
struct StreamContext {
    id: u32,
    filters_active: bool,
    filters: FilterKindContainer<Vec<Filter>>,
    filtered_msgs: Vec<usize>, // indizes to all_msgs vec
    all_msgs_last_processed_len: usize, // last len of all_msgs reflected in filtered_msgs
    msgs_to_send: std::ops::Range<usize>, // the requested window
    msgs_sent: std::ops::Range<usize>,
}

/// next stream id. Zero is used as "no lifecycle" so first one must start with 1
static NEXT_STREAM_ID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);

impl StreamContext{
    fn from(
        log: &slog::Logger,
        json_str: &str,
    ) -> Result<StreamContext, Box<dyn std::error::Error>> {
        // parse json
        let v = serde_json::from_str::<serde_json::Value>(json_str)?;
        debug!(log, "StreamContext::from({}) = {:?}", json_str, v);

        let mut start_idx = 0;
        let mut end_idx = 20; // todo
        let mut filters : FilterKindContainer<Vec<Filter>> = Default::default();

        match &v["window"] {
            serde_json::Value::Array(a) => {
                debug!(log, "StreamContext window={:?}", a);
                if a.len() != 2 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("'window' expects array with two elements. got {}", a.len())
                    ).into());    
                } else {
                    start_idx = a[0].as_u64().unwrap_or(0) as usize; // todo better err and not ignore
                    end_idx = a[1].as_u64().unwrap_or(20) as usize; // todo better err and not default 20
                }
            }
            serde_json::Value::Null => {} // keep defaults
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "wrong type for 'window'"
                ).into());
            }
        }

        match &v["filters"] {
            serde_json::Value::Array(a) => {
                for filter in a {
                    debug!(log, "StreamContext filters got '{}'", filter.to_string());
                    let filter_struct = Filter::from_json(&filter.to_string())?;
                    filters[filter_struct.kind].push(filter_struct);
                }
            }
            serde_json::Value::Null => {} // no filters
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "wrong type for 'filters'"
                ).into());
            }
        }

        // todo think about Marker, Event...
        let filters_active = filters[FilterKind::Positive].len() + filters[FilterKind::Negative].len()  > 0;

        Ok(StreamContext {
            id: NEXT_STREAM_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            filters,
            filters_active,
            filtered_msgs: Vec::new(),
            all_msgs_last_processed_len: 0,
            msgs_to_send: std::ops::Range { start: start_idx, end: end_idx },
            msgs_sent: std::ops::Range { start: 0, end: 0 },
        })
    }
}

#[derive(Debug)]
struct FileContext {
    file_names: Vec<String>,
    file_names_index: usize,
    f: Option<BufReader<File>>,
    parsing_thread: Option<(
        std::thread::JoinHandle<Result<(), Box<dyn std::error::Error + Send + Sync>>>,
        std::sync::mpsc::Receiver<adlt::dlt::DltMessage>,
    )>,

    all_msgs: Vec<adlt::dlt::DltMessage>,

    streams : Vec<StreamContext>,
}

impl FileContext {
    fn from(file_names: Vec<String>) -> Result<FileContext, std::io::Error> {
        // check whether at least the first file can be opened:
        if file_names.len() < 1 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "at least one file name needed",
            ));
        }

        let fi = File::open(&file_names[0])?;
        // info!(log, "opened file {} {:?}", &input_file_name, &fi);
        const BUFREADER_CAPACITY: usize = 0x10000 * 50;
        let f = Some(BufReader::with_capacity(BUFREADER_CAPACITY, fi));

        Ok(FileContext {
            file_names,
            file_names_index: 0,
            f: f,
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
    info!(log, "got text message {:?}", t);
    let cmd_params: Vec<&str> = t.splitn(2, " ").collect();
    let command = if cmd_params.len() >= 1 {
        cmd_params[0]
    } else {
        ""
    };
    let params = if cmd_params.len() >= 2 {
        cmd_params[1]
    } else {
        ""
    };
    info!(log, "got command '{}'", command);
    info!(log, "got params  '{}'", params);
    // websocket.write_message(Message::Binary(vec!(0x0u8, 0x1u8, 0x2u8))).unwrap();

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
                match FileContext::from(vec![params.to_string()]) {
                    // todo support multiple
                    Ok(mut s) => {
                        let f: Option<BufReader<File>> = s.f;
                        s.f = None;

                        let (lcs_r, lcs_w) = evmap::new::<
                            adlt::lifecycle::LifecycleId,
                            adlt::lifecycle::LifecycleItem,
                        >();
                        // setup parsing thread
                        //let f: Option<BufReader<File>> = (&file_context).as_mut().unwrap().f;
                        s.parsing_thread = Some(create_parser_thread(log.clone(), f));
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
                file_context.take(); // = None;
                websocket
                    .write_message(Message::Text(format!("ok: '{}'!", command)))
                    .unwrap(); // todo
                // todo send info with 0 msgs
            } else {
                websocket
                    .write_message(Message::Text(format!(
                        "err: close failed as no file open. open first!"
                    )))
                    .unwrap(); // todo
            }
        }
        "stream" => {
            match file_context {
                Some(fc) => {
                    let stream = StreamContext::from(log, params);
                    match stream {
                        Ok(stream) => {
                            websocket
                                .write_message(Message::Text(format!(
                                    "ok: stream {{\"id\":{}, \"number_filters\":[{},{}]}}",
                                    stream.id, stream.filters[FilterKind::Positive].len(), stream.filters[FilterKind::Negative].len()
                                )))
                                .unwrap(); // todo
                            fc.streams.push(stream);
                        }
                        Err(e) => {
                            websocket
                                .write_message(Message::Text(format!(
                                    "err: stream failed with err '{}' from '{}'!",
                                    e, params
                                )))
                                .unwrap(); // todo
                        }
                    }
                }
                None => {
                    websocket
                        .write_message(Message::Text(format!(
                            "err: stream failed as no file open. open first!"
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
                                .write_message(Message::Text(format!(
                                    "err: stop stream failed. No file opened!"
                                )))
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
) {
    let mut got_new_msgs = false;
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(50);
    match &fc.parsing_thread {
        Some((_pt, rx)) => {
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
        _ => {}
    }
    // inform about new msgs
    if got_new_msgs && websocket.can_write() {
        websocket
            .write_message(Message::Text(format!(
                "info: all_msgs.len={}",
                fc.all_msgs.len()
            )))
            .unwrap(); // todo
    }

    // in any stream any messages to send?
    let all_msgs_len = fc.all_msgs.len();
    for mut stream in &mut fc.streams {

        let mut new_stream_msgs = false; // todo needed?
        // more messages avail?
        if all_msgs_len > stream.all_msgs_last_processed_len {
            if stream.filters_active {
                // check msgs from _processed_len to all_msgs_len
                // todo use parallel iterator
                for i in stream.all_msgs_last_processed_len .. all_msgs_len {
                    let msg : &adlt::dlt::DltMessage = &fc.all_msgs[i];
                    let mut matches = stream.filters[FilterKind::Positive].len() == 0;

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
                                debug!(log, "stream {} got pos matching msg idx={}", stream.id, i);
                                break;
                            }
                        }
                    }

                    if matches {
                        stream.filtered_msgs.push(i);
                        new_stream_msgs = true;
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

        let stream_msgs_len = if stream.filters_active { stream.filtered_msgs.len() } else { fc.all_msgs.len() };

        if stream.msgs_sent.end < stream.msgs_to_send.end
            && stream.msgs_sent.end <= stream_msgs_len
        {
            // send some more...
            let new_end = std::cmp::min(stream_msgs_len, stream.msgs_to_send.end);
            debug!(log, "sending {}..{}", stream.msgs_sent.end, new_end);
            for i in stream.msgs_sent.end..new_end {
                let data = Vec::<u8>::with_capacity(65000);
                let mut writer = std::io::BufWriter::new(data);
                let msg_idx = if stream.filters_active { stream.filtered_msgs[i] } else { i };
                fc.all_msgs[msg_idx].header_as_text_to_write(&mut writer).unwrap();
                let data = writer.into_inner().unwrap();
                websocket
                    .write_message(Message::Text(format!(
                        "stream:{} msg({}):{}",
                        stream.id,
                        i, // or msg_idx or both? rethink with binary stream format
                        String::from_utf8(data).unwrap()
                    )))
                    .unwrap();
            }
            stream.msgs_sent.end = new_end;
            debug!(log, "did send {:?}", stream.msgs_sent);
        }
    }
}

/// create a parser thread including a channel
///
/// The thread reads data from the BufReader, parses the DLT messages via `parse_dlt_with_storage_header`
/// and forwards the DLT messages to the mpsc channel.
/// Returns the thread handle and the channel receiver where the parsed messages will be send to.
fn create_parser_thread(
    log: slog::Logger,
    mut f: Option<BufReader<File>>,
) -> (
    std::thread::JoinHandle<Result<(), Box<dyn std::error::Error + Send + Sync>>>,
    std::sync::mpsc::Receiver<adlt::dlt::DltMessage>,
) {
    let (tx, rx) = std::sync::mpsc::channel();
    (
        std::thread::spawn(
            move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                info!(log, "parser_thread started");
                let mut bytes_processed: u64 = 0;
                let mut bytes_per_file: u64 = 0;
                let mut number_messages: adlt::dlt::DltMessageIndexType = 0;
                let mut last_data = false;

                loop {
                    if f.is_none() {
                        // todo load next file
                        break;
                    }
                    let reader: &mut BufReader<File> = f.as_mut().unwrap();
                    match adlt::dlt::parse_dlt_with_storage_header(number_messages, &mut *reader) {
                        Ok((res, msg)) => {
                            bytes_per_file += res as u64;
                            number_messages += 1;

                            tx.send(msg)?; // todo handle error?
                                           // get more data from BufReader:
                            if !last_data && (reader.buffer().len() < 0x10000) {
                                // read more data
                                let pos = std::io::SeekFrom::Start(bytes_per_file);
                                reader.seek(pos).unwrap();
                                reader.fill_buf().expect("fill_buf 2 failed!");
                                last_data = reader.buffer().len() < 0x10000;
                            }
                        }
                        Err(error) => match error.kind() {
                            adlt::dlt::ErrorKind::InvalidData(_str) => {
                                bytes_per_file += 1;
                                reader.consume(1); // skip 1 byte and check for new valid storage_header
                                info!(log, "skipped 1 byte at {}", bytes_per_file);
                            }
                            _ => {
                                debug!(log, "finished processing a file"; "bytes_per_file"=>bytes_per_file, "number_messages"=>number_messages);
                                f.unwrap();
                                f = None; // check for next file on next it
                                last_data = false;
                                bytes_processed += bytes_per_file;
                                bytes_per_file = 0;
                                info!(log, "got Error {}", error);
                            }
                        },
                    };
                }
                drop(tx);
                info!(log, "parser_thread stopped"; "bytes_processed" => bytes_processed);
                Ok(())
            },
        ),
        rx,
    )
}
