// copyright Matthias Behr, (c) 2022
//
// todos:
// [ ] - add auto store for console usage
// [ ] - add unit test coverage!

use crate::{
    dlt::{
        DltArg, DltChar4, DltMessage, DltMessageLogType, DltMessageType, DLT_SCOD_ASCII,
        DLT_SCOD_UTF8, DLT_TYPE_INFO_SINT, DLT_TYPE_INFO_UINT,
    },
    plugins::plugin::{Plugin, PluginState},
};
use serde_json::json;
use std::{
    any::Any,
    collections::HashMap,
    error::Error,
    fmt,
    fs::File,
    io::Write,
    str::FromStr,
    sync::{Arc, RwLock},
};

#[derive(Debug)]
struct FileTransferPluginError {
    msg: String,
}

impl FileTransferPluginError {}

impl From<String> for FileTransferPluginError {
    fn from(err: String) -> FileTransferPluginError {
        FileTransferPluginError { msg: err }
    }
}

impl From<&str> for FileTransferPluginError {
    fn from(err: &str) -> FileTransferPluginError {
        FileTransferPluginError::from(err.to_owned())
    }
}

impl fmt::Display for FileTransferPluginError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", &self.msg)
    }
}

impl Error for FileTransferPluginError {}

#[derive(Debug, PartialEq)]
enum FileTransferState {
    /// we handle the case where only the FLST message is lost but the FLDA starts with the 1st package
    MissingStart,
    /// transfer started with a regular FLST message, but not completed yet or not detected yet as incomplete
    Started,
    /// final state for successfully completed transfers
    Complete,
    /// final state for corrupt/incomplete detected transfers. A transfer stays in Started as long as a corruption/incompleteness is detected.
    Incomplete,
}

#[derive(Debug)]
/// data structure kept/created per recognized file transfer
struct FileTransfer {
    ecu: DltChar4,
    lifecycle: u32,
    serial: u64,
    state: FileTransferState,
    file_name: String,
    file_size: u64,
    file_creation_date: String,
    nr_packages: u64,
    buffer_size: u64,
    next_package: u64,
    recvd_packages: u64,
    file_data: Vec<u8>,
}

/// internal data for completed files. This contains the file data for completed transfers and is
/// stored inside the .internal_data member of the plugin state.
struct FileTransferStateData {
    /// map from idx within the plugin.transfers vec to the file_data
    completed_transfers: HashMap<usize, Vec<u8>>,
}

impl FileTransfer {
    /// process FLDA packages
    ///
    /// returns whether the state changed and shall be updated
    ///
    /// ### Arguments:
    /// * `package_nr` - nr of this package. Packages start with 1.
    /// * `arg` - argument with the payload_raw
    /// * `do_save` - whether the payload should be kept/added to the file_data member
    ///
    fn add_flda(&mut self, package_nr: u64, arg: &DltArg, do_save: bool) -> bool {
        // auto-learn package size?
        if package_nr == 1 && self.buffer_size == 0 {
            self.buffer_size = arg.payload_raw.len() as u64;
        }

        if self.state == FileTransferState::Started || self.state == FileTransferState::MissingStart
        {
            self.recvd_packages += 1;
            if package_nr == self.next_package {
                // package contains data?
                if arg.payload_raw.len() as u64 == self.buffer_size
                    || (self.next_package == self.nr_packages
                        && (arg.payload_raw.len() as u64) < self.buffer_size)
                // last package may be smaller
                {
                    self.next_package += 1;
                    if do_save {
                        self.file_data.extend_from_slice(arg.payload_raw);
                    }
                }
            }
            self.check_finished(false)
        } else {
            println!(
                "FileTransfer add_flda got unexpected package {} on (in)complete!",
                package_nr
            );
            false
        }
    }

    /// checks whether the transfer is finished/completed/incomplete
    /// returns whether state is changed and shall be updated
    ///
    /// ### Arguments:
    /// * `from_flfi` - indicates whether the call is coming from processing a FLFI packet. For FLFI the state is move to Incomplete if e.g. too many packages have been received.
    fn check_finished(&mut self, from_flfi: bool) -> bool {
        if from_flfi {
            if self.recvd_packages == self.next_package - 1 {
                if self.state == FileTransferState::MissingStart {
                    // we missed the start but got all others
                    self.state = FileTransferState::Complete;
                    if self.file_size == 0 {
                        self.file_size = self.file_data.len() as u64;
                    }
                    true
                } else {
                    false
                }
                // todo auto store?
            } else {
                self.state = FileTransferState::Incomplete;
                true
            }
        } else if self.next_package > self.nr_packages
            && (self.file_size == 0 || self.file_size as usize == self.file_data.len())
        {
            self.state = FileTransferState::Complete;
            true
        } else if self.recvd_packages >= self.nr_packages {
            self.state = FileTransferState::Incomplete;
            true
        } else {
            false
        }
    }
}

#[derive(Debug)]
pub struct FileTransferPlugin {
    name: String,
    enabled: bool,
    allow_save: bool,
    keep_flda: bool,
    apid: Option<DltChar4>,
    ctid: Option<DltChar4>,
    state: Arc<RwLock<PluginState>>,
    transfers: Vec<FileTransfer>,
    transfers_idx: HashMap<(DltChar4, u32, u64), usize>, // map ecu, lifecycle, serial
}

impl<'a> Plugin for FileTransferPlugin {
    fn name(&self) -> &str {
        &self.name
    }
    fn enabled(&self) -> bool {
        self.enabled
    }

    fn state(&self) -> Arc<RwLock<PluginState>> {
        self.state.clone()
    }

    /// check a msg for rewrite.
    /// returns false if the msg should be discarded, true otherwise
    /// we do check all rewrite configs. So one config could change a msg for further processing with next config
    /// currently the rewrite array with javascrip functions is not supported.
    /// Instead the replacement is done based on the capture group names:
    ///  - text -> setting payloadText
    ///  - timeStamp -> setting the timestamp_dms with the value captured in Seconds (can include parts of) (multiplied by 10_000)
    fn process_msg(&mut self, msg: &mut DltMessage) -> bool {
        if !self.enabled {
            return true;
        }

        if let Some(apid) = &self.apid {
            if let Some(m_apid) = msg.apid() {
                if apid != m_apid {
                    return true;
                }
            } else {
                return true;
            }
        }

        if let Some(ctid) = &self.ctid {
            if let Some(m_ctid) = msg.ctid() {
                if ctid != m_ctid {
                    return true;
                }
            } else {
                return true;
            }
        }

        if msg.is_verbose() && msg.mstp() == DltMessageType::Log(DltMessageLogType::Info) {
            match msg.noar() {
                8 => {
                    if FileTransferPlugin::is_type(msg, "FLST") {
                        // file transfer start
                        let mut serial = 0;
                        let mut file_name = String::new();
                        let mut file_size = 0;
                        let mut file_creation_date = String::new();
                        let mut nr_packages = 0;
                        let mut buffer_size = 0;
                        let args = msg.into_iter();
                        for (i, arg) in args.enumerate() {
                            match i {
                                0 => {} // FLST
                                1 => {
                                    // serial
                                    if let Ok(s) = arg_as_uint(&arg) {
                                        serial = s;
                                    } else {
                                        println!("FLST unexpected serial type!");
                                        break;
                                    }
                                }
                                2 => {
                                    // filename
                                    if let Ok(name) = arg_as_string(&arg) {
                                        file_name += &name;
                                    }
                                }
                                3 => {
                                    // fileSize
                                    if let Ok(s) = arg_as_uint(&arg) {
                                        file_size = s;
                                    } else {
                                        println!("FLST unexpected file size type!");
                                        break;
                                    }
                                }
                                4 => {
                                    // file creation date
                                    if let Ok(name) = arg_as_string(&arg) {
                                        file_creation_date += &name;
                                    }
                                }
                                5 => {
                                    // nr packages
                                    if let Ok(s) = arg_as_uint(&arg) {
                                        nr_packages = s;
                                    } else {
                                        println!("FLST unexpected nr_packages type!");
                                        break;
                                    }
                                }
                                6 => {
                                    // buffer size
                                    if let Ok(s) = arg_as_uint(&arg) {
                                        buffer_size = s;
                                    } else {
                                        println!("FLST unexpected buffer_size type!");
                                        break;
                                    }
                                    break;
                                }
                                _ => {}
                            }
                        }
                        /*println!(
                            "FLST serial={} file_name={} file_size={} file_creation_date()={} nr_packages={} buffer_size={}",
                            serial, file_name, file_size, file_creation_date, nr_packages, buffer_size
                        );*/
                        if nr_packages > 0 && buffer_size > 0 {
                            self.transfers.push(FileTransfer {
                                ecu: msg.ecu,
                                lifecycle: msg.lifecycle,
                                state: FileTransferState::Started,
                                serial,
                                file_name,
                                file_size,
                                file_creation_date,
                                nr_packages,
                                buffer_size,
                                next_package: 1,
                                recvd_packages: 0,
                                file_data: Vec::with_capacity(if self.allow_save {
                                    (nr_packages * buffer_size) as usize
                                } else {
                                    0
                                }),
                            });
                            self.transfers_idx
                                .insert((msg.ecu, msg.lifecycle, serial), self.transfers.len() - 1);
                            self.update_state();
                        }
                    }
                }
                5 => {
                    if FileTransferPlugin::is_type(msg, "FLDA") {
                        // file transfer data
                        let mut serial = u64::MAX;
                        let mut package_nr = u64::MAX;
                        let args = msg.into_iter();
                        for (i, arg) in args.enumerate() {
                            match i {
                                0 => {} // FLDA
                                1 => {
                                    if let Ok(s) = arg_as_uint(&arg) {
                                        serial = s;
                                    } else {
                                        println!("FLDA unexpected serial type!");
                                        break;
                                    }
                                }
                                2 => {
                                    if let Ok(s) = arg_as_uint(&arg) {
                                        // is weirdly a SINT32...
                                        package_nr = s;
                                    } else {
                                        println!("FLDA unexpected package_nr type!");
                                        break;
                                    }
                                }
                                3 => {
                                    if let Some(file_transfer_idx) =
                                        self.transfers_idx.get(&(msg.ecu, msg.lifecycle, serial))
                                    {
                                        let file_transfer =
                                            self.transfers.get_mut(*file_transfer_idx).unwrap();
                                        if file_transfer.add_flda(package_nr, &arg, self.allow_save)
                                        {
                                            self.update_state();
                                        }
                                    } else if package_nr == 0 {
                                        // incomplete, but can recover as this is the first package
                                        let mut file_transfer = FileTransfer {
                                            ecu: msg.ecu,
                                            lifecycle: msg.lifecycle,
                                            state: FileTransferState::Started,
                                            serial,
                                            file_name: "<missing_flst>".to_owned(),
                                            file_size: 0,
                                            file_creation_date: "".to_owned(),
                                            nr_packages: u64::MAX,
                                            buffer_size: 0,
                                            next_package: 1,
                                            recvd_packages: 0,
                                            file_data: Vec::new(),
                                        };
                                        let _ = file_transfer.add_flda(
                                            package_nr,
                                            &arg,
                                            self.allow_save,
                                        ); // ignore return value, we do update_state anyhow
                                        self.transfers.push(file_transfer);
                                        self.transfers_idx.insert(
                                            (msg.ecu, msg.lifecycle, serial),
                                            self.transfers.len() - 1,
                                        );
                                        self.update_state();
                                    }
                                    break;
                                }
                                _ => {}
                            }
                        }

                        if !self.keep_flda {
                            return false;
                        }
                    }
                }
                3 => {
                    if FileTransferPlugin::is_type(msg, "FLFI") {
                        // file transfer finish
                        let mut serial = u64::MAX;
                        let args = msg.into_iter();
                        for (i, arg) in args.enumerate() {
                            match i {
                                0 => {} // FLDA
                                1 => {
                                    if let Ok(s) = arg_as_uint(&arg) {
                                        serial = s;
                                    } else {
                                        println!("FLDA unexpected serial type!");
                                        break;
                                    }
                                    break;
                                }
                                _ => {}
                            }
                        }
                        if let Some(file_transfer_idx) =
                            self.transfers_idx.get(&(msg.ecu, msg.lifecycle, serial))
                        {
                            let file_transfer = self.transfers.get_mut(*file_transfer_idx).unwrap();
                            // mark as finished:
                            if file_transfer.check_finished(true) {
                                self.update_state();
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        true
    }
}

impl FileTransferPlugin {
    pub fn from_json(
        config: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<FileTransferPlugin, Box<dyn Error>> {
        let name = match &config.get("name") {
            Some(serde_json::Value::String(s)) => Some(s.clone()),
            _ => {
                return Err(
                    FileTransferPluginError::from("config 'name' not a string/missing").into(),
                )
            }
        };
        if name.is_none() {
            return Err(FileTransferPluginError::from("FileTransferPlugin: name missing").into());
        }
        let enabled = match &config.get("enabled") {
            Some(serde_json::Value::Bool(b)) => *b,
            None => true, // default to true
            _ => return Err(FileTransferPluginError::from("config 'enabled' not a bool").into()),
        };

        let allow_save = match &config.get("allowSave") {
            Some(serde_json::Value::Bool(b)) => *b,
            None => true, // default to true
            _ => return Err(FileTransferPluginError::from("config 'allowSave' not a bool").into()),
        };

        let keep_flda = match &config.get("keepFLDA") {
            Some(serde_json::Value::Bool(b)) => *b,
            None => false, // default to false
            _ => return Err(FileTransferPluginError::from("config 'keepFLDA' not a bool").into()),
        };

        let apid = match &config.get("apid") {
            Some(serde_json::Value::String(s)) => match DltChar4::from_str(s) {
                Ok(apid) => Some(apid),
                Err(e) => {
                    return Err(FileTransferPluginError::from(format!(
                        "config 'apid' failed parsing with:{:?}",
                        e
                    ))
                    .into())
                }
            },
            None => None,
            _ => return Err(FileTransferPluginError::from("config 'apid' not a string").into()),
        };
        let ctid = match &config.get("ctid") {
            Some(serde_json::Value::String(s)) => match DltChar4::from_str(s) {
                Ok(apid) => Some(apid),
                Err(e) => {
                    return Err(FileTransferPluginError::from(format!(
                        "config 'ctid' failed parsing with:{:?}",
                        e
                    ))
                    .into())
                }
            },
            None => None,
            _ => return Err(FileTransferPluginError::from("config 'ctid' not a string").into()),
        };

        let state = PluginState {
            value: serde_json::json!({"name":name, "treeItems":[]}),
            internal_data: Some(Box::new(FileTransferStateData {
                completed_transfers: HashMap::new(),
            })),
            apply_command: Some(FileTransferPlugin::apply_command),
            generation: 1,
            // ..Default::default()
        };

        Ok(FileTransferPlugin {
            name: name.unwrap(),
            enabled,
            allow_save,
            keep_flda,
            apid,
            ctid,
            transfers: Vec::new(),
            transfers_idx: HashMap::new(),
            state: Arc::new(RwLock::new(state)),
        })
    }

    /// update the plugin state object so that it reflects state changes.
    ///
    /// Generates the treeItems with the file transfers found and their status.
    ///
    /// It moves as well any completed transfers with buffers to the internal_data so
    /// that apply_command can be performed on it.
    fn update_state(&mut self) {
        let mut state = self.state.write().unwrap();

        // if we have completed transfers with buffer, move them to FileTransferStateData:
        let completed_transfers = self
            .transfers
            .iter_mut()
            .enumerate()
            .filter(|(_, t)| !t.file_data.is_empty() && t.state == FileTransferState::Complete)
            .collect::<Vec<_>>();
        if !completed_transfers.is_empty() {
            if let Some(internal_data) = &mut state.internal_data {
                match internal_data.downcast_mut::<FileTransferStateData>() {
                    Some(internal_data) => {
                        for (idx, t) in completed_transfers {
                            internal_data
                                .completed_transfers
                                .insert(idx, std::mem::take(&mut t.file_data));
                        }
                    }
                    None => {}
                }
            }
        }

        state.value = serde_json::json!({"name":self.name, "treeItems":
            self.transfers.iter().enumerate().map(|(idx,t)|{json!({
                "label":
                match t.state {
                    FileTransferState::Started => {
                        format!("Incomplete file transfer '{}', missing {} got {}/{}", t.file_name, t.next_package, t.recvd_packages, t.nr_packages)
                    },
                    FileTransferState::Complete => {
                        format!("'{}', {}kb", t.file_name, t.file_size/1024)
                    }
                    FileTransferState::MissingStart => {
                        format!("Incomplete file transfer. Missing FLST. Got {} packages.", t.recvd_packages)
                    }
                    FileTransferState::Incomplete => {
                        format!("Incomplete file transfer. Missed package {}", t.next_package)
                    }

                },
                "iconPath": match t.state {
                    FileTransferState::Complete => "file",
                    _ => "warning",
                },
                "contextValue": match t.state {
                    FileTransferState::Complete if self.allow_save => json!("canSave"),
                    _ => json!(null)
                },
                "cmdCtx": match t.state {
                    FileTransferState::Complete if self.allow_save => json!({"save":{"basename":t.file_name, "idx":idx }}),
                    _ => json!(null)
                },
                "tooltip":format!("{}, LC id={}, serial #{}, '{}', created at '{}', file size {} ", t.ecu, t.lifecycle, t.serial, t.file_name, t.file_creation_date, t.file_size),
            })}).collect::<Vec<serde_json::Value>>()
        });
        state.generation += 1;
    }

    /// apply a command for the FileTransferPlugin
    ///
    /// This is quite messy as the Plugins are +Send and the main flow - processing messages - should
    /// not be blocked by any mutex,... is optimized for speed.
    /// But as the commands usually come from a different thread the PluginState.internal_data is used
    /// to pass/store data that needs to be processed by the command.
    /// ## Arguments:
    /// * `internal_data` - provides the internal data from the PluginState state.internal_data. So the caller doesn't need to keep the plugin but needs to have access to the plugin state only.
    /// * `cmd` - command to perform. Only "save" is supported.
    /// * `params` - parameter object for the command. Here a "saveAs" string member contains the path&filename where to save the file.
    /// * `ctx` - context object that references which file transfer is to be saved. ctx.save.idx is used to identify the file transfer data.
    ///
    /// returns true if the command has been processed sucessfully.
    fn apply_command(
        internal_data: &Option<Box<dyn Any + Send + Sync>>,
        cmd: &str,
        params: Option<&serde_json::Map<String, serde_json::Value>>,
        ctx: Option<&serde_json::Map<String, serde_json::Value>>,
    ) -> bool {
        if let Some(internal_data) = internal_data {
            match internal_data.downcast_ref::<FileTransferStateData>() {
                Some(state_data) => {
                    println!(
                        "FileTransferPlugin::apply_command(cmd:{}, params:{:?}, ctx:{:?})... ",
                        cmd, params, ctx,
                    );
                    println!(
                        "got internal FileTransferStateData! #transfers={}",
                        state_data.completed_transfers.len()
                    );

                    match cmd {
                        "save" => {
                            // get the ctx.save.idx:
                            // and params.saveAs
                            if let (Some(params), Some(ctx)) = (params, ctx) {
                                if let (Some(save_as), Some(idx)) = (
                                    params.get("saveAs").and_then(serde_json::Value::as_str),
                                    ctx.get("save")
                                        .and_then(serde_json::Value::as_object)
                                        .and_then(|f| f.get("idx"))
                                        .and_then(serde_json::Value::as_u64),
                                ) {
                                    if let Some(data) =
                                        state_data.completed_transfers.get(&(idx as usize))
                                    {
                                        // hurray... lets write this to file:
                                        println!(" saving {} bytes to {}", data.len(), save_as);
                                        match File::create(save_as)
                                            .and_then(|mut f| f.write_all(data))
                                        {
                                            Ok(_) => true,
                                            Err(e) => {
                                                println!("saving failed with err '{}'", e);
                                                false
                                            }
                                        }
                                    } else {
                                        println!("didn't found idx {}", idx);
                                        false
                                    }
                                } else {
                                    false
                                }
                            } else {
                                false
                            }
                        }
                        _ => false,
                    }
                }
                None => {
                    println!("no internal FileTransferStateData!");
                    false
                }
            }
        } else {
            false
        }
    }

    /// check whether a msg is a file transfer message of type_str
    ///
    /// The messages have as first and last payload argument a string
    /// with that type.
    /// Does only work for type_str with len 4!
    pub fn is_type(msg: &DltMessage, type_str: &str) -> bool {
        // the msg for a type starts and ends with that string
        // we dont check noar here again
        let mut args_iter = msg.into_iter();
        if let Some(arg0) = args_iter.next() {
            if arg0.scod() == DLT_SCOD_ASCII && arg0.payload_raw.len() == 5 {
                // todo hardcoded for perfo 4 plus 0
                if arg0.payload_raw[0..4].eq(type_str.as_bytes()) {
                    if let Some(arg1) = args_iter.last() {
                        if arg1.scod() == DLT_SCOD_ASCII
                            && arg1.payload_raw.len() == 5
                            && arg1.payload_raw[0..4].eq(type_str.as_bytes())
                        {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }
}

fn arg_as_uint(arg: &crate::dlt::DltArg) -> Result<u64, ()> {
    let is_uint = arg.type_info & DLT_TYPE_INFO_UINT > 0;
    if is_uint {
        match arg.payload_raw.len() {
            4 => Ok(if arg.is_big_endian {
                u32::from_be_bytes(arg.payload_raw.try_into().unwrap())
            } else {
                u32::from_le_bytes(arg.payload_raw.try_into().unwrap())
            } as u64),
            8 => Ok(if arg.is_big_endian {
                u64::from_be_bytes(arg.payload_raw.try_into().unwrap())
            } else {
                u64::from_le_bytes(arg.payload_raw.try_into().unwrap())
            }),
            2 => Ok(if arg.is_big_endian {
                u16::from_be_bytes(arg.payload_raw.try_into().unwrap())
            } else {
                u16::from_le_bytes(arg.payload_raw.try_into().unwrap())
            } as u64),
            1 => Ok(arg.payload_raw[0] as u64),
            // todo 16... not yet supported here
            _ => Err(()),
        }
    } else {
        let is_sint = arg.type_info & DLT_TYPE_INFO_SINT > 0;
        if is_sint {
            match arg.payload_raw.len() {
                4 => {
                    let i = if arg.is_big_endian {
                        i32::from_be_bytes(arg.payload_raw.try_into().unwrap())
                    } else {
                        i32::from_le_bytes(arg.payload_raw.try_into().unwrap())
                    };
                    if i >= 0 {
                        Ok(i as u64)
                    } else {
                        Err(())
                    }
                }
                8 => {
                    let i = if arg.is_big_endian {
                        i64::from_be_bytes(arg.payload_raw.try_into().unwrap())
                    } else {
                        i64::from_le_bytes(arg.payload_raw.try_into().unwrap())
                    };
                    if i >= 0 {
                        Ok(i as u64)
                    } else {
                        Err(())
                    }
                }
                2 => {
                    let i = if arg.is_big_endian {
                        i16::from_be_bytes(arg.payload_raw.try_into().unwrap())
                    } else {
                        i16::from_le_bytes(arg.payload_raw.try_into().unwrap())
                    };
                    if i >= 0 {
                        Ok(i as u64)
                    } else {
                        Err(())
                    }
                }
                1 => {
                    if arg.payload_raw[0] as i8 >= 0 {
                        Ok(arg.payload_raw[0] as u64)
                    } else {
                        Err(())
                    }
                }
                // todo 16... not yet supported here
                _ => Err(()),
            }
        } else {
            println!("arg_as_uint got type_info={}", arg.type_info);
            Err(())
        }
    }
}

fn arg_as_string(arg: &crate::dlt::DltArg) -> Result<String, ()> {
    if arg.is_string() && arg.payload_raw.len() > 1 {
        match arg.scod() {
            DLT_SCOD_ASCII => {
                let (s, _) = encoding_rs::WINDOWS_1252
                    .decode_without_bom_handling(&arg.payload_raw[0..arg.payload_raw.len() - 1]);
                Ok(String::from(s))
            }
            DLT_SCOD_UTF8 => {
                let s = String::from_utf8_lossy(&arg.payload_raw[0..arg.payload_raw.len() - 1]);
                Ok(String::from(s))
            }
            _ => {
                println!("FLST unexpected filename scod {}", arg.scod());
                Err(())
            }
        }
    } else {
        Err(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn init_plugin() {
        // good case:
        let cfg = json!({"name":"foo","enabled": false, });
        let p = FileTransferPlugin::from_json(cfg.as_object().unwrap());
        assert!(p.is_ok());
        let p = p.unwrap();
        assert_eq!(p.name, "foo");
        assert!(!p.enabled);

        assert!(p.allow_save);
        assert!(!p.keep_flda);
        assert!(p.apid.is_none());
        assert!(p.ctid.is_none());

        let state = p.state();
        let state = state.read().unwrap();
        assert_eq!(state.generation, 1); // first update done
        let state_value = &state.value;
        assert!(state_value.is_object());
        let state_obj = state_value.as_object().unwrap();
        assert!(state_obj.contains_key("name"));
        assert!(state_obj.contains_key("treeItems"));
        let tree_items = state_obj.get("treeItems").unwrap();
        assert!(tree_items.is_array());
        assert_eq!(tree_items.as_array().unwrap().len(), 0);
        // state can be debug printed:
        assert!(!format!("{:?}", state).is_empty());

        // name missing: -> err
        let cfg = json!({"enabled": false});
        let p = FileTransferPlugin::from_json(cfg.as_object().unwrap());
        assert!(p.is_err());

        // enabled missing -> default true
        let cfg = json!({"name": "f"});
        let p = FileTransferPlugin::from_json(cfg.as_object().unwrap()).unwrap();
        assert!(p.enabled);

        // complete example
        let cfg =
            json!({"name": "f", "apid":"apid", "ctid":"ctid", "allowSave":false, "keepFLDA":true});
        let p = FileTransferPlugin::from_json(cfg.as_object().unwrap()).unwrap();
        assert!(p.enabled);
        assert!(!p.allow_save);
        assert!(p.keep_flda);
        assert!(p.apid.is_some());
        assert!(p.ctid.is_some());
    }
}
