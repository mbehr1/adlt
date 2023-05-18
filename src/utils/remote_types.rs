use bincode::Encode;
// we use bincode serialization
#[derive(Encode, bincode::Decode)]
pub struct BinLifecycle {
    pub id: u32,
    pub ecu: u32, // Vec<u8>, // todo bincode-typescript doesn't support [u8;4] ... add support or misuse as u32
    pub nr_msgs: u32,
    pub start_time: u64,
    pub end_time: u64,
    pub sw_version: Option<String>,
    pub resume_time: Option<u64>, // if it was a resumed lifecycle. start_time refers to the reference time for the timestamp_dms of the msgs. This time should be shown to the user.
}

#[derive(Encode, bincode::Decode)]
pub struct BinDltMsg {
    pub index: u32, // todo use DltMessageIndexType!
    pub reception_time: u64,
    pub timestamp_dms: u32,
    pub ecu: u32,
    pub apid: u32,
    pub ctid: u32,
    pub lifecycle_id: u32, // todo use lifecycle::LifecycleId
    pub htyp: u8,
    pub mcnt: u8,
    pub verb_mstp_mtin: u8,
    pub noar: u8,
    pub payload_as_text: String, // todo and option for payload as vec[u8]?
}

#[derive(Encode, bincode::Decode)]
pub struct BinFileInfo {
    pub nr_msgs: u32, // todo change with index
}

/// info about the ECU/APIDs/CTIDs
#[derive(Encode, bincode::Decode)]
pub struct BinEcuStats {
    pub ecu: u32,
    pub nr_msgs: u32, // todo change with index
    pub apids: Vec<BinApidInfo>,
}

#[derive(Encode, bincode::Decode)]
pub struct BinApidInfo {
    pub apid: u32,
    pub desc: Option<String>,
    pub ctids: Vec<BinCtidInfo>,
}

#[derive(Encode, bincode::Decode)]
pub struct BinCtidInfo {
    pub ctid: u32,
    pub nr_msgs: u32, // todo change with index
    pub desc: Option<String>,
}

#[derive(Encode, bincode::Decode)]
pub struct BinStreamInfo {
    // todo change with index
    pub stream_id: u32,
    pub nr_stream_msgs: u32,
    pub nr_file_msgs_processed: u32,
    pub nr_file_msgs_total: u32,
}

#[derive(Encode, bincode::Decode)]
pub enum BinType {
    FileInfo(BinFileInfo),
    Lifecycles(Vec<BinLifecycle>),
    DltMsgs((u32, Vec<BinDltMsg>)), // stream id and Vec
    EacInfo(Vec<BinEcuStats>),
    PluginState(Vec<String>), // serialized json from each plugin with generation update
    StreamInfo(BinStreamInfo),
}
