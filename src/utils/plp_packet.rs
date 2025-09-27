use pnet_macros::packet;
use pnet_macros_support::types::u16be;

#[allow(unexpected_cfgs)]
#[packet]
pub struct Plp {
    pub probe_id: u16be,
    pub counter: u16be,
    pub version: u8,
    pub plp_type: u8,
    pub msg_type: u16be, // aka data_type in tecmp?
    pub reserved: u16be,
    pub probe_flags: u16be,
    #[payload]
    pub payload: Vec<u8>,
}
