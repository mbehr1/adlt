mod error;
pub use error::Error;

#[macro_use] // for dlt_args!
mod ser_verb_payload;

pub use ser_verb_payload::{add_to_serializer, to_payload, DltVerbArgTypeWrapper, Serializer};
