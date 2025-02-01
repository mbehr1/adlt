use serde::{ser, Serialize};

use crate::dlt::{
    DLT_SCOD_UTF8, DLT_TYLE_16BIT, DLT_TYLE_32BIT, DLT_TYLE_64BIT, DLT_TYLE_8BIT,
    DLT_TYPE_INFO_BOOL, DLT_TYPE_INFO_FLOA, DLT_TYPE_INFO_RAWD, DLT_TYPE_INFO_SINT,
    DLT_TYPE_INFO_STRG, DLT_TYPE_INFO_UINT,
};

use super::error::{Error, Result};

/// Serialize data as verbose dlt message payload
///
/// endianess is used as host endianess
///
/// counterpart for DltMessageA,rgIterator (todo add as Deserializer later...)
pub struct Serializer {
    pub output: Vec<u8>,
}

/// return payload as vec of bytes for a single dlt verbose argument
pub fn to_payload<T>(value: &T) -> Result<Vec<u8>>
where
    T: Serialize,
{
    let mut serializer = Serializer {
        output: Vec::default(),
    };
    value.serialize(&mut serializer)?;
    Ok(serializer.output)
}

pub fn add_to_serializer<T>(serializer: &mut Serializer, value: &T) -> Result<()>
where
    T: Serialize,
{
    value.serialize(serializer)
}

/// return noar and payload as vec from multiple arguments
#[macro_export]
macro_rules! dlt_args {
    ( $( $x:expr ),* ) => {
        (||->Result<(u8, Vec<u8>), $crate::serde_verb_payload::Error>{
            let mut serializer = $crate::serde_verb_payload::Serializer{
                output: Vec::default(),
            };
            // todo shall we iterate over all args and determine a rough length estimate?
            let mut nr_args = 0;
            $(
                    //$x.serialize(&mut serializer)?;
                    $crate::serde_verb_payload::add_to_serializer(&mut serializer, &$x)?;
                    nr_args += 1;
            )*
            // todo return err if nr_args > 0xff?
            Ok((nr_args, serializer.output))
        })()
    };
}

impl ser::Serializer for &mut Serializer {
    // The output type produced by this `Serializer` during successful
    // serialization. Most serializers that produce text or binary output should
    // set `Ok = ()` and serialize into an `io::Write` or buffer contained
    // within the `Serializer` instance, as happens here. Serializers that build
    // in-memory data structures may be simplified by using `Ok` to propagate
    // the data structure around.
    type Ok = ();

    // The error type when some error occurs during serialization.
    type Error = Error;

    // Associated types for keeping track of additional state while serializing
    // compound data structures like sequences and maps. In this case no
    // additional state is required beyond what is already stored in the
    // Serializer struct.
    type SerializeSeq = Self;
    type SerializeTuple = Self;
    type SerializeTupleStruct = Self;
    type SerializeTupleVariant = Self;
    type SerializeMap = Self;
    type SerializeStruct = Self;
    type SerializeStructVariant = Self;

    fn serialize_bool(self, v: bool) -> Result<()> {
        let type_info = DLT_TYPE_INFO_BOOL | (DLT_TYLE_8BIT as u32);
        self.output.extend_from_slice(&type_info.to_ne_bytes());
        let iv: u8 = if v { 1 } else { 0 };
        self.output.extend_from_slice(&iv.to_ne_bytes());
        Ok(())
    }

    fn serialize_i8(self, v: i8) -> Result<()> {
        let type_info = DLT_TYPE_INFO_SINT | (DLT_TYLE_8BIT as u32);
        self.output.extend_from_slice(&type_info.to_ne_bytes());
        self.output.extend_from_slice(&v.to_ne_bytes());
        Ok(())
    }

    fn serialize_i16(self, v: i16) -> Result<()> {
        let type_info = DLT_TYPE_INFO_SINT | (DLT_TYLE_16BIT as u32);
        self.output.extend_from_slice(&type_info.to_ne_bytes());
        self.output.extend_from_slice(&v.to_ne_bytes());
        Ok(())
    }

    fn serialize_i32(self, v: i32) -> Result<()> {
        let type_info = DLT_TYPE_INFO_SINT | (DLT_TYLE_32BIT as u32);
        self.output.extend_from_slice(&type_info.to_ne_bytes());
        self.output.extend_from_slice(&v.to_ne_bytes());
        Ok(())
    }

    fn serialize_i64(self, v: i64) -> Result<()> {
        let type_info = DLT_TYPE_INFO_SINT | (DLT_TYLE_64BIT as u32);
        self.output.extend_from_slice(&type_info.to_ne_bytes());
        self.output.extend_from_slice(&v.to_ne_bytes());
        Ok(())
    }

    fn serialize_u8(self, v: u8) -> Result<()> {
        let type_info = DLT_TYPE_INFO_UINT | (DLT_TYLE_8BIT as u32);
        self.output.extend_from_slice(&type_info.to_ne_bytes());
        self.output.extend_from_slice(&v.to_ne_bytes());
        Ok(())
    }

    fn serialize_u16(self, v: u16) -> Result<()> {
        let type_info = DLT_TYPE_INFO_UINT | (DLT_TYLE_16BIT as u32);
        self.output.extend_from_slice(&type_info.to_ne_bytes());
        self.output.extend_from_slice(&v.to_ne_bytes());
        Ok(())
    }

    fn serialize_u32(self, v: u32) -> Result<()> {
        let type_info = DLT_TYPE_INFO_UINT | (DLT_TYLE_32BIT as u32);
        self.output.extend_from_slice(&type_info.to_ne_bytes());
        self.output.extend_from_slice(&v.to_ne_bytes());
        Ok(())
    }

    fn serialize_u64(self, v: u64) -> Result<()> {
        let type_info = DLT_TYPE_INFO_UINT | (DLT_TYLE_64BIT as u32);
        self.output.extend_from_slice(&type_info.to_ne_bytes());
        self.output.extend_from_slice(&v.to_ne_bytes());
        Ok(())
    }

    // todo for i/u/f128/?

    fn serialize_f32(self, v: f32) -> Result<()> {
        let type_info = DLT_TYPE_INFO_FLOA | (DLT_TYLE_32BIT as u32);
        self.output.extend_from_slice(&type_info.to_ne_bytes());
        self.output.extend_from_slice(&v.to_ne_bytes());
        Ok(())
    }

    fn serialize_f64(self, v: f64) -> Result<()> {
        let type_info = DLT_TYPE_INFO_FLOA | (DLT_TYLE_64BIT as u32);
        self.output.extend_from_slice(&type_info.to_ne_bytes());
        self.output.extend_from_slice(&v.to_ne_bytes());
        Ok(())
    }

    fn serialize_char(self, v: char) -> Result<()> {
        self.serialize_str(&v.to_string())
    }

    fn serialize_str(self, v: &str) -> Result<()> {
        if v.len() >= 0xffff {
            return Err(Error::DataTooLarge);
        }
        let type_info = DLT_TYPE_INFO_STRG | DLT_SCOD_UTF8;
        self.output.extend_from_slice(&type_info.to_ne_bytes());
        let len: u16 = 1 + v.len() as u16;
        self.output.extend_from_slice(&len.to_ne_bytes());
        self.output.extend_from_slice(v.as_bytes());
        self.output.push(0); // shall be null terminated
        Ok(())
    }

    fn serialize_bytes(self, v: &[u8]) -> Result<()> {
        if v.len() > 0xffff {
            return Err(Error::DataTooLarge);
        }
        let type_info = DLT_TYPE_INFO_RAWD;
        self.output.extend_from_slice(&type_info.to_ne_bytes());
        let len: u16 = v.len() as u16;
        self.output.extend_from_slice(&len.to_ne_bytes());
        self.output.extend_from_slice(v);
        Ok(())
    }

    // an absent optional:
    fn serialize_none(self) -> Result<()> {
        self.serialize_unit()
    }

    fn serialize_some<T>(self, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(self)
    }

    fn serialize_unit(self) -> Result<()> {
        Err(Error::Nyi) // todo bad as it counts as an argument!
    }

    // Unit struct means a named value containing no data.
    fn serialize_unit_struct(self, _name: &'static str) -> Result<()> {
        self.serialize_unit()
    }

    // When serializing a unit variant (or any other kind of variant), formats
    // can choose whether to keep track of it by index or by name. Binary
    // formats typically use the index of the variant and human-readable formats
    // typically use the name.
    // todo???
    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
    ) -> Result<()> {
        self.serialize_str(variant)
    }

    // As is done here, serializers are encouraged to treat newtype structs as
    // insignificant wrappers around the data they contain.
    fn serialize_newtype_struct<T>(self, _name: &'static str, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        // todo could use vari here to add the name!
        value.serialize(self)
    }

    // Note that newtype variant (and all of the other variant serialization
    // methods) refer exclusively to the "externally tagged" enum
    // representation.
    //
    // Serialize this to as payload as TODO!
    fn serialize_newtype_variant<T>(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        variant.serialize(&mut *self)?;
        value.serialize(&mut *self)?;
        Err(Error::Nyi)
    }

    // Now we get to the serialization of compound types.
    //
    // The start of the sequence, each value, and the end are three separate
    // method calls. This one is responsible only for serializing the start,
    // which in JSON is `[`.
    //
    // The length of the sequence may or may not be known ahead of time. This
    // doesn't make a difference in JSON because the length is not represented
    // explicitly in the serialized form. Some serializers may only be able to
    // support sequences for which the length is known up front.
    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq> {
        // TODO
        Err(Error::Nyi)
    }

    // Tuples look just like sequences in JSON. Some formats may be able to
    // represent tuples more efficiently by omitting the length, since tuple
    // means that the corresponding `Deserialize implementation will know the
    // length without needing to look at the serialized data.
    fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple> {
        self.serialize_seq(Some(len))
    }

    // Tuple structs look just like sequences in JSON.
    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleStruct> {
        self.serialize_seq(Some(len))
    }

    // Tuple variants are represented in JSON as `{ NAME: [DATA...] }`. Again
    // this method is only responsible for the externally tagged representation.
    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant> {
        // variant.serialize(&mut *self)?;
        Err(Error::Nyi)
    }

    // Maps are represented in JSON as `{ K: V, K: V, ... }`. TODO DLT?
    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap> {
        Err(Error::Nyi)
    }

    // Structs look just like maps in JSON. In particular, JSON requires that we
    // serialize the field names of the struct. Other formats may be able to
    // omit the field names when serializing structs because the corresponding
    // Deserialize implementation is required to know what the keys are without
    // looking at the serialized data.
    fn serialize_struct(self, _name: &'static str, len: usize) -> Result<Self::SerializeStruct> {
        self.serialize_map(Some(len))
    }

    // Struct variants are represented in JSON as `{ NAME: { K: V, ... } }`.
    // This is the externally tagged representation.
    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant> {
        //variant.serialize(&mut *self)?;
        Err(Error::Nyi)
    }
}

// The following 7 impls deal with the serialization of compound types like
// sequences and maps. Serialization of such types is begun by a Serializer
// method and followed by zero or more calls to serialize individual elements of
// the compound type and one call to end the compound type.
//
// This impl is SerializeSeq so these methods are called after `serialize_seq`
// is called on the Serializer.
impl ser::SerializeSeq for &mut Serializer {
    // Must match the `Ok` type of the serializer.
    type Ok = ();
    // Must match the `Error` type of the serializer.
    type Error = Error;

    // Serialize a single element of the sequence.
    fn serialize_element<T>(&mut self, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        /*if !self.output.ends_with('[') {
            self.output += ",";
        }*/
        value.serialize(&mut **self)
    }

    // Close the sequence.
    fn end(self) -> Result<()> {
        // self.output += "]";
        Ok(())
    }
}

// Same thing but for tuples.
impl ser::SerializeTuple for &mut Serializer {
    type Ok = ();
    type Error = Error;

    fn serialize_element<T>(&mut self, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        /*if !self.output.ends_with('[') {
            self.output += ",";
        }*/
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        // self.output += "]";
        Ok(())
    }
}

// Same thing but for tuple structs.
impl ser::SerializeTupleStruct for &mut Serializer {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T>(&mut self, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        /*if !self.output.ends_with('[') {
            self.output += ",";
        }*/
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        // self.output += "]";
        Ok(())
    }
}

// Tuple variants are a little different. Refer back to the
// `serialize_tuple_variant` method above:
//
//    self.output += "{";
//    variant.serialize(&mut *self)?;
//    self.output += ":[";
//
// So the `end` method in this impl is responsible for closing both the `]` and
// the `}`.
impl ser::SerializeTupleVariant for &mut Serializer {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T>(&mut self, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        /*if !self.output.ends_with('[') {
            self.output += ",";
        }*/
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        // self.output += "]}";
        Ok(())
    }
}

// Some `Serialize` types are not able to hold a key and value in memory at the
// same time so `SerializeMap` implementations are required to support
// `serialize_key` and `serialize_value` individually.
//
// There is a third optional method on the `SerializeMap` trait. The
// `serialize_entry` method allows serializers to optimize for the case where
// key and value are both available simultaneously. In JSON it doesn't make a
// difference so the default behavior for `serialize_entry` is fine.
impl ser::SerializeMap for &mut Serializer {
    type Ok = ();
    type Error = Error;

    // The Serde data model allows map keys to be any serializable type. JSON
    // only allows string keys so the implementation below will produce invalid
    // JSON if the key serializes as something other than a string.
    //
    // A real JSON serializer would need to validate that map keys are strings.
    // This can be done by using a different Serializer to serialize the key
    // (instead of `&mut **self`) and having that other serializer only
    // implement `serialize_str` and return an error on any other data type.
    fn serialize_key<T>(&mut self, key: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        /*if !self.output.ends_with('{') {
            self.output += ",";
        }*/
        key.serialize(&mut **self)
    }

    // It doesn't make a difference whether the colon is printed at the end of
    // `serialize_key` or at the beginning of `serialize_value`. In this case
    // the code is a bit simpler having it here.
    fn serialize_value<T>(&mut self, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        //self.output += ":";
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        // self.output += "}";
        Ok(())
    }
}

// Structs are like maps in which the keys are constrained to be compile-time
// constant strings.
impl ser::SerializeStruct for &mut Serializer {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T>(&mut self, key: &'static str, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        /*if !self.output.ends_with('{') {
            self.output += ",";
        }*/
        key.serialize(&mut **self)?;
        // self.output += ":";
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        // self.output += "}";
        Ok(())
    }
}

impl ser::SerializeStructVariant for &mut Serializer {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T>(&mut self, key: &'static str, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        /*if !self.output.ends_with('{') {
            self.output += ",";
        }*/
        key.serialize(&mut **self)?;
        // self.output += ":";
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::dlt::{
        DltChar4, DltExtendedHeader, DltMessage, DltStandardHeader, DLT_STD_HDR_BIG_ENDIAN,
        DLT_STD_HDR_VERSION,
    };

    use super::to_payload;

    #[test]
    fn test_u16() {
        let test: u16 = 0x4243;
        let payload = to_payload(&test).unwrap();
        assert_eq!(payload.len(), 6); // u32 type_info and 2 bytes from u16

        // see that the arg iter returns the same as text:
        let is_big_endian = cfg!(target_endian = "big");

        let m = DltMessage {
            index: 0,
            reception_time_us: 0,
            ecu: DltChar4::from_buf(b"ECU1"),
            timestamp_dms: 0,
            standard_header: DltStandardHeader {
                htyp: if is_big_endian {
                    DLT_STD_HDR_VERSION | DLT_STD_HDR_BIG_ENDIAN
                } else {
                    DLT_STD_HDR_VERSION
                }, // little end
                len: 100,
                mcnt: 0,
            },
            extended_header: Some(DltExtendedHeader {
                verb_mstp_mtin: 1,
                noar: 1,
                apid: DltChar4::from_buf(b"APID"),
                ctid: DltChar4::from_buf(b"CTID"),
            }),
            lifecycle: 0,
            payload,
            payload_text: None,
        };
        let args_iter = m.into_iter();
        assert_eq!(args_iter.count(), 1);
        assert_eq!(m.payload_as_text().unwrap(), "16963");
    }

    #[test]
    fn test_str() {
        let test = "fooBar";
        let payload = to_payload(&test).unwrap();
        assert_eq!(payload.len(), 4 + 2 + 7); // u32 type_info and 2 bytes len plus 6 bytes plus null term

        // see that the arg iter returns the same as text:
        let is_big_endian = cfg!(target_endian = "big");

        let m = DltMessage {
            index: 0,
            reception_time_us: 0,
            ecu: DltChar4::from_buf(b"ECU1"),
            timestamp_dms: 0,
            standard_header: DltStandardHeader {
                htyp: if is_big_endian {
                    DLT_STD_HDR_VERSION | DLT_STD_HDR_BIG_ENDIAN
                } else {
                    DLT_STD_HDR_VERSION
                }, // little end
                len: 100,
                mcnt: 0,
            },
            extended_header: Some(DltExtendedHeader {
                verb_mstp_mtin: 1,
                noar: 1,
                apid: DltChar4::from_buf(b"APID"),
                ctid: DltChar4::from_buf(b"CTID"),
            }),
            lifecycle: 0,
            payload,
            payload_text: None,
        };
        let args_iter = m.into_iter();
        assert_eq!(args_iter.count(), 1);
        assert_eq!(m.payload_as_text().unwrap(), test);
    }

    #[test]
    fn test_dlt_args_macro() {
        let (noar, payload) =
            dlt_args!(42u8, 0x4243u16, 0x42434445u32, 0x4243444546474849u64).unwrap();
        assert_eq!(noar, 4);
        assert_eq!(
            payload.len(),
            ((noar * 4) + 1 + 2 + 4 + 8) as usize,
            "payload={:?}",
            payload
        );
        let (noar, payload) =
            dlt_args!(42i8, -4243i16, -42434445i32, -4243444546474849i64).unwrap();
        assert_eq!(noar, 4);
        assert_eq!(
            payload.len(),
            ((noar * 4) + 1 + 2 + 4 + 8) as usize,
            "payload={:?}",
            payload
        );
        let (noar, payload) = dlt_args!(1.0f32, 2.0f64).unwrap();
        assert_eq!(noar, 2);
        assert_eq!(
            payload.len(),
            ((noar * 4) + 4 + 8) as usize,
            "payload={:?}",
            payload
        );

        let (noar, payload) = dlt_args!(true, false, 'c').unwrap();
        assert_eq!(noar, 3);
        assert_eq!(
            payload.len(),
            ((noar * 4) + 1 + 1 + 2 + 1 + 1) as usize,
            "payload={:?}",
            payload
        );

        // raw data (byte array/vec) need to be wrapped into a serde_bytes::Bytes to avoid serialization as sequence
        let (noar, payload) = dlt_args!(serde_bytes::Bytes::new(&[0u8, 1u8, 2u8])).unwrap();
        assert_eq!(noar, 1);
        assert_eq!(
            payload.len(),
            ((noar * 4) + 2 + 3) as usize,
            "payload={:?}",
            payload
        );
    }

    #[test]
    fn test_not_supported_args() {
        // test that we get an error for not supported args:
        let res = dlt_args!(None::<bool>);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().to_string(), "not yet implemented! (Nyi)");
        let res = dlt_args!(Some(42u8));
        assert!(res.is_ok()); // we do support Some(...) as the orig type
        let res = dlt_args!(std::collections::HashMap::<String, u32>::new());
        assert!(res.is_err());
        let res = dlt_args!(std::collections::BTreeMap::<String, u32>::new());
        assert!(res.is_err());
        let res = dlt_args!(std::collections::HashSet::<String>::new());
        assert!(res.is_err());
        let res = dlt_args!(std::collections::BTreeSet::<u32>::new());
        assert!(res.is_err());
        let res = dlt_args!(std::collections::LinkedList::<String>::new());
        assert!(res.is_err());
        let res = dlt_args!(std::collections::VecDeque::<bool>::new());
        assert!(res.is_err());
        let res = dlt_args!(std::collections::BinaryHeap::<u32>::new());
        assert!(res.is_err());
        let res = dlt_args!(&[1u8, 2]);
        assert!(res.is_err());
        let res = dlt_args!(&[true, false]); // var size (slice) array of bool
        assert!(res.is_err());
        let res = dlt_args!([true, false]); // fixed size array of bool
        assert!(res.is_err());
    }
}
