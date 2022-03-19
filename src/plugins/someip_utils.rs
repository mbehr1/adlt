// copyright Matthias Behr, (c) 2022
//
// todos:
// [ ] CODED-TYPE.MIN-LENGTH usage (e.g. MIN-LENGTH = 8???)
// [ ] type and length field sizes from utilization complete usage
//

use super::fibex::{
    BaseDataType, Category, Coding, ComplexDatatypeClass, Datatype, DatatypeType, Encoding, Enum,
    FibexData, FibexError, HoTermination, Method, MethodIdType, Parameter, Service, Utilization,
};
use bitvec::{field::BitField, order::Lsb0, prelude::*};
use lazy_static::lazy_static;
use std::{
    collections::HashMap,
    convert::TryInto,
    io::{ErrorKind, Write},
};

lazy_static! {
    /// message type indicator see PRS_SOMEIP_00055
    static ref MSG_TYPE_MAP: HashMap<u8, &'static str> = vec![
        (0, "> "), // request
        (1, "> "), // request no return
        (2, "* "), // notif
        (0x20, "> "), // TP request
        (0x21, "> "), // TP request no return
        (0x22, "* "), // TP notif
        (0x23, "< "), // TP resp
        (0x24, "! "), // TP err
        (0x80, "< "), // resp
        (0x81, "! "), // err
    ].into_iter().collect();

    /// return codes according to PRS_SOMEIP_00191
    static ref RETURN_CODE_MAP: HashMap<u8, &'static str> = vec![
        (0, "[OK]"),
        (1, "[NOT OK]"),
        (2, "[UNKNOWN SERVICE]"),
        (3, "[UNKNOWN METHOD]"),
        (4, "[NOT READY]"),
        (5, "[NOT REACHABLE]"),
        (6, "[TIMEOUT]"),
        (7, "[WRONG PROTOCOL VERSION]"),
        (8, "[WRONG INTERFACE VERSION]"),
        (9, "[MALFORMED MESSAGE]"),
        (0xa, "[WRONG MESSAGE TYPE]"),
    ].into_iter().collect();

    static ref NO_SHORT_NAME:String = "<no SHORT-NAME>".to_string();
    static ref EMPTY_SERVICES_VEC:Vec<Service> = Vec::new();
}

/// decode a someip header and payload according to RS_SOMEIP_00027
/// into a string that follows the conventions:
/// - symbol for request (<), response (<), notification (*) or errors (!)
/// - (client-id:session-id)
/// - service name
/// - (instance id in hex).
/// - method or event short name. E.g. set_fieldName_field (setter for field 'fieldName')
/// - payload (as json parseable string)
/// - return code e.g. [OK]
pub fn decode_someip_header_and_payload(
    fd: &FibexData,
    inst_id: u32,
    header: &[u8],
    payload: &[u8],
) -> Result<String, FibexError> {
    if header.len() < 16 {
        Err(FibexError::new("header too short"))
    } else {
        let mut res = String::with_capacity(1024); // todo or even longer?
        let str_rc = *RETURN_CODE_MAP.get(&header[15]).unwrap_or(&"UNKNOWN RC!"); // todo add 0x0b-1f and 0x20-0x53 as RESERVED
        let str_symbol = *MSG_TYPE_MAP.get(&header[14]).unwrap_or(&"? ");

        let service_id = u16::from_be_bytes(header[0..2].try_into().unwrap());
        let method_id = u16::from_be_bytes(header[2..4].try_into().unwrap());
        let msg_length = u32::from_be_bytes(header[4..8].try_into().unwrap());
        let client_id = u16::from_be_bytes(header[8..10].try_into().unwrap());
        let session_id = u16::from_be_bytes(header[10..12].try_into().unwrap());

        let major = header[13];
        let message_type = header[14];

        if msg_length < 8 {
            return Err(FibexError::new("header.length too short (<8)!"));
        }
        let payload_length = msg_length - 8;

        let service = fd
            .elements
            .services_map_by_sid_major
            .get(&(service_id, major))
            .unwrap_or(&EMPTY_SERVICES_VEC);

        res += str_symbol;

        if !service.is_empty() {
            let service = &service[0]; // we take the first one, ignoring the rest
            let service_name = service.short_name.as_ref().unwrap_or(&NO_SHORT_NAME);

            let method = service.methods_by_mid.get(&method_id);
            if let Some(method) = method {
                match method {
                    MethodIdType::Method(method) => {
                        let method_name = method.short_name.as_ref().unwrap_or(&NO_SHORT_NAME);

                        // parse parameter...
                        let payload_str =
                            decode_payload(fd, message_type, method, payload_length, payload)?;

                        res += &format!(
                            "({:04x}:{:04x}) {}({:04x}).{}{}",
                            client_id, session_id, service_name, inst_id, method_name, payload_str
                        );
                    }
                    MethodIdType::Notifier { field } => {
                        // todo change to writer directly!
                        let mut parsed_bits = 0u32;
                        let available_bits =
                            std::cmp::min(payload_length, payload.len() as u32) * 8;

                        let mut writer = Vec::with_capacity(2 * 1024);
                        {
                            let writer = &mut writer;
                            let ctx = &mut SomeipDecodingCtx {
                                fd,
                                parsed_bits: &mut parsed_bits,
                                available_bits,
                                payload,
                            };
                            field.to_writer(writer, ctx, None).ok(); // .map_err(|e| FibexError { msg: e.to_string() })?;
                        }
                        let payload_str = unsafe { String::from_utf8_unchecked(writer) };
                        let field_name = field.short_name.as_ref();
                        if let Some(field_name) = field_name {
                            res += &format!(
                                "({:04x}:{:04x}) {}({:04x}).changed_{}_field{{\"{}\":{}}}",
                                client_id,
                                session_id,
                                service_name,
                                inst_id,
                                field_name,
                                field_name,
                                payload_str
                            );
                        } else {
                            res += &format!(
                                "({:04x}:{:04x}) {}({:04x}).changed_<no shortname>{}_field{{{}:{}}}",
                                client_id,
                                session_id,
                                service_name,
                                inst_id,
                                &field.id,
                                &field.id,
                                payload_str
                            );
                        }
                    }
                    MethodIdType::Setter { field } => {
                        // todo change to writer directly!
                        let mut parsed_bits = 0u32;
                        let available_bits =
                            std::cmp::min(payload_length, payload.len() as u32) * 8;

                        let mut writer = Vec::with_capacity(2 * 1024);
                        {
                            let writer = &mut writer;
                            let ctx = &mut SomeipDecodingCtx {
                                fd,
                                parsed_bits: &mut parsed_bits,
                                available_bits,
                                payload,
                            };
                            field.to_writer(writer, ctx, None).ok(); // .map_err(|e| FibexError { msg: e.to_string() })?;
                        }
                        let payload_str = unsafe { String::from_utf8_unchecked(writer) };
                        let field_name = field.short_name.as_ref();
                        if let Some(field_name) = field_name {
                            res += &format!(
                                "({:04x}:{:04x}) {}({:04x}).set_{}_field{{\"{}\":{}}}",
                                client_id,
                                session_id,
                                service_name,
                                inst_id,
                                field_name,
                                field_name,
                                payload_str
                            );
                        } else {
                            res += &format!(
                                "({:04x}:{:04x}) {}({:04x}).set_<no shortname>{}_field{{{}:{}}}",
                                client_id,
                                session_id,
                                service_name,
                                inst_id,
                                &field.id,
                                &field.id,
                                payload_str
                            );
                        }
                    }
                    MethodIdType::Getter { field } => {
                        // todo change to writer directly!
                        let mut parsed_bits = 0u32;
                        let available_bits =
                            std::cmp::min(payload_length, payload.len() as u32) * 8;

                        let mut writer = Vec::with_capacity(2 * 1024);
                        {
                            let writer = &mut writer;
                            let ctx = &mut SomeipDecodingCtx {
                                fd,
                                parsed_bits: &mut parsed_bits,
                                available_bits,
                                payload,
                            };
                            field.to_writer(writer, ctx, None).ok(); // .map_err(|e| FibexError { msg: e.to_string() })?;
                        }
                        let payload_str = unsafe { String::from_utf8_unchecked(writer) };
                        let field_name = field.short_name.as_ref();
                        if let Some(field_name) = field_name {
                            res += &format!(
                                "({:04x}:{:04x}) {}({:04x}).get_{}_field{{\"{}\":{}}}",
                                client_id,
                                session_id,
                                service_name,
                                inst_id,
                                field_name,
                                field_name,
                                payload_str
                            );
                        } else {
                            res += &format!(
                                "({:04x}:{:04x}) {}({:04x}).get_<no shortname>{}_field{{{}:{}}}",
                                client_id,
                                session_id,
                                service_name,
                                inst_id,
                                &field.id,
                                &field.id,
                                payload_str
                            );
                        }
                    } /*_ => {
                          res += &format!(
                              "({:04x}:{:04x}) {}({:04x}).<nyi MethodIdType {:?}>",
                              client_id, session_id, service_name, inst_id, method
                          );
                      }*/
                }
            } else {
                // service but no known method/field
                res += &format!(
                    "({:04x}:{:04x}) {}({:04x}) SOME/IP unknown or unsupported method with id {} ({:x}) ",
                    client_id, session_id, service_name, inst_id, method_id, method_id
                );
            }
        } else {
            // no service?
            res += &format!(
                "({:04x}:{:04x}) unknown service with id {} and major {} ({:04x}).",
                client_id, session_id, service_id, major, inst_id
            );
        };
        // payload

        res += str_rc;

        Ok(res)
    }
}

/// decode the payload as an object in json format
fn decode_payload(
    fd: &FibexData,
    message_type: u8,
    method: &Method,
    payload_length_according_header: u32,
    payload: &[u8],
) -> Result<String, FibexError> {
    // todo change to writer instead of String for perfo
    //let mut res = String::with_capacity(1024); // todo better heuristics?
    let mut writer = Vec::with_capacity(2 * 1024); // todo better heuristics?

    let params = match message_type {
        0x80 | 0x23 => &method.return_params,
        _ => &method.input_params, // todo events/fields
    };

    if !params.is_empty() {
        // the params are already sorted by POSITION
        // parse until payload_length or payload is at the end
        // we want to output the json in the order of the params. so we cannot use an serde_json::Value::Object directly (as its a map)
        let mut parsed_bits = 0u32;
        let available_bits =
            std::cmp::min(payload_length_according_header, payload.len() as u32) * 8;
        // todo think about which one to use or which error handling... this might be similar to recorded len vs. orig len for pcaps
        let writer = &mut writer;
        let ctx = &mut SomeipDecodingCtx {
            fd,
            parsed_bits: &mut parsed_bits,
            available_bits,
            payload,
        };

        for (index, param) in params.iter().enumerate() {
            // write a string representation for that parameter like "short-name":value_as_json
            if index == 0 {
                writer
                    .write_fmt(format_args!("{{"))
                    .map_err(|e| FibexError { msg: e.to_string() })?;
            } else {
                writer
                    .write_fmt(format_args!(","))
                    .map_err(|e| FibexError { msg: e.to_string() })?;
            }
            if let Some(short_name) = &param.short_name {
                writer
                    .write_fmt(format_args!("\"{}\":", short_name))
                    .map_err(|e| FibexError { msg: e.to_string() })?;
            } else {
                writer
                    .write_fmt(format_args!("\"{}\":", param.position))
                    .map_err(|e| FibexError { msg: e.to_string() })?;
            };

            if *ctx.parsed_bits >= ctx.available_bits {
                writer
                    .write_fmt(format_args!("\"<adlt.err! no payload remaining>\""))
                    .map_err(|e| FibexError { msg: e.to_string() })?;
            } else {
                // now the real payload
                param
                    .to_writer(writer, ctx, None) // todo Utilization/serialization-attributes in Method
                    .map_err(|e| FibexError { msg: e.to_string() })?;
            }
        }
        writer
            .write_fmt(format_args!("}}"))
            .map_err(|e| FibexError { msg: e.to_string() })?;
    } else {
        writer
            .write_fmt(format_args!("{{}}"))
            .map_err(|e| FibexError { msg: e.to_string() })?;
    }
    let res = unsafe { String::from_utf8_unchecked(writer) }; // we do know its proper utf8 strings... (todo ensure for each encoding!)

    Ok(res)
}

impl Parameter {
    fn to_writer<W>(
        &self,
        writer: &mut W,
        ctx: &mut SomeipDecodingCtx,
        parent_utilization: Option<&Utilization>,
    ) -> std::io::Result<()>
    where
        W: std::io::Write,
    {
        // we need to merge the parameters from utilization
        // parent has preference but on a per flag level:
        let mut new_util = Utilization {
            coding_ref: None,
            bit_length: None,
            min_bit_length: None,
            max_bit_length: None,
            is_high_low_byte_order: None,
            serialization_attributes: None,
        };
        let utilization = if parent_utilization.and(self.utilization.as_ref()).is_some() {
            // need to merge
            let pu = parent_utilization.unwrap();
            let su = self.utilization.as_ref().unwrap();
            new_util.coding_ref = pu.coding_ref.as_ref().or(su.coding_ref.as_ref()).cloned();
            new_util.bit_length = pu.bit_length.or(su.bit_length);
            new_util.min_bit_length = pu.min_bit_length.or(su.min_bit_length);
            new_util.max_bit_length = pu.max_bit_length.or(su.max_bit_length);
            new_util.is_high_low_byte_order =
                pu.is_high_low_byte_order.or(su.is_high_low_byte_order);
            new_util.serialization_attributes = pu
                .serialization_attributes
                .as_ref()
                .or(su.serialization_attributes.as_ref())
                .cloned(); // todo or for members here as well?
            Some(&new_util)
        } else {
            parent_utilization.or(self.utilization.as_ref()) // we prefer the parent util
        };
        if *ctx.parsed_bits >= ctx.available_bits {
            Err(std::io::Error::new(
                ErrorKind::Other,
                "no more data to decode Parameter!",
            ))
        } else {
            // find the datatype:
            let datatype = ctx
                .fd
                .elements
                .datatypes_map_by_id
                .get(&self.datatype_ref)
                .ok_or_else(|| {
                    std::io::Error::new(
                        ErrorKind::Other,
                        format!("datatype {} for {} not found!", self.datatype_ref, self.id),
                    )
                })?;

            if self.array_dimensions.is_empty() {
                // writer.write_fmt(format_args!("P='{}', util={:?}", self.id, utilization))?;
                datatype.to_writer(writer, ctx, utilization)?;
            } else {
                self.write_array_dim(writer, ctx, 0, datatype, utilization)
                    .unwrap_or_else(|e| {
                        writer
                            .write_fmt(format_args!("got err {}.", e))
                            .unwrap_or_default();
                    }); // todo?;
            }
            Ok(())
        }
    }

    fn write_array_dim<W>(
        &self,
        writer: &mut W,
        ctx: &mut SomeipDecodingCtx,
        dim: usize,
        datatype: &Datatype,
        utilization: Option<&Utilization>,
    ) -> std::io::Result<()>
    where
        W: std::io::Write,
    {
        if self.array_dimensions.len() <= dim {
            Err(std::io::Error::new(
                ErrorKind::Other,
                format!("dimension {} < len! for {}", dim, self.id),
            )) // todo check alignment here at byte border at least!
        } else {
            let static_nr_elems = self.array_dimensions[dim].minimum_size.and_then(|mini| {
                self.array_dimensions[dim].maximum_size.and_then(|maxi| {
                    if mini == maxi {
                        Some(mini)
                    } else {
                        None
                    }
                })
            });

            let length_field_size = utilization
                .and_then(|u| u.serialization_attributes.as_ref())
                .and_then(|s| s.array_length_field_size)
                .unwrap_or(32);

            writer.write_all(b"[")?;
            let array_len_bits: u64 = if static_nr_elems.is_none() {
                if ctx.remaining_bits() < length_field_size {
                    return Err(std::io::Error::new(
                        ErrorKind::Other,
                        format!("not enough bits available for {}", self.id),
                    ));
                }

                get_int_bits::<u64>(true, length_field_size, ctx) * 8 // todo endianess?
            } else {
                if length_field_size > 0 {
                    writer.write_fmt(format_args!(
                    "adlt.err! unsupported array with min_size = max_size but length_field_size={} for datatype {}",
                    length_field_size, datatype.id
                ))?;
                }
                // for static sized ones we set it to the max avail
                ctx.remaining_bits() as u64
            };
            let arr_end_bits = if array_len_bits > ctx.remaining_bits() as u64 {
                ctx.remaining_bits() // reduce silently here. could add an error text... (xx bits missing for encoding...)
            } else {
                array_len_bits as u32 + *(ctx.parsed_bits)
            };

            let mut elem_nr = 0u32;
            while *ctx.parsed_bits < arr_end_bits {
                if elem_nr > 0 {
                    writer.write_all(b",")?;
                    // todo if array.dim... (currently only 1dim arrays supported!)
                    // todo bit-padding...
                }

                let parsed_before = *ctx.parsed_bits;
                datatype.to_writer(writer, ctx, utilization)?; // todo or util from array?
                if parsed_before == *ctx.parsed_bits {
                    writer.write_fmt(format_args!(
                        "adlt.err! datatype {} didn't consume bits!",
                        datatype.id
                    ))?;
                    break;
                }
                elem_nr += 1;
                if let Some(static_nr_elems) = static_nr_elems {
                    // todo could use this to check for MAXIMUM-SIZE only as well.
                    if elem_nr >= static_nr_elems {
                        break;
                    }
                }
            }

            writer.write_all(b"]")?;
            Ok(())
        }
    }
}

impl Datatype {
    fn to_writer<W>(
        &self,
        writer: &mut W,
        ctx: &mut SomeipDecodingCtx,
        utilization: Option<&Utilization>,
    ) -> std::io::Result<()>
    where
        W: std::io::Write,
    {
        if *ctx.parsed_bits >= ctx.available_bits {
            Err(std::io::Error::new(
                ErrorKind::Other,
                "no more data to decode Datatype!",
            ))
        } else {
            match &self.datatype {
                DatatypeType::Common(coding_ref) => {
                    // todo weird. Some DATATYPEs have a UINT32 but then a utilization coding_ref as uint8 with mainly providing
                    // an SCALE-CONSTR VALIDITY... (which is again > 32bit value) -> generator bug.
                    // as workaround take here only the utilization coding if it has a BIT-LENGTH provided!

                    let coding = utilization
                        .and_then(|u| u.coding_ref.as_ref())
                        .and_then(|coding_ref| ctx.fd.pi.codings.get(coding_ref))
                        .and_then(|c| {
                            if let Some(coded_type) = &c.coded_type {
                                if coded_type.bit_length.is_some() {
                                    Some(c)
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        })
                        .or_else(|| ctx.fd.pi.codings.get(coding_ref));

                    let coding = coding.ok_or_else(|| {
                        std::io::Error::new(
                            ErrorKind::Other,
                            format!(
                                "coding {} for datatype {} for {} not found!",
                                coding_ref, self.id, self.id
                            ),
                        )
                    })?;
                    coding.to_writer(writer, ctx, None, utilization)?;
                }
                DatatypeType::EnumType { coding_ref, enums } => {
                    let coding_ref = utilization
                        .and_then(|u| u.coding_ref.as_ref())
                        .unwrap_or(coding_ref);
                    let coding = ctx.fd.pi.codings.get(coding_ref).ok_or_else(|| {
                        std::io::Error::new(
                            ErrorKind::Other,
                            format!(
                                "coding {} for enum datatype {} for {} not found!",
                                coding_ref, self.id, self.id
                            ),
                        )
                    })?;
                    coding.to_writer(writer, ctx, Some(enums), utilization)?;
                }
                DatatypeType::ComplexType(cdt) => match &cdt.class {
                    ComplexDatatypeClass::Typedef => {
                        if cdt.members.len() == 1 {
                            cdt.members[0].to_writer(writer, ctx, utilization)?;
                        // todo add test
                        } else {
                            return Err(std::io::Error::new(
                                ErrorKind::Other,
                                format!(
                                    "complex typedef {} has {} member. Expected 1!",
                                    self.id,
                                    cdt.members.len()
                                ),
                            ));
                        }
                    }
                    ComplexDatatypeClass::Structure => {
                        writer.write_all(b"{")?;
                        for (index, member) in cdt.members.iter().enumerate() {
                            if index > 0 {
                                writer.write_all(b",")?;
                            }
                            if let Some(short_name) = &member.short_name {
                                writer.write_fmt(format_args!("\"{}\":", short_name))?;
                            } else {
                                writer.write_fmt(format_args!("{}:", index))?;
                            }
                            member.to_writer(writer, ctx, utilization)?;
                        }
                        writer.write_all(b"}")?;
                    }
                    ComplexDatatypeClass::Union => {
                        // todo type/length sizes!
                        if ctx.remaining_bits() >= 8 * 8 {
                            let length: u32 = get_int_bits(true, u32::BITS, ctx); // see PRS_SOMEIP_00126: size of data and padding in bytes. does not include the length and type field
                            let union_type: u32 = get_int_bits(true, u32::BITS, ctx);

                            let union_start_bits = *ctx.parsed_bits;
                            // union-type seems 1-based index to members:
                            if union_type > 0 && union_type <= cdt.members.len() as u32 {
                                let member = &cdt.members[(union_type - 1) as usize];
                                if let Some(short_name) = &member.short_name {
                                    writer.write_fmt(format_args!("{{\"{}\":", short_name))?;
                                } else {
                                    writer.write_fmt(format_args!("{{{}:", union_type))?;
                                }
                                member.to_writer(writer, ctx, utilization)?; // todo restrict payload size here as we do know the length
                                writer.write_all(b"}")?;
                            } else {
                                writer.write_fmt(format_args!(
                                    "adlt.someip.err Union {} with len {} and unknown type {}",
                                    self.id, length, union_type,
                                ))?;
                            }

                            let union_end_bits = *ctx.parsed_bits;
                            let length_bits = length * 8;
                            let expected_end_bits = union_start_bits + length_bits;
                            match union_end_bits.cmp(&expected_end_bits) {
                                std::cmp::Ordering::Less => {
                                    // normal case, might be less, pad
                                    *ctx.parsed_bits = expected_end_bits;
                                }
                                std::cmp::Ordering::Greater => {
                                    writer.write_fmt(format_args!(
                                        "adlt.someip.err Union {} with len {} and type {} parsed too many bits +{}",
                                        self.id, length, union_type, union_end_bits-expected_end_bits
                                    ))?;
                                    *ctx.parsed_bits = expected_end_bits;
                                }
                                _ => {}
                            };
                        } else {
                            writer.write_fmt(format_args!(
                                "not enough bits available for {}",
                                self.id
                            ))?;
                        }
                    }
                },
            };

            Ok(())
        }
    }
}

impl Coding {
    fn to_writer<W>(
        &self,
        writer: &mut W,
        ctx: &mut SomeipDecodingCtx,
        enums: Option<&Vec<Enum>>,
        utilization: Option<&Utilization>,
    ) -> std::io::Result<()>
    where
        W: std::io::Write,
    {
        if *ctx.parsed_bits >= ctx.available_bits {
            return Err(std::io::Error::new(
                ErrorKind::Other,
                "no more data to decode Coding!",
            ));
        } else if let Some(coded_type) = &self.coded_type {
            let bit_length = utilization
                .and_then(|u| u.bit_length)
                .or(coded_type.bit_length);

            let big_endian = utilization
                .and_then(|u| u.is_high_low_byte_order)
                .unwrap_or(true); // default to big endian

            if let Some(base_data_type) = &coded_type.base_data_type {
                match &base_data_type {
                    BaseDataType::AUint8 => {
                        write_int_val::<u8, W>(writer, big_endian, &bit_length, ctx, enums)?
                    }
                    BaseDataType::AUint16 => {
                        write_int_val::<u16, W>(writer, big_endian, &bit_length, ctx, enums)?
                    }
                    BaseDataType::AUint32 => {
                        write_int_val::<u32, W>(writer, big_endian, &bit_length, ctx, enums)?
                    }
                    BaseDataType::AUint64 => {
                        write_int_val::<u64, W>(writer, big_endian, &bit_length, ctx, enums)?
                    }
                    BaseDataType::AInt8 => {
                        write_int_val::<i8, W>(writer, big_endian, &bit_length, ctx, enums)?
                    }
                    BaseDataType::AInt16 => {
                        write_int_val::<i16, W>(writer, big_endian, &bit_length, ctx, enums)?
                    }
                    BaseDataType::AInt32 => {
                        write_int_val::<i32, W>(writer, big_endian, &bit_length, ctx, enums)?
                    }
                    BaseDataType::AInt64 => {
                        write_int_val::<i64, W>(writer, big_endian, &bit_length, ctx, enums)?
                    }
                    BaseDataType::AFloat64 => {
                        // todo check that we're on a byte boundary?
                        // check that bit_length is f64 bitlength?
                        let val_u64: u64 =
                            get_int_bits(big_endian, bit_length.unwrap_or(u64::BITS), ctx);
                        let val = f64::from_bits(val_u64);
                        writer.write_fmt(format_args!("{}", val))?
                    }
                    BaseDataType::AFloat32 => {
                        // todo check that we're on a byte boundary?
                        // check that bit_length is f64 bitlength?
                        let val_u32: u32 =
                            get_int_bits(big_endian, bit_length.unwrap_or(u32::BITS), ctx);
                        let val = f32::from_bits(val_u32);
                        writer.write_fmt(format_args!("{}", val))?
                    }
                    BaseDataType::AUnicode2String => {
                        // todo fail if not on byte boundary!
                        // todo util.length-field-size!

                        let mut term_len = 1usize;
                        match coded_type.category {
                            Category::LeadingLengthInfoType | Category::StandardLengthType => {
                                // ENCODING UTF-8 or UCS-2
                                let encoder = match coded_type.encoding {
                                    Some(Encoding::Utf8) => encoding_rs::UTF_8,
                                    Some(Encoding::Ucs2) => {
                                        term_len = 2; // two byte zero term (each char is fixed two bytes)
                                        encoding_rs::UTF_16BE
                                    }
                                    Some(Encoding::Iso8859_1) => encoding_rs::ISO_8859_15, // todo???
                                    Some(Encoding::Iso8859_2) => encoding_rs::ISO_8859_2,
                                    _ => {
                                        writer.write_fmt(format_args!("adlt.someip unexpected encoding {:?} for AUnicode2String!", coded_type.encoding))?;
                                        encoding_rs::UTF_8
                                    }
                                };
                                // TERMINATION ZERO todo!
                                match coded_type.termination {
                                    Some(HoTermination::Zero) => {} // expected, we dont search for it but remove the last byte
                                    _ => {
                                        writer.write_fmt(format_args!("adlt.someip unexpected termination {:?} for AUnicode2String!", coded_type.termination))?;
                                    }
                                };
                                let len_bytes = match coded_type.category {
                                    Category::LeadingLengthInfoType => {
                                        let length_field_size = 32; // todo!
                                        if ctx.remaining_bits() < length_field_size {
                                            return Err(std::io::Error::new(
                                                ErrorKind::Other,
                                                format!(
                                                    "not enough bits available for {}",
                                                    self.id
                                                ),
                                            ));
                                        }
                                        let len_bytes: usize =
                                            get_int_bits(true, length_field_size, ctx);
                                        // todo endianess?
                                        len_bytes
                                    }
                                    Category::StandardLengthType => {
                                        (bit_length.unwrap_or_default() / 8) as usize
                                    } // better default???
                                    _ => 0,
                                };

                                let len_bytes_wo_term = if len_bytes >= term_len {
                                    len_bytes - term_len
                                } else {
                                    len_bytes
                                }; // remove term zero todo only if...

                                if ctx.remaining_bits() >= 8 {
                                    let payload_start_idx = ((*ctx.parsed_bits) >> 3) as usize;
                                    let payload_end_idx = payload_start_idx + len_bytes_wo_term;
                                    let payload_end_idx = if payload_end_idx > ctx.payload.len() {
                                        ctx.payload.len()
                                    } else {
                                        payload_end_idx
                                    };
                                    //let s = String::from_utf8_lossy(&ctx.payload[payload_start_idx..payload_end_idx]);
                                    //writer.write_fmt(format_args!("\"{}\"", s))?;
                                    let (cow, _had_malformed) = encoder.decode_with_bom_removal(
                                        &ctx.payload[payload_start_idx..payload_end_idx],
                                    );
                                    writer.write_fmt(format_args!("\"{}\"", cow))?;
                                }
                                *ctx.parsed_bits += len_bytes as u32 * 8;
                            }
                            _ => {
                                writer.write_fmt(format_args!(
                                    "adlt.someip.nyi! Coding Category {:?}: {:?}",
                                    coded_type.category, base_data_type
                                ))?;
                                return Err(std::io::Error::new(
                                    ErrorKind::Other,
                                    format!("nyi {:?} on decode Coding {:?}!", coded_type, self),
                                ));
                            }
                        }
                    }
                    _ => {
                        // todo other types!
                        writer.write_fmt(format_args!(
                            "adlt.someip.nyi! Coding base_data_type: {:?}",
                            base_data_type
                        ))?;
                        return Err(std::io::Error::new(
                            ErrorKind::Other,
                            format!("nyi {:?} on decode Coding {:?}!", coded_type, self),
                        ));
                    }
                }
                return Ok(());
            }
        };
        Err(std::io::Error::new(
            ErrorKind::Other,
            format!(
                "no coded-type/base-data-type to decode Coding '{:?}'",
                self.short_name
            ),
        ))
    }
}

fn write_int_val<I: funty::Integral, W: std::io::Write>(
    writer: &mut W,
    big_endian: bool,
    bit_length: &Option<u32>,
    ctx: &mut SomeipDecodingCtx,
    enums: Option<&Vec<Enum>>,
) -> std::io::Result<()> {
    let bit_length = bit_length.unwrap_or(I::BITS);
    let val: I = get_int_bits(big_endian, bit_length, ctx);
    if let Some(enums) = enums {
        // todo change to hashmap. for now iterate:
        let a_enum = enums.iter().find(|e| {
            if e.value < 0 && I::ZERO == I::MIN {
                // todo add test case and doc
                // I is unsigned type but enum value is neg...
                e.value == -(val.as_i128()) // todo workaround for some fibex generators generating enums always as unsigned types
            } else {
                e.value == val.as_i128()
            }
        });
        if let Some(a_enum) = a_enum {
            if let Some(synonym) = &a_enum.synonym {
                writer.write_fmt(format_args!("\"{}\"", synonym))
            } else {
                writer.write_fmt(format_args!("<adlt.someip.no synonym!>{}", val))
                // or indicate missing synonym for known enum?
            }
        } else {
            writer.write_fmt(format_args!("{}", val)) // or indicate missing enum?
        }
    } else if I::BITS > u32::BITS {
        // for js/ts/node json compatibility we persist those big numbers as strings: // todo add test case and doc
        writer.write_fmt(format_args!(r#""{}n""#, val))
    } else {
        writer.write_fmt(format_args!("{}", val))
    }
}

fn get_int_bits<I>(big_endian: bool, bit_length: u32, ctx: &mut SomeipDecodingCtx) -> I
where
    I: funty::Integral,
{
    let bitslice: &BitSlice<u8, Lsb0> = bitvec::prelude::BitSlice::from_slice(ctx.payload);
    let slice_start = *ctx.parsed_bits as usize;
    let slice_end = std::cmp::min(*ctx.parsed_bits + bit_length, ctx.available_bits) as usize;
    *ctx.parsed_bits += bit_length; // we increase in any case (as the caller will abort on next param)
    if slice_end <= slice_start {
        I::ZERO
    } else {
        let val: I = if big_endian {
            bitslice[slice_start..slice_end].load_be()
        } else {
            bitslice[slice_start..slice_end].load_le()
        };
        val
    }
}

struct SomeipDecodingCtx<'a, 'b> {
    fd: &'b FibexData,
    parsed_bits: &'a mut u32,
    available_bits: u32,
    payload: &'a [u8],
}

impl<'a, 'b> SomeipDecodingCtx<'a, 'b> {
    fn remaining_bits(&self) -> u32 {
        if *self.parsed_bits < self.available_bits {
            self.available_bits - *self.parsed_bits
        } else {
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn too_short_header() {
        let fd = FibexData::new();

        let r = decode_someip_header_and_payload(
            &fd,
            1234,
            &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            &[],
        );
        assert!(r.is_err());
    }
    #[test]
    fn basic_header1() {
        let mut fd = FibexData::new();
        let path = Path::new("tests/fibex1.xml");
        assert!(path.exists());
        assert!(fd.load_fibex_file(path).is_ok());

        let r = decode_someip_header_and_payload(
            &fd,
            0x4d2,
            &[
                0xfa, 0x62, 0x3, 0xe8, 0, 0, 0, 9, 0xf3, 0x34, 0x45, 0x56, 0, 1, 0, 4,
            ],
            &[42],
        );
        assert!(r.is_ok(), "{:?}", r);
        let r = r.unwrap();
        assert_eq!(
            r,
            r#"> (f334:4556) TestService1API(04d2).submitPar1{"Param1":42}[NOT READY]"#
        );
        // return code should be set to 0 for a request (PRS_SOMEIP_00058) but for testing we use a different value here

        // invalid rc
        let r = decode_someip_header_and_payload(
            &fd,
            12,
            &[0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 15, 2, 42],
            &[],
        );
        assert!(r.is_ok(), "{:?}", r);
        let r = r.unwrap();
        assert_eq!(
            r,
            "* (0000:0000) unknown service with id 0 and major 15 (000c).UNKNOWN RC!"
        );
    }
}
