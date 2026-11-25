//! Core OPC UA built-in types (Part 6, §5.1).

use std::fmt;
use std::hash::{BuildHasherDefault, Hasher};

/// OPC UA NodeId. Numeric ids are by far the most common, so they are kept
/// inline (8 bytes payload, no heap) and hashed with a couple of instructions.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum NodeId {
    Numeric(u16, u32),
    String(u16, Box<str>),
    Guid(u16, [u8; 16]),
    Opaque(u16, Box<[u8]>),
}

impl std::hash::Hash for NodeId {
    /// A numeric id is hashed as one 64-bit word (a single multiply with
    /// `FxHasher`) instead of discriminant + namespace + value.
    #[inline(always)]
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            NodeId::Numeric(ns, v) => state.write_u64((*ns as u64) << 32 | *v as u64),
            NodeId::String(ns, s) => {
                state.write_u64(1 << 48 | *ns as u64);
                state.write(s.as_bytes());
            }
            NodeId::Guid(ns, g) => {
                state.write_u64(2 << 48 | *ns as u64);
                state.write(g);
            }
            NodeId::Opaque(ns, b) => {
                state.write_u64(3 << 48 | *ns as u64);
                state.write(b);
            }
        }
    }
}

impl NodeId {
    pub const NULL: NodeId = NodeId::Numeric(0, 0);

    #[inline(always)]
    pub const fn ns0(id: u32) -> NodeId {
        NodeId::Numeric(0, id)
    }

    #[inline(always)]
    pub fn namespace(&self) -> u16 {
        match self {
            NodeId::Numeric(ns, _) | NodeId::String(ns, _) | NodeId::Guid(ns, _) | NodeId::Opaque(ns, _) => *ns,
        }
    }

    pub fn with_namespace(self, ns: u16) -> NodeId {
        match self {
            NodeId::Numeric(_, v) => NodeId::Numeric(ns, v),
            NodeId::String(_, v) => NodeId::String(ns, v),
            NodeId::Guid(_, v) => NodeId::Guid(ns, v),
            NodeId::Opaque(_, v) => NodeId::Opaque(ns, v),
        }
    }

    #[inline(always)]
    pub fn is_null(&self) -> bool {
        match self {
            NodeId::Numeric(0, 0) => true,
            NodeId::String(0, s) => s.is_empty(),
            NodeId::Guid(0, g) => g == &[0u8; 16],
            NodeId::Opaque(0, b) => b.is_empty(),
            _ => false,
        }
    }

    /// Returns the numeric id when this is a namespace 0 numeric node.
    #[inline(always)]
    pub fn as_ns0(&self) -> Option<u32> {
        match self {
            NodeId::Numeric(0, v) => Some(*v),
            _ => None,
        }
    }

    /// Parses the standard string form: `ns=2;i=42`, `s=Foo`, `g=...`, `b=...`.
    /// The namespace part is optional (defaults to 0).
    pub fn parse(text: &str) -> Result<NodeId, String> {
        let text = text.trim();
        let (ns, rest) = match text.strip_prefix("ns=") {
            Some(r) => {
                let (n, rest) = r.split_once(';').ok_or_else(|| format!("invalid NodeId '{text}': missing ';'"))?;
                let n: u16 = n.parse().map_err(|_| format!("invalid NodeId '{text}': bad namespace"))?;
                (n, rest)
            }
            None => (0, text),
        };
        let (kind, value) =
            rest.split_once('=').ok_or_else(|| format!("invalid NodeId '{text}': missing identifier type"))?;
        match kind {
            "i" => value
                .parse::<u32>()
                .map(|v| NodeId::Numeric(ns, v))
                .map_err(|_| format!("invalid NodeId '{text}': bad numeric identifier")),
            "s" => {
                if value.is_empty() {
                    return Err(format!("invalid NodeId '{text}': empty string identifier"));
                }
                Ok(NodeId::String(ns, value.into()))
            }
            "g" => parse_guid(value)
                .map(|g| NodeId::Guid(ns, g))
                .ok_or_else(|| format!("invalid NodeId '{text}': bad GUID")),
            "b" => decode_base64(value)
                .map(|b| NodeId::Opaque(ns, b.into_boxed_slice()))
                .ok_or_else(|| format!("invalid NodeId '{text}': bad base64")),
            _ => Err(format!("invalid NodeId '{text}': unknown identifier type '{kind}'")),
        }
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ns = self.namespace();
        if ns != 0 {
            write!(f, "ns={ns};")?;
        }
        match self {
            NodeId::Numeric(_, v) => write!(f, "i={v}"),
            NodeId::String(_, v) => write!(f, "s={v}"),
            NodeId::Guid(_, g) => write!(f, "g={}", format_guid(g)),
            NodeId::Opaque(_, b) => write!(f, "b={}", b.len()),
        }
    }
}

/// GUIDs are encoded in binary as Data1 (LE u32), Data2 (LE u16), Data3 (LE u16), Data4 (8 bytes).
/// We store them directly in that wire layout.
fn parse_guid(text: &str) -> Option<[u8; 16]> {
    let hex: Vec<u8> = text.bytes().filter(|b| *b != b'-').collect();
    if hex.len() != 32 || text.len() != 36 {
        return None;
    }
    let mut raw = [0u8; 16];
    for (i, chunk) in hex.chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk).ok()?;
        raw[i] = u8::from_str_radix(s, 16).ok()?;
    }
    // Textual form is big-endian for the first three groups.
    let mut out = raw;
    out[0..4].copy_from_slice(&[raw[3], raw[2], raw[1], raw[0]]);
    out[4..6].copy_from_slice(&[raw[5], raw[4]]);
    out[6..8].copy_from_slice(&[raw[7], raw[6]]);
    Some(out)
}

fn format_guid(g: &[u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        g[3], g[2], g[1], g[0], g[5], g[4], g[7], g[6], g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15]
    )
}

pub fn decode_base64(text: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => (c - b'A') as u32,
            b'a'..=b'z' => (c - b'a' + 26) as u32,
            b'0'..=b'9' => (c - b'0' + 52) as u32,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        })
    }
    let bytes: Vec<u8> = text.bytes().filter(|b| *b != b'=').collect();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let mut acc = 0u32;
        for (i, c) in chunk.iter().enumerate() {
            acc |= val(*c)? << (18 - 6 * i);
        }
        let n = chunk.len();
        if n < 2 {
            return None;
        }
        out.push((acc >> 16) as u8);
        if n > 2 {
            out.push((acc >> 8) as u8);
        }
        if n > 3 {
            out.push(acc as u8);
        }
    }
    Some(out)
}

/// FxHash: tiny, very fast non-cryptographic hasher (as used inside rustc).
/// Lookups are done on server-owned keys, never on attacker-chosen sets large
/// enough to matter, and the table is rebuilt on every reload.
#[derive(Default, Clone, Copy)]
pub struct FxHasher {
    hash: u64,
}

const FX_SEED: u64 = 0x51_7c_c1_b7_27_22_0a_95;

impl FxHasher {
    #[inline(always)]
    fn add(&mut self, word: u64) {
        self.hash = (self.hash.rotate_left(5) ^ word).wrapping_mul(FX_SEED);
    }
}

impl Hasher for FxHasher {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        let mut chunks = bytes.chunks_exact(8);
        for c in &mut chunks {
            self.add(u64::from_le_bytes(c.try_into().unwrap()));
        }
        let rem = chunks.remainder();
        if !rem.is_empty() {
            let mut buf = [0u8; 8];
            buf[..rem.len()].copy_from_slice(rem);
            self.add(u64::from_le_bytes(buf));
        }
    }
    #[inline(always)]
    fn write_u8(&mut self, i: u8) {
        self.add(i as u64)
    }
    #[inline(always)]
    fn write_u16(&mut self, i: u16) {
        self.add(i as u64)
    }
    #[inline(always)]
    fn write_u32(&mut self, i: u32) {
        self.add(i as u64)
    }
    #[inline(always)]
    fn write_u64(&mut self, i: u64) {
        self.add(i)
    }
    #[inline(always)]
    fn write_usize(&mut self, i: usize) {
        self.add(i as u64)
    }
    #[inline(always)]
    fn finish(&self) -> u64 {
        self.hash
    }
}

pub type FxBuild = BuildHasherDefault<FxHasher>;
pub type FxHashMap<K, V> = std::collections::HashMap<K, V, FxBuild>;

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct QualifiedName {
    pub ns: u16,
    pub name: Box<str>,
}

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct LocalizedText {
    pub locale: Option<Box<str>>,
    pub text: Option<Box<str>>,
}

impl LocalizedText {
    pub fn new(text: &str) -> Self {
        LocalizedText { locale: None, text: Some(text.into()) }
    }
}

/// Opaque, already-encoded extension object body.
#[derive(Clone, PartialEq, Debug)]
pub struct ExtensionObject {
    pub type_id: NodeId,
    /// 0 = no body, 1 = binary body, 2 = XML body.
    pub encoding: u8,
    pub body: Box<[u8]>,
}

/// OPC UA built-in type ids (Part 6, §5.1.2).
pub mod builtin {
    pub const BOOLEAN: u8 = 1;
    pub const SBYTE: u8 = 2;
    pub const BYTE: u8 = 3;
    pub const INT16: u8 = 4;
    pub const UINT16: u8 = 5;
    pub const INT32: u8 = 6;
    pub const UINT32: u8 = 7;
    pub const INT64: u8 = 8;
    pub const UINT64: u8 = 9;
    pub const FLOAT: u8 = 10;
    pub const DOUBLE: u8 = 11;
    pub const STRING: u8 = 12;
    pub const DATETIME: u8 = 13;
    pub const GUID: u8 = 14;
    pub const BYTESTRING: u8 = 15;
    pub const XMLELEMENT: u8 = 16;
    pub const NODEID: u8 = 17;
    pub const EXPANDEDNODEID: u8 = 18;
    pub const STATUSCODE: u8 = 19;
    pub const QUALIFIEDNAME: u8 = 20;
    pub const LOCALIZEDTEXT: u8 = 21;
    pub const EXTENSIONOBJECT: u8 = 22;
    pub const DATAVALUE: u8 = 23;
    pub const VARIANT: u8 = 24;
    pub const DIAGNOSTICINFO: u8 = 25;
}

#[derive(Clone, PartialEq, Debug, Default)]
pub enum Variant {
    #[default]
    Empty,
    Boolean(bool),
    SByte(i8),
    Byte(u8),
    Int16(i16),
    UInt16(u16),
    Int32(i32),
    UInt32(u32),
    Int64(i64),
    UInt64(u64),
    Float(f32),
    Double(f64),
    String(Option<Box<str>>),
    DateTime(i64),
    Guid([u8; 16]),
    ByteString(Option<Box<[u8]>>),
    XmlElement(Option<Box<str>>),
    NodeId(Box<NodeId>),
    ExpandedNodeId(Box<ExpandedNodeId>),
    StatusCode(u32),
    QualifiedName(Box<QualifiedName>),
    LocalizedText(Box<LocalizedText>),
    ExtensionObject(Box<ExtensionObject>),
    Array(Box<VariantArray>),
}

#[derive(Clone, PartialEq, Debug)]
pub struct VariantArray {
    pub type_id: u8,
    pub items: Vec<Variant>,
    pub dims: Option<Vec<i32>>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ExpandedNodeId {
    pub node_id: NodeId,
    pub namespace_uri: Option<Box<str>>,
    pub server_index: u32,
}

impl Variant {
    /// Built-in type id of this value (for arrays: of its elements).
    pub fn type_id(&self) -> u8 {
        use builtin::*;
        match self {
            Variant::Empty => 0,
            Variant::Boolean(_) => BOOLEAN,
            Variant::SByte(_) => SBYTE,
            Variant::Byte(_) => BYTE,
            Variant::Int16(_) => INT16,
            Variant::UInt16(_) => UINT16,
            Variant::Int32(_) => INT32,
            Variant::UInt32(_) => UINT32,
            Variant::Int64(_) => INT64,
            Variant::UInt64(_) => UINT64,
            Variant::Float(_) => FLOAT,
            Variant::Double(_) => DOUBLE,
            Variant::String(_) => STRING,
            Variant::DateTime(_) => DATETIME,
            Variant::Guid(_) => GUID,
            Variant::ByteString(_) => BYTESTRING,
            Variant::XmlElement(_) => XMLELEMENT,
            Variant::NodeId(_) => NODEID,
            Variant::ExpandedNodeId(_) => EXPANDEDNODEID,
            Variant::StatusCode(_) => STATUSCODE,
            Variant::QualifiedName(_) => QUALIFIEDNAME,
            Variant::LocalizedText(_) => LOCALIZEDTEXT,
            Variant::ExtensionObject(_) => EXTENSIONOBJECT,
            Variant::Array(a) => a.type_id,
        }
    }

    pub fn string(s: &str) -> Variant {
        Variant::String(Some(s.into()))
    }

    pub fn string_array(items: &[&str]) -> Variant {
        Variant::Array(Box::new(VariantArray {
            type_id: builtin::STRING,
            items: items.iter().map(|s| Variant::string(s)).collect(),
            dims: None,
        }))
    }
}

#[derive(Clone, PartialEq, Debug, Default)]
pub struct DataValue {
    pub value: Option<Variant>,
    pub status: Option<u32>,
    pub source_timestamp: Option<i64>,
    pub source_picoseconds: Option<u16>,
    pub server_timestamp: Option<i64>,
    pub server_picoseconds: Option<u16>,
}

impl DataValue {
    pub fn value(v: Variant) -> Self {
        DataValue { value: Some(v), ..Default::default() }
    }
    pub fn status(code: u32) -> Self {
        DataValue { status: Some(code), ..Default::default() }
    }
}

/// UTC "now" as OPC UA DateTime (100 ns ticks since 1601-01-01).
#[inline]
#[allow(clippy::unnecessary_cast)] // time_t / c_long are not i64 on every target
pub fn now_ticks() -> i64 {
    const EPOCH_DIFF_SECS: i64 = 11_644_473_600;
    let mut t = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: valid pointer; CLOCK_REALTIME always exists (vDSO, no syscall).
    unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut t) };
    (t.tv_sec as i64 + EPOCH_DIFF_SECS) * 10_000_000 + t.tv_nsec as i64 / 100
}

/// Like [`now_ticks`] from `CLOCK_REALTIME_COARSE`: the time of the last
/// kernel tick (1-4 ms resolution), read without the hardware counter. Used
/// where the resolution is enough (ResponseHeader timestamps): ~4x cheaper on
/// aarch64, ~6x on x86_64.
#[inline]
#[allow(clippy::unnecessary_cast)] // time_t / c_long are not i64 on every target
pub fn coarse_now_ticks() -> i64 {
    const EPOCH_DIFF_SECS: i64 = 11_644_473_600;
    let mut t = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: valid pointer; CLOCK_REALTIME_COARSE exists on every Linux.
    unsafe { libc::clock_gettime(libc::CLOCK_REALTIME_COARSE, &mut t) };
    (t.tv_sec as i64 + EPOCH_DIFF_SECS) * 10_000_000 + t.tv_nsec as i64 / 100
}

/// Well-known namespace 0 node ids (subset used by the server).
pub mod ids {
    // Data types
    pub const BASE_DATA_TYPE: u32 = 24;
    pub const STRUCTURE: u32 = 22;
    pub const NUMBER: u32 = 26;
    pub const INTEGER: u32 = 27;
    pub const UINTEGER: u32 = 28;
    pub const ENUMERATION: u32 = 29;
    pub const SERVER_STATE: u32 = 852;
    pub const SERVER_STATUS_DATA_TYPE: u32 = 862;
    pub const BUILD_INFO: u32 = 338;
    pub const UTC_TIME: u32 = 294;

    // Reference types
    pub const REFERENCES: u32 = 31;
    pub const NON_HIERARCHICAL_REFERENCES: u32 = 32;
    pub const HIERARCHICAL_REFERENCES: u32 = 33;
    pub const HAS_CHILD: u32 = 34;
    pub const ORGANIZES: u32 = 35;
    pub const HAS_EVENT_SOURCE: u32 = 36;
    pub const HAS_MODELLING_RULE: u32 = 37;
    pub const HAS_ENCODING: u32 = 38;
    pub const HAS_DESCRIPTION: u32 = 39;
    pub const HAS_TYPE_DEFINITION: u32 = 40;
    pub const GENERATES_EVENT: u32 = 41;
    pub const AGGREGATES: u32 = 44;
    pub const HAS_SUBTYPE: u32 = 45;
    pub const HAS_PROPERTY: u32 = 46;
    pub const HAS_COMPONENT: u32 = 47;
    pub const HAS_NOTIFIER: u32 = 48;
    pub const HAS_ORDERED_COMPONENT: u32 = 49;

    // Object / variable types
    pub const BASE_OBJECT_TYPE: u32 = 58;
    pub const FOLDER_TYPE: u32 = 61;
    pub const BASE_VARIABLE_TYPE: u32 = 62;
    pub const BASE_DATA_VARIABLE_TYPE: u32 = 63;
    pub const PROPERTY_TYPE: u32 = 68;
    pub const SERVER_TYPE: u32 = 2004;
    pub const SERVER_STATUS_TYPE: u32 = 2138;

    // Folders
    pub const ROOT_FOLDER: u32 = 84;
    pub const OBJECTS_FOLDER: u32 = 85;
    pub const TYPES_FOLDER: u32 = 86;
    pub const VIEWS_FOLDER: u32 = 87;
    pub const OBJECT_TYPES_FOLDER: u32 = 88;
    pub const VARIABLE_TYPES_FOLDER: u32 = 89;
    pub const DATA_TYPES_FOLDER: u32 = 90;
    pub const REFERENCE_TYPES_FOLDER: u32 = 91;

    // Server object
    pub const SERVER: u32 = 2253;
    pub const SERVER_SERVER_ARRAY: u32 = 2254;
    pub const SERVER_NAMESPACE_ARRAY: u32 = 2255;
    pub const SERVER_SERVER_STATUS: u32 = 2256;
    pub const SERVER_SERVER_STATUS_START_TIME: u32 = 2257;
    pub const SERVER_SERVER_STATUS_CURRENT_TIME: u32 = 2258;
    pub const SERVER_SERVER_STATUS_STATE: u32 = 2259;
    pub const SERVER_SERVER_STATUS_BUILD_INFO: u32 = 2260;
    pub const SERVER_SERVICE_LEVEL: u32 = 2267;

    // Binary encodings of structures
    pub const SERVER_STATUS_DATA_TYPE_ENCODING: u32 = 864;
    pub const BUILD_INFO_ENCODING: u32 = 340;
    pub const ANONYMOUS_IDENTITY_TOKEN_ENCODING: u32 = 321;
    pub const USERNAME_IDENTITY_TOKEN_ENCODING: u32 = 324;
    pub const X509_IDENTITY_TOKEN_ENCODING: u32 = 327;

    // Service requests / responses (binary encoding ids)
    pub const SERVICE_FAULT: u32 = 397;
    pub const FIND_SERVERS_REQUEST: u32 = 422;
    pub const FIND_SERVERS_RESPONSE: u32 = 425;
    pub const GET_ENDPOINTS_REQUEST: u32 = 428;
    pub const GET_ENDPOINTS_RESPONSE: u32 = 431;
    pub const OPEN_SECURE_CHANNEL_REQUEST: u32 = 446;
    pub const OPEN_SECURE_CHANNEL_RESPONSE: u32 = 449;
    pub const CLOSE_SECURE_CHANNEL_REQUEST: u32 = 452;
    pub const CREATE_SESSION_REQUEST: u32 = 461;
    pub const CREATE_SESSION_RESPONSE: u32 = 464;
    pub const ACTIVATE_SESSION_REQUEST: u32 = 467;
    pub const ACTIVATE_SESSION_RESPONSE: u32 = 470;
    pub const CLOSE_SESSION_REQUEST: u32 = 473;
    pub const CLOSE_SESSION_RESPONSE: u32 = 476;
    pub const BROWSE_REQUEST: u32 = 527;
    pub const BROWSE_RESPONSE: u32 = 530;
    pub const BROWSE_NEXT_REQUEST: u32 = 533;
    pub const BROWSE_NEXT_RESPONSE: u32 = 536;
    pub const TRANSLATE_BROWSE_PATHS_REQUEST: u32 = 554;
    pub const TRANSLATE_BROWSE_PATHS_RESPONSE: u32 = 557;
    pub const REGISTER_NODES_REQUEST: u32 = 560;
    pub const REGISTER_NODES_RESPONSE: u32 = 563;
    pub const UNREGISTER_NODES_REQUEST: u32 = 566;
    pub const UNREGISTER_NODES_RESPONSE: u32 = 569;
    pub const READ_REQUEST: u32 = 631;
    pub const READ_RESPONSE: u32 = 634;
    pub const WRITE_REQUEST: u32 = 673;
    pub const WRITE_RESPONSE: u32 = 676;
    pub const CREATE_MONITORED_ITEMS_REQUEST: u32 = 751;
    pub const CREATE_MONITORED_ITEMS_RESPONSE: u32 = 754;
    pub const MODIFY_MONITORED_ITEMS_REQUEST: u32 = 763;
    pub const MODIFY_MONITORED_ITEMS_RESPONSE: u32 = 766;
    pub const SET_MONITORING_MODE_REQUEST: u32 = 769;
    pub const SET_MONITORING_MODE_RESPONSE: u32 = 772;
    pub const SET_TRIGGERING_REQUEST: u32 = 775;
    pub const SET_TRIGGERING_RESPONSE: u32 = 778;
    pub const DELETE_MONITORED_ITEMS_REQUEST: u32 = 781;
    pub const DELETE_MONITORED_ITEMS_RESPONSE: u32 = 784;
    pub const CREATE_SUBSCRIPTION_REQUEST: u32 = 787;
    pub const CREATE_SUBSCRIPTION_RESPONSE: u32 = 790;
    pub const MODIFY_SUBSCRIPTION_REQUEST: u32 = 793;
    pub const MODIFY_SUBSCRIPTION_RESPONSE: u32 = 796;
    pub const SET_PUBLISHING_MODE_REQUEST: u32 = 799;
    pub const SET_PUBLISHING_MODE_RESPONSE: u32 = 802;
    pub const PUBLISH_REQUEST: u32 = 826;
    pub const PUBLISH_RESPONSE: u32 = 829;
    pub const REPUBLISH_REQUEST: u32 = 832;
    pub const REPUBLISH_RESPONSE: u32 = 835;
    pub const TRANSFER_SUBSCRIPTIONS_REQUEST: u32 = 841;
    pub const TRANSFER_SUBSCRIPTIONS_RESPONSE: u32 = 844;
    pub const DELETE_SUBSCRIPTIONS_REQUEST: u32 = 847;
    pub const DELETE_SUBSCRIPTIONS_RESPONSE: u32 = 850;

    // Notifications and filters (binary encodings)
    pub const DATA_CHANGE_FILTER_ENCODING: u32 = 724;
    pub const EVENT_FILTER_ENCODING: u32 = 727;
    pub const AGGREGATE_FILTER_ENCODING: u32 = 730;
    pub const DATA_CHANGE_NOTIFICATION_ENCODING: u32 = 811;
    pub const STATUS_CHANGE_NOTIFICATION_ENCODING: u32 = 820;
}

/// Status codes (Part 4, §7.39 and Part 6 annex).
pub mod status {
    pub const GOOD: u32 = 0;
    pub const UNCERTAIN_INITIAL_VALUE: u32 = 0x4092_0000;
    pub const BAD_UNEXPECTED_ERROR: u32 = 0x8001_0000;
    pub const BAD_INTERNAL_ERROR: u32 = 0x8002_0000;
    pub const BAD_ENCODING_ERROR: u32 = 0x8006_0000;
    pub const BAD_DECODING_ERROR: u32 = 0x8007_0000;
    pub const BAD_ENCODING_LIMITS_EXCEEDED: u32 = 0x8008_0000;
    pub const BAD_TIMEOUT: u32 = 0x800A_0000;
    pub const BAD_SERVICE_UNSUPPORTED: u32 = 0x800B_0000;
    pub const BAD_NOTHING_TO_DO: u32 = 0x800F_0000;
    pub const BAD_TOO_MANY_OPERATIONS: u32 = 0x8010_0000;
    pub const BAD_SECURITY_CHECKS_FAILED: u32 = 0x8013_0000;
    pub const BAD_USER_ACCESS_DENIED: u32 = 0x801F_0000;
    pub const BAD_IDENTITY_TOKEN_INVALID: u32 = 0x8020_0000;
    pub const BAD_IDENTITY_TOKEN_REJECTED: u32 = 0x8021_0000;
    pub const BAD_SECURE_CHANNEL_ID_INVALID: u32 = 0x8022_0000;
    pub const BAD_SESSION_ID_INVALID: u32 = 0x8025_0000;
    pub const BAD_SESSION_CLOSED: u32 = 0x8026_0000;
    pub const BAD_SESSION_NOT_ACTIVATED: u32 = 0x8027_0000;
    pub const BAD_REQUEST_HEADER_INVALID: u32 = 0x802A_0000;
    pub const BAD_TIMESTAMPS_TO_RETURN_INVALID: u32 = 0x802B_0000;
    pub const BAD_NODE_ID_INVALID: u32 = 0x8033_0000;
    pub const BAD_NODE_ID_UNKNOWN: u32 = 0x8034_0000;
    pub const BAD_ATTRIBUTE_ID_INVALID: u32 = 0x8035_0000;
    pub const BAD_INDEX_RANGE_INVALID: u32 = 0x8036_0000;
    pub const BAD_DATA_ENCODING_INVALID: u32 = 0x8038_0000;
    pub const BAD_DATA_ENCODING_UNSUPPORTED: u32 = 0x8039_0000;
    pub const BAD_NOT_READABLE: u32 = 0x803A_0000;
    pub const BAD_NOT_WRITABLE: u32 = 0x803B_0000;
    pub const BAD_CONTINUATION_POINT_INVALID: u32 = 0x804A_0000;
    pub const BAD_NO_CONTINUATION_POINTS: u32 = 0x804B_0000;
    pub const BAD_REFERENCE_TYPE_ID_INVALID: u32 = 0x804C_0000;
    pub const BAD_BROWSE_DIRECTION_INVALID: u32 = 0x804D_0000;
    pub const BAD_SECURITY_POLICY_REJECTED: u32 = 0x8055_0000;
    pub const BAD_TOO_MANY_SESSIONS: u32 = 0x8056_0000;
    pub const BAD_BROWSE_NAME_INVALID: u32 = 0x8060_0000;
    pub const BAD_VIEW_ID_UNKNOWN: u32 = 0x806B_0000;
    pub const BAD_NO_MATCH: u32 = 0x806F_0000;
    pub const BAD_MAX_AGE_INVALID: u32 = 0x8070_0000;
    pub const BAD_WRITE_NOT_SUPPORTED: u32 = 0x8073_0000;
    pub const BAD_TYPE_MISMATCH: u32 = 0x8074_0000;
    pub const BAD_TCP_MESSAGE_TYPE_INVALID: u32 = 0x807E_0000;
    pub const BAD_TCP_MESSAGE_TOO_LARGE: u32 = 0x8080_0000;
    pub const BAD_TCP_INTERNAL_ERROR: u32 = 0x8082_0000;
    pub const BAD_TCP_ENDPOINT_URL_INVALID: u32 = 0x8083_0000;
    pub const BAD_SEQUENCE_NUMBER_INVALID: u32 = 0x8088_0000;
    pub const BAD_REQUEST_TOO_LARGE: u32 = 0x80B8_0000;
    pub const BAD_RESPONSE_TOO_LARGE: u32 = 0x80B9_0000;
    pub const BAD_PROTOCOL_VERSION_UNSUPPORTED: u32 = 0x80BE_0000;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_node_ids() {
        assert_eq!(NodeId::parse("ns=5;i=1000").unwrap(), NodeId::Numeric(5, 1000));
        assert_eq!(NodeId::parse("i=85").unwrap(), NodeId::ns0(85));
        assert_eq!(NodeId::parse("ns=2;s=Pump.Speed").unwrap(), NodeId::String(2, "Pump.Speed".into()));
        let g = NodeId::parse("ns=1;g=09087e75-8e5e-499b-954f-f2a9603db28a").unwrap();
        assert_eq!(g.to_string(), "ns=1;g=09087e75-8e5e-499b-954f-f2a9603db28a");
        assert_eq!(NodeId::parse("b=AQID").unwrap(), NodeId::Opaque(0, vec![1, 2, 3].into()));
        assert!(NodeId::parse("ns=x;i=1").is_err());
        assert!(NodeId::parse("i=abc").is_err());
        assert!(NodeId::parse("q=1").is_err());
    }
}
