//! UA Binary encoding (Part 6, §5.2).
//!
//! Decoding is zero-copy where it matters: strings and byte strings are
//! returned as borrowed slices of the receive buffer. Every length is bounded
//! before anything is allocated, so a hostile peer cannot make the server
//! allocate more than the message it actually sent.

use crate::types::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeError;

impl From<DecodeError> for u32 {
    fn from(_: DecodeError) -> u32 {
        status::BAD_DECODING_ERROR
    }
}

pub type DResult<T> = Result<T, DecodeError>;

/// Nesting limit for variants / diagnostic infos (Part 6 recommends a limit).
const MAX_DEPTH: u32 = 32;

pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

macro_rules! read_le {
    ($name:ident, $t:ty) => {
        #[inline(always)]
        pub fn $name(&mut self) -> DResult<$t> {
            const N: usize = std::mem::size_of::<$t>();
            let b = self.take(N)?;
            Ok(<$t>::from_le_bytes(b.try_into().unwrap()))
        }
    };
}

impl<'a> Reader<'a> {
    #[inline(always)]
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    #[inline(always)]
    pub fn position(&self) -> usize {
        self.pos
    }

    #[inline(always)]
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    #[inline(always)]
    pub fn rest(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }

    #[inline(always)]
    pub fn take(&mut self, n: usize) -> DResult<&'a [u8]> {
        if n > self.remaining() {
            return Err(DecodeError);
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    read_le!(u16, u16);
    read_le!(i16, i16);
    read_le!(u32, u32);
    read_le!(i32, i32);
    read_le!(u64, u64);
    read_le!(i64, i64);
    read_le!(f32, f32);
    read_le!(f64, f64);

    #[inline(always)]
    pub fn u8(&mut self) -> DResult<u8> {
        if self.pos >= self.buf.len() {
            return Err(DecodeError);
        }
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }

    #[inline(always)]
    pub fn i8(&mut self) -> DResult<i8> {
        self.u8().map(|v| v as i8)
    }

    #[inline(always)]
    pub fn bool(&mut self) -> DResult<bool> {
        self.u8().map(|v| v != 0)
    }

    /// Array / string length prefix. -1 is null. Returns `None` for null.
    /// `min_elem_size` lets us reject lengths that cannot fit in the rest of
    /// the buffer before any allocation happens.
    #[inline(always)]
    pub fn length(&mut self, min_elem_size: usize) -> DResult<Option<usize>> {
        let n = self.i32()?;
        if n < 0 {
            return Ok(None);
        }
        let n = n as usize;
        if n.saturating_mul(min_elem_size.max(1)) > self.remaining() && min_elem_size > 0 {
            return Err(DecodeError);
        }
        Ok(Some(n))
    }

    #[inline]
    pub fn bytes(&mut self) -> DResult<Option<&'a [u8]>> {
        match self.length(1)? {
            None => Ok(None),
            Some(n) => self.take(n).map(Some),
        }
    }

    #[inline]
    pub fn str(&mut self) -> DResult<Option<&'a str>> {
        match self.bytes()? {
            None => Ok(None),
            Some(b) => std::str::from_utf8(b).map(Some).map_err(|_| DecodeError),
        }
    }

    pub fn string_owned(&mut self) -> DResult<Option<Box<str>>> {
        Ok(self.str()?.map(Into::into))
    }

    pub fn guid(&mut self) -> DResult<[u8; 16]> {
        Ok(self.take(16)?.try_into().unwrap())
    }

    pub fn node_id(&mut self) -> DResult<NodeId> {
        let enc = self.u8()?;
        self.node_id_body(enc & 0x3F)
    }

    fn node_id_body(&mut self, enc: u8) -> DResult<NodeId> {
        Ok(match enc {
            0x00 => NodeId::Numeric(0, self.u8()? as u32),
            0x01 => {
                let ns = self.u8()? as u16;
                NodeId::Numeric(ns, self.u16()? as u32)
            }
            0x02 => {
                let ns = self.u16()?;
                NodeId::Numeric(ns, self.u32()?)
            }
            0x03 => {
                let ns = self.u16()?;
                NodeId::String(ns, self.str()?.unwrap_or("").into())
            }
            0x04 => {
                let ns = self.u16()?;
                NodeId::Guid(ns, self.guid()?)
            }
            0x05 => {
                let ns = self.u16()?;
                NodeId::Opaque(ns, self.bytes()?.unwrap_or(&[]).into())
            }
            _ => return Err(DecodeError),
        })
    }

    pub fn expanded_node_id(&mut self) -> DResult<ExpandedNodeId> {
        let enc = self.u8()?;
        let node_id = self.node_id_body(enc & 0x3F)?;
        let namespace_uri = if enc & 0x80 != 0 { self.string_owned()? } else { None };
        let server_index = if enc & 0x40 != 0 { self.u32()? } else { 0 };
        Ok(ExpandedNodeId { node_id, namespace_uri, server_index })
    }

    pub fn qualified_name(&mut self) -> DResult<QualifiedName> {
        let ns = self.u16()?;
        let name = self.str()?.unwrap_or("").into();
        Ok(QualifiedName { ns, name })
    }

    pub fn localized_text(&mut self) -> DResult<LocalizedText> {
        let mask = self.u8()?;
        let locale = if mask & 1 != 0 { self.string_owned()? } else { None };
        let text = if mask & 2 != 0 { self.string_owned()? } else { None };
        Ok(LocalizedText { locale, text })
    }

    /// Returns (type id, encoding, borrowed body).
    pub fn extension_object_raw(&mut self) -> DResult<(NodeId, u8, &'a [u8])> {
        let type_id = self.node_id()?;
        let enc = self.u8()?;
        let body: &'a [u8] = match enc {
            0 => &[],
            1 | 2 => self.bytes()?.unwrap_or(&[]),
            _ => return Err(DecodeError),
        };
        Ok((type_id, enc, body))
    }

    pub fn extension_object(&mut self) -> DResult<ExtensionObject> {
        let (type_id, encoding, body) = self.extension_object_raw()?;
        Ok(ExtensionObject { type_id, encoding, body: body.into() })
    }

    pub fn diagnostic_info(&mut self) -> DResult<()> {
        self.diagnostic_info_depth(0)
    }

    fn diagnostic_info_depth(&mut self, depth: u32) -> DResult<()> {
        if depth > MAX_DEPTH {
            return Err(DecodeError);
        }
        let mask = self.u8()?;
        for bit in [0x01u8, 0x02, 0x04, 0x08] {
            if mask & bit != 0 {
                self.i32()?;
            }
        }
        if mask & 0x10 != 0 {
            self.str()?;
        }
        if mask & 0x20 != 0 {
            self.u32()?;
        }
        if mask & 0x40 != 0 {
            self.diagnostic_info_depth(depth + 1)?;
        }
        Ok(())
    }

    pub fn variant(&mut self) -> DResult<Variant> {
        self.variant_depth(0)
    }

    fn variant_depth(&mut self, depth: u32) -> DResult<Variant> {
        if depth > MAX_DEPTH {
            return Err(DecodeError);
        }
        let enc = self.u8()?;
        let ty = enc & 0x3F;
        if enc & 0x80 == 0 {
            if enc & 0x40 != 0 {
                return Err(DecodeError);
            }
            return self.scalar(ty, depth);
        }
        let n = self.length(1)?.unwrap_or(0);
        let mut items = Vec::with_capacity(n);
        for _ in 0..n {
            items.push(self.scalar(ty, depth)?);
        }
        let dims = if enc & 0x40 != 0 {
            let dn = self.length(4)?.unwrap_or(0);
            let mut dims = Vec::with_capacity(dn);
            let mut product: usize = 1;
            for _ in 0..dn {
                let d = self.i32()?;
                if d < 0 {
                    return Err(DecodeError);
                }
                product = product.saturating_mul(d as usize);
                dims.push(d);
            }
            if product != n {
                return Err(DecodeError);
            }
            Some(dims)
        } else {
            None
        };
        Ok(Variant::Array(Box::new(VariantArray { type_id: ty, items, dims })))
    }

    fn scalar(&mut self, ty: u8, depth: u32) -> DResult<Variant> {
        use builtin::*;
        Ok(match ty {
            0 => Variant::Empty,
            BOOLEAN => Variant::Boolean(self.bool()?),
            SBYTE => Variant::SByte(self.i8()?),
            BYTE => Variant::Byte(self.u8()?),
            INT16 => Variant::Int16(self.i16()?),
            UINT16 => Variant::UInt16(self.u16()?),
            INT32 => Variant::Int32(self.i32()?),
            UINT32 => Variant::UInt32(self.u32()?),
            INT64 => Variant::Int64(self.i64()?),
            UINT64 => Variant::UInt64(self.u64()?),
            FLOAT => Variant::Float(self.f32()?),
            DOUBLE => Variant::Double(self.f64()?),
            STRING => Variant::String(self.string_owned()?),
            DATETIME => Variant::DateTime(self.i64()?),
            GUID => Variant::Guid(self.guid()?),
            BYTESTRING => Variant::ByteString(self.bytes()?.map(Into::into)),
            XMLELEMENT => Variant::XmlElement(self.string_owned()?),
            NODEID => Variant::NodeId(Box::new(self.node_id()?)),
            EXPANDEDNODEID => Variant::ExpandedNodeId(Box::new(self.expanded_node_id()?)),
            STATUSCODE => Variant::StatusCode(self.u32()?),
            QUALIFIEDNAME => Variant::QualifiedName(Box::new(self.qualified_name()?)),
            LOCALIZEDTEXT => Variant::LocalizedText(Box::new(self.localized_text()?)),
            EXTENSIONOBJECT => Variant::ExtensionObject(Box::new(self.extension_object()?)),
            VARIANT => self.variant_depth(depth + 1)?,
            // DataValue and DiagnosticInfo inside a Variant are legal but have
            // no meaning for this server's data model.
            _ => return Err(DecodeError),
        })
    }

    pub fn data_value(&mut self) -> DResult<DataValue> {
        let mask = self.u8()?;
        let mut dv = DataValue::default();
        if mask & 0x01 != 0 {
            dv.value = Some(self.variant()?);
        }
        if mask & 0x02 != 0 {
            dv.status = Some(self.u32()?);
        }
        if mask & 0x04 != 0 {
            dv.source_timestamp = Some(self.i64()?);
        }
        if mask & 0x10 != 0 {
            dv.source_picoseconds = Some(self.u16()?);
        }
        if mask & 0x08 != 0 {
            dv.server_timestamp = Some(self.i64()?);
        }
        if mask & 0x20 != 0 {
            dv.server_picoseconds = Some(self.u16()?);
        }
        Ok(dv)
    }

    /// Decodes an array whose elements are at least `min_size` bytes each.
    pub fn array<T>(&mut self, min_size: usize, mut f: impl FnMut(&mut Self) -> DResult<T>) -> DResult<Vec<T>> {
        let n = self.length(min_size)?.unwrap_or(0);
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            v.push(f(self)?);
        }
        Ok(v)
    }

    /// Skips an array of strings (e.g. localeIds) without allocating.
    pub fn skip_string_array(&mut self) -> DResult<()> {
        let n = self.length(4)?.unwrap_or(0);
        for _ in 0..n {
            self.str()?;
        }
        Ok(())
    }
}

/// Append-only encoder writing into a reusable buffer.
pub struct Writer<'a> {
    pub buf: &'a mut Vec<u8>,
}

macro_rules! write_le {
    ($name:ident, $t:ty) => {
        #[inline(always)]
        pub fn $name(&mut self, v: $t) {
            self.buf.extend_from_slice(&v.to_le_bytes());
        }
    };
}

impl<'a> Writer<'a> {
    #[inline(always)]
    pub fn new(buf: &'a mut Vec<u8>) -> Self {
        Writer { buf }
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    #[inline(always)]
    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }
    #[inline(always)]
    pub fn i8(&mut self, v: i8) {
        self.buf.push(v as u8);
    }
    #[inline(always)]
    pub fn bool(&mut self, v: bool) {
        self.buf.push(v as u8);
    }
    write_le!(u16, u16);
    write_le!(i16, i16);
    write_le!(u32, u32);
    write_le!(i32, i32);
    write_le!(u64, u64);
    write_le!(i64, i64);
    write_le!(f32, f32);
    write_le!(f64, f64);

    #[inline(always)]
    pub fn raw(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }

    #[inline(always)]
    pub fn patch_u32(&mut self, at: usize, v: u32) {
        self.buf[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }

    #[inline]
    pub fn bytes(&mut self, b: Option<&[u8]>) {
        match b {
            None => self.i32(-1),
            Some(b) => {
                self.i32(b.len() as i32);
                self.raw(b);
            }
        }
    }

    #[inline]
    pub fn str(&mut self, s: Option<&str>) {
        self.bytes(s.map(str::as_bytes))
    }

    #[inline]
    pub fn string(&mut self, s: &str) {
        self.bytes(Some(s.as_bytes()))
    }

    #[inline]
    pub fn null_array(&mut self) {
        self.i32(-1);
    }

    #[inline]
    pub fn empty_array(&mut self) {
        self.i32(0);
    }

    pub fn string_array(&mut self, items: &[&str]) {
        self.i32(items.len() as i32);
        for s in items {
            self.string(s);
        }
    }

    /// Smallest valid encoding is chosen (Part 6 §5.2.2.9).
    #[inline]
    pub fn node_id(&mut self, id: &NodeId) {
        self.node_id_flags(id, 0)
    }

    fn node_id_flags(&mut self, id: &NodeId, flags: u8) {
        match id {
            NodeId::Numeric(0, v) if *v <= 0xFF => {
                self.u8(flags);
                self.u8(*v as u8);
            }
            NodeId::Numeric(ns, v) if *ns <= 0xFF && *v <= 0xFFFF => {
                self.u8(0x01 | flags);
                self.u8(*ns as u8);
                self.u16(*v as u16);
            }
            NodeId::Numeric(ns, v) => {
                self.u8(0x02 | flags);
                self.u16(*ns);
                self.u32(*v);
            }
            NodeId::String(ns, s) => {
                self.u8(0x03 | flags);
                self.u16(*ns);
                self.string(s);
            }
            NodeId::Guid(ns, g) => {
                self.u8(0x04 | flags);
                self.u16(*ns);
                self.raw(g);
            }
            NodeId::Opaque(ns, b) => {
                self.u8(0x05 | flags);
                self.u16(*ns);
                self.bytes(Some(b));
            }
        }
    }

    pub fn expanded_node_id(&mut self, id: &ExpandedNodeId) {
        let mut flags = 0;
        if id.namespace_uri.is_some() {
            flags |= 0x80;
        }
        if id.server_index != 0 {
            flags |= 0x40;
        }
        self.node_id_flags(&id.node_id, flags);
        if let Some(uri) = &id.namespace_uri {
            self.string(uri);
        }
        if id.server_index != 0 {
            self.u32(id.server_index);
        }
    }

    /// ExpandedNodeId pointing to a local node.
    #[inline]
    pub fn local_expanded_node_id(&mut self, id: &NodeId) {
        self.node_id(id)
    }

    pub fn qualified_name(&mut self, q: &QualifiedName) {
        self.u16(q.ns);
        self.string(&q.name);
    }

    pub fn localized_text(&mut self, t: &LocalizedText) {
        let mask = (t.locale.is_some() as u8) | ((t.text.is_some() as u8) << 1);
        self.u8(mask);
        if let Some(l) = &t.locale {
            self.string(l);
        }
        if let Some(x) = &t.text {
            self.string(x);
        }
    }

    /// LocalizedText with only a text part.
    #[inline]
    pub fn text(&mut self, t: &str) {
        self.u8(2);
        self.string(t);
    }

    #[inline]
    pub fn null_extension_object(&mut self) {
        // Null NodeId (2 bytes) + encoding byte 0.
        self.raw(&[0, 0, 0]);
    }

    /// Starts a binary-encoded extension object; returns the position of the
    /// length prefix, to be closed with [`Writer::end_extension_object`].
    #[inline]
    pub fn begin_extension_object(&mut self, encoding_id: u32) -> usize {
        self.node_id(&NodeId::ns0(encoding_id));
        self.u8(1);
        let at = self.len();
        self.i32(0);
        at
    }

    #[inline]
    pub fn end_extension_object(&mut self, at: usize) {
        let len = (self.len() - at - 4) as u32;
        self.patch_u32(at, len);
    }

    pub fn extension_object(&mut self, e: &ExtensionObject) {
        self.node_id(&e.type_id);
        self.u8(e.encoding);
        if e.encoding != 0 {
            self.bytes(Some(&e.body));
        }
    }

    #[inline]
    pub fn empty_diagnostic_info(&mut self) {
        self.u8(0);
    }

    pub fn variant(&mut self, v: &Variant) {
        match v {
            Variant::Array(a) => {
                let mut enc = a.type_id | 0x80;
                if a.dims.is_some() {
                    enc |= 0x40;
                }
                self.u8(enc);
                self.i32(a.items.len() as i32);
                for item in &a.items {
                    if a.type_id == builtin::VARIANT {
                        self.variant(item);
                    } else {
                        self.scalar(item);
                    }
                }
                if let Some(d) = &a.dims {
                    self.i32(d.len() as i32);
                    for x in d {
                        self.i32(*x);
                    }
                }
            }
            _ => {
                self.u8(v.type_id());
                self.scalar(v);
            }
        }
    }

    #[inline]
    fn scalar(&mut self, v: &Variant) {
        match v {
            Variant::Empty => {}
            Variant::Boolean(x) => self.bool(*x),
            Variant::SByte(x) => self.i8(*x),
            Variant::Byte(x) => self.u8(*x),
            Variant::Int16(x) => self.i16(*x),
            Variant::UInt16(x) => self.u16(*x),
            Variant::Int32(x) => self.i32(*x),
            Variant::UInt32(x) => self.u32(*x),
            Variant::Int64(x) => self.i64(*x),
            Variant::UInt64(x) => self.u64(*x),
            Variant::Float(x) => self.f32(*x),
            Variant::Double(x) => self.f64(*x),
            Variant::String(s) | Variant::XmlElement(s) => self.str(s.as_deref()),
            Variant::DateTime(x) => self.i64(*x),
            Variant::Guid(g) => self.raw(g),
            Variant::ByteString(b) => self.bytes(b.as_deref()),
            Variant::NodeId(n) => self.node_id(n),
            Variant::ExpandedNodeId(n) => self.expanded_node_id(n),
            Variant::StatusCode(s) => self.u32(*s),
            Variant::QualifiedName(q) => self.qualified_name(q),
            Variant::LocalizedText(t) => self.localized_text(t),
            Variant::ExtensionObject(e) => self.extension_object(e),
            Variant::Array(_) => self.variant(v),
        }
    }

    pub fn data_value(&mut self, dv: &DataValue) {
        let mut mask = 0u8;
        if dv.value.is_some() {
            mask |= 0x01;
        }
        if dv.status.is_some_and(|s| s != 0) {
            mask |= 0x02;
        }
        if dv.source_timestamp.is_some() {
            mask |= 0x04;
        }
        if dv.server_timestamp.is_some() {
            mask |= 0x08;
        }
        if dv.source_picoseconds.is_some() {
            mask |= 0x10;
        }
        if dv.server_picoseconds.is_some() {
            mask |= 0x20;
        }
        self.u8(mask);
        if let Some(v) = &dv.value {
            self.variant(v);
        }
        if mask & 0x02 != 0 {
            self.u32(dv.status.unwrap());
        }
        if let Some(t) = dv.source_timestamp {
            self.i64(t);
        }
        if let Some(p) = dv.source_picoseconds {
            self.u16(p);
        }
        if let Some(t) = dv.server_timestamp {
            self.i64(t);
        }
        if let Some(p) = dv.server_picoseconds {
            self.u16(p);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip_variant(v: Variant) {
        let mut buf = Vec::new();
        Writer::new(&mut buf).variant(&v);
        let mut r = Reader::new(&buf);
        assert_eq!(r.variant().unwrap(), v);
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn variants_roundtrip() {
        roundtrip_variant(Variant::Empty);
        roundtrip_variant(Variant::Boolean(true));
        roundtrip_variant(Variant::Int16(-42));
        roundtrip_variant(Variant::UInt64(u64::MAX));
        roundtrip_variant(Variant::Double(3.5));
        roundtrip_variant(Variant::string("héllo"));
        roundtrip_variant(Variant::String(None));
        roundtrip_variant(Variant::NodeId(Box::new(NodeId::String(3, "x".into()))));
        roundtrip_variant(Variant::LocalizedText(Box::new(LocalizedText::new("t"))));
        roundtrip_variant(Variant::string_array(&["a", "b"]));
        roundtrip_variant(Variant::Array(Box::new(VariantArray {
            type_id: builtin::INT32,
            items: (0..6).map(Variant::Int32).collect(),
            dims: Some(vec![2, 3]),
        })));
    }

    #[test]
    fn node_id_compact_encodings() {
        for (id, expected_len) in [
            (NodeId::ns0(85), 2),
            (NodeId::Numeric(5, 1000), 4),
            (NodeId::Numeric(300, 1), 7),
            (NodeId::Numeric(1, 70000), 7),
            (NodeId::String(1, "ab".into()), 9),
            (NodeId::Guid(1, [7; 16]), 19),
        ] {
            let mut buf = Vec::new();
            Writer::new(&mut buf).node_id(&id);
            assert_eq!(buf.len(), expected_len, "{id}");
            assert_eq!(Reader::new(&buf).node_id().unwrap(), id);
        }
    }

    #[test]
    fn data_value_roundtrip() {
        let dv = DataValue {
            value: Some(Variant::Float(1.5)),
            status: Some(status::UNCERTAIN_INITIAL_VALUE),
            source_timestamp: Some(1),
            source_picoseconds: None,
            server_timestamp: Some(2),
            server_picoseconds: Some(3),
        };
        let mut buf = Vec::new();
        Writer::new(&mut buf).data_value(&dv);
        assert_eq!(Reader::new(&buf).data_value().unwrap(), dv);
    }

    #[test]
    fn hostile_lengths_rejected() {
        // String claiming 1 GiB with 2 bytes of payload.
        let mut buf = Vec::new();
        Writer::new(&mut buf).i32(1 << 30);
        buf.extend_from_slice(b"ab");
        assert!(Reader::new(&buf).str().is_err());
        // Array of 2^31-1 Int32.
        let buf = [0x86u8, 0xFF, 0xFF, 0xFF, 0x7F];
        assert!(Reader::new(&buf).variant().is_err());
        // Deeply nested variants.
        let buf = vec![builtin::VARIANT; 100];
        assert!(Reader::new(&buf).variant().is_err());
        // Bad UTF-8.
        let buf = [2u8, 0, 0, 0, 0xFF, 0xFE];
        assert!(Reader::new(&buf).str().is_err());
    }
}
