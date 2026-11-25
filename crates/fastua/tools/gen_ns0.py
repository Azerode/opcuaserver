#!/usr/bin/env python3
"""Generates the namespace 0 tables of fastua from the official nodeset.

    python3 crates/fastua/tools/gen_ns0.py Opc.Ua.NodeSet2.xml

Writes crates/fastua/data/ns0.bin (every node of namespace 0, with its
attributes, static value and references) and crates/fastua/src/ns0_ref_types.rs
(the reference type hierarchy, used by Browse). The nodeset is the one of
https://github.com/OPCFoundation/UA-Nodeset at the tag in NODESET_TAG.

ns0.bin layout, little endian, strings and values in UA binary encoding:
  "FUA0" u32 node_count, then per node:
    u32 id, u8 node_class, QualifiedName browse_name, LocalizedText display_name,
    u8 has_description [LocalizedText], class attributes:
      Object        u8 event_notifier
      Variable      u32 data_type, i32 value_rank, u8 access_level, u8 has_value [Variant]
      VariableType  u8 is_abstract, u32 data_type, i32 value_rank
      ObjectType    u8 is_abstract
      DataType      u8 is_abstract, u8 has_definition [Variant: StructureDefinition
                    or EnumDefinition ExtensionObject, the DataTypeDefinition attribute]
      ReferenceType u8 is_abstract, u8 symmetric, u8 has_inverse [LocalizedText]
      Method        (none)
    u32 ref_count, then per reference: u32 type, u8 forward, u32 target
"""
import base64, datetime, os, struct, sys
import xml.etree.ElementTree as ET

NODESET_TAG = "UA-1.05.07-2026-07-30"
NS = "{http://opcfoundation.org/UA/2011/03/UANodeSet.xsd}"
T = "{http://opcfoundation.org/UA/2008/02/Types.xsd}"
CLASSES = {"UAObject": 1, "UAVariable": 2, "UAMethod": 4, "UAObjectType": 8,
           "UAVariableType": 16, "UAReferenceType": 32, "UADataType": 64}
BUILTIN = {"Boolean": 1, "SByte": 2, "Byte": 3, "Int16": 4, "UInt16": 5, "Int32": 6, "UInt32": 7,
           "Int64": 8, "UInt64": 9, "Float": 10, "Double": 11, "String": 12, "DateTime": 13,
           "ByteString": 15, "NodeId": 17, "LocalizedText": 21, "ExtensionObject": 22}
INT_FMT = {"SByte": "<b", "Byte": "<B", "Int16": "<h", "UInt16": "<H", "Int32": "<i",
           "UInt32": "<I", "Int64": "<q", "UInt64": "<Q"}


def numeric(nid, aliases):
    nid = aliases.get(nid, nid)
    if not nid.startswith("i="):
        raise ValueError(f"not a namespace 0 numeric NodeId: {nid}")
    return int(nid[2:])


def string(s):
    if s is None:
        return struct.pack("<i", -1)
    b = s.encode()
    return struct.pack("<i", len(b)) + b


def node_id(n):
    if n < 256:
        return bytes([0, n])
    if n < 65536:
        return struct.pack("<BBH", 1, 0, n)
    return struct.pack("<BHI", 2, 0, n)


def loc_text(locale, text):
    mask = (1 if locale else 0) | (2 if text is not None else 0)
    out = bytes([mask])
    if locale:
        out += string(locale)
    if text is not None:
        out += string(text)
    return out


def child_text(el, name):
    c = el.find(T + name)
    return None if c is None else (c.text or "")


def lt_xml(el):
    if el is None:
        return loc_text(None, None)
    return loc_text(child_text(el, "Locale"), child_text(el, "Text"))


def ext_body(el, aliases):
    """(binary encoding id, body) of an ExtensionObject <Body> child."""
    name = el.tag.replace(T, "")
    if name == "Argument":
        dims = el.find(T + "ArrayDimensions")
        dims = [] if dims is None else [int(x.text) for x in dims]
        body = string(child_text(el, "Name"))
        dt = el.find(T + "DataType")
        body += node_id(numeric(child_text(dt, "Identifier"), aliases))
        body += struct.pack("<i", int(child_text(el, "ValueRank") or -1))
        body += struct.pack("<i", len(dims)) + b"".join(struct.pack("<I", d) for d in dims) if dims else struct.pack("<i", -1)
        body += lt_xml(el.find(T + "Description"))
        return 298, body
    if name == "EnumValueType":
        body = struct.pack("<q", int(child_text(el, "Value") or 0))
        body += lt_xml(el.find(T + "DisplayName")) + lt_xml(el.find(T + "Description"))
        return 8251, body
    if name == "EUInformation":
        body = string(child_text(el, "NamespaceUri")) + struct.pack("<i", int(child_text(el, "UnitId") or 0))
        body += lt_xml(el.find(T + "DisplayName")) + lt_xml(el.find(T + "Description"))
        return 889, body
    raise ValueError(f"unsupported ExtensionObject body {name}")


def scalar(kind, el, aliases):
    if kind == "Boolean":
        return bytes([1 if (el.text or "").strip() == "true" else 0])
    if kind in INT_FMT:
        return struct.pack(INT_FMT[kind], int(el.text))
    if kind == "Double":
        return struct.pack("<d", float(el.text))
    if kind == "Float":
        return struct.pack("<f", float(el.text))
    if kind == "String":
        return string(el.text or "")
    if kind == "LocalizedText":
        return lt_xml(el)
    if kind == "ByteString":
        return struct.pack("<i", -1) if el.text is None else (lambda b: struct.pack("<i", len(b)) + b)(base64.b64decode(el.text))
    if kind == "DateTime":
        t = datetime.datetime.fromisoformat(el.text.replace("Z", "+00:00"))
        epoch = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
        return struct.pack("<q", int((t - epoch).total_seconds() * 10_000_000))
    if kind == "NodeId":
        return node_id(numeric(child_text(el, "Identifier"), aliases))
    if kind == "ExtensionObject":
        body_el = el.find(T + "Body")
        enc, body = ext_body(body_el[0], aliases)
        return node_id(enc) + b"\x01" + struct.pack("<i", len(body)) + body
    raise ValueError(f"unsupported value type {kind}")


def variant(v, aliases):
    kind = v.tag.replace(T, "")
    if kind.startswith("ListOf"):
        k = kind[6:]
        items = list(v)
        return bytes([BUILTIN[k] | 0x80]) + struct.pack("<i", len(items)) + b"".join(scalar(k, i, aliases) for i in items)
    return bytes([BUILTIN[kind]]) + scalar(kind, v, aliases)


STRUCTURE, ENUMERATION = 22, 29


def data_type_definition(e, me, aliases, supertype, encodings, names):
    """Binary DataTypeDefinition of a UADataType, or None."""
    d = e.find(NS + "Definition")
    if d is None:
        return None
    chain, t = [], me
    while t in supertype:
        t = supertype[t]
        chain.append(t)
    fields = d.findall(NS + "Field")
    if ENUMERATION in chain or d.get("IsOptionSet") == "true":
        body = struct.pack("<i", len(fields))
        for i, f in enumerate(fields):
            desc = f.find(NS + "Description")
            dn = f.find(NS + "DisplayName")
            value = int(f.get("Value", 1 << i if d.get("IsOptionSet") == "true" else i))
            body += struct.pack("<q", value)
            body += loc_text(None, dn.text if dn is not None else f.get("Name"))
            body += loc_text(desc.get("Locale"), desc.text or "") if desc is not None else loc_text(None, None)
            body += string(f.get("Name"))
        enc = 123  # EnumDefinition_Encoding_DefaultBinary
    elif STRUCTURE in chain or me == STRUCTURE:
        union = d.get("IsUnion") == "true"
        optional = any(f.get("IsOptional") == "true" for f in fields)
        structure_type = 2 if union else 1 if optional else 0
        body = node_id(encodings.get(me, 0)) + node_id(supertype.get(me, STRUCTURE)) + struct.pack("<i", structure_type)
        body += struct.pack("<i", len(fields))
        for f in fields:
            desc = f.find(NS + "Description")
            dims = [int(x) for x in f.get("ArrayDimensions", "").split(",") if x]
            body += string(f.get("Name"))
            body += loc_text(desc.get("Locale"), desc.text or "") if desc is not None else loc_text(None, None)
            body += node_id(numeric(f.get("DataType", "i=24"), aliases))
            body += struct.pack("<i", int(f.get("ValueRank", "-1")))
            body += (struct.pack("<i", len(dims)) + b"".join(struct.pack("<I", x) for x in dims)) if dims else struct.pack("<i", -1)
            body += struct.pack("<I", int(f.get("MaxStringLength", "0")))
            body += bytes([1 if f.get("IsOptional") == "true" else 0])
        enc = 122  # StructureDefinition_Encoding_DefaultBinary
    else:
        return None
    return bytes([BUILTIN["ExtensionObject"]]) + node_id(enc) + b"\x01" + struct.pack("<i", len(body)) + body


def main():
    src = sys.argv[1]
    here = os.path.dirname(os.path.abspath(__file__))
    root = ET.parse(src).getroot()
    aliases = {a.get("Alias"): a.text for a in root.find(NS + "Aliases")}
    elems = [e for e in root if e.tag.replace(NS, "") in CLASSES]
    ids = {e.get("NodeId") for e in elems}
    # References as forward (src, type, dst) triples, both directions merged.
    triples = set()
    for e in elems:
        me = numeric(e.get("NodeId"), aliases)
        for r in e.iter(NS + "Reference"):
            if r.text not in ids:
                continue
            t, other = numeric(r.get("ReferenceType"), aliases), numeric(r.text, aliases)
            fwd = r.get("IsForward", "true") != "false"
            triples.add((me, t, other) if fwd else (other, t, me))
    names = {numeric(e.get("NodeId"), aliases): e.get("BrowseName") for e in elems}
    supertype = {d: s for s, t, d in triples if t == 45}
    encodings = {s: d for s, t, d in triples if t == 38 and names.get(d) == "Default Binary"}
    refs = {}
    for s, t, d in sorted(triples):
        refs.setdefault(s, []).append((t, 1, d))
        refs.setdefault(d, []).append((t, 0, s))

    out = bytearray(b"FUA0" + struct.pack("<I", len(elems)))
    parents = []
    for e in elems:
        cls = e.tag.replace(NS, "")
        me = numeric(e.get("NodeId"), aliases)
        bn = e.get("BrowseName")
        ns, _, name = bn.partition(":") if ":" in bn and bn.split(":")[0].isdigit() else ("0", "", bn)
        out += struct.pack("<IB", me, CLASSES[cls]) + struct.pack("<H", int(ns)) + string(name)
        dn = e.find(NS + "DisplayName")
        out += loc_text(dn.get("Locale") if dn is not None else None, dn.text if dn is not None else name)
        desc = e.find(NS + "Description")
        out += b"\x01" + loc_text(desc.get("Locale"), desc.text or "") if desc is not None else b"\x00"
        abstract = 1 if e.get("IsAbstract") == "true" else 0
        if cls == "UAObject":
            out += bytes([int(e.get("EventNotifier", "0"))])
        elif cls == "UAVariable":
            out += struct.pack("<Ii", numeric(e.get("DataType", "i=24"), aliases), int(e.get("ValueRank", "-1")))
            out += bytes([int(e.get("AccessLevel", "1"))])
            v = e.find(NS + "Value")
            out += b"\x01" + variant(v[0], aliases) if v is not None and len(v) else b"\x00"
        elif cls == "UAVariableType":
            out += bytes([abstract]) + struct.pack("<Ii", numeric(e.get("DataType", "i=24"), aliases), int(e.get("ValueRank", "-2")))
        elif cls == "UAObjectType":
            out += bytes([abstract])
        elif cls == "UADataType":
            definition = data_type_definition(e, me, aliases, supertype, encodings, names)
            out += bytes([abstract]) + (b"\x01" + definition if definition else b"\x00")
        elif cls == "UAReferenceType":
            inv = e.find(NS + "InverseName")
            out += bytes([abstract, 1 if e.get("Symmetric") == "true" else 0])
            out += b"\x01" + loc_text(inv.get("Locale"), inv.text or "") if inv is not None else b"\x00"
            for t, fwd, d in refs.get(me, []):
                if t == 45 and not fwd:
                    parents.append((me, d))
        rs = refs.get(me, [])
        out += struct.pack("<I", len(rs)) + b"".join(struct.pack("<IBI", *r) for r in rs)

    with open(os.path.join(here, "..", "data", "ns0.bin"), "wb") as f:
        f.write(out)
    with open(os.path.join(here, "..", "src", "ns0_ref_types.rs"), "w") as f:
        f.write(f"// Generated by tools/gen_ns0.py from Opc.Ua.NodeSet2.xml ({NODESET_TAG}). Do not edit.\n\n")
        f.write("/// (reference type, parent reference type) of every standard reference type, sorted.\n")
        f.write("pub const REF_TYPE_PARENT: &[(u32, u32)] = &[\n")
        for c, p in sorted(parents):
            f.write(f"    ({c}, {p}),\n")
        f.write("];\n")
    print(f"{len(elems)} nodes, {len(triples)} references, {len(out)} bytes, {len(parents)} reference types")


if __name__ == "__main__":
    main()
