#!/usr/bin/env python3
"""Generates the data type table of fastua's JSON encoding.

    python3 crates/fastua/tools/gen_types.py Opc.Ua.NodeSet2.Services.xml

Writes crates/fastua/data/types.bin: every DataType of namespace 0 (services
included) with its supertype, encodings and definition, from the nodeset of
https://github.com/OPCFoundation/UA-Nodeset at the tag in NODESET_TAG of
gen_ns0.py.

types.bin layout, little endian, strings as u16 length + UTF-8:
  "FUAT" u32 type_count, then per type:
    u32 id, u32 supertype (0 = none), u32 binary_encoding, u32 json_encoding,
    u8 kind (0 structure, 1 structure with optional fields, 2 union,
             3 enumeration, 4 no definition), string name, u16 field_count,
    then per field:
      structure: string name, u32 data_type, i32 value_rank, u8 optional
      enumeration: string name, i64 value
"""
import os, struct, sys
import xml.etree.ElementTree as ET

NS = "{http://opcfoundation.org/UA/2011/03/UANodeSet.xsd}"


def numeric(nid, aliases):
    nid = aliases.get(nid, nid)
    if not nid.startswith("i="):
        raise ValueError(f"unexpected NodeId {nid}")
    return int(nid[2:])


def s(text):
    b = text.encode()
    return struct.pack("<H", len(b)) + b


def main():
    root = ET.parse(sys.argv[1]).getroot()
    aliases = {a.get("Alias"): a.text for a in root.iter(NS + "Alias")}
    encodings = {}  # data type -> {browse name: id}
    for obj in root.iter(NS + "UAObject"):
        for ref in obj.iter(NS + "Reference"):
            if ref.get("ReferenceType") == "HasEncoding" and ref.get("IsForward") == "false":
                dt = numeric(ref.text, aliases)
                encodings.setdefault(dt, {})[obj.get("BrowseName")] = numeric(obj.get("NodeId"), aliases)
    out = []
    for dt in root.iter(NS + "UADataType"):
        tid = numeric(dt.get("NodeId"), aliases)
        parent = 0
        for ref in dt.iter(NS + "Reference"):
            if ref.get("ReferenceType") == "HasSubtype" and ref.get("IsForward") == "false":
                parent = numeric(ref.text, aliases)
        enc = encodings.get(tid, {})
        name = dt.get("BrowseName").split(":")[-1]
        d = dt.find(NS + "Definition")
        fields = [] if d is None else d.findall(NS + "Field")
        if d is None:
            kind = 4
        elif d.get("IsUnion") == "true":
            kind = 2
        elif fields and all(f.get("DataType") is None for f in fields) and any(f.get("Value") for f in fields):
            kind = 3
        elif any(f.get("IsOptional") == "true" for f in fields):
            kind = 1
        else:
            kind = 0
        rec = struct.pack("<IIII", tid, parent, enc.get("Default Binary", 0), enc.get("Default JSON", 0))
        rec += struct.pack("<B", kind) + s(name) + struct.pack("<H", len(fields))
        for f in fields:
            if kind == 3:
                rec += s(f.get("Name")) + struct.pack("<q", int(f.get("Value") or 0))
            else:
                rec += s(f.get("Name")) + struct.pack(
                    "<IiB",
                    numeric(f.get("DataType") or "i=24", aliases),
                    int(f.get("ValueRank") or -1),
                    1 if f.get("IsOptional") == "true" else 0,
                )
        out.append((tid, rec))
    out.sort()
    data = b"FUAT" + struct.pack("<I", len(out)) + b"".join(r for _, r in out)
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "types.bin")
    with open(path, "wb") as f:
        f.write(data)
    print(f"{len(out)} data types, {len(data)} bytes -> {os.path.normpath(path)}")


if __name__ == "__main__":
    main()
