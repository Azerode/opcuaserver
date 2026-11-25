//! Loading of the node configuration directory.
//!
//! Every `*.json` file (searched recursively) describes one namespace. The
//! format is the one already used by this repository:
//!
//! ```json
//! {
//!   "Name": "Machine1",
//!   "Namespace": "Machine1",
//!   "Subscriptions": [
//!     { "Name": "FLAGS",
//!       "Items": [ { "Name": "PC", "NodeId": "ns=5;i=1000", "Type": "System.Int16" } ] }
//!   ]
//! }
//! ```
//!
//! The `ns=` part of each NodeId is ignored: the server assigns the namespace
//! index from the `Namespace` URI and keeps it stable across reloads.

use crate::types::{builtin, NodeId};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Deserialize, Debug)]
struct RawFile {
    #[serde(rename = "Name")]
    name: Option<String>,
    #[serde(rename = "Namespace")]
    namespace: String,
    #[serde(rename = "Subscriptions", alias = "Groups", default)]
    groups: Vec<RawGroup>,
}

#[derive(Deserialize, Debug)]
struct RawGroup {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Items", default)]
    items: Vec<RawItem>,
}

#[derive(Deserialize, Debug)]
struct RawItem {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "NodeId")]
    node_id: String,
    #[serde(rename = "Type")]
    data_type: String,
    #[serde(rename = "Writable", default = "default_true")]
    writable: bool,
    #[serde(rename = "EURange", default)]
    eu_range: Option<RawRange>,
    #[serde(rename = "Historizing", default)]
    historizing: bool,
    /// Values kept in the history (default 10 000).
    #[serde(rename = "HistoryCapacity", default)]
    history_capacity: Option<u32>,
}

/// `{"Low": 0, "High": 100}` or `[0, 100]`.
#[derive(Deserialize, Debug)]
#[serde(untagged)]
enum RawRange {
    Object {
        #[serde(rename = "Low", alias = "low")]
        low: f64,
        #[serde(rename = "High", alias = "high")]
        high: f64,
    },
    Pair(f64, f64),
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq)]
pub struct NamespaceConfig {
    pub source: PathBuf,
    pub uri: String,
    pub name: String,
    pub groups: Vec<GroupConfig>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GroupConfig {
    pub name: String,
    pub items: Vec<ItemConfig>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ItemConfig {
    pub name: String,
    /// NodeId with namespace index 0; the real index is set by the server.
    pub node_id: NodeId,
    pub data_type: u8,
    pub writable: bool,
    /// EURange (low, high): the variable becomes an AnalogItemType and
    /// supports percent deadbands.
    pub eu_range: Option<(f64, f64)>,
    /// Values kept in the history; `None` = not historized.
    pub history: Option<usize>,
}

/// Maps a type name (`System.Int16`, `Int16`, `int16`, `Single`…) to a built-in type id.
pub fn parse_type(name: &str) -> Option<u8> {
    use builtin::*;
    let n = name.trim();
    let n = n.strip_prefix("System.").unwrap_or(n);
    Some(match n.to_ascii_lowercase().as_str() {
        "boolean" | "bool" => BOOLEAN,
        "sbyte" | "int8" => SBYTE,
        "byte" | "uint8" => BYTE,
        "int16" | "short" => INT16,
        "uint16" | "ushort" => UINT16,
        "int32" | "int" => INT32,
        "uint32" | "uint" => UINT32,
        "int64" | "long" => INT64,
        "uint64" | "ulong" => UINT64,
        "float" | "single" => FLOAT,
        "double" => DOUBLE,
        "string" => STRING,
        "datetime" => DATETIME,
        "guid" => GUID,
        "bytestring" | "byte[]" => BYTESTRING,
        _ => return None,
    })
}

pub fn parse_file(path: &Path, text: &str) -> Result<NamespaceConfig, String> {
    let raw: RawFile = serde_json::from_str(text).map_err(|e| format!("{}: {e}", path.display()))?;
    if raw.namespace.trim().is_empty() {
        return Err(format!("{}: empty Namespace", path.display()));
    }
    let mut groups = Vec::with_capacity(raw.groups.len());
    for g in raw.groups {
        let mut items = Vec::with_capacity(g.items.len());
        for it in g.items {
            let node_id = NodeId::parse(&it.node_id)
                .map_err(|e| format!("{}: item '{}': {e}", path.display(), it.name))?
                .with_namespace(0);
            let data_type = parse_type(&it.data_type).ok_or_else(|| {
                format!("{}: item '{}': unsupported type '{}'", path.display(), it.name, it.data_type)
            })?;
            let eu_range = match it.eu_range {
                None => None,
                Some(RawRange::Object { low, high } | RawRange::Pair(low, high)) => {
                    if !(low.is_finite() && high.is_finite() && low <= high) {
                        return Err(format!("{}: item '{}': invalid EURange [{low}, {high}]", path.display(), it.name));
                    }
                    if crate::value::bits_as_f64(data_type, 0).is_none() {
                        return Err(format!("{}: item '{}': EURange needs a numeric Type", path.display(), it.name));
                    }
                    Some((low, high))
                }
            };
            let history = match (it.historizing, it.history_capacity) {
                (false, _) => None,
                (true, Some(0)) => {
                    return Err(format!("{}: item '{}': HistoryCapacity must be > 0", path.display(), it.name))
                }
                (true, cap) => Some(cap.map_or(crate::history::DEFAULT_CAPACITY, |c| c as usize)),
            };
            items.push(ItemConfig { name: it.name, node_id, data_type, writable: it.writable, eu_range, history });
        }
        groups.push(GroupConfig { name: g.name, items });
    }
    let uri = raw.namespace.trim().to_string();
    Ok(NamespaceConfig { source: path.to_path_buf(), name: raw.name.unwrap_or_else(|| uri.clone()), uri, groups })
}

/// Lists config files in a stable order (so namespace indexes assigned on
/// first start are deterministic).
pub fn list_files(dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d)? {
            let entry = entry?;
            let path = entry.path();
            let ft = entry.file_type()?;
            if ft.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e.eq_ignore_ascii_case("json")) {
                out.push(path);
            }
        }
    }
    out.sort();
    Ok(out)
}

/// Loads every file. Any error aborts the whole load so that a half-written
/// file never makes nodes disappear: the previous address space stays live.
pub fn load_dir(dir: &Path) -> Result<Vec<NamespaceConfig>, String> {
    let files = list_files(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let mut out: Vec<NamespaceConfig> = Vec::with_capacity(files.len());
    for f in files {
        let text = std::fs::read_to_string(&f).map_err(|e| format!("{}: {e}", f.display()))?;
        let ns = parse_file(&f, &text)?;
        if let Some(prev) = out.iter().find(|n| n.uri == ns.uri) {
            return Err(format!(
                "namespace '{}' defined twice ({} and {})",
                ns.uri,
                prev.source.display(),
                f.display()
            ));
        }
        out.push(ns);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_existing_format() {
        let text = r#"{
            "Name": "Machine1", "Url": "opc.tcp://x:4840", "Namespace": "Machine1",
            "Subscriptions": [
              { "Name": "FLAGS", "Items": [
                { "Name": "PC", "NodeId": "ns=5;i=1000", "Type": "System.Int16" },
                { "Name": "S", "NodeId": "s=Speed", "Type": "Double", "Writable": false,
                  "EURange": { "Low": -10, "High": 90 } },
                { "Name": "T", "NodeId": "i=7", "Type": "Float", "EURange": [0, 5], "Historizing": true },
                { "Name": "H", "NodeId": "i=8", "Type": "Int32", "Historizing": true, "HistoryCapacity": 50 } ] } ] }"#;
        let ns = parse_file(Path::new("m.json"), text).unwrap();
        assert_eq!(ns.uri, "Machine1");
        assert_eq!(ns.groups[0].items[0].node_id, NodeId::Numeric(0, 1000));
        assert_eq!(ns.groups[0].items[0].data_type, builtin::INT16);
        assert!(!ns.groups[0].items[1].writable);
        assert_eq!(ns.groups[0].items[0].eu_range, None);
        assert_eq!(ns.groups[0].items[1].eu_range, Some((-10.0, 90.0)));
        assert_eq!(ns.groups[0].items[2].eu_range, Some((0.0, 5.0)));
        assert_eq!(ns.groups[0].items[0].history, None);
        assert_eq!(ns.groups[0].items[2].history, Some(crate::history::DEFAULT_CAPACITY));
        assert_eq!(ns.groups[0].items[3].history, Some(50));
    }

    #[test]
    fn rejects_bad_files() {
        assert!(parse_file(Path::new("a"), "{").is_err());
        assert!(parse_file(Path::new("a"), r#"{"Namespace":""}"#).is_err());
        let bad_type =
            r#"{"Namespace":"x","Subscriptions":[{"Name":"g","Items":[{"Name":"a","NodeId":"i=1","Type":"Quux"}]}]}"#;
        assert!(parse_file(Path::new("a"), bad_type).unwrap_err().contains("unsupported type"));
        let bad_range = r#"{"Namespace":"x","Subscriptions":[{"Name":"g","Items":[
            {"Name":"a","NodeId":"i=1","Type":"Double","EURange":[5,1]}]}]}"#;
        assert!(parse_file(Path::new("a"), bad_range).unwrap_err().contains("EURange"));
        let text_range = r#"{"Namespace":"x","Subscriptions":[{"Name":"g","Items":[
            {"Name":"a","NodeId":"i=1","Type":"String","EURange":[0,1]}]}]}"#;
        assert!(parse_file(Path::new("a"), text_range).unwrap_err().contains("numeric"));
    }

    #[test]
    fn loads_repository_configs() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/machines");
        let all = load_dir(&dir).unwrap();
        assert_eq!(all.len(), 3);
    }
}
