//! Immutable address space snapshots.
//!
//! A snapshot is built once per configuration (re)load and then only read.
//! All references are resolved to dense `u32` indexes at build time, so a
//! Browse never hashes anything after the starting node, and a Read is one
//! hash lookup plus a seqlock read.

use crate::config::NamespaceConfig;
use crate::types::*;
use crate::value::ValueCell;
use std::sync::Arc;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum NodeClass {
    Object = 1,
    Variable = 2,
    Method = 4,
    ObjectType = 8,
    VariableType = 16,
    ReferenceType = 32,
    DataType = 64,
    View = 128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ref {
    /// Reference type (always a namespace 0 numeric id in this server).
    pub type_id: u32,
    pub forward: bool,
    pub target: u32,
}

/// Where a variable gets its value from.
pub enum ValueSource {
    Static(Variant),
    Cell(Arc<ValueCell>),
    CurrentTime,
    ServerStatus,
    /// A ServerDiagnosticsSummary field, or the whole summary
    /// ([`crate::diagnostics::SUMMARY`]).
    Diagnostics(u8),
}

pub const ACCESS_READ: u8 = 0x01;
pub const ACCESS_WRITE: u8 = 0x02;

pub enum NodeKind {
    Object { event_notifier: u8 },
    Variable { data_type: NodeId, value_rank: i32, access: u8, value: ValueSource },
    ObjectType { is_abstract: bool },
    VariableType { is_abstract: bool, data_type: NodeId, value_rank: i32 },
    ReferenceType { is_abstract: bool, symmetric: bool, inverse_name: Option<LocalizedText> },
    DataType { is_abstract: bool },
    Method { executable: bool },
}

pub struct Node {
    pub id: NodeId,
    pub browse_name: QualifiedName,
    pub display_name: LocalizedText,
    pub description: Option<LocalizedText>,
    pub refs: Vec<Ref>,
    pub kind: NodeKind,
}

impl Node {
    #[inline]
    pub fn class(&self) -> NodeClass {
        match self.kind {
            NodeKind::Object { .. } => NodeClass::Object,
            NodeKind::Variable { .. } => NodeClass::Variable,
            NodeKind::ObjectType { .. } => NodeClass::ObjectType,
            NodeKind::VariableType { .. } => NodeClass::VariableType,
            NodeKind::ReferenceType { .. } => NodeClass::ReferenceType,
            NodeKind::DataType { .. } => NodeClass::DataType,
            NodeKind::Method { .. } => NodeClass::Method,
        }
    }

    /// Target of the forward HasProperty reference named `name`.
    pub fn property<'a>(&self, space: &'a AddressSpace, name: &str) -> Option<&'a Node> {
        self.refs
            .iter()
            .filter(|r| r.forward && r.type_id == ids::HAS_PROPERTY)
            .map(|r| space.node(r.target))
            .find(|n| n.browse_name.ns == 0 && &*n.browse_name.name == name)
    }

    /// EURange (low, high) of an AnalogItem.
    pub fn eu_range(&self, space: &AddressSpace) -> Option<(f64, f64)> {
        let NodeKind::Variable { value: ValueSource::Static(Variant::ExtensionObject(x)), .. } =
            &self.property(space, "EURange")?.kind
        else {
            return None;
        };
        if x.type_id != NodeId::ns0(ids::RANGE_ENCODING) || x.encoding != 1 || x.body.len() != 16 {
            return None;
        }
        let low = f64::from_le_bytes(x.body[..8].try_into().unwrap());
        let high = f64::from_le_bytes(x.body[8..].try_into().unwrap());
        Some((low, high))
    }

    /// Target of the HasTypeDefinition reference, if any.
    pub fn type_definition(&self) -> Option<u32> {
        self.refs.iter().find(|r| r.forward && r.type_id == ids::HAS_TYPE_DEFINITION).map(|r| r.target)
    }
}

/// Static description of the server, used for ServerStatus and discovery.
#[derive(Clone, Debug)]
pub struct ServerInfo {
    pub application_uri: String,
    pub product_uri: String,
    pub application_name: String,
    pub manufacturer_name: String,
    pub product_name: String,
    pub software_version: String,
    pub build_number: String,
    pub build_date: i64,
    pub start_time: i64,
    /// Published in Server/ServerCapabilities.
    pub limits: crate::server::Limits,
    /// Shared by every snapshot and clone.
    pub diagnostics: Arc<crate::diagnostics::Diagnostics>,
}

impl Default for ServerInfo {
    fn default() -> Self {
        let host = std::env::var("HOSTNAME").unwrap_or_else(|_| "localhost".into());
        ServerInfo {
            application_uri: format!("urn:{host}:fastua"),
            product_uri: "urn:fastua".into(),
            application_name: "fastua OPC UA Server".into(),
            manufacturer_name: "fastua".into(),
            product_name: "fastua".into(),
            software_version: env!("CARGO_PKG_VERSION").into(),
            build_number: env!("CARGO_PKG_VERSION").into(),
            build_date: 0,
            start_time: now_ticks(),
            limits: Default::default(),
            diagnostics: Default::default(),
        }
    }
}

pub struct AddressSpace {
    pub nodes: Vec<Node>,
    index: FxHashMap<NodeId, u32>,
    /// Per namespace, numeric id -> node index (`u32::MAX` = absent) when the
    /// namespace's numeric ids are dense enough: one bounds check and one load
    /// instead of hashing and probing. Empty for sparse namespaces.
    dense: Vec<Box<[u32]>>,
    pub namespaces: Vec<Arc<str>>,
    pub generation: u64,
    pub info: Arc<ServerInfo>,
    /// Shared by every snapshot: events outlive reloads.
    pub events: Arc<crate::events::EventBus>,
    /// Shared by every snapshot: condition states outlive reloads.
    pub alarms: Arc<crate::alarms::Alarms>,
}

impl AddressSpace {
    #[inline]
    pub fn find(&self, id: &NodeId) -> Option<u32> {
        if let NodeId::Numeric(ns, v) = *id {
            if let Some(t) = self.dense.get(ns as usize).filter(|t| !t.is_empty()) {
                // The table holds every numeric id of the namespace.
                return t.get(v as usize).copied().filter(|&i| i != u32::MAX);
            }
        }
        self.index.get(id).copied()
    }

    #[inline]
    pub fn node(&self, idx: u32) -> &Node {
        &self.nodes[idx as usize]
    }

    #[inline]
    pub fn get(&self, id: &NodeId) -> Option<&Node> {
        self.find(id).map(|i| self.node(i))
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Value cell of a configured variable, for reuse across reloads.
    fn cell(&self, id: &NodeId) -> Option<&Arc<ValueCell>> {
        match &self.get(id)?.kind {
            NodeKind::Variable { value: ValueSource::Cell(c), .. } => Some(c),
            _ => None,
        }
    }
}

/// Parent of a standard reference type (namespace 0).
#[inline]
pub fn ref_type_parent(t: u32) -> Option<u32> {
    crate::ns0::ref_type_parent(t)
}

/// Whether `t` is `base` or (when `include_subtypes`) one of its subtypes.
#[inline]
pub fn ref_type_matches(t: u32, base: u32, include_subtypes: bool) -> bool {
    if t == base || base == 0 {
        return true;
    }
    if !include_subtypes {
        return false;
    }
    let mut cur = t;
    while let Some(p) = ref_type_parent(cur) {
        if p == base {
            return true;
        }
        cur = p;
    }
    false
}

pub fn is_known_ref_type(t: u32) -> bool {
    t == ids::REFERENCES || ref_type_parent(t).is_some()
}

/// Stable assignment of namespace URIs to indexes. Lives for the whole life
/// of the process: a URI never changes index, even if its file disappears and
/// comes back, because clients are allowed to cache indexes.
pub struct NamespaceRegistry {
    uris: Vec<Arc<str>>,
}

pub const NS0_URI: &str = "http://opcfoundation.org/UA/";

impl NamespaceRegistry {
    pub fn new(application_uri: &str) -> Self {
        NamespaceRegistry { uris: vec![NS0_URI.into(), application_uri.into()] }
    }

    pub fn index_of(&mut self, uri: &str) -> Result<u16, String> {
        if let Some(i) = self.uris.iter().position(|u| &**u == uri) {
            return Ok(i as u16);
        }
        if self.uris.len() > u16::MAX as usize {
            return Err("too many namespaces".into());
        }
        self.uris.push(uri.into());
        Ok((self.uris.len() - 1) as u16)
    }

    pub fn uris(&self) -> &[Arc<str>] {
        &self.uris
    }
}

struct Builder {
    nodes: Vec<Node>,
    index: FxHashMap<NodeId, u32>,
}

impl Builder {
    fn add(&mut self, node: Node) -> Result<u32, String> {
        let idx = self.nodes.len() as u32;
        if self.index.insert(node.id.clone(), idx).is_some() {
            return Err(format!("duplicate NodeId {}", node.id));
        }
        self.nodes.push(node);
        Ok(idx)
    }

    fn link(&mut self, src: u32, type_id: u32, dst: u32) {
        self.nodes[src as usize].refs.push(Ref { type_id, forward: true, target: dst });
        self.nodes[dst as usize].refs.push(Ref { type_id, forward: false, target: src });
    }

    fn idx(&self, ns0: u32) -> u32 {
        self.index[&NodeId::ns0(ns0)]
    }

    fn basic(id: NodeId, name: &str, ns: u16, kind: NodeKind) -> Node {
        Node {
            id,
            browse_name: QualifiedName { ns, name: name.into() },
            display_name: LocalizedText::new(name),
            description: None,
            refs: Vec::new(),
            kind,
        }
    }

    fn ns0(&mut self, id: u32, name: &str, kind: NodeKind) -> u32 {
        self.add(Self::basic(NodeId::ns0(id), name, 0, kind)).expect("ns0 ids are unique")
    }

    fn folder(&mut self, id: u32, name: &str, parent: u32) -> u32 {
        let n = self.ns0(id, name, NodeKind::Object { event_notifier: 0 });
        let ft = self.idx(ids::FOLDER_TYPE);
        self.link(n, ids::HAS_TYPE_DEFINITION, ft);
        let p = self.idx(parent);
        self.link(p, ids::ORGANIZES, n);
        n
    }

    fn subtype(&mut self, parent: u32, child: u32) {
        let (p, c) = (self.idx(parent), self.idx(child));
        self.link(p, ids::HAS_SUBTYPE, c);
    }

    fn property(&mut self, id: u32, name: &str, parent: u32, data_type: u32, value_rank: i32, value: ValueSource) {
        let n = self.ns0(
            id,
            name,
            NodeKind::Variable { data_type: NodeId::ns0(data_type), value_rank, access: ACCESS_READ, value },
        );
        let pt = self.idx(ids::PROPERTY_TYPE);
        self.link(n, ids::HAS_TYPE_DEFINITION, pt);
        let p = self.idx(parent);
        self.link(p, ids::HAS_PROPERTY, n);
    }

    fn object(&mut self, id: u32, name: &str, parent: u32, type_def: u32) -> u32 {
        let n = self.ns0(id, name, NodeKind::Object { event_notifier: 0 });
        let td = self.idx(type_def);
        self.link(n, ids::HAS_TYPE_DEFINITION, td);
        let p = self.idx(parent);
        self.link(p, ids::HAS_COMPONENT, n);
        n
    }

    fn method(&mut self, id: u32, name: &str, parent: u32, inputs: &[Argument], outputs: &[Argument]) {
        let n = self.ns0(id, name, NodeKind::Method { executable: true });
        let p = self.idx(parent);
        self.link(p, ids::HAS_COMPONENT, n);
        for (args, name, prop) in [(inputs, "InputArguments", id + 1), (outputs, "OutputArguments", id + 2)] {
            if args.is_empty() {
                continue;
            }
            let items = args.iter().map(Argument::encode).collect();
            let value = Variant::Array(Box::new(VariantArray { type_id: builtin::EXTENSIONOBJECT, items, dims: None }));
            self.property(prop, name, id, ids::ARGUMENT, 1, ValueSource::Static(value));
        }
    }

    fn component_var(&mut self, id: u32, name: &str, parent: u32, data_type: u32, type_def: u32, value: ValueSource) {
        let n = self.ns0(
            id,
            name,
            NodeKind::Variable { data_type: NodeId::ns0(data_type), value_rank: -1, access: ACCESS_READ, value },
        );
        let td = self.idx(type_def);
        self.link(n, ids::HAS_TYPE_DEFINITION, td);
        let p = self.idx(parent);
        self.link(p, ids::HAS_COMPONENT, n);
    }
}

/// A method argument description (Argument structure).
pub struct Argument {
    pub name: &'static str,
    pub data_type: u32,
    pub value_rank: i32,
}

impl Argument {
    fn encode(&self) -> Variant {
        use crate::codec::Writer;
        let mut body = Vec::new();
        let mut w = Writer::new(&mut body);
        w.string(self.name);
        w.node_id(&NodeId::ns0(self.data_type));
        w.i32(self.value_rank);
        if self.value_rank > 0 {
            w.i32(1);
            w.u32(0);
        } else {
            w.null_array();
        }
        w.u8(0); // description
        Variant::ExtensionObject(Box::new(ExtensionObject {
            type_id: NodeId::ns0(ids::ARGUMENT_ENCODING),
            encoding: 1,
            body: body.into(),
        }))
    }
}

const DATA_TYPES: &[(u32, &str, u32, bool)] = &[
    // (id, name, parent, abstract)
    (ids::BASE_DATA_TYPE, "BaseDataType", 0, true),
    (1, "Boolean", ids::BASE_DATA_TYPE, false),
    (ids::NUMBER, "Number", ids::BASE_DATA_TYPE, true),
    (ids::INTEGER, "Integer", ids::NUMBER, true),
    (ids::UINTEGER, "UInteger", ids::NUMBER, true),
    (2, "SByte", ids::INTEGER, false),
    (3, "Byte", ids::UINTEGER, false),
    (4, "Int16", ids::INTEGER, false),
    (5, "UInt16", ids::UINTEGER, false),
    (6, "Int32", ids::INTEGER, false),
    (7, "UInt32", ids::UINTEGER, false),
    (8, "Int64", ids::INTEGER, false),
    (9, "UInt64", ids::UINTEGER, false),
    (10, "Float", ids::NUMBER, false),
    (11, "Double", ids::NUMBER, false),
    (12, "String", ids::BASE_DATA_TYPE, false),
    (13, "DateTime", ids::BASE_DATA_TYPE, false),
    (ids::UTC_TIME, "UtcTime", 13, false),
    (crate::events::types::DURATION, "Duration", 11, false),
    (295, "LocaleId", 12, false),
    (14, "Guid", ids::BASE_DATA_TYPE, false),
    (15, "ByteString", ids::BASE_DATA_TYPE, false),
    (16, "XmlElement", ids::BASE_DATA_TYPE, false),
    (17, "NodeId", ids::BASE_DATA_TYPE, false),
    (18, "ExpandedNodeId", ids::BASE_DATA_TYPE, false),
    (19, "StatusCode", ids::BASE_DATA_TYPE, false),
    (20, "QualifiedName", ids::BASE_DATA_TYPE, false),
    (21, "LocalizedText", ids::BASE_DATA_TYPE, false),
    (ids::STRUCTURE, "Structure", ids::BASE_DATA_TYPE, true),
    (23, "DataValue", ids::BASE_DATA_TYPE, false),
    (25, "DiagnosticInfo", ids::BASE_DATA_TYPE, false),
    (ids::ENUMERATION, "Enumeration", ids::BASE_DATA_TYPE, true),
    (ids::SERVER_STATE, "ServerState", ids::ENUMERATION, false),
    (ids::BUILD_INFO, "BuildInfo", ids::STRUCTURE, false),
    (ids::SERVER_STATUS_DATA_TYPE, "ServerStatusDataType", ids::STRUCTURE, false),
    (ids::RANGE, "Range", ids::STRUCTURE, false),
    (ids::ARGUMENT, "Argument", ids::STRUCTURE, false),
    (ids::SIGNED_SOFTWARE_CERTIFICATE, "SignedSoftwareCertificate", ids::STRUCTURE, false),
    (ids::REDUNDANCY_SUPPORT, "RedundancySupport", ids::ENUMERATION, false),
];

const REF_TYPES: &[(u32, &str, Option<&str>, bool, bool)] = &[
    // (id, name, inverse name, abstract, symmetric)
    (ids::REFERENCES, "References", None, true, true),
    (ids::HIERARCHICAL_REFERENCES, "HierarchicalReferences", Some("InverseHierarchicalReferences"), true, false),
    (ids::NON_HIERARCHICAL_REFERENCES, "NonHierarchicalReferences", None, true, true),
    (ids::HAS_CHILD, "HasChild", Some("ChildOf"), true, false),
    (ids::ORGANIZES, "Organizes", Some("OrganizedBy"), false, false),
    (ids::HAS_EVENT_SOURCE, "HasEventSource", Some("EventSourceOf"), false, false),
    (ids::HAS_MODELLING_RULE, "HasModellingRule", Some("ModellingRuleOf"), false, false),
    (ids::HAS_ENCODING, "HasEncoding", Some("EncodingOf"), false, false),
    (ids::HAS_DESCRIPTION, "HasDescription", Some("DescriptionOf"), false, false),
    (ids::HAS_TYPE_DEFINITION, "HasTypeDefinition", Some("TypeDefinitionOf"), false, false),
    (ids::GENERATES_EVENT, "GeneratesEvent", Some("GeneratedBy"), false, false),
    (ids::AGGREGATES, "Aggregates", Some("AggregatedBy"), true, false),
    (ids::HAS_SUBTYPE, "HasSubtype", Some("SubtypeOf"), false, false),
    (ids::HAS_PROPERTY, "HasProperty", Some("PropertyOf"), false, false),
    (ids::HAS_COMPONENT, "HasComponent", Some("ComponentOf"), false, false),
    (ids::HAS_NOTIFIER, "HasNotifier", Some("NotifierOf"), false, false),
    (ids::HAS_ORDERED_COMPONENT, "HasOrderedComponent", Some("OrderedComponentOf"), false, false),
    (ids::HAS_CONDITION, "HasCondition", Some("IsConditionOf"), false, false),
];

fn build_ns0(b: &mut Builder, namespaces: &[Arc<str>], info: &ServerInfo) {
    // Root and the type folders come first: everything else links to them.
    b.ns0(ids::ROOT_FOLDER, "Root", NodeKind::Object { event_notifier: 0 });
    b.ns0(ids::BASE_OBJECT_TYPE, "BaseObjectType", NodeKind::ObjectType { is_abstract: false });
    b.ns0(ids::FOLDER_TYPE, "FolderType", NodeKind::ObjectType { is_abstract: false });
    b.ns0(ids::SERVER_TYPE, "ServerType", NodeKind::ObjectType { is_abstract: false });
    let vt = |dt: u32, rank: i32, abs: bool| NodeKind::VariableType {
        is_abstract: abs,
        data_type: NodeId::ns0(dt),
        value_rank: rank,
    };
    b.ns0(ids::BASE_VARIABLE_TYPE, "BaseVariableType", vt(ids::BASE_DATA_TYPE, -2, true));
    b.ns0(ids::BASE_DATA_VARIABLE_TYPE, "BaseDataVariableType", vt(ids::BASE_DATA_TYPE, -2, false));
    b.ns0(ids::PROPERTY_TYPE, "PropertyType", vt(ids::BASE_DATA_TYPE, -2, false));
    b.ns0(ids::SERVER_STATUS_TYPE, "ServerStatusType", vt(ids::SERVER_STATUS_DATA_TYPE, -1, false));
    b.ns0(ids::DATA_ITEM_TYPE, "DataItemType", vt(ids::BASE_DATA_TYPE, -2, false));
    b.ns0(ids::BUILD_INFO_TYPE, "BuildInfoType", vt(ids::BUILD_INFO, -1, false));
    for (id, name) in [
        (ids::SERVER_CAPABILITIES_TYPE, "ServerCapabilitiesType"),
        (ids::SERVER_DIAGNOSTICS_TYPE, "ServerDiagnosticsType"),
        (ids::VENDOR_SERVER_INFO_TYPE, "VendorServerInfoType"),
        (ids::SERVER_REDUNDANCY_TYPE, "ServerRedundancyType"),
        (ids::OPERATION_LIMITS_TYPE, "OperationLimitsType"),
        (ids::HISTORY_SERVER_CAPABILITIES_TYPE, "HistoryServerCapabilitiesType"),
        (crate::aggregates::AGGREGATE_FUNCTION_TYPE, "AggregateFunctionType"),
    ] {
        b.ns0(id, name, NodeKind::ObjectType { is_abstract: false });
    }
    b.ns0(ids::ANALOG_ITEM_TYPE, "AnalogItemType", vt(ids::NUMBER, -2, false));

    let root = b.idx(ids::ROOT_FOLDER);
    let ft = b.idx(ids::FOLDER_TYPE);
    b.link(root, ids::HAS_TYPE_DEFINITION, ft);
    b.folder(ids::OBJECTS_FOLDER, "Objects", ids::ROOT_FOLDER);
    b.folder(ids::TYPES_FOLDER, "Types", ids::ROOT_FOLDER);
    b.folder(ids::VIEWS_FOLDER, "Views", ids::ROOT_FOLDER);
    b.folder(ids::OBJECT_TYPES_FOLDER, "ObjectTypes", ids::TYPES_FOLDER);
    b.folder(ids::VARIABLE_TYPES_FOLDER, "VariableTypes", ids::TYPES_FOLDER);
    b.folder(ids::DATA_TYPES_FOLDER, "DataTypes", ids::TYPES_FOLDER);
    b.folder(ids::REFERENCE_TYPES_FOLDER, "ReferenceTypes", ids::TYPES_FOLDER);

    // Object types
    let (otf, bot) = (b.idx(ids::OBJECT_TYPES_FOLDER), b.idx(ids::BASE_OBJECT_TYPE));
    b.link(otf, ids::ORGANIZES, bot);
    b.subtype(ids::BASE_OBJECT_TYPE, ids::FOLDER_TYPE);
    b.subtype(ids::BASE_OBJECT_TYPE, ids::SERVER_TYPE);
    for t in [
        ids::SERVER_CAPABILITIES_TYPE,
        ids::SERVER_DIAGNOSTICS_TYPE,
        ids::VENDOR_SERVER_INFO_TYPE,
        ids::SERVER_REDUNDANCY_TYPE,
        ids::OPERATION_LIMITS_TYPE,
        ids::HISTORY_SERVER_CAPABILITIES_TYPE,
        crate::aggregates::AGGREGATE_FUNCTION_TYPE,
    ] {
        b.subtype(ids::BASE_OBJECT_TYPE, t);
    }

    // Variable types
    let (vtf, bvt) = (b.idx(ids::VARIABLE_TYPES_FOLDER), b.idx(ids::BASE_VARIABLE_TYPE));
    b.link(vtf, ids::ORGANIZES, bvt);
    b.subtype(ids::BASE_VARIABLE_TYPE, ids::BASE_DATA_VARIABLE_TYPE);
    b.subtype(ids::BASE_VARIABLE_TYPE, ids::PROPERTY_TYPE);
    b.subtype(ids::BASE_DATA_VARIABLE_TYPE, ids::SERVER_STATUS_TYPE);
    b.subtype(ids::BASE_DATA_VARIABLE_TYPE, ids::DATA_ITEM_TYPE);
    b.subtype(ids::BASE_DATA_VARIABLE_TYPE, ids::BUILD_INFO_TYPE);
    b.subtype(ids::DATA_ITEM_TYPE, ids::ANALOG_ITEM_TYPE);

    // Data types
    for &(id, name, parent, abs) in DATA_TYPES {
        b.ns0(id, name, NodeKind::DataType { is_abstract: abs });
        if parent != 0 {
            b.subtype(parent, id);
        }
    }
    let (dtf, bdt) = (b.idx(ids::DATA_TYPES_FOLDER), b.idx(ids::BASE_DATA_TYPE));
    b.link(dtf, ids::ORGANIZES, bdt);

    // Reference types
    for &(id, name, inverse, abs, sym) in REF_TYPES {
        b.ns0(
            id,
            name,
            NodeKind::ReferenceType { is_abstract: abs, symmetric: sym, inverse_name: inverse.map(LocalizedText::new) },
        );
    }
    // Their HasSubtype hierarchy comes from the nodeset (merge_nodeset).
    let (rtf, refs) = (b.idx(ids::REFERENCE_TYPES_FOLDER), b.idx(ids::REFERENCES));
    b.link(rtf, ids::ORGANIZES, refs);

    // Modelling rules (instance declarations of the event types use them).
    b.ns0(ids::MODELLING_RULE_TYPE, "ModellingRuleType", NodeKind::ObjectType { is_abstract: false });
    b.subtype(ids::BASE_OBJECT_TYPE, ids::MODELLING_RULE_TYPE);
    let mrt = b.idx(ids::MODELLING_RULE_TYPE);
    for (id, name) in [(ids::MODELLING_RULE_MANDATORY, "Mandatory"), (ids::MODELLING_RULE_OPTIONAL, "Optional")] {
        let n = b.ns0(id, name, NodeKind::Object { event_notifier: 0 });
        b.link(n, ids::HAS_TYPE_DEFINITION, mrt);
    }
    let mandatory = b.idx(ids::MODELLING_RULE_MANDATORY);

    // Types the condition fields are instances of (Part 5 §B, Part 9).
    use crate::alarms::types as at;
    for (id, name, parent, abs) in [
        (at::STATE_VARIABLE_TYPE, "StateVariableType", ids::BASE_DATA_VARIABLE_TYPE, false),
        (at::TWO_STATE_VARIABLE_TYPE, "TwoStateVariableType", at::STATE_VARIABLE_TYPE, false),
        (at::FINITE_STATE_VARIABLE_TYPE, "FiniteStateVariableType", at::STATE_VARIABLE_TYPE, false),
        (at::CONDITION_VARIABLE_TYPE, "ConditionVariableType", ids::BASE_DATA_VARIABLE_TYPE, false),
    ] {
        b.ns0(id, name, vt(21, -1, abs));
        b.subtype(parent, id);
    }
    for (id, name, parent, abs) in [
        (at::STATE_MACHINE_TYPE, "StateMachineType", ids::BASE_OBJECT_TYPE, false),
        (at::FINITE_STATE_MACHINE_TYPE, "FiniteStateMachineType", at::STATE_MACHINE_TYPE, true),
        (
            at::EXCLUSIVE_LIMIT_STATE_MACHINE_TYPE,
            "ExclusiveLimitStateMachineType",
            at::FINITE_STATE_MACHINE_TYPE,
            false,
        ),
        (at::BASE_CONDITION_CLASS_TYPE, "BaseConditionClassType", ids::BASE_OBJECT_TYPE, true),
        (at::PROCESS_CONDITION_CLASS_TYPE, "ProcessConditionClassType", at::BASE_CONDITION_CLASS_TYPE, true),
    ] {
        b.ns0(id, name, NodeKind::ObjectType { is_abstract: abs });
        b.subtype(parent, id);
    }

    // Event types and their fields. A field named `A/B` is a child of
    // field `A`; a field with children is a component variable (or, with
    // data type 0, an object).
    for t in crate::events::EVENT_TYPES {
        b.ns0(t.id, t.name, NodeKind::ObjectType { is_abstract: t.is_abstract });
        b.subtype(t.parent, t.id);
        for &(decl, name, data_type, rank) in t.fields {
            let (parent, leaf) = match name.rsplit_once('/') {
                Some((p, leaf)) => (t.fields.iter().find(|f| f.1 == p).map_or(t.id, |f| f.0), leaf),
                None => (t.id, name),
            };
            let has_children = t
                .fields
                .iter()
                .any(|f| f.1.len() > name.len() && f.1.starts_with(name) && f.1.as_bytes()[name.len()] == b'/');
            if data_type == 0 {
                b.object(decl, leaf, parent, at::EXCLUSIVE_LIMIT_STATE_MACHINE_TYPE);
            } else if has_children {
                let type_def = if leaf == "CurrentState" {
                    at::FINITE_STATE_VARIABLE_TYPE
                } else if leaf.ends_with("State") {
                    at::TWO_STATE_VARIABLE_TYPE
                } else {
                    at::CONDITION_VARIABLE_TYPE
                };
                b.component_var(decl, leaf, parent, data_type, type_def, ValueSource::Static(Variant::Empty));
            } else {
                b.property(decl, leaf, parent, data_type, rank, ValueSource::Static(Variant::Empty));
            }
            let d = b.idx(decl);
            b.link(d, ids::HAS_MODELLING_RULE, mandatory);
        }
    }
    // Condition methods (Part 9 §5.5, §5.7).
    let event_id = || Argument { name: "EventId", data_type: 15, value_rank: -1 };
    let comment = || Argument { name: "Comment", data_type: 21, value_rank: -1 };
    let sub = || Argument { name: "SubscriptionId", data_type: 288, value_rank: -1 };
    use crate::events::types::{ACKNOWLEDGEABLE_CONDITION_TYPE as ACK, CONDITION_TYPE as COND};
    b.method(at::DISABLE, "Disable", COND, &[], &[]);
    b.method(at::ENABLE, "Enable", COND, &[], &[]);
    b.method(at::ADD_COMMENT, "AddComment", COND, &[event_id(), comment()], &[]);
    b.method(at::CONDITION_REFRESH, "ConditionRefresh", COND, &[sub()], &[]);
    b.method(
        at::CONDITION_REFRESH2,
        "ConditionRefresh2",
        COND,
        &[sub(), Argument { name: "MonitoredItemId", data_type: 288, value_rank: -1 }],
        &[],
    );
    b.method(at::ACKNOWLEDGE, "Acknowledge", ACK, &[event_id(), comment()], &[]);
    b.method(at::CONFIRM, "Confirm", ACK, &[event_id(), comment()], &[]);

    // Server object: the root notifier of every event.
    let server = b.ns0(ids::SERVER, "Server", NodeKind::Object { event_notifier: 1 });
    let (objects, st) = (b.idx(ids::OBJECTS_FOLDER), b.idx(ids::SERVER_TYPE));
    b.link(objects, ids::ORGANIZES, server);
    b.link(server, ids::HAS_TYPE_DEFINITION, st);
    let ns_items: Vec<Variant> = namespaces.iter().map(|u| Variant::string(u)).collect();
    b.property(
        ids::SERVER_NAMESPACE_ARRAY,
        "NamespaceArray",
        ids::SERVER,
        12,
        1,
        ValueSource::Static(Variant::Array(Box::new(VariantArray {
            type_id: builtin::STRING,
            items: ns_items,
            dims: None,
        }))),
    );
    b.property(
        ids::SERVER_SERVER_ARRAY,
        "ServerArray",
        ids::SERVER,
        12,
        1,
        ValueSource::Static(Variant::string_array(&[&info.application_uri])),
    );
    b.property(ids::SERVER_SERVICE_LEVEL, "ServiceLevel", ids::SERVER, 3, -1, ValueSource::Static(Variant::Byte(255)));
    b.component_var(
        ids::SERVER_SERVER_STATUS,
        "ServerStatus",
        ids::SERVER,
        ids::SERVER_STATUS_DATA_TYPE,
        ids::SERVER_STATUS_TYPE,
        ValueSource::ServerStatus,
    );
    b.component_var(
        ids::SERVER_SERVER_STATUS_START_TIME,
        "StartTime",
        ids::SERVER_SERVER_STATUS,
        ids::UTC_TIME,
        ids::BASE_DATA_VARIABLE_TYPE,
        ValueSource::Static(Variant::DateTime(info.start_time)),
    );
    b.component_var(
        ids::SERVER_SERVER_STATUS_CURRENT_TIME,
        "CurrentTime",
        ids::SERVER_SERVER_STATUS,
        ids::UTC_TIME,
        ids::BASE_DATA_VARIABLE_TYPE,
        ValueSource::CurrentTime,
    );
    b.component_var(
        ids::SERVER_SERVER_STATUS_STATE,
        "State",
        ids::SERVER_SERVER_STATUS,
        ids::SERVER_STATE,
        ids::BASE_DATA_VARIABLE_TYPE,
        ValueSource::Static(Variant::Int32(0)),
    );
    build_server_details(b, info);
    merge_nodeset(b);
    diagnostics_values(b);
}

/// Live values of ServerDiagnosticsSummary, and empty per-session arrays
/// (per-session diagnostics are not collected: EnabledFlag is false).
fn diagnostics_values(b: &mut Builder) {
    use crate::diagnostics::{FIELD_NODES, SUMMARY, SUMMARY_NODE};
    let mut set = |id: u32, v: ValueSource| {
        let i = b.idx(id);
        if let NodeKind::Variable { value, .. } = &mut b.nodes[i as usize].kind {
            *value = v;
        }
    };
    set(SUMMARY_NODE, ValueSource::Diagnostics(SUMMARY));
    for (i, &id) in FIELD_NODES.iter().enumerate() {
        set(id, ValueSource::Diagnostics(i as u8));
    }
    // SamplingIntervalDiagnosticsArray, SubscriptionDiagnosticsArray,
    // SessionDiagnosticsArray, SessionSecurityDiagnosticsArray.
    for id in [2289, 2290, 3707, 3708] {
        let empty =
            Variant::Array(Box::new(VariantArray { type_id: builtin::EXTENSIONOBJECT, items: vec![], dims: None }));
        set(id, ValueSource::Static(empty));
    }
}

/// Completes namespace 0 from the official nodeset (see [`crate::ns0`]).
///
/// Nodes built above keep their attributes and live values; the nodeset adds
/// the missing nodes and references. A node keeps at most one
/// HasTypeDefinition and one HasModellingRule, and two nodes already linked
/// by a hierarchical reference get no second one.
fn merge_nodeset(b: &mut Builder) {
    let nodes = crate::ns0::nodes();
    // Every reference appears on both of its nodes: keep the forward side.
    let mut refs = Vec::with_capacity(nodes.iter().map(|n| n.refs.len()).sum::<usize>() / 2);
    for n in nodes {
        refs.extend(n.refs.iter().filter(|r| r.1).map(|&(t, _, d)| (n.id, t, d)));
        let id = NodeId::ns0(n.id);
        if let Some(&i) = b.index.get(&id) {
            let node = &mut b.nodes[i as usize];
            if node.description.is_none() {
                node.description = n.description;
            }
            continue;
        }
        b.nodes.push(Node {
            id: id.clone(),
            browse_name: n.browse_name,
            display_name: n.display_name,
            description: n.description,
            refs: Vec::with_capacity(n.refs.len()),
            kind: n.kind,
        });
        b.index.insert(id, b.nodes.len() as u32 - 1);
    }
    let hierarchical = |t| ref_type_matches(t, ids::HIERARCHICAL_REFERENCES, true);
    for (s, t, d) in refs {
        let (Some(&si), Some(&di)) = (b.index.get(&NodeId::ns0(s)), b.index.get(&NodeId::ns0(d))) else {
            continue;
        };
        let single = t == ids::HAS_TYPE_DEFINITION || t == ids::HAS_MODELLING_RULE;
        let linked = b.nodes[si as usize].refs.iter().any(|r| {
            r.forward
                && (r.type_id == t && (single || r.target == di)
                    || r.target == di && hierarchical(t) && hierarchical(r.type_id))
        });
        // A type has one supertype.
        let second_parent = t == ids::HAS_SUBTYPE
            && b.nodes[di as usize].refs.iter().any(|r| !r.forward && r.type_id == ids::HAS_SUBTYPE);
        if !linked && !second_parent {
            b.link(si, t, di);
        }
    }
}

/// ServerStatus/BuildInfo, ServerCapabilities, diagnostics, redundancy,
/// auditing and the Server methods (Part 5 §6.3.1, §8.3.2).
fn build_server_details(b: &mut Builder, info: &ServerInfo) {
    let bdv = ids::BASE_DATA_VARIABLE_TYPE;
    let status = ids::SERVER_SERVER_STATUS;
    b.component_var(
        ids::SERVER_SERVER_STATUS_BUILD_INFO,
        "BuildInfo",
        status,
        ids::BUILD_INFO,
        ids::BUILD_INFO_TYPE,
        ValueSource::Static(encode_build_info(info)),
    );
    let bi = ids::SERVER_SERVER_STATUS_BUILD_INFO;
    let s = |v: &str| ValueSource::Static(Variant::string(v));
    b.component_var(2262, "ProductUri", bi, 12, bdv, s(&info.product_uri));
    b.component_var(2263, "ManufacturerName", bi, 12, bdv, s(&info.manufacturer_name));
    b.component_var(2261, "ProductName", bi, 12, bdv, s(&info.product_name));
    b.component_var(2264, "SoftwareVersion", bi, 12, bdv, s(&info.software_version));
    b.component_var(2265, "BuildNumber", bi, 12, bdv, s(&info.build_number));
    b.component_var(2266, "BuildDate", bi, ids::UTC_TIME, bdv, ValueSource::Static(Variant::DateTime(info.build_date)));
    b.component_var(2992, "SecondsTillShutdown", status, 7, bdv, ValueSource::Static(Variant::UInt32(0)));
    b.component_var(
        2993,
        "ShutdownReason",
        status,
        21,
        bdv,
        ValueSource::Static(Variant::LocalizedText(Box::default())),
    );

    let l = &info.limits;
    let caps = ids::SERVER_SERVER_CAPABILITIES;
    b.object(caps, "ServerCapabilities", ids::SERVER, ids::SERVER_CAPABILITIES_TYPE);
    let fixed = |v: Variant| ValueSource::Static(v);
    b.property(
        2269,
        "ServerProfileArray",
        caps,
        12,
        1,
        fixed(Variant::string_array(&["http://opcfoundation.org/UA-Profile/Server/StandardUA2017"])),
    );
    b.property(2271, "LocaleIdArray", caps, 295, 1, fixed(Variant::string_array(&[])));
    b.property(2272, "MinSupportedSampleRate", caps, 290, -1, fixed(Variant::Double(l.min_sampling_interval_ms)));
    let cps = l.max_browse_continuation_points.min(u16::MAX as usize) as u16;
    b.property(2735, "MaxBrowseContinuationPoints", caps, 5, -1, fixed(Variant::UInt16(cps)));
    b.property(2736, "MaxQueryContinuationPoints", caps, 5, -1, fixed(Variant::UInt16(0)));
    b.property(2737, "MaxHistoryContinuationPoints", caps, 5, -1, fixed(Variant::UInt16(0)));
    let no_certs =
        Variant::Array(Box::new(VariantArray { type_id: builtin::EXTENSIONOBJECT, items: vec![], dims: None }));
    b.property(3704, "SoftwareCertificates", caps, ids::SIGNED_SOFTWARE_CERTIFICATE, 1, fixed(no_certs));
    b.property(11702, "MaxArrayLength", caps, 7, -1, fixed(Variant::UInt32(l.max_message_size)));
    b.property(11703, "MaxStringLength", caps, 7, -1, fixed(Variant::UInt32(l.max_message_size)));
    b.property(12911, "MaxByteStringLength", caps, 7, -1, fixed(Variant::UInt32(l.max_message_size)));
    // OPC UA 1.05 capabilities (0 = no limit).
    let sat = |v: usize| Variant::UInt32(v.min(u32::MAX as usize) as u32);
    let subs = l.max_sessions.saturating_mul(l.max_subscriptions_per_session);
    for (id, name, value) in [
        (24095, "MaxSessions", sat(l.max_sessions)),
        (24096, "MaxSubscriptions", sat(subs)),
        (24097, "MaxMonitoredItems", sat(subs.saturating_mul(l.max_monitored_items_per_subscription))),
        (24098, "MaxSubscriptionsPerSession", sat(l.max_subscriptions_per_session)),
        (24104, "MaxMonitoredItemsPerSubscription", sat(l.max_monitored_items_per_subscription)),
        (24099, "MaxSelectClauseParameters", Variant::UInt32(0)),
        (24100, "MaxWhereClauseParameters", Variant::UInt32(0)),
        (31916, "MaxMonitoredItemsQueueSize", Variant::UInt32(l.max_queue_size)),
    ] {
        b.property(id, name, caps, 7, -1, fixed(value));
    }
    let ops = ids::OPERATION_LIMITS;
    b.object(ops, "OperationLimits", caps, ids::OPERATION_LIMITS_TYPE);
    let per_call = Variant::UInt32(l.max_operations_per_request.min(u32::MAX as usize) as u32);
    for (id, name) in [
        (11705, "MaxNodesPerRead"),
        (11707, "MaxNodesPerWrite"),
        (11709, "MaxNodesPerMethodCall"),
        (11710, "MaxNodesPerBrowse"),
        (11711, "MaxNodesPerRegisterNodes"),
        (11712, "MaxNodesPerTranslateBrowsePathsToNodeIds"),
        (11714, "MaxMonitoredItemsPerCall"),
    ] {
        b.property(id, name, ops, 7, -1, fixed(per_call.clone()));
    }
    b.property(11713, "MaxNodesPerNodeManagement", ops, 7, -1, fixed(Variant::UInt32(0)));
    for (id, name) in [(12165, "MaxNodesPerHistoryReadData"), (12167, "MaxNodesPerHistoryUpdateData")] {
        b.property(id, name, ops, 7, -1, fixed(per_call.clone()));
    }
    for (id, name) in [(12166, "MaxNodesPerHistoryReadEvents"), (12168, "MaxNodesPerHistoryUpdateEvents")] {
        b.property(id, name, ops, 7, -1, fixed(Variant::UInt32(0)));
    }

    // Historical access (Part 11 §5.4.2).
    let hist = ids::HISTORY_SERVER_CAPABILITIES;
    b.object(hist, "HistoryServerCapabilities", caps, ids::HISTORY_SERVER_CAPABILITIES_TYPE);
    for (id, name, value) in [
        (11193, "AccessHistoryDataCapability", true),
        (11242, "AccessHistoryEventsCapability", false),
        (11196, "InsertDataCapability", true),
        (11197, "ReplaceDataCapability", true),
        (11198, "UpdateDataCapability", true),
        (11199, "DeleteRawCapability", true),
        (11200, "DeleteAtTimeCapability", true),
        (11275, "InsertAnnotationCapability", false),
        (11281, "InsertEventCapability", false),
        (11282, "ReplaceEventCapability", false),
        (11283, "UpdateEventCapability", false),
        (11502, "DeleteEventCapability", false),
        (19091, "ServerTimestampSupported", true),
    ] {
        b.property(id, name, hist, 1, -1, fixed(Variant::Boolean(value)));
    }
    let max_values = crate::history::MAX_RETURN_VALUES as u32;
    b.property(11273, "MaxReturnDataValues", hist, 7, -1, fixed(Variant::UInt32(max_values)));
    b.property(11274, "MaxReturnEventValues", hist, 7, -1, fixed(Variant::UInt32(0)));
    b.object(ids::HISTORY_AGGREGATE_FUNCTIONS, "AggregateFunctions", hist, ids::FOLDER_TYPE);
    b.folder(2996, "ModellingRules", ids::SERVER_SERVER_CAPABILITIES);
    b.folder(2997, "AggregateFunctions", ids::SERVER_SERVER_CAPABILITIES);
    // `folder` links with Organizes; capabilities hold them as components.
    for f in [2996, 2997] {
        let (c, n) = (b.idx(caps), b.idx(f));
        let r = b.nodes[c as usize].refs.iter_mut().find(|r| r.forward && r.target == n).unwrap();
        r.type_id = ids::HAS_COMPONENT;
        let r = b.nodes[n as usize].refs.iter_mut().find(|r| !r.forward && r.target == c).unwrap();
        r.type_id = ids::HAS_COMPONENT;
    }
    for rule in [ids::MODELLING_RULE_MANDATORY, ids::MODELLING_RULE_OPTIONAL] {
        let (f, r) = (b.idx(2996), b.idx(rule));
        b.link(f, ids::ORGANIZES, r);
    }
    // The aggregates, listed in both AggregateFunctions folders.
    let fn_type = b.idx(crate::aggregates::AGGREGATE_FUNCTION_TYPE);
    let folders = [b.idx(2997), b.idx(ids::HISTORY_AGGREGATE_FUNCTIONS)];
    for &(id, name) in crate::aggregates::FUNCTIONS {
        let n = b.ns0(id, name, NodeKind::Object { event_notifier: 0 });
        b.link(n, ids::HAS_TYPE_DEFINITION, fn_type);
        for f in folders {
            b.link(f, ids::ORGANIZES, n);
        }
    }

    let diag = 2274;
    b.object(diag, "ServerDiagnostics", ids::SERVER, ids::SERVER_DIAGNOSTICS_TYPE);
    b.property(2294, "EnabledFlag", diag, 1, -1, fixed(Variant::Boolean(false)));
    b.object(2295, "VendorServerInfo", ids::SERVER, ids::VENDOR_SERVER_INFO_TYPE);
    b.object(2296, "ServerRedundancy", ids::SERVER, ids::SERVER_REDUNDANCY_TYPE);
    b.property(3709, "RedundancySupport", 2296, ids::REDUNDANCY_SUPPORT, -1, fixed(Variant::Int32(0)));
    b.property(2994, "Auditing", ids::SERVER, 1, -1, fixed(Variant::Boolean(true)));

    let sub_id = Argument { name: "SubscriptionId", data_type: 7, value_rank: -1 };
    b.method(
        ids::SERVER_GET_MONITORED_ITEMS,
        "GetMonitoredItems",
        ids::SERVER,
        &[sub_id],
        &[
            Argument { name: "ServerHandles", data_type: 7, value_rank: 1 },
            Argument { name: "ClientHandles", data_type: 7, value_rank: 1 },
        ],
    );
    b.method(
        ids::SERVER_RESEND_DATA,
        "ResendData",
        ids::SERVER,
        &[Argument { name: "SubscriptionId", data_type: 7, value_rank: -1 }],
        &[],
    );
}

/// The BuildInfo structure.
fn encode_build_info(info: &ServerInfo) -> Variant {
    use crate::codec::Writer;
    let mut body = Vec::new();
    let mut w = Writer::new(&mut body);
    w.string(&info.product_uri);
    w.string(&info.manufacturer_name);
    w.string(&info.product_name);
    w.string(&info.software_version);
    w.string(&info.build_number);
    w.i64(info.build_date);
    Variant::ExtensionObject(Box::new(ExtensionObject {
        type_id: NodeId::ns0(ids::BUILD_INFO_ENCODING),
        encoding: 1,
        body: body.into(),
    }))
}

/// A `Range` structure value.
pub fn range_value(low: f64, high: f64) -> Variant {
    let mut body = [0u8; 16];
    body[..8].copy_from_slice(&low.to_le_bytes());
    body[8..].copy_from_slice(&high.to_le_bytes());
    Variant::ExtensionObject(Box::new(ExtensionObject {
        type_id: NodeId::ns0(ids::RANGE_ENCODING),
        encoding: 1,
        body: body.into(),
    }))
}

/// The condition of a variable, set on its cell once the build succeeded.
struct PendingAlarm {
    cell: Arc<ValueCell>,
    cfg: Option<crate::alarms::AlarmConfig>,
    id: NodeId,
    source: NodeId,
    name: String,
}

/// Builds a new snapshot. Cells of variables that still exist with the same
/// data type are taken over from `previous`, so values survive reloads.
pub fn build(
    configs: &[NamespaceConfig],
    registry: &mut NamespaceRegistry,
    previous: Option<&AddressSpace>,
    info: Arc<ServerInfo>,
    generation: u64,
) -> Result<AddressSpace, String> {
    // Assign indexes first so NamespaceArray is complete.
    let mut assigned = Vec::with_capacity(configs.len());
    for c in configs {
        assigned.push(registry.index_of(&c.uri)?);
    }
    let namespaces = registry.uris().to_vec();

    let capacity = 6144
        + configs
            .iter()
            .map(|c| {
                1 + c
                    .groups
                    .iter()
                    .map(|g| 1 + g.items.iter().map(|i| 1 + i.eu_range.is_some() as usize).sum::<usize>())
                    .sum::<usize>()
            })
            .sum::<usize>();
    let mut b = Builder {
        nodes: Vec::with_capacity(capacity),
        index: FxHashMap::with_capacity_and_hasher(capacity, Default::default()),
    };
    build_ns0(&mut b, &namespaces, &info);

    let objects = b.idx(ids::OBJECTS_FOLDER);
    let folder_type = b.idx(ids::FOLDER_TYPE);
    let bdv_type = b.idx(ids::BASE_DATA_VARIABLE_TYPE);
    let analog_type = b.idx(ids::ANALOG_ITEM_TYPE);
    let property_type = b.idx(ids::PROPERTY_TYPE);
    let created = now_ticks();
    let mut fresh = 0usize;
    let mut stamp = None;
    let mut history: Vec<(Arc<ValueCell>, Option<usize>)> = Vec::new();
    let events = previous.map(|p| p.events.clone()).unwrap_or_default();
    let alarms = previous.map(|p| p.alarms.clone()).unwrap_or_default();
    // Applied once the build succeeded, like history.
    let mut conditions: Vec<PendingAlarm> = Vec::new();

    for (c, &ns) in configs.iter().zip(&assigned) {
        let folder_id = |path: &str| NodeId::String(ns, format!("__folder/{path}").into());
        let mk_folder = |id: NodeId, name: &str| Node {
            id,
            browse_name: QualifiedName { ns, name: name.into() },
            display_name: LocalizedText::new(name),
            description: None,
            refs: Vec::new(),
            kind: NodeKind::Object { event_notifier: 0 },
        };
        let root = b.add(mk_folder(folder_id(&c.name), &c.name)).map_err(|e| format!("{}: {e}", c.source.display()))?;
        b.link(objects, ids::ORGANIZES, root);
        b.link(root, ids::HAS_TYPE_DEFINITION, folder_type);

        for g in &c.groups {
            let gid = folder_id(&format!("{}/{}", c.name, g.name));
            let group = b.add(mk_folder(gid, &g.name)).map_err(|e| format!("{}: {e}", c.source.display()))?;
            b.link(root, ids::ORGANIZES, group);
            b.link(group, ids::HAS_TYPE_DEFINITION, folder_type);

            for it in &g.items {
                let id = it.node_id.clone().with_namespace(ns);
                let cell =
                    previous.and_then(|p| p.cell(&id)).filter(|c| c.kind() == it.data_type).cloned().unwrap_or_else(
                        || {
                            // New cells share change stamps in blocks of 64.
                            let lane = (fresh % crate::value::BLOCK) as u32;
                            if lane == 0 {
                                stamp = Some(crate::value::new_stamp());
                            }
                            fresh += 1;
                            Arc::new(ValueCell::with_stamp(it.data_type, created, stamp.unwrap(), lane))
                        },
                    );
                let mut access = if it.writable { ACCESS_READ | ACCESS_WRITE } else { ACCESS_READ };
                if it.history.is_some() {
                    use crate::history::{ACCESS_HISTORY_READ, ACCESS_HISTORY_WRITE};
                    access |= ACCESS_HISTORY_READ | if it.writable { ACCESS_HISTORY_WRITE } else { 0 };
                }
                // Applied once the whole build succeeded (a failed reload
                // must leave the live cells untouched).
                history.push((cell.clone(), it.history));
                let alarm_id = NodeId::String(ns, format!("__alarm/{}", it.node_id).into());
                conditions.push(PendingAlarm {
                    cell: cell.clone(),
                    cfg: it.alarm.clone(),
                    id: alarm_id.clone(),
                    source: id.clone(),
                    name: it.name.clone(),
                });
                let var = b
                    .add(Node {
                        id,
                        browse_name: QualifiedName { ns, name: it.name.as_str().into() },
                        display_name: LocalizedText::new(&it.name),
                        description: None,
                        refs: Vec::with_capacity(2),
                        kind: NodeKind::Variable {
                            data_type: NodeId::ns0(it.data_type as u32),
                            value_rank: -1,
                            access,
                            value: ValueSource::Cell(cell),
                        },
                    })
                    .map_err(|e| format!("{}: item '{}': {e}", c.source.display(), it.name))?;
                b.link(group, ids::HAS_COMPONENT, var);
                if let Some(a) = &it.alarm {
                    let name = format!("{}Alarm", it.name);
                    let cond = b
                        .add(Node {
                            id: alarm_id,
                            browse_name: QualifiedName { ns, name: name.as_str().into() },
                            display_name: LocalizedText::new(&name),
                            description: None,
                            refs: Vec::with_capacity(2),
                            kind: NodeKind::Object { event_notifier: 0 },
                        })
                        .map_err(|e| format!("{}: item '{}': {e}", c.source.display(), it.name))?;
                    let td = b.idx(a.type_id());
                    b.link(cond, ids::HAS_TYPE_DEFINITION, td);
                    b.link(var, ids::HAS_CONDITION, cond);
                }
                let Some((low, high)) = it.eu_range else {
                    b.link(var, ids::HAS_TYPE_DEFINITION, bdv_type);
                    continue;
                };
                b.link(var, ids::HAS_TYPE_DEFINITION, analog_type);
                let prop = b
                    .add(Node {
                        id: NodeId::String(ns, format!("__prop/{}/EURange", it.node_id).into()),
                        browse_name: QualifiedName { ns: 0, name: "EURange".into() },
                        display_name: LocalizedText::new("EURange"),
                        description: None,
                        refs: Vec::with_capacity(2),
                        kind: NodeKind::Variable {
                            data_type: NodeId::ns0(ids::RANGE),
                            value_rank: -1,
                            access: ACCESS_READ,
                            value: ValueSource::Static(range_value(low, high)),
                        },
                    })
                    .map_err(|e| format!("{}: item '{}': {e}", c.source.display(), it.name))?;
                b.link(var, ids::HAS_PROPERTY, prop);
                b.link(prop, ids::HAS_TYPE_DEFINITION, property_type);
            }
        }
    }

    for (cell, capacity) in history {
        cell.set_history(capacity);
    }
    let mut keep = Vec::new();
    for PendingAlarm { cell, cfg, id, source, name } in conditions {
        let Some(cfg) = cfg else {
            cell.set_alarm(None);
            continue;
        };
        let (cond, new) = alarms.upsert(id.clone(), source, &name, cfg, &events);
        if new {
            // Evaluate the current value, unless nothing was written yet.
            let s = cell.read();
            if s.status != status::UNCERTAIN_INITIAL_VALUE {
                cond.evaluate(&s.value, s.status, s.source_ts);
            }
        }
        cell.set_alarm(Some(cond));
        keep.push(id);
    }
    alarms.retain(&keep);
    let dense = dense_tables(&b.nodes, namespaces.len());
    Ok(AddressSpace { nodes: b.nodes, index: b.index, dense, namespaces, generation, info, events, alarms })
}

/// Builds the direct lookup tables of [`AddressSpace::dense`]. A namespace
/// gets one when its largest numeric id is at most 4x its numeric node count
/// (plus a small slack) and below 2^24: at most 16 bytes per node. Namespace 0
/// always gets one.
fn dense_tables(nodes: &[Node], namespaces: usize) -> Vec<Box<[u32]>> {
    let mut stats = vec![(0usize, 0u32); namespaces];
    for n in nodes {
        if let NodeId::Numeric(ns, v) = n.id {
            if let Some(s) = stats.get_mut(ns as usize) {
                s.0 += 1;
                s.1 = s.1.max(v);
            }
        }
    }
    let mut tables: Vec<Box<[u32]>> = stats
        .iter()
        .enumerate()
        .map(|(ns, &(count, max))| {
            let len = max as usize + 1;
            // Namespace 0 (~5 500 nodes up to i=33 000) always gets one: 130 KB.
            if count > 0 && (len <= 4 * count + 64 || ns == 0) && len < 1 << 24 {
                vec![u32::MAX; len].into_boxed_slice()
            } else {
                Box::default()
            }
        })
        .collect();
    for (i, n) in nodes.iter().enumerate() {
        if let NodeId::Numeric(ns, v) = n.id {
            if let Some(t) = tables.get_mut(ns as usize).filter(|t| !t.is_empty()) {
                t[v as usize] = i as u32;
            }
        }
    }
    tables
}

/// Encodes the ServerStatusDataType structure (as an ExtensionObject body).
pub fn encode_server_status(info: &ServerInfo) -> Variant {
    use crate::codec::Writer;
    let mut body = Vec::with_capacity(160);
    let mut w = Writer::new(&mut body);
    w.i64(info.start_time);
    w.i64(now_ticks());
    w.i32(0); // Running
    w.string(&info.product_uri);
    w.string(&info.manufacturer_name);
    w.string(&info.product_name);
    w.string(&info.software_version);
    w.string(&info.build_number);
    w.i64(info.build_date);
    w.u32(0); // SecondsTillShutdown
    w.u8(0); // ShutdownReason: empty LocalizedText
    Variant::ExtensionObject(Box::new(ExtensionObject {
        type_id: NodeId::ns0(ids::SERVER_STATUS_DATA_TYPE_ENCODING),
        encoding: 1,
        body: body.into(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{GroupConfig, ItemConfig};
    use std::path::PathBuf;

    fn cfg(uri: &str, items: &[(u32, u8)]) -> NamespaceConfig {
        NamespaceConfig {
            source: PathBuf::from(format!("{uri}.json")),
            uri: uri.into(),
            name: uri.into(),
            groups: vec![GroupConfig {
                name: "G".into(),
                items: items
                    .iter()
                    .map(|(i, t)| ItemConfig {
                        name: format!("v{i}"),
                        node_id: NodeId::Numeric(0, *i),
                        data_type: *t,
                        writable: true,
                        eu_range: None,
                        history: None,
                        alarm: None,
                    })
                    .collect(),
            }],
        }
    }

    /// The direct tables must give the same answers as the hash index.
    #[test]
    fn dense_and_hash_lookups_agree() {
        let info = Arc::new(ServerInfo::default());
        let mut reg = NamespaceRegistry::new("urn:test");
        let dense: Vec<(u32, u8)> = (0..50).map(|i| (i * 2, builtin::INT32)).collect();
        let sparse = [(5, builtin::INT32), (1_000_000, builtin::DOUBLE)];
        let a = build(&[cfg("D", &dense), cfg("S", &sparse)], &mut reg, None, info, 1).unwrap();
        assert!(!a.dense[2].is_empty(), "namespace D should get a table");
        assert!(a.dense[3].is_empty(), "namespace S is too sparse");
        for ns in 0..5u16 {
            for v in (0..120).chain([1_000_000, u32::MAX]) {
                let id = NodeId::Numeric(ns, v);
                assert_eq!(a.find(&id), a.index.get(&id).copied(), "{id}");
            }
        }
        assert!(a.find(&NodeId::Numeric(2, 4)).is_some());
        assert!(a.find(&NodeId::Numeric(2, 5)).is_none());
        assert!(a.find(&NodeId::Numeric(3, 1_000_000)).is_some());
    }

    #[test]
    fn namespaces_are_stable_and_values_survive() {
        let info = Arc::new(ServerInfo::default());
        let mut reg = NamespaceRegistry::new("urn:test");
        let a = build(
            &[cfg("A", &[(1, builtin::INT32)]), cfg("B", &[(1, builtin::DOUBLE)])],
            &mut reg,
            None,
            info.clone(),
            1,
        )
        .unwrap();
        assert_eq!(&*a.namespaces[2], "A");
        assert_eq!(&*a.namespaces[3], "B");
        let NodeKind::Variable { value: ValueSource::Cell(c), .. } = &a.get(&NodeId::Numeric(3, 1)).unwrap().kind
        else {
            panic!()
        };
        c.write(&Variant::Double(4.5), 0, 1, 1);

        // A disappears, C appears, B keeps its index and its value.
        let b2 = build(
            &[cfg("B", &[(1, builtin::DOUBLE)]), cfg("C", &[(7, builtin::BOOLEAN)])],
            &mut reg,
            Some(&a),
            info.clone(),
            2,
        )
        .unwrap();
        assert!(b2.get(&NodeId::Numeric(2, 1)).is_none());
        assert_eq!(&*b2.namespaces[4], "C");
        let NodeKind::Variable { value: ValueSource::Cell(c2), .. } = &b2.get(&NodeId::Numeric(3, 1)).unwrap().kind
        else {
            panic!()
        };
        assert_eq!(c2.read().value, Variant::Double(4.5));

        // Type change resets the value.
        let b3 = build(&[cfg("B", &[(1, builtin::INT16)])], &mut reg, Some(&b2), info, 3).unwrap();
        let NodeKind::Variable { value: ValueSource::Cell(c3), .. } = &b3.get(&NodeId::Numeric(3, 1)).unwrap().kind
        else {
            panic!()
        };
        assert_eq!(c3.read().value, Variant::Int16(0));
    }

    #[test]
    fn duplicate_node_ids_rejected() {
        let mut reg = NamespaceRegistry::new("urn:test");
        let err = build(
            &[cfg("A", &[(1, builtin::INT32), (1, builtin::INT32)])],
            &mut reg,
            None,
            Arc::new(ServerInfo::default()),
            1,
        );
        assert!(err.is_err());
    }

    /// Namespace 0 matches the official nodeset and is well formed.
    #[test]
    fn namespace_zero_is_complete_and_consistent() {
        let mut reg = NamespaceRegistry::new("urn:test");
        let a = build(&[cfg("A", &[(1, builtin::INT32)])], &mut reg, None, Arc::new(ServerInfo::default()), 1).unwrap();
        let mut problems = Vec::new();
        for n in crate::ns0::nodes() {
            match a.get(&NodeId::ns0(n.id)) {
                None => problems.push(format!("i={} missing", n.id)),
                Some(m) if m.browse_name != n.browse_name => {
                    problems.push(format!("i={}: browse name {} vs {}", n.id, m.browse_name.name, n.browse_name.name))
                }
                Some(m) if std::mem::discriminant(&m.kind) != std::mem::discriminant(&n.kind) => {
                    problems.push(format!("i={}: node class {:?}", n.id, m.class()))
                }
                _ => {}
            }
        }
        let hier = |t| ref_type_matches(t, ids::HIERARCHICAL_REFERENCES, true);
        for (i, n) in a.nodes.iter().enumerate() {
            let count = |f: &dyn Fn(&Ref) -> bool| n.refs.iter().filter(|r| f(r)).count();
            if count(&|r| r.forward && r.type_id == ids::HAS_TYPE_DEFINITION) > 1 {
                problems.push(format!("{}: several type definitions", n.id));
            }
            if matches!(n.class(), NodeClass::Object | NodeClass::Variable)
                && count(&|r| r.forward && r.type_id == ids::HAS_TYPE_DEFINITION) == 0
            {
                problems.push(format!("{}: no type definition", n.id));
            }
            if count(&|r| !r.forward && r.type_id == ids::HAS_SUBTYPE) > 1 {
                problems.push(format!("{}: several supertypes", n.id));
            }
            for r in &n.refs {
                let twins = n
                    .refs
                    .iter()
                    .filter(|o| o.forward == r.forward && o.target == r.target && hier(o.type_id) && hier(r.type_id))
                    .count();
                if r.forward && hier(r.type_id) && twins > 1 {
                    problems.push(format!("{} -> {}: several hierarchical references", n.id, a.node(r.target).id));
                }
                let back = a
                    .node(r.target)
                    .refs
                    .iter()
                    .any(|o| o.type_id == r.type_id && o.forward != r.forward && o.target == i as u32);
                if !back {
                    problems.push(format!("{}: reference without its inverse", n.id));
                }
            }
        }
        // Everything is reachable from Root, or from one of the few standalone
        // nodes of the nodeset (the DataTypeEncoding names, some property
        // names, the FileSystem object): nodes no reference points to.
        let roots: Vec<u32> = (0..a.nodes.len() as u32).filter(|&i| a.node(i).refs.iter().all(|r| r.forward)).collect();
        assert!(roots.len() < 64, "{} nodes without parent", roots.len());
        let mut seen = vec![false; a.nodes.len()];
        let mut stack = roots;
        while let Some(i) = stack.pop() {
            if std::mem::replace(&mut seen[i as usize], true) {
                continue;
            }
            stack.extend(a.node(i).refs.iter().filter(|r| r.forward).map(|r| r.target));
        }
        let orphans: Vec<_> = a.nodes.iter().zip(&seen).filter(|(_, s)| !**s).map(|(n, _)| n.id.to_string()).collect();
        if !orphans.is_empty() {
            problems.push(format!("{} unreachable nodes, e.g. {:?}", orphans.len(), &orphans[..orphans.len().min(10)]));
        }
        problems.sort();
        problems.dedup();
        assert!(problems.is_empty(), "{} problems:\n{}", problems.len(), problems[..problems.len().min(60)].join("\n"));
    }

    #[test]
    fn subtype_matching() {
        assert!(ref_type_matches(ids::HAS_COMPONENT, ids::HIERARCHICAL_REFERENCES, true));
        assert!(!ref_type_matches(ids::HAS_COMPONENT, ids::HIERARCHICAL_REFERENCES, false));
        assert!(!ref_type_matches(ids::HAS_TYPE_DEFINITION, ids::HIERARCHICAL_REFERENCES, true));
        assert!(ref_type_matches(ids::ORGANIZES, ids::REFERENCES, true));
    }
}
