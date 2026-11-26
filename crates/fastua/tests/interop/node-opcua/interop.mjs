// Interoperability check of fastua against the node-opcua client.
//
// usage: serve.sh <fastua> node interop.mjs   (FASTUA_URL, FASTUA_WORK set by serve.sh)
//
// Covers the services of the Standard 2017 UA Server profile as node-opcua
// uses them: discovery, every RSA security policy and mode, user tokens,
// Browse / BrowseNext / TranslateBrowsePaths over the whole namespace 0,
// Read of every attribute of every node (node-opcua decodes strictly),
// Write of every built-in type, RegisterNodes, subscriptions (data changes,
// events, alarms), Call, HistoryRead (raw, processed, events) and
// DataTypeDefinition decoding. Exits non-zero on failure.
import {
    AttributeIds,
    BrowseDirection,
    DataType,
    HistoryReadRequest,
    MessageSecurityMode,
    NodeClass,
    NodeId,
    OPCUAClient,
    ReadEventDetails,
    SecurityPolicy,
    StatusCodes,
    TimestampsToReturn,
    UserTokenType,
    Variant,
    VariantArrayType,
    constructEventFilter,
    makeBrowsePath,
    ofType,
    resolveNodeId,
} from "node-opcua-client";
import { OPCUACertificateManager } from "node-opcua-certificate-manager";

const URL = process.env.FASTUA_URL;
const WORK = process.env.FASTUA_WORK;
const failures = [];

function check(label, ok, detail) {
    console.log(`${ok ? "PASS" : "FAIL"} ${label}${detail !== undefined ? `  (${detail})` : ""}`);
    if (!ok) failures.push(label);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const certificateManager = new OPCUACertificateManager({
    rootFolder: `${WORK}/node-opcua-pki`,
    automaticallyAcceptUnknownCertificate: true,
});

async function connect(policy = SecurityPolicy.None, mode = MessageSecurityMode.None, user = null) {
    const client = OPCUAClient.create({
        applicationName: "fastua-interop-node-opcua",
        applicationUri: "urn:fastua:interop:node-opcua",
        securityPolicy: policy,
        securityMode: mode,
        endpointMustExist: true,
        connectionStrategy: { maxRetry: 0 },
        clientCertificateManager: certificateManager,
        requestedSessionTimeout: 60000,
        defaultSecureTokenLifetime: 60000,
    });
    await client.connect(URL);
    const userIdentity = user
        ? { type: UserTokenType.UserName, userName: user[0], password: user[1] }
        : { type: UserTokenType.Anonymous };
    try {
        const session = await client.createSession(userIdentity);
        return { client, session };
    } catch (e) {
        await client.disconnect();
        throw e;
    }
}

async function close({ client, session }) {
    await session.close();
    await client.disconnect();
}

async function expectError(label, fn, name) {
    try {
        await fn();
        check(label, false, "no error");
    } catch (e) {
        check(label, String(e.message ?? e).includes(name), String(e.message ?? e).split("\n")[0]);
    }
}

async function discovery() {
    const client = OPCUAClient.create({ endpointMustExist: false, connectionStrategy: { maxRetry: 0 } });
    await client.connect(URL);
    const endpoints = await client.getEndpoints();
    const servers = await client.findServers();
    await client.disconnect();
    const policies = new Set(endpoints.map((e) => e.securityPolicyUri));
    for (const p of [SecurityPolicy.None, SecurityPolicy.Basic256Sha256, SecurityPolicy.Aes128_Sha256_RsaOaep,
        SecurityPolicy.Aes256_Sha256_RsaPss]) {
        check(`GetEndpoints offers ${p.split("#")[1]}`, policies.has(p));
    }
    const tcp = endpoints.filter((e) => e.endpointUrl.startsWith("opc.tcp:"));
    check("endpoints carry the server certificate", tcp.filter((e) => e.securityMode !== MessageSecurityMode.None)
        .every((e) => e.serverCertificate && e.serverCertificate.length > 0));
    check("endpoints carry user token policies", tcp.every((e) => e.userIdentityTokens.length > 0));
    check("https endpoint advertised", endpoints.some((e) => e.endpointUrl.startsWith("opc.https:")
        && e.transportProfileUri.endsWith("https-uabinary")));
    check("FindServers", servers.length === 1 && servers[0].applicationUri === "urn:fastua:interop:server",
        servers.map((s) => s.applicationUri).join());
}

async function policies() {
    const modes = [MessageSecurityMode.Sign, MessageSecurityMode.SignAndEncrypt];
    const list = [[SecurityPolicy.None, MessageSecurityMode.None]];
    for (const p of [SecurityPolicy.Basic256Sha256, SecurityPolicy.Aes128_Sha256_RsaOaep,
        SecurityPolicy.Aes256_Sha256_RsaPss]) {
        for (const m of modes) list.push([p, m]);
    }
    for (const [p, m] of list) {
        const label = `${p.split("#")[1]} ${MessageSecurityMode[m]}`;
        try {
            const s = await connect(p, m);
            // 600 values: a response over several chunks.
            const values = await s.session.read(Array(600).fill({ nodeId: "i=2256", attributeId: AttributeIds.Value }));
            const state = await s.session.read({ nodeId: "i=2259", attributeId: AttributeIds.Value });
            check(label, values.length === 600 && values.every((v) => v.statusCode.isGood()) && state.value.value === 0);
            await close(s);
        } catch (e) {
            check(label, false, e.message);
        }
    }
}

// Browses the whole tree under a node, following hierarchical references in
// small pages (BrowseNext), and returns every node found.
async function crawl(session, root) {
    const seen = new Map([[root.toString(), NodeClass.Object]]);
    let frontier = [root];
    let pages = 0;
    while (frontier.length) {
        const next = [];
        for (let i = 0; i < frontier.length; i += 50) {
            const batch = frontier.slice(i, i + 50);
            let results = await session.browse(batch.map((nodeId) => ({
                nodeId,
                browseDirection: BrowseDirection.Forward,
                referenceTypeId: "HierarchicalReferences",
                includeSubtypes: true,
                resultMask: 63,
            })));
            for (;;) {
                const cps = [];
                for (const r of results) {
                    if (!r.statusCode.isGood()) throw new Error(`browse: ${r.statusCode.toString()}`);
                    for (const ref of r.references ?? []) {
                        const key = ref.nodeId.toString();
                        if (!seen.has(key)) {
                            seen.set(key, ref.nodeClass);
                            next.push(ref.nodeId);
                        }
                    }
                    if (r.continuationPoint && r.continuationPoint.length) cps.push(r.continuationPoint);
                }
                if (!cps.length) break;
                pages++;
                results = await session.browseNext(cps, false);
            }
        }
        frontier = next;
    }
    return { nodes: seen, pages };
}

const MANDATORY = {
    [NodeClass.Object]: ["EventNotifier"],
    [NodeClass.Variable]: ["Value", "DataType", "ValueRank", "AccessLevel", "UserAccessLevel", "Historizing"],
    [NodeClass.Method]: ["Executable", "UserExecutable"],
    [NodeClass.ObjectType]: ["IsAbstract"],
    [NodeClass.VariableType]: ["DataType", "ValueRank", "IsAbstract"],
    [NodeClass.ReferenceType]: ["IsAbstract", "Symmetric"],
    [NodeClass.DataType]: ["IsAbstract"],
    [NodeClass.View]: ["ContainsNoLoops", "EventNotifier"],
};

async function addressSpace(session) {
    const t0 = Date.now();
    // Small pages: exercises continuation points and BrowseNext.
    session.requestedMaxReferencesPerNode = 7;
    const { nodes, pages } = await crawl(session, resolveNodeId("RootFolder"));
    session.requestedMaxReferencesPerNode = 10000;
    check("browse the whole address space (BrowseNext pages)", nodes.size > 4000 && pages > 0,
        `${nodes.size} nodes, ${pages} pages, ${Date.now() - t0} ms`);
    // Every attribute of every node, in batches: node-opcua decodes each
    // value against its declared data type.
    const ids = [...nodes.keys()];
    let bad = [];
    let reads = 0;
    for (let i = 0; i < ids.length; i += 200) {
        const batch = ids.slice(i, i + 200);
        const req = [];
        for (const id of batch) {
            for (const a of ["NodeId", "NodeClass", "BrowseName", "DisplayName", "Description", "WriteMask",
                "UserWriteMask", ...(MANDATORY[nodes.get(id)] ?? [])]) {
                req.push({ nodeId: id, attributeId: AttributeIds[a], name: a });
            }
        }
        const res = await session.read(req);
        reads += res.length;
        res.forEach((dv, k) => {
            const sc = dv.statusCode;
            const optional = req[k].name === "Description" || req[k].name === "WriteMask"
                || req[k].name === "UserWriteMask";
            // Value may be unreadable for some nodes, never a protocol error.
            const ok = sc.isGood() || (optional && sc === StatusCodes.BadAttributeIdInvalid)
                || (req[k].name === "Value" && sc !== StatusCodes.BadAttributeIdInvalid
                    && sc !== StatusCodes.BadDecodingError);
            if (!ok) bad.push(`${req[k].nodeId} ${req[k].name}: ${sc.name}`);
        });
    }
    check("read mandatory attributes of every node", bad.length === 0,
        `${reads} attributes${bad.length ? ", " + bad.slice(0, 5).join("; ") : ""}`);

    // DataTypeDefinition of every structure and enumeration data type.
    const types = ids.filter((id) => nodes.get(id) === NodeClass.DataType);
    const defs = await session.read(types.map((nodeId) => ({ nodeId, attributeId: AttributeIds.DataTypeDefinition })));
    const withDef = defs.filter((d) => d.statusCode.isGood());
    bad = defs.filter((d) => !d.statusCode.isGood() && d.statusCode !== StatusCodes.BadAttributeIdInvalid);
    check("DataTypeDefinition", withDef.length > 200 && bad.length === 0,
        `${withDef.length} of ${types.length} types, ${bad.length} errors`);
    // A structure built from its DataTypeDefinition (ServerStatusDataType).
    const status = await session.read({ nodeId: "i=2256", attributeId: AttributeIds.Value });
    check("ServerStatus decodes as ServerStatusDataType",
        status.value.value?.buildInfo?.productUri !== undefined && status.value.value.state === 0,
        status.value.value?.constructor?.name);
    const ext = await session.constructExtensionObject(new NodeId(NodeId.NodeIdType.NUMERIC, 338, 0), {});
    check("constructExtensionObject(BuildInfo)", ext && "productUri" in ext);

    // Reverse and inverse browse, reference type filters.
    const inv = await session.browse({ nodeId: "i=2253", browseDirection: BrowseDirection.Inverse,
        referenceTypeId: "Organizes", includeSubtypes: false, resultMask: 63 });
    check("inverse browse (Server -> Objects)", inv.references?.some((r) => r.nodeId.value === 85),
        inv.references?.map((r) => r.nodeId.toString()).join());
    const typeDef = await session.browse({ nodeId: "i=2253", browseDirection: BrowseDirection.Forward,
        referenceTypeId: "HasTypeDefinition", includeSubtypes: false, resultMask: 63 });
    check("HasTypeDefinition (ServerType)", typeDef.references?.length === 1 && typeDef.references[0].nodeId.value === 2004);
    const unknown = await session.browse({ nodeId: "ns=0;i=999999", browseDirection: BrowseDirection.Forward });
    check("browse unknown node", unknown.statusCode === StatusCodes.BadNodeIdUnknown, unknown.statusCode.name);
}

async function plant(session, ns) {
    const id = (s) => (typeof s === "number" ? `ns=${ns};i=${s}` : `ns=${ns};s=${s}`);
    // TranslateBrowsePaths.
    const paths = await session.translateBrowsePath([
        makeBrowsePath("RootFolder", `/Objects/${ns}:Plant/${ns}:Line/${ns}:Speed`),
        makeBrowsePath("RootFolder", "/Objects/Server/ServerStatus/CurrentTime"),
        makeBrowsePath("RootFolder", "/Objects/Nope"),
    ]);
    check("TranslateBrowsePaths", paths[0].targets?.[0]?.targetId.toString() === id(1)
        && paths[1].targets?.[0]?.targetId.value === 2258
        && paths[2].statusCode === StatusCodes.BadNoMatch,
        paths.map((p) => p.statusCode.name).join());

    // Attributes of a configured variable.
    const attrs = await session.read(["BrowseName", "DisplayName", "DataType", "ValueRank", "AccessLevel",
        "UserAccessLevel", "Historizing", "MinimumSamplingInterval"].map((a) => ({ nodeId: id("Level"), attributeId: AttributeIds[a] })));
    check("variable attributes", attrs.every((d) => d.statusCode.isGood())
        && attrs[0].value.value.name === "Level" && attrs[2].value.value.value === 11
        && attrs[3].value.value === -1 && (attrs[4].value.value & 3) === 3 && attrs[6].value.value === true,
        attrs.map((d) => String(d.value.value)).join(" | "));

    // Write and read back every built-in type of the namespace.
    const now = new Date(Math.floor(Date.now() / 1000) * 1000);
    const cases = [
        [id(1), DataType.Int32, -123456],
        [id(2), DataType.Boolean, true],
        [id(3), DataType.UInt64, [0x12345678, 0x9abcdef0]],
        [id("Recipe"), DataType.String, "Pâte à crêpes"],
        [id("Ratio"), DataType.Float, 0.5],
        [id("Stamp"), DataType.DateTime, now],
        [id("Id"), DataType.Guid, "72962B91-FA75-4AE6-8D28-B404DC7DAF63"],
        [id("Blob"), DataType.ByteString, Buffer.from([0, 1, 2, 254, 255])],
    ];
    const ws = await session.write(cases.map(([nodeId, dataType, value]) => ({
        nodeId, attributeId: AttributeIds.Value, value: { value: new Variant({ dataType, value, arrayType: VariantArrayType.Scalar }) },
    })));
    check("write every type", ws.every((s) => s.isGood()), ws.map((s) => s.name).join());
    const back = await session.read(cases.map(([nodeId]) => ({ nodeId, attributeId: AttributeIds.Value })));
    const same = back.map((d, k) => JSON.stringify(d.value.value) === JSON.stringify(cases[k][2])
        || (d.value.value instanceof Date && d.value.value.getTime() === now.getTime())
        || String(d.value.value).toUpperCase() === String(cases[k][2]).toUpperCase());
    check("read back every type", same.every(Boolean), back.map((d) => JSON.stringify(d.value.value)).join(" | "));
    const wrong = await session.write({ nodeId: id(1), attributeId: AttributeIds.Value,
        value: { value: new Variant({ dataType: DataType.String, value: "x" }) } });
    check("write with wrong type", wrong === StatusCodes.BadTypeMismatch, wrong.name);
    const ro = await session.write({ nodeId: "i=2259", attributeId: AttributeIds.Value,
        value: { value: new Variant({ dataType: DataType.Int32, value: 1 }) } });
    check("write of a read-only variable", ro === StatusCodes.BadNotWritable || ro === StatusCodes.BadUserAccessDenied, ro.name);

    // Index range on a ByteString.
    const part = await session.read({ nodeId: id("Blob"), attributeId: AttributeIds.Value, indexRange: "1:2" });
    check("read with index range", part.value.value?.length === 2 && part.value.value[0] === 1, JSON.stringify(part.value.value));

    // RegisterNodes.
    const reg = await session.registerNodes([id(1), id("Level")]);
    const regRead = await session.read({ nodeId: reg[0], attributeId: AttributeIds.Value });
    check("RegisterNodes", reg.length === 2 && regRead.value.value === -123456, reg.map(String).join());
    await session.unregisterNodes(reg);
    return id;
}

async function subscriptions(session, id) {
    const sub = await session.createSubscription2({
        requestedPublishingInterval: 20, requestedLifetimeCount: 600, requestedMaxKeepAliveCount: 10,
        maxNotificationsPerPublish: 0, publishingEnabled: true, priority: 1,
    });
    const values = [];
    const item = await sub.monitor({ nodeId: id(1), attributeId: AttributeIds.Value },
        { samplingInterval: 10, queueSize: 10, discardOldest: true }, TimestampsToReturn.Both);
    item.on("changed", (dv) => values.push(dv.value.value));
    await sleep(200);
    for (const v of [1, 2, 3]) {
        await session.write({ nodeId: id(1), attributeId: AttributeIds.Value,
            value: { value: new Variant({ dataType: DataType.Int32, value: v }) } });
        await sleep(50);
    }
    await sleep(200);
    check("data change notifications", values[0] === -123456 && values.slice(-3).join() === "1,2,3", values.join());

    // Events: the writes above raised audit write events.
    const fields = ["EventId", "EventType", "SourceName", "Message", "Severity", "Time"];
    const events = [];
    const ev = await sub.monitor({ nodeId: "i=2253", attributeId: AttributeIds.EventNotifier },
        { samplingInterval: 0, queueSize: 100, filter: constructEventFilter(fields) }, TimestampsToReturn.Both);
    ev.on("changed", (list) => events.push(list));
    await sleep(200);
    await session.write({ nodeId: id(1), attributeId: AttributeIds.Value,
        value: { value: new Variant({ dataType: DataType.Int32, value: 4 }) } });
    await sleep(300);
    const audit = events.filter((e) => e[1].value?.toString() === "ns=0;i=2100");
    check("event notifications (AuditWriteUpdateEventType)", audit.length >= 1, events.map((e) => e[1].value?.toString()).join());

    // Alarm on Level: raise, acknowledge.
    const alarms = [];
    const al = await sub.monitor({ nodeId: "i=2253", attributeId: AttributeIds.EventNotifier },
        { samplingInterval: 0, queueSize: 100, filter: constructEventFilter(
            ["EventId", "EventType", "SourceName", "Severity", "ConditionName", "ActiveState.Id", "AckedState.Id",
                "LimitState.CurrentState"], ofType("ExclusiveLimitAlarmType")) }, TimestampsToReturn.Both);
    al.on("changed", (list) => alarms.push(list));
    await sleep(200);
    await session.write({ nodeId: id("Level"), attributeId: AttributeIds.Value,
        value: { value: new Variant({ dataType: DataType.Double, value: 120 }) } });
    await sleep(300);
    const active = alarms.find((e) => e[5].value === true && e[6].value === false);
    check("alarm raised", active && active[3].value === 600 && active[7].value?.text === "High",
        alarms.map((e) => e.map((f) => String(f.value)).join("/")).join(" ; "));
    if (active) {
        const conditionId = new NodeId(NodeId.NodeIdType.STRING, "__alarm/s=Level", id.ns);
        const ack = await session.call({
            objectId: conditionId, methodId: "i=9111",
            inputArguments: [new Variant({ dataType: DataType.ByteString, value: active[0].value }),
                new Variant({ dataType: DataType.LocalizedText, value: { text: "node-opcua" } })],
        });
        await sleep(300);
        check("Acknowledge through Call", ack.statusCode.isGood() && alarms.some((e) => e[6].value === true),
            ack.statusCode.name);
    }

    // Call: GetMonitoredItems.
    const mi = await session.getMonitoredItems(sub.subscriptionId);
    check("Call GetMonitoredItems", mi.serverHandles.length === 3, JSON.stringify(mi.serverHandles));
    const badCall = await session.call({ objectId: "i=2253", methodId: "i=11492",
        inputArguments: [new Variant({ dataType: DataType.UInt32, value: 999999 })] });
    check("Call with an unknown subscription", badCall.statusCode === StatusCodes.BadSubscriptionIdInvalid,
        badCall.statusCode.name);
    await sub.terminate();
}

async function history(session, id) {
    for (const v of [10, 20, 30, 40]) {
        await session.write({ nodeId: id("Level"), attributeId: AttributeIds.Value,
            value: { value: new Variant({ dataType: DataType.Double, value: v }) } });
        await sleep(5);
    }
    const start = new Date(Date.now() - 600000);
    const end = new Date(Date.now() + 1000);
    const raw = await session.readHistoryValue(id("Level"), start, end);
    // Bounds without a value come back as BadBoundNotFound.
    const vals = raw.historyData?.dataValues?.filter((d) => d.statusCode.isGood()).map((d) => d.value.value) ?? [];
    check("HistoryRead raw", raw.statusCode.isGood() && vals.slice(-4).join() === "10,20,30,40", vals.join());
    const paged = await session.readHistoryValue(id("Level"), start, end,
        { numValuesPerNode: 2, returnBounds: false });
    check("HistoryRead continuation point", paged.continuationPoint?.length > 0 && paged.historyData.dataValues.length === 2);
    const agg = await session.readAggregateValue({ nodeId: id("Level") }, start, end, AggregateMax(), 0);
    check("HistoryRead processed (Maximum)", agg.statusCode.isGood()
        && agg.historyData.dataValues[0].value.value === 120, JSON.stringify(agg.historyData?.dataValues?.[0]?.value?.value));
    const events = await session.historyRead(new HistoryReadRequest({
        nodesToRead: [{ nodeId: "i=2253" }],
        historyReadDetails: new ReadEventDetails({
            startTime: start, endTime: end, numValuesPerNode: 0,
            filter: constructEventFilter(["EventType", "SourceName", "Message"]),
        }),
        timestampsToReturn: TimestampsToReturn.Both,
    }));
    const evs = events.results?.[0]?.historyData?.events ?? [];
    check("HistoryRead events (Server)", events.results?.[0]?.statusCode.isGood() && evs.length > 0,
        `${events.results?.[0]?.statusCode.name}, ${evs.length} events`);
}

function AggregateMax() {
    return resolveNodeId("AggregateFunction_Maximum");
}

async function users() {
    const anon = await connect();
    const w = await anon.session.write({ nodeId: "ns=2;i=1", attributeId: AttributeIds.Value,
        value: { value: new Variant({ dataType: DataType.Int32, value: 1 }) } });
    check("anonymous write refused", w === StatusCodes.BadUserAccessDenied, w.name);
    await close(anon);
    const viewer = await connect(SecurityPolicy.Basic256Sha256, MessageSecurityMode.Sign, ["viewer", "s3cret"]);
    const vw = await viewer.session.write({ nodeId: "ns=2;i=1", attributeId: AttributeIds.Value,
        value: { value: new Variant({ dataType: DataType.Int32, value: 1 }) } });
    check("viewer write refused", vw === StatusCodes.BadUserAccessDenied, vw.name);
    await close(viewer);
    await expectError("wrong password rejected",
        () => connect(SecurityPolicy.Basic256Sha256, MessageSecurityMode.SignAndEncrypt, ["operator", "nope"]),
        "BadUserAccessDenied");
    // Password over an unsecured channel: encrypted with the server key.
    const plain = await connect(SecurityPolicy.None, MessageSecurityMode.None, ["operator", "s3cret"]);
    check("user name over SecurityPolicy None", true);
    await close(plain);
}

async function main() {
    await discovery();
    await policies();
    await users();
    const s = await connect(SecurityPolicy.Aes256_Sha256_RsaPss, MessageSecurityMode.SignAndEncrypt, ["operator", "s3cret"]);
    try {
        const nsArray = await s.session.readNamespaceArray();
        const ns = nsArray.indexOf("urn:fastua:interop:plant");
        check("namespace array", ns > 0, nsArray.join());
        await addressSpace(s.session);
        const id = await plant(s.session, ns);
        id.ns = ns;
        await subscriptions(s.session, id);
        await history(s.session, id);
    } finally {
        await close(s);
    }
}

try {
    await main();
} catch (e) {
    check("exception", false, e.stack ?? e);
}
await certificateManager.dispose();
if (failures.length) {
    console.log(`${failures.length} failure(s): ${failures.join(", ")}`);
    process.exit(1);
}
console.log("all node-opcua interop checks passed");
process.exit(0);
