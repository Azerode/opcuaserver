/* Interoperability check of the RSA security policies and the services of
 * the Standard 2017 UA Server profile against the open62541 client.
 *
 * usage: serve.sh <fastua> ./open62541_services   (FASTUA_URL set by serve.sh)
 *
 * For SecurityPolicy None and every RSA policy and mode: a session, reads
 * and a large read (a multi-chunk response). Then, as user operator:
 * TranslateBrowsePaths, Browse / BrowseNext, Write / Read, RegisterNodes,
 * a subscription with data change and event monitored items, Call and
 * HistoryRead. Exits non-zero on failure. */

#include <open62541/client_config_default.h>
#include <open62541/client_highlevel.h>
#include <open62541/client_subscriptions.h>
#include <open62541/plugin/certificategroup_default.h>
#include <open62541/plugin/create_certificate.h>
#include <open62541/plugin/log_stdout.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CLIENT_URI "urn:fastua:interop:open62541"
#define POLICY_PREFIX "http://opcfoundation.org/UA/SecurityPolicy#"

static int failures = 0;

static void check(const char *label, int ok, const char *detail) {
    printf("%s %s%s%s%s\n", ok ? "PASS" : "FAIL", label, detail ? "  (" : "", detail ? detail : "",
           detail ? ")" : "");
    fflush(stdout);
    if(!ok)
        failures++;
}

static UA_ByteString cert, key;

static UA_StatusCode makeCert(void) {
    UA_String subject[2] = {UA_STRING_STATIC("O=fastua-interop"), UA_STRING_STATIC("CN=open62541 interop client")};
    UA_String san[2] = {UA_STRING_STATIC("DNS:localhost"), UA_STRING_STATIC("URI:" CLIENT_URI)};
    UA_KeyValueMap *kvm = UA_KeyValueMap_new();
    UA_UInt16 days = 30;
    UA_UInt16 bits = 2048;
    UA_KeyValueMap_setScalar(kvm, UA_QUALIFIEDNAME(0, "expires-in-days"), &days, &UA_TYPES[UA_TYPES_UINT16]);
    UA_KeyValueMap_setScalar(kvm, UA_QUALIFIEDNAME(0, "key-size-bits"), &bits, &UA_TYPES[UA_TYPES_UINT16]);
    UA_StatusCode res =
        UA_CreateCertificate(UA_Log_Stdout, subject, 2, san, 2, UA_CERTIFICATEFORMAT_DER, kvm, &key, &cert);
    UA_KeyValueMap_delete(kvm);
    return res;
}

static UA_Client *newClient(const char *policy, UA_MessageSecurityMode mode, const char *user, const char *pass) {
    UA_Client *client = UA_Client_new();
    UA_ClientConfig *cc = UA_Client_getConfig(client);
    cc->logging = UA_Log_Stdout_new(UA_LOGLEVEL_WARNING);
    if(UA_ClientConfig_setDefaultEncryption(cc, cert, key, NULL, 0, NULL, 0) != UA_STATUSCODE_GOOD) {
        UA_Client_delete(client);
        return NULL;
    }
    if(cc->certificateVerification.clear)
        cc->certificateVerification.clear(&cc->certificateVerification);
    UA_CertificateGroup_AcceptAll(&cc->certificateVerification);
    char uri[128];
    snprintf(uri, sizeof(uri), POLICY_PREFIX "%s", policy);
    cc->securityPolicyUri = UA_STRING_ALLOC(uri);
    cc->securityMode = mode;
    UA_String_clear(&cc->clientDescription.applicationUri);
    cc->clientDescription.applicationUri = UA_STRING_ALLOC(CLIENT_URI);
    if(user && UA_ClientConfig_setAuthenticationUsername(cc, user, pass) != UA_STATUSCODE_GOOD) {
        UA_Client_delete(client);
        return NULL;
    }
    return client;
}

static void dropClient(UA_Client *client) {
    if(!client)
        return;
    UA_Client_disconnect(client);
    UA_Client_delete(client);
}

static UA_StatusCode readMany(UA_Client *client) {
    enum { N = 3000 };
    UA_ReadValueId *ids = (UA_ReadValueId *)UA_Array_new(N, &UA_TYPES[UA_TYPES_READVALUEID]);
    for(size_t i = 0; i < N; i++) {
        ids[i].nodeId = UA_NS0ID(SERVER_SERVERSTATUS);
        ids[i].attributeId = UA_ATTRIBUTEID_VALUE;
    }
    UA_ReadRequest req;
    UA_ReadRequest_init(&req);
    req.nodesToRead = ids;
    req.nodesToReadSize = N;
    UA_ReadResponse resp = UA_Client_Service_read(client, req);
    UA_StatusCode res = resp.responseHeader.serviceResult;
    if(res == UA_STATUSCODE_GOOD && resp.resultsSize != N)
        res = UA_STATUSCODE_BADUNEXPECTEDERROR;
    for(size_t i = 0; res == UA_STATUSCODE_GOOD && i < resp.resultsSize; i++) {
        res = resp.results[i].status;
        /* Decoded as a ServerStatusDataType structure. */
        if(res == UA_STATUSCODE_GOOD &&
           !UA_Variant_hasScalarType(&resp.results[i].value, &UA_TYPES[UA_TYPES_SERVERSTATUSDATATYPE]))
            res = UA_STATUSCODE_BADDATATYPEIDUNKNOWN;
    }
    UA_ReadResponse_clear(&resp);
    UA_Array_delete(ids, N, &UA_TYPES[UA_TYPES_READVALUEID]);
    return res;
}

static void policies(const char *url) {
    static const char *names[] = {"None", "Basic256Sha256", "Aes128_Sha256_RsaOaep", "Aes256_Sha256_RsaPss"};
    char label[160];
    for(size_t p = 0; p < 4; p++) {
        for(int m = 0; m < (p ? 2 : 1); m++) {
            UA_MessageSecurityMode mode = p == 0 ? UA_MESSAGESECURITYMODE_NONE
                                          : m == 0 ? UA_MESSAGESECURITYMODE_SIGN
                                                   : UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;
            snprintf(label, sizeof(label), "%s %s", names[p],
                     p == 0 ? "None" : m == 0 ? "Sign" : "SignAndEncrypt");
            UA_Client *client = newClient(names[p], mode, NULL, NULL);
            UA_StatusCode res = client ? UA_Client_connect(client, url) : UA_STATUSCODE_BADINTERNALERROR;
            if(res == UA_STATUSCODE_GOOD)
                res = readMany(client);
            check(label, res == UA_STATUSCODE_GOOD, UA_StatusCode_name(res));
            dropClient(client);
        }
    }
}

static UA_StatusCode writeValue(UA_Client *client, UA_NodeId id, const void *v, const UA_DataType *t) {
    UA_Variant var;
    UA_Variant_setScalar(&var, (void *)(uintptr_t)v, t);
    return UA_Client_writeValueAttribute(client, id, &var);
}

/* Subscription callbacks. */
static UA_Int32 lastValues[16];
static size_t nValues = 0;
static size_t auditEvents = 0;

static void dataChanged(UA_Client *c, UA_UInt32 subId, void *subCtx, UA_UInt32 monId, void *monCtx,
                        UA_DataValue *value) {
    (void)c, (void)subId, (void)subCtx, (void)monId, (void)monCtx;
    if(value->hasValue && UA_Variant_hasScalarType(&value->value, &UA_TYPES[UA_TYPES_INT32]) && nValues < 16)
        lastValues[nValues++] = *(UA_Int32 *)value->value.data;
}

static void eventReceived(UA_Client *c, UA_UInt32 subId, void *subCtx, UA_UInt32 monId, void *monCtx,
                          const UA_KeyValueMap fields) {
    (void)c, (void)subId, (void)subCtx, (void)monId, (void)monCtx;
    UA_NodeId audit = UA_NS0ID(AUDITWRITEUPDATEEVENTTYPE);
    for(size_t i = 0; i < fields.mapSize; i++) {
        const UA_Variant *v = &fields.map[i].value;
        if(UA_Variant_hasScalarType(v, &UA_TYPES[UA_TYPES_NODEID]) && UA_NodeId_equal((UA_NodeId *)v->data, &audit))
            auditEvents++;
    }
}

static void iterate(UA_Client *client, int ms) {
    for(int i = 0; i < ms / 10; i++)
        UA_Client_run_iterate(client, 10);
}

static UA_Int32 int32(int v) { return (UA_Int32)v; }

static void history(UA_Client *client, UA_NodeId level);

static void services(const char *url) {
    char detail[256];
    UA_Client *client = newClient("Aes256_Sha256_RsaPss", UA_MESSAGESECURITYMODE_SIGNANDENCRYPT, "operator", "s3cret");
    UA_StatusCode res = client ? UA_Client_connect(client, url) : UA_STATUSCODE_BADINTERNALERROR;
    check("operator session (Aes256_Sha256_RsaPss)", res == UA_STATUSCODE_GOOD, UA_StatusCode_name(res));
    if(res != UA_STATUSCODE_GOOD) {
        dropClient(client);
        return;
    }
    UA_UInt16 ns = 0;
    UA_String nsUri = UA_STRING_STATIC("urn:fastua:interop:plant");
    res = UA_Client_NamespaceGetIndex(client, &nsUri, &ns);
    check("namespace index", res == UA_STATUSCODE_GOOD && ns > 0, UA_StatusCode_name(res));
    UA_NodeId speed = UA_NODEID_NUMERIC(ns, 1);
    UA_NodeId recipe = UA_NODEID_STRING(ns, "Recipe");
    UA_NodeId level = UA_NODEID_STRING(ns, "Level");

    /* TranslateBrowsePaths: Objects/Plant/Line/Speed. */
    {
        UA_RelativePathElement elems[3];
        const char *names[3] = {"Plant", "Line", "Speed"};
        for(int i = 0; i < 3; i++) {
            UA_RelativePathElement_init(&elems[i]);
            elems[i].referenceTypeId = UA_NS0ID(HIERARCHICALREFERENCES);
            elems[i].includeSubtypes = true;
            elems[i].targetName = UA_QUALIFIEDNAME(ns, (char *)(uintptr_t)names[i]);
        }
        UA_BrowsePath bp;
        UA_BrowsePath_init(&bp);
        bp.startingNode = UA_NS0ID(OBJECTSFOLDER);
        bp.relativePath.elements = elems;
        bp.relativePath.elementsSize = 3;
        UA_TranslateBrowsePathsToNodeIdsRequest req;
        UA_TranslateBrowsePathsToNodeIdsRequest_init(&req);
        req.browsePaths = &bp;
        req.browsePathsSize = 1;
        UA_TranslateBrowsePathsToNodeIdsResponse resp = UA_Client_Service_translateBrowsePathsToNodeIds(client, req);
        int ok = resp.responseHeader.serviceResult == UA_STATUSCODE_GOOD && resp.resultsSize == 1 &&
                 resp.results[0].targetsSize == 1 &&
                 UA_NodeId_equal(&resp.results[0].targets[0].targetId.nodeId, &speed);
        check("TranslateBrowsePaths", ok, UA_StatusCode_name(resp.responseHeader.serviceResult));
        UA_TranslateBrowsePathsToNodeIdsResponse_clear(&resp);
    }

    /* Browse the Server object in pages of 3 references (BrowseNext), and
     * compare with a single Browse. */
    {
        UA_BrowseRequest req;
        UA_BrowseRequest_init(&req);
        UA_BrowseDescription bd;
        UA_BrowseDescription_init(&bd);
        bd.nodeId = UA_NS0ID(SERVER);
        bd.resultMask = UA_BROWSERESULTMASK_ALL;
        bd.browseDirection = UA_BROWSEDIRECTION_BOTH;
        bd.includeSubtypes = true;
        req.nodesToBrowse = &bd;
        req.nodesToBrowseSize = 1;
        UA_BrowseResponse all = UA_Client_Service_browse(client, req);
        size_t total = all.resultsSize ? all.results[0].referencesSize : 0;
        req.requestedMaxReferencesPerNode = 3;
        UA_BrowseResponse resp = UA_Client_Service_browse(client, req);
        size_t paged = 0, pages = 0;
        UA_StatusCode st = resp.responseHeader.serviceResult;
        if(st == UA_STATUSCODE_GOOD && resp.resultsSize == 1) {
            paged = resp.results[0].referencesSize;
            UA_ByteString cp = UA_BYTESTRING_NULL;
            UA_ByteString_copy(&resp.results[0].continuationPoint, &cp);
            while(cp.length > 0 && pages < 100) {
                UA_BrowseNextRequest nreq;
                UA_BrowseNextRequest_init(&nreq);
                nreq.continuationPoints = &cp;
                nreq.continuationPointsSize = 1;
                UA_BrowseNextResponse nresp = UA_Client_Service_browseNext(client, nreq);
                UA_ByteString_clear(&cp);
                pages++;
                if(nresp.responseHeader.serviceResult != UA_STATUSCODE_GOOD || nresp.resultsSize != 1) {
                    st = nresp.responseHeader.serviceResult ? nresp.responseHeader.serviceResult
                                                            : UA_STATUSCODE_BADUNEXPECTEDERROR;
                    UA_BrowseNextResponse_clear(&nresp);
                    break;
                }
                if(nresp.results[0].referencesSize > 3)
                    st = UA_STATUSCODE_BADUNEXPECTEDERROR;
                paged += nresp.results[0].referencesSize;
                UA_ByteString_copy(&nresp.results[0].continuationPoint, &cp);
                UA_BrowseNextResponse_clear(&nresp);
            }
            UA_ByteString_clear(&cp);
        }
        snprintf(detail, sizeof(detail), "%zu references, %zu in %zu pages, %s", total, paged, pages,
                 UA_StatusCode_name(st));
        check("Browse / BrowseNext", st == UA_STATUSCODE_GOOD && total > 10 && paged == total && pages > 2, detail);
        UA_BrowseResponse_clear(&resp);
        UA_BrowseResponse_clear(&all);
    }

    /* Write / Read. */
    {
        UA_Int32 v = 4242;
        res = writeValue(client, speed, &v, &UA_TYPES[UA_TYPES_INT32]);
        UA_String s = UA_STRING("open62541 recipe");
        if(res == UA_STATUSCODE_GOOD)
            res = writeValue(client, recipe, &s, &UA_TYPES[UA_TYPES_STRING]);
        UA_Variant out;
        UA_Variant_init(&out);
        if(res == UA_STATUSCODE_GOOD)
            res = UA_Client_readValueAttribute(client, speed, &out);
        int ok = res == UA_STATUSCODE_GOOD && UA_Variant_hasScalarType(&out, &UA_TYPES[UA_TYPES_INT32]) &&
                 *(UA_Int32 *)out.data == 4242;
        UA_Variant_clear(&out);
        UA_Client_readValueAttribute(client, recipe, &out);
        ok = ok && UA_Variant_hasScalarType(&out, &UA_TYPES[UA_TYPES_STRING]) && UA_String_equal((UA_String *)out.data, &s);
        UA_Variant_clear(&out);
        check("Write / Read", ok, UA_StatusCode_name(res));
        UA_Double d = 1.0;
        res = writeValue(client, speed, &d, &UA_TYPES[UA_TYPES_DOUBLE]);
        check("Write with wrong type", res == UA_STATUSCODE_BADTYPEMISMATCH, UA_StatusCode_name(res));
        UA_LocalizedText lt = UA_LOCALIZEDTEXT("", "x");
        res = UA_Client_writeDisplayNameAttribute(client, speed, &lt);
        check("Write of DisplayName refused", res == UA_STATUSCODE_BADNOTWRITABLE, UA_StatusCode_name(res));
        UA_QualifiedName bn;
        res = UA_Client_readBrowseNameAttribute(client, speed, &bn);
        check("Read BrowseName", res == UA_STATUSCODE_GOOD && bn.namespaceIndex == ns, UA_StatusCode_name(res));
        UA_QualifiedName_clear(&bn);
    }

    /* RegisterNodes. */
    {
        UA_RegisterNodesRequest req;
        UA_RegisterNodesRequest_init(&req);
        req.nodesToRegister = &speed;
        req.nodesToRegisterSize = 1;
        UA_RegisterNodesResponse resp = UA_Client_Service_registerNodes(client, req);
        int ok = resp.responseHeader.serviceResult == UA_STATUSCODE_GOOD && resp.registeredNodeIdsSize == 1;
        UA_Variant out;
        UA_Variant_init(&out);
        if(ok)
            ok = UA_Client_readValueAttribute(client, resp.registeredNodeIds[0], &out) == UA_STATUSCODE_GOOD &&
                 UA_Variant_hasScalarType(&out, &UA_TYPES[UA_TYPES_INT32]);
        UA_Variant_clear(&out);
        check("RegisterNodes", ok, UA_StatusCode_name(resp.responseHeader.serviceResult));
        if(resp.registeredNodeIdsSize) {
            UA_UnregisterNodesRequest ureq;
            UA_UnregisterNodesRequest_init(&ureq);
            ureq.nodesToUnregister = resp.registeredNodeIds;
            ureq.nodesToUnregisterSize = resp.registeredNodeIdsSize;
            UA_UnregisterNodesResponse uresp = UA_Client_Service_unregisterNodes(client, ureq);
            UA_UnregisterNodesResponse_clear(&uresp);
        }
        UA_RegisterNodesResponse_clear(&resp);
    }

    /* Subscription: data changes and events. */
    {
        UA_CreateSubscriptionRequest sreq = UA_CreateSubscriptionRequest_default();
        sreq.requestedPublishingInterval = 20;
        UA_CreateSubscriptionResponse sresp = UA_Client_Subscriptions_create(client, sreq, NULL, NULL, NULL);
        UA_UInt32 subId = sresp.subscriptionId;
        check("CreateSubscription", sresp.responseHeader.serviceResult == UA_STATUSCODE_GOOD,
              UA_StatusCode_name(sresp.responseHeader.serviceResult));
        UA_MonitoredItemCreateRequest mreq = UA_MonitoredItemCreateRequest_default(speed);
        mreq.requestedParameters.samplingInterval = 10;
        mreq.requestedParameters.queueSize = 10;
        UA_MonitoredItemCreateResult mres =
            UA_Client_MonitoredItems_createDataChange(client, subId, UA_TIMESTAMPSTORETURN_BOTH, mreq, NULL,
                                                      dataChanged, NULL);
        check("CreateMonitoredItems (data change)", mres.statusCode == UA_STATUSCODE_GOOD,
              UA_StatusCode_name(mres.statusCode));

        UA_SimpleAttributeOperand select[2];
        UA_QualifiedName names[2] = {UA_QUALIFIEDNAME(0, "EventType"), UA_QUALIFIEDNAME(0, "SourceName")};
        for(int i = 0; i < 2; i++) {
            UA_SimpleAttributeOperand_init(&select[i]);
            select[i].typeDefinitionId = UA_NS0ID(BASEEVENTTYPE);
            select[i].browsePath = &names[i];
            select[i].browsePathSize = 1;
            select[i].attributeId = UA_ATTRIBUTEID_VALUE;
        }
        UA_EventFilter filter;
        UA_EventFilter_init(&filter);
        filter.selectClauses = select;
        filter.selectClausesSize = 2;
        UA_MonitoredItemCreateRequest ereq;
        UA_MonitoredItemCreateRequest_init(&ereq);
        ereq.itemToMonitor.nodeId = UA_NS0ID(SERVER);
        ereq.itemToMonitor.attributeId = UA_ATTRIBUTEID_EVENTNOTIFIER;
        ereq.monitoringMode = UA_MONITORINGMODE_REPORTING;
        ereq.requestedParameters.queueSize = 100;
        UA_ExtensionObject_setValue(&ereq.requestedParameters.filter, &filter, &UA_TYPES[UA_TYPES_EVENTFILTER]);
        UA_MonitoredItemCreateResult eres =
            UA_Client_MonitoredItems_createEvent(client, subId, UA_TIMESTAMPSTORETURN_BOTH, ereq, NULL,
                                                 eventReceived, NULL);
        check("CreateMonitoredItems (events)", eres.statusCode == UA_STATUSCODE_GOOD,
              UA_StatusCode_name(eres.statusCode));
        iterate(client, 300);
        nValues = 0;
        auditEvents = 0;
        for(int v = 1; v <= 3; v++) {
            UA_Int32 x = int32(v);
            writeValue(client, speed, &x, &UA_TYPES[UA_TYPES_INT32]);
            iterate(client, 60);
        }
        iterate(client, 300);
        snprintf(detail, sizeof(detail), "%zu values, last %d", nValues, nValues ? lastValues[nValues - 1] : -1);
        check("data change notifications", nValues >= 3 && lastValues[nValues - 3] == 1 &&
                                               lastValues[nValues - 2] == 2 && lastValues[nValues - 1] == 3,
              detail);
        snprintf(detail, sizeof(detail), "%zu AuditWriteUpdateEventType events", auditEvents);
        check("event notifications", auditEvents >= 3, detail);

        /* Call GetMonitoredItems. */
        UA_Variant in;
        UA_Variant_setScalar(&in, &subId, &UA_TYPES[UA_TYPES_UINT32]);
        size_t outSize = 0;
        UA_Variant *out = NULL;
        res = UA_Client_call(client, UA_NS0ID(SERVER), UA_NS0ID(SERVER_GETMONITOREDITEMS), 1, &in, &outSize, &out);
        check("Call GetMonitoredItems", res == UA_STATUSCODE_GOOD && outSize == 2 && out[0].arrayLength == 2,
              UA_StatusCode_name(res));
        UA_Array_delete(out, outSize, &UA_TYPES[UA_TYPES_VARIANT]);
        UA_MonitoredItemCreateResult_clear(&mres);
        UA_MonitoredItemCreateResult_clear(&eres);
        res = UA_Client_Subscriptions_deleteSingle(client, subId);
        check("DeleteSubscriptions", res == UA_STATUSCODE_GOOD, UA_StatusCode_name(res));
    }

    history(client, level);
    dropClient(client);
}

static size_t historyValues = 0;
static UA_Double historyLast = 0;

static UA_Boolean historyCb(UA_Client *c, const UA_NodeId *node, UA_Boolean moreData,
                            const UA_ExtensionObject *data, void *ctx) {
    (void)c, (void)node, (void)moreData, (void)ctx;
    if(data->content.decoded.type != &UA_TYPES[UA_TYPES_HISTORYDATA])
        return true;
    UA_HistoryData *h = (UA_HistoryData *)data->content.decoded.data;
    for(size_t i = 0; i < h->dataValuesSize; i++) {
        if(h->dataValues[i].hasValue &&
           UA_Variant_hasScalarType(&h->dataValues[i].value, &UA_TYPES[UA_TYPES_DOUBLE])) {
            historyValues++;
            historyLast = *(UA_Double *)h->dataValues[i].value.data;
        }
    }
    return true;
}

static void history(UA_Client *client, UA_NodeId level) {
    UA_DateTime start = UA_DateTime_now() - 600 * UA_DATETIME_SEC;
    for(int i = 1; i <= 5; i++) {
        UA_Double d = 10.0 * i;
        writeValue(client, level, &d, &UA_TYPES[UA_TYPES_DOUBLE]);
    }
    UA_DateTime end = UA_DateTime_now() + UA_DATETIME_SEC;
    /* Two values per call: the client follows the continuation points. */
    UA_StatusCode res =
        UA_Client_HistoryRead_raw(client, &level, historyCb, start, end, UA_STRING_NULL, false, 2,
                                  UA_TIMESTAMPSTORETURN_BOTH, NULL);
    char detail[128];
    snprintf(detail, sizeof(detail), "%s, %zu values, last %g", UA_StatusCode_name(res), historyValues, historyLast);
    check("HistoryRead raw (continuation points)", res == UA_STATUSCODE_GOOD && historyValues >= 5 &&
                                                       historyLast == 50.0, detail);
}

static void users(const char *url) {
    UA_Client *client = newClient("None", UA_MESSAGESECURITYMODE_NONE, NULL, NULL);
    UA_StatusCode res = client ? UA_Client_connect(client, url) : UA_STATUSCODE_BADINTERNALERROR;
    UA_Int32 v = 1;
    if(res == UA_STATUSCODE_GOOD) {
        UA_UInt16 ns = 2;
        res = writeValue(client, UA_NODEID_NUMERIC(ns, 1), &v, &UA_TYPES[UA_TYPES_INT32]);
    }
    check("anonymous write refused", res == UA_STATUSCODE_BADUSERACCESSDENIED, UA_StatusCode_name(res));
    dropClient(client);

    client = newClient("Basic256Sha256", UA_MESSAGESECURITYMODE_SIGNANDENCRYPT, "operator", "nope");
    res = client ? UA_Client_connect(client, url) : UA_STATUSCODE_BADINTERNALERROR;
    check("wrong password refused", res != UA_STATUSCODE_GOOD, UA_StatusCode_name(res));
    dropClient(client);

    client = newClient("Basic256Sha256", UA_MESSAGESECURITYMODE_SIGN, "viewer", "s3cret");
    res = client ? UA_Client_connect(client, url) : UA_STATUSCODE_BADINTERNALERROR;
    if(res == UA_STATUSCODE_GOOD)
        res = writeValue(client, UA_NODEID_NUMERIC(2, 1), &v, &UA_TYPES[UA_TYPES_INT32]);
    check("viewer write refused", res == UA_STATUSCODE_BADUSERACCESSDENIED, UA_StatusCode_name(res));
    dropClient(client);
}

int main(int argc, char *argv[]) {
    const char *url = argc > 1 ? argv[1] : getenv("FASTUA_URL");
    if(!url) {
        fprintf(stderr, "usage: %s [opc.tcp://host:port] (or FASTUA_URL)\n", argv[0]);
        return 2;
    }
    if(makeCert() != UA_STATUSCODE_GOOD) {
        check("client certificate", 0, NULL);
        return 1;
    }
    policies(url);
    users(url);
    services(url);
    UA_ByteString_clear(&cert);
    UA_ByteString_clear(&key);
    printf("%d failure(s)\n", failures);
    return failures ? 1 : 0;
}
