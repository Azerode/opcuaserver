/* Interoperability check of the ECC AEAD security policies against the
 * open62541 client (the reference implementation of the
 * SecureChannelEnhancements).
 *
 * usage: open62541_ecc <opc.tcp://host:port> <trusted user certificates dir>
 *
 * For every ECC_* AEAD policy and both secure modes: anonymous session, reads,
 * a browse and a large read (multi-chunk response). Then, per policy, an X.509
 * user token on the same curve (channel-bound user token signature) and a user
 * name / password (EccEncryptedSecret), and per curve a security token renewal
 * (IKM chaining). The server must run with --trust-all-clients and a users file
 * with operator / s3cret. Exits non-zero on failure. */

#include <open62541/client_config_default.h>
#include <open62541/client_highlevel.h>
#include <open62541/plugin/certificategroup_default.h>
#include <open62541/plugin/create_certificate.h>
#include <open62541/plugin/log_stdout.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PREFIX "http://opcfoundation.org/UA/SecurityPolicy#ECC_"
#define CLIENT_URI "urn:fastua:interop:open62541"

static int failures = 0;

static void check(const char *label, int ok, const char *detail) {
    printf("%s %s%s%s%s\n", ok ? "PASS" : "FAIL", label, detail ? "  (" : "", detail ? detail : "",
           detail ? ")" : "");
    fflush(stdout);
    if(!ok)
        failures++;
}

typedef UA_StatusCode (*AddPolicy)(UA_ClientConfig *, const UA_ByteString *, const UA_ByteString *);

static const struct {
    const char *name;
    const char *curve; /* UA_CreateCertificate "ecc-curve" */
    AddPolicy add;
} POLICIES[] = {
    {"nistP256_AesGcm", "prime256v1", UA_ClientConfig_addSecurityPolicyEccNistP256AesGcm},
    {"nistP256_ChaChaPoly", "prime256v1", UA_ClientConfig_addSecurityPolicyEccNistP256ChaChaPoly},
    {"nistP384_AesGcm", "secp384r1", UA_ClientConfig_addSecurityPolicyEccNistP384AesGcm},
    {"nistP384_ChaChaPoly", "secp384r1", UA_ClientConfig_addSecurityPolicyEccNistP384ChaChaPoly},
    {"curve25519_AesGcm", "ed25519", UA_ClientConfig_addSecurityPolicyEccCurve25519AesGcm},
    {"curve25519_ChaChaPoly", "ed25519", UA_ClientConfig_addSecurityPolicyEccCurve25519ChaChaPoly},
};
#define NPOLICIES (sizeof(POLICIES) / sizeof(POLICIES[0]))

static UA_StatusCode makeCert(const char *curve, const char *cn, const char *uri, UA_ByteString *cert,
                              UA_ByteString *key) {
    UA_String subject[2] = {UA_STRING_STATIC("O=fastua-interop"), UA_STRING((char *)(uintptr_t)cn)};
    char uriSan[256];
    snprintf(uriSan, sizeof(uriSan), "URI:%s", uri);
    UA_String san[2] = {UA_STRING_STATIC("DNS:localhost"), UA_STRING(uriSan)};
    UA_KeyValueMap *kvm = UA_KeyValueMap_new();
    UA_String type = UA_STRING("ec");
    UA_String c = UA_STRING((char *)(uintptr_t)curve);
    UA_UInt16 days = 30;
    UA_KeyValueMap_setScalar(kvm, UA_QUALIFIEDNAME(0, "key-type"), &type, &UA_TYPES[UA_TYPES_STRING]);
    UA_KeyValueMap_setScalar(kvm, UA_QUALIFIEDNAME(0, "ecc-curve"), &c, &UA_TYPES[UA_TYPES_STRING]);
    UA_KeyValueMap_setScalar(kvm, UA_QUALIFIEDNAME(0, "expires-in-days"), &days, &UA_TYPES[UA_TYPES_UINT16]);
    UA_StatusCode res =
        UA_CreateCertificate(UA_Log_Stdout, subject, 2, san, 2, UA_CERTIFICATEFORMAT_DER, kvm, key, cert);
    UA_KeyValueMap_delete(kvm);
    return res;
}

static int hasPolicy(UA_ClientConfig *cc, const char *uri) {
    UA_String u = UA_STRING((char *)(uintptr_t)uri);
    for(size_t i = 0; i < cc->securityPoliciesSize; i++)
        if(UA_String_equal(&cc->securityPolicies[i].policyUri, &u))
            return 1;
    return 0;
}

/* A client for one policy and mode, with an X.509 user token if userCert. */
static UA_Client *newClient(size_t p, UA_MessageSecurityMode mode, const UA_ByteString *cert,
                            const UA_ByteString *key, const UA_ByteString *userCert,
                            const UA_ByteString *userKey, UA_UInt32 lifetime) {
    char uri[128];
    snprintf(uri, sizeof(uri), PREFIX "%s", POLICIES[p].name);
    UA_Client *client = UA_Client_new();
    UA_ClientConfig *cc = UA_Client_getConfig(client);
    cc->logging = UA_Log_Stdout_new(UA_LOGLEVEL_WARNING);
    if(UA_ClientConfig_setDefaultEncryption(cc, *cert, *key, NULL, 0, NULL, 0) != UA_STATUSCODE_GOOD) {
        UA_Client_delete(client);
        return NULL;
    }
    if(!hasPolicy(cc, uri) && POLICIES[p].add(cc, cert, key) != UA_STATUSCODE_GOOD) {
        UA_Client_delete(client);
        return NULL;
    }
    if(cc->certificateVerification.clear)
        cc->certificateVerification.clear(&cc->certificateVerification);
    UA_CertificateGroup_AcceptAll(&cc->certificateVerification);
    cc->securityPolicyUri = UA_STRING_ALLOC(uri);
    cc->securityMode = mode;
    UA_String_clear(&cc->clientDescription.applicationUri);
    cc->clientDescription.applicationUri = UA_STRING_ALLOC(CLIENT_URI);
    if(lifetime)
        cc->secureChannelLifeTime = lifetime;
    if(userCert && UA_ClientConfig_setAuthenticationCert(cc, *userCert, *userKey) != UA_STATUSCODE_GOOD) {
        UA_Client_delete(client);
        return NULL;
    }
    return client;
}

static UA_StatusCode readCurrentTime(UA_Client *client) {
    UA_Variant v;
    UA_Variant_init(&v);
    UA_StatusCode res = UA_Client_readValueAttribute(client, UA_NS0ID(SERVER_SERVERSTATUS_CURRENTTIME), &v);
    if(res == UA_STATUSCODE_GOOD && !UA_Variant_hasScalarType(&v, &UA_TYPES[UA_TYPES_DATETIME]))
        res = UA_STATUSCODE_BADTYPEMISMATCH;
    UA_Variant_clear(&v);
    return res;
}

/* One Read with many nodes: a response larger than one chunk. */
static UA_StatusCode readMany(UA_Client *client) {
    enum { N = 4000 };
    UA_ReadValueId *ids = (UA_ReadValueId *)UA_Array_new(N, &UA_TYPES[UA_TYPES_READVALUEID]);
    for(size_t i = 0; i < N; i++) {
        ids[i].nodeId = UA_NS0ID(SERVER_NAMESPACEARRAY);
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
    for(size_t i = 0; res == UA_STATUSCODE_GOOD && i < resp.resultsSize; i++)
        res = resp.results[i].status;
    UA_ReadResponse_clear(&resp);
    UA_Array_delete(ids, N, &UA_TYPES[UA_TYPES_READVALUEID]);
    return res;
}

static UA_StatusCode browseObjects(UA_Client *client) {
    UA_BrowseRequest req;
    UA_BrowseRequest_init(&req);
    UA_BrowseDescription bd;
    UA_BrowseDescription_init(&bd);
    bd.nodeId = UA_NS0ID(OBJECTSFOLDER);
    bd.resultMask = UA_BROWSERESULTMASK_ALL;
    bd.browseDirection = UA_BROWSEDIRECTION_FORWARD;
    req.nodesToBrowse = &bd;
    req.nodesToBrowseSize = 1;
    UA_BrowseResponse resp = UA_Client_Service_browse(client, req);
    UA_StatusCode res = resp.responseHeader.serviceResult;
    if(res == UA_STATUSCODE_GOOD && (resp.resultsSize != 1 || resp.results[0].referencesSize == 0))
        res = UA_STATUSCODE_BADUNEXPECTEDERROR;
    UA_BrowseResponse_clear(&resp);
    return res;
}

int main(int argc, char *argv[]) {
    if(argc < 3) {
        fprintf(stderr, "usage: %s <opc.tcp://host:port> <trusted user certificates dir>\n", argv[0]);
        return 2;
    }
    const char *url = argv[1];
    const char *userDir = argv[2];
    char label[256];
    const UA_MessageSecurityMode modes[2] = {UA_MESSAGESECURITYMODE_SIGN, UA_MESSAGESECURITYMODE_SIGNANDENCRYPT};

    for(size_t p = 0; p < NPOLICIES; p++) {
        UA_ByteString cert = UA_BYTESTRING_NULL, key = UA_BYTESTRING_NULL;
        UA_ByteString ucert = UA_BYTESTRING_NULL, ukey = UA_BYTESTRING_NULL;
        if(makeCert(POLICIES[p].curve, "CN=open62541 interop client", CLIENT_URI, &cert, &key) != UA_STATUSCODE_GOOD ||
           makeCert(POLICIES[p].curve, "CN=interop user", "urn:fastua:interop:user", &ucert, &ukey) !=
               UA_STATUSCODE_GOOD) {
            check(POLICIES[p].name, 0, "certificate generation failed");
            continue;
        }
        char path[1024];
        snprintf(path, sizeof(path), "%s/open62541_%s.der", userDir, POLICIES[p].name);
        FILE *f = fopen(path, "wb");
        if(f) {
            fwrite(ucert.data, 1, ucert.length, f);
            fclose(f);
        }

        for(size_t m = 0; m < 2; m++) {
            const char *mname = m ? "SignAndEncrypt" : "Sign";
            snprintf(label, sizeof(label), "ECC_%s %s anonymous", POLICIES[p].name, mname);
            UA_Client *client = newClient(p, modes[m], &cert, &key, NULL, NULL, 0);
            UA_StatusCode res = client ? UA_Client_connect(client, url) : UA_STATUSCODE_BADINTERNALERROR;
            if(res == UA_STATUSCODE_GOOD)
                res = readCurrentTime(client);
            if(res == UA_STATUSCODE_GOOD)
                res = browseObjects(client);
            if(res == UA_STATUSCODE_GOOD)
                res = readMany(client);
            check(label, res == UA_STATUSCODE_GOOD, UA_StatusCode_name(res));
            if(client) {
                UA_Client_disconnect(client);
                UA_Client_delete(client);
            }
        }

        /* X.509 user token: channel-bound user token signature. */
        snprintf(label, sizeof(label), "ECC_%s SignAndEncrypt X.509 user", POLICIES[p].name);
        UA_Client *client = newClient(p, modes[1], &cert, &key, &ucert, &ukey, 0);
        UA_StatusCode res = client ? UA_Client_connect(client, url) : UA_STATUSCODE_BADINTERNALERROR;
        if(res == UA_STATUSCODE_GOOD)
            res = readCurrentTime(client);
        check(label, res == UA_STATUSCODE_GOOD, UA_StatusCode_name(res));
        if(client) {
            UA_Client_disconnect(client);
            UA_Client_delete(client);
        }

        /* User name / password: an EccEncryptedSecret for the ephemeral key
         * the server returns in CreateSession. */
        snprintf(label, sizeof(label), "ECC_%s SignAndEncrypt user name", POLICIES[p].name);
        client = newClient(p, modes[1], &cert, &key, NULL, NULL, 0);
        res = client ? UA_ClientConfig_setAuthenticationUsername(UA_Client_getConfig(client), "operator", "s3cret")
                     : UA_STATUSCODE_BADINTERNALERROR;
        if(res == UA_STATUSCODE_GOOD)
            res = UA_Client_connect(client, url);
        if(res == UA_STATUSCODE_GOOD)
            res = readCurrentTime(client);
        check(label, res == UA_STATUSCODE_GOOD, UA_StatusCode_name(res));
        if(client) {
            UA_Client_disconnect(client);
            UA_Client_delete(client);
        }

        snprintf(label, sizeof(label), "ECC_%s wrong password refused", POLICIES[p].name);
        client = newClient(p, modes[1], &cert, &key, NULL, NULL, 0);
        res = client ? UA_ClientConfig_setAuthenticationUsername(UA_Client_getConfig(client), "operator", "nope")
                     : UA_STATUSCODE_BADINTERNALERROR;
        if(res == UA_STATUSCODE_GOOD)
            res = UA_Client_connect(client, url);
        check(label, res != UA_STATUSCODE_GOOD, UA_StatusCode_name(res));
        if(client) {
            UA_Client_disconnect(client);
            UA_Client_delete(client);
        }

        /* Token renewal once per curve: the server's minimum lifetime is 10 s,
         * the client renews at 75 % of it. */
        if(strstr(POLICIES[p].name, "AesGcm")) {
            snprintf(label, sizeof(label), "ECC_%s token renewal", POLICIES[p].name);
            client = newClient(p, modes[1], &cert, &key, NULL, NULL, 10000);
            res = client ? UA_Client_connect(client, url) : UA_STATUSCODE_BADINTERNALERROR;
            /* 15 s of reads: past the token's 125 % grace period, so this
             * only passes if the renewed token works. */
            for(int i = 0; res == UA_STATUSCODE_GOOD && i < 150; i++) {
                res = UA_Client_run_iterate(client, 100);
                if(res == UA_STATUSCODE_GOOD)
                    res = readCurrentTime(client);
            }
            check(label, res == UA_STATUSCODE_GOOD, UA_StatusCode_name(res));
            if(client) {
                UA_Client_disconnect(client);
                UA_Client_delete(client);
            }
        }
        UA_ByteString_clear(&cert);
        UA_ByteString_clear(&key);
        UA_ByteString_clear(&ucert);
        UA_ByteString_clear(&ukey);
    }
    printf("%d failure(s)\n", failures);
    return failures ? 1 : 0;
}
