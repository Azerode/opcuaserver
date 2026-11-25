/* Reference server for the comparative benchmark (tests/compare/README.md).
 *
 * usage: open62541_server <port> <output dir>
 *
 * Same data as tests/compare/config/machine.json: 100 Int32 variables, ns=1;i=1..100,
 * readable and writable by anonymous users. Endpoints: None, Basic256Sha256
 * and ECC_nistP256_AesGcm (Sign and SignAndEncrypt), every client certificate
 * accepted. Writes its RSA and ECC certificates (DER) to the output dir and
 * the file "ready" once listening. */

#include <open62541/plugin/certificategroup_default.h>
#include <open62541/plugin/create_certificate.h>
#include <open62541/plugin/log_stdout.h>
#include <open62541/server.h>
#include <open62541/server_config_default.h>

#include <stdio.h>
#include <stdlib.h>

static UA_StatusCode makeCert(const char *keyType, const char *curve, UA_ByteString *cert, UA_ByteString *key) {
    UA_String subject[2] = {UA_STRING_STATIC("O=open62541"), UA_STRING_STATIC("CN=open62541 compare")};
    UA_String san[2] = {UA_STRING_STATIC("DNS:localhost"), UA_STRING_STATIC("URI:urn:open62541.server.application")};
    UA_KeyValueMap *kvm = UA_KeyValueMap_new();
    UA_String type = UA_STRING((char *)(uintptr_t)keyType);
    UA_UInt16 days = 30;
    UA_KeyValueMap_setScalar(kvm, UA_QUALIFIEDNAME(0, "key-type"), &type, &UA_TYPES[UA_TYPES_STRING]);
    if(curve) {
        UA_String c = UA_STRING((char *)(uintptr_t)curve);
        UA_KeyValueMap_setScalar(kvm, UA_QUALIFIEDNAME(0, "ecc-curve"), &c, &UA_TYPES[UA_TYPES_STRING]);
    } else {
        UA_UInt16 bits = 2048;
        UA_KeyValueMap_setScalar(kvm, UA_QUALIFIEDNAME(0, "key-size-bits"), &bits, &UA_TYPES[UA_TYPES_UINT16]);
    }
    UA_KeyValueMap_setScalar(kvm, UA_QUALIFIEDNAME(0, "expires-in-days"), &days, &UA_TYPES[UA_TYPES_UINT16]);
    UA_StatusCode res =
        UA_CreateCertificate(UA_Log_Stdout, subject, 2, san, 2, UA_CERTIFICATEFORMAT_DER, kvm, key, cert);
    UA_KeyValueMap_delete(kvm);
    return res;
}

static void writeFile(const char *dir, const char *name, const UA_ByteString *b) {
    char path[1024];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    FILE *f = fopen(path, "wb");
    if(f) {
        if(b)
            fwrite(b->data, 1, b->length, f);
        fclose(f);
    }
}

static void ready(UA_Server *server, void *dir) { writeFile((const char *)dir, "ready", NULL); }

int main(int argc, char **argv) {
    if(argc < 3) {
        fprintf(stderr, "usage: %s <port> <output dir>\n", argv[0]);
        return 2;
    }
    UA_UInt16 port = (UA_UInt16)atoi(argv[1]);

    UA_ByteString cert, key, eccCert, eccKey;
    if(makeCert("RSA", NULL, &cert, &key) != UA_STATUSCODE_GOOD ||
       makeCert("ec", "prime256v1", &eccCert, &eccKey) != UA_STATUSCODE_GOOD)
        return 1;
    writeFile(argv[2], "server_rsa.der", &cert);
    writeFile(argv[2], "server_ecc.der", &eccCert);

    UA_Server *server = UA_Server_new();
    UA_ServerConfig *config = UA_Server_getConfig(server);
    UA_ServerConfig_setDefaultWithSecurityPolicies(config, port, &cert, &key, NULL, 0, NULL, 0, NULL, 0);
    UA_ServerConfig_addSecurityPolicyEccNistP256AesGcm(config, &eccCert, &eccKey);
    UA_ServerConfig_addAllEndpoints(config);
    if(config->secureChannelPKI.clear)
        config->secureChannelPKI.clear(&config->secureChannelPKI);
    UA_CertificateGroup_AcceptAll(&config->secureChannelPKI);
    if(config->sessionPKI.clear)
        config->sessionPKI.clear(&config->sessionPKI);
    UA_CertificateGroup_AcceptAll(&config->sessionPKI);
    config->maxSessions = 0;
    config->maxSecureChannels = 0;

    for(UA_UInt32 i = 1; i <= 100; i++) {
        UA_VariableAttributes attr = UA_VariableAttributes_default;
        UA_Int32 v = 0;
        UA_Variant_setScalar(&attr.value, &v, &UA_TYPES[UA_TYPES_INT32]);
        attr.accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;
        attr.userAccessLevel = attr.accessLevel;
        attr.dataType = UA_TYPES[UA_TYPES_INT32].typeId;
        char name[16];
        snprintf(name, sizeof(name), "V%u", i);
        attr.displayName = UA_LOCALIZEDTEXT("en", name);
        UA_Server_addVariableNode(server, UA_NODEID_NUMERIC(1, i), UA_NS0ID(OBJECTSFOLDER), UA_NS0ID(ORGANIZES),
                                  UA_QUALIFIEDNAME(1, name), UA_NS0ID(BASEDATAVARIABLETYPE), attr, NULL, NULL);
    }
    UA_Server_addTimedCallback(server, ready, argv[2], UA_DateTime_nowMonotonic() + UA_DATETIME_MSEC, NULL);
    UA_StatusCode res = UA_Server_runUntilInterrupt(server);
    UA_Server_delete(server);
    return res == UA_STATUSCODE_GOOD ? 0 : 1;
}
