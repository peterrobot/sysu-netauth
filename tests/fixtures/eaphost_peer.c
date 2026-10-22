// Exercise the actual DLL through the Windows SDK's callback declarations.
// No registration, credentials file, Npcap, elevation, or network changes.
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <eaptypes.h>
#include <eapmethodpeerapis.h>

typedef DWORD (WINAPI *GetInfo)(EAP_TYPE *, EAP_PEER_METHOD_ROUTINES *, EAP_ERROR **);
typedef VOID (WINAPI *FreeMemory)(void *);

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "EAPHost ABI check failed at line %d: %s\n", __LINE__, #condition); \
    return 1; } } while (0)

int wmain(int argc, wchar_t **argv) {
    HMODULE dll;
    GetInfo get_info;
    FreeMemory free_memory;
    EAP_TYPE type = {4, 0, 0};
    EAP_PEER_METHOD_ROUTINES api = {0};
    EAP_ERROR *error = (EAP_ERROR *)1;
    EAP_SESSION_HANDLE session = NULL;
    BYTE config[] = "SYSU-EAP-MD5-v1";
    // UTF-8 JSON; the method must use GBK password bytes for the MD5 response.
    BYTE user[] = "{\"username\":\"netid\",\"password\":\"\xe5\xaf\x86\xe7\xa0\x81\"}";
    BYTE request[22] = {1, 7, 0, 22, 4, 16};
    BYTE response[64] = {0};
    BYTE digest[16] = {0x9c, 0xc1, 0x1d, 0x1f, 0xe7, 0xfd, 0x61, 0xac,
        0x0f, 0xb8, 0x2b, 0x25, 0xbe, 0xb2, 0xcc, 0xe9};
    EapPeerMethodOutput output = {0};
    EapPeerMethodResult result = {0};
    BOOL invoke_ui = TRUE;
    BYTE *user_out = NULL;
    DWORD user_size = 0, size;
    LPWSTR identity = NULL;
    int i;

    CHECK(argc == 2);
    dll = LoadLibraryW(argv[1]);
    CHECK(dll != NULL);
    get_info = (GetInfo)GetProcAddress(dll, "EapPeerGetInfo");
    free_memory = (FreeMemory)GetProcAddress(dll, "EapPeerFreeMemory");
    CHECK(get_info && free_memory && GetProcAddress(dll, "EapPeerFreeErrorMemory"));
    CHECK(get_info(&type, &api, &error) == ERROR_SUCCESS && error == NULL);
    CHECK(api.pEapType && api.pEapType->type == 4 && api.dwVersion == 1);
    CHECK(api.EapPeerInitialize(&error) == ERROR_SUCCESS);

    CHECK(api.EapPeerGetIdentity(EAP_FLAG_MACHINE_AUTH, sizeof(config)-1, config, sizeof(user)-1, user, NULL,
        &invoke_ui, &user_size, &user_out, &identity, &error) == ERROR_SUCCESS);
    CHECK(!invoke_ui && identity && wcscmp(identity, L"netid") == 0);
    CHECK(user_size > 0 && user_out);
    CHECK(api.EapPeerBeginSession(EAP_FLAG_MACHINE_AUTH, NULL, NULL, sizeof(config)-1, config, user_size,
        user_out, 1500, &session, &error) == ERROR_SUCCESS && session != NULL);
    free_memory(identity);
    free_memory(user_out);

    // Never report success before a valid challenge, even on host success.
    CHECK(api.EapPeerGetResult(session, EapPeerMethodResultSuccess, &result, &error) == ERROR_SUCCESS);
    CHECK(!result.fIsSuccess && !result.fSaveUserData && !result.fSaveConnectionData);
    for (i = 0; i < 16; ++i) request[6+i] = (BYTE)i;
    CHECK(api.EapPeerProcessRequestPacket(session, sizeof(request), (EapPacket *)request,
        &output, &error) == ERROR_SUCCESS && output.action == EapPeerMethodResponseActionSend);
    size = 5;
    CHECK(api.EapPeerGetResponsePacket(session, &size, (EapPacket *)response, &error) == ERROR_INSUFFICIENT_BUFFER);
    CHECK(size == 27 && response[0] == 0);
    size = sizeof(response);
    CHECK(api.EapPeerGetResponsePacket(session, &size, (EapPacket *)response, &error) == ERROR_SUCCESS);
    CHECK(size == 27 && response[0] == 2 && response[1] == 7 && response[4] == 4 && response[5] == 16);
    CHECK(memcmp(response+6, digest, 16) == 0 && memcmp(response+22, "netid", 5) == 0);
    CHECK(api.EapPeerGetResult(session, EapPeerMethodResultSuccess, &result, &error) == ERROR_SUCCESS);
    CHECK(result.fIsSuccess && !result.fSaveUserData && result.pUserData == NULL);
    CHECK(api.EapPeerGetResult(session, EapPeerMethodResultFailure, &result, &error) == ERROR_SUCCESS);
    CHECK(!result.fIsSuccess);

    // Continue answering challenges without an intervening terminal packet.
    request[1] = 8;
    CHECK(api.EapPeerProcessRequestPacket(session, sizeof(request), (EapPacket *)request,
        &output, &error) == ERROR_SUCCESS && output.action == EapPeerMethodResponseActionSend);
    CHECK(api.EapPeerProcessRequestPacket(session, sizeof(request)-1, (EapPacket *)request,
        &output, &error) == ERROR_SUCCESS && output.action == EapPeerMethodResponseActionDiscard);
    size = sizeof(response);
    CHECK(api.EapPeerGetResponsePacket(session, &size, (EapPacket *)response, &error) == ERROR_INVALID_STATE);
    CHECK(api.EapPeerEndSession(session, &error) == ERROR_SUCCESS);
    CHECK(api.EapPeerEndSession(session, &error) == ERROR_INVALID_HANDLE);
    CHECK(api.EapPeerBeginSession(0, NULL, NULL, 0, NULL, sizeof(user)-1, user, 1500,
        &session, &error) == ERROR_INVALID_DATA && session == NULL);
    type.type = 13;
    CHECK(get_info(&type, &api, &error) == ERROR_NOT_SUPPORTED && api.EapPeerBeginSession == NULL);
    type.type = 4;
    CHECK(get_info(&type, &api, &error) == ERROR_SUCCESS);
    CHECK(api.EapPeerShutdown(&error) == ERROR_SUCCESS);
    CHECK(FreeLibrary(dll));
    puts("EAPHost DLL ABI and authentication checks passed");
    return 0;
}
