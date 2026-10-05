/* Test-only forwarding module: real SoftHSM with ownership counters and bounded faults. */
#include <pkcs11.h>
#include <dlfcn.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

static CK_FUNCTION_LIST_PTR real;
static CK_FUNCTION_LIST functions;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static CK_SESSION_HANDLE handles[4096];
static unsigned long live, opened, closed, finalized, close_attempts, invalid_closes, logout_attempts;
static unsigned long fault, fault_code;

/* Indices: opens, closes, finalizes, live handles, close attempts, invalid closes. */
unsigned long test_counter(unsigned long index) {
    pthread_mutex_lock(&lock);
    unsigned long values[] = {opened, closed, finalized, live, close_attempts, invalid_closes, logout_attempts};
    unsigned long result = index < 7 ? values[index] : 0;
    pthread_mutex_unlock(&lock);
    return result;
}
void test_fault(unsigned long operation, unsigned long code) {
    pthread_mutex_lock(&lock);
    fault = operation; fault_code = code;
    pthread_mutex_unlock(&lock);
}
static CK_RV injected(unsigned long operation) {
    pthread_mutex_lock(&lock);
    CK_RV result = fault == operation ? fault_code : CKR_OK;
    pthread_mutex_unlock(&lock);
    return result;
}
static CK_RV initialize(CK_VOID_PTR args) {
    CK_RV rv = injected(1);
    return rv ? rv : real->C_Initialize(args);
}
static CK_RV open_session(CK_SLOT_ID slot, CK_FLAGS flags, CK_VOID_PTR app, CK_NOTIFY notify, CK_SESSION_HANDLE_PTR out) {
    CK_RV rv = injected(2);
    if (rv) return rv;
    rv = real->C_OpenSession(slot, flags, app, notify, out);
    if (rv == CKR_OK) {
        pthread_mutex_lock(&lock);
        if (live == 4096) abort();
        handles[live++] = *out; opened++;
        pthread_mutex_unlock(&lock);
    }
    return rv;
}
static CK_RV close_session(CK_SESSION_HANDLE handle) {
    pthread_mutex_lock(&lock); close_attempts++; pthread_mutex_unlock(&lock);
    CK_RV rv = injected(3);
    if (rv) return rv;
    rv = real->C_CloseSession(handle);
    pthread_mutex_lock(&lock);
    if (rv == CKR_OK) {
        unsigned long i;
        for (i = 0; i < live && handles[i] != handle; i++) {}
        if (i == live) invalid_closes++;
        else { handles[i] = handles[--live]; closed++; }
    } else invalid_closes++;
    pthread_mutex_unlock(&lock);
    return rv;
}
static CK_RV logout_session(CK_SESSION_HANDLE handle) {
    pthread_mutex_lock(&lock); logout_attempts++; pthread_mutex_unlock(&lock);
    CK_RV rv = injected(8);
    return rv ? rv : real->C_Logout(handle);
}
static CK_RV finalize(CK_VOID_PTR args) {
    CK_RV rv = real->C_Finalize(args);
    if (rv == CKR_OK) {
        pthread_mutex_lock(&lock); finalized++; live = 0; pthread_mutex_unlock(&lock);
    }
    return rv;
}
static CK_RV encrypt_init(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE k) {
    CK_RV rv = injected(4); return rv ? rv : real->C_EncryptInit(h,m,k);
}
static CK_RV encrypt(CK_SESSION_HANDLE h, CK_BYTE_PTR in, CK_ULONG n, CK_BYTE_PTR out, CK_ULONG_PTR size) {
    CK_RV rv = injected(5); return rv ? rv : real->C_Encrypt(h,in,n,out,size);
}
static CK_RV decrypt_init(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE k) {
    CK_RV rv = injected(6); return rv ? rv : real->C_DecryptInit(h,m,k);
}
static CK_RV decrypt(CK_SESSION_HANDLE h, CK_BYTE_PTR in, CK_ULONG n, CK_BYTE_PTR out, CK_ULONG_PTR size) {
    CK_RV rv = injected(7); return rv ? rv : real->C_Decrypt(h,in,n,out,size);
}
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR out) {
    pthread_mutex_lock(&lock);
    if (!real) {
        const char *path = getenv("CRYPTO11_TEST_MODULE");
        void *library = path ? dlopen(path, RTLD_NOW | RTLD_LOCAL) : NULL;
        CK_C_GetFunctionList get = library ? (CK_C_GetFunctionList)dlsym(library, "C_GetFunctionList") : NULL;
        if (!get || get(&real) != CKR_OK) { pthread_mutex_unlock(&lock); return CKR_GENERAL_ERROR; }
        functions = *real;
        functions.C_Initialize = initialize;
        functions.C_OpenSession = open_session;
        functions.C_CloseSession = close_session;
        functions.C_Finalize = finalize;
        functions.C_Logout = logout_session;
        functions.C_EncryptInit = encrypt_init;
        functions.C_Encrypt = encrypt;
        functions.C_DecryptInit = decrypt_init;
        functions.C_Decrypt = decrypt;
    }
    *out = &functions;
    pthread_mutex_unlock(&lock);
    return CKR_OK;
}
