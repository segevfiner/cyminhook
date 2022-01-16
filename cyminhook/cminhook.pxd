from libc.stddef cimport wchar_t

cdef extern from "MinHook.h":
    ctypedef void* LPVOID
    ctypedef const char* LPCSTR;
    ctypedef const wchar_t* LPCWSTR;

    ctypedef enum MH_STATUS:
        # Unknown error. Should not be returned.
        MH_UNKNOWN

        # Successful.
        MH_OK

        # MinHook is already initialized.
        MH_ERROR_ALREADY_INITIALIZED

        # MinHook is not initialized yet, or already uninitialized.
        MH_ERROR_NOT_INITIALIZED

        # The hook for the specified target function is already created.
        MH_ERROR_ALREADY_CREATED

        # The hook for the specified target function is not created yet.
        MH_ERROR_NOT_CREATED

        # The hook for the specified target function is already enabled.
        MH_ERROR_ENABLED

        # The hook for the specified target function is not enabled yet, or already
        # disabled.
        MH_ERROR_DISABLED

        # The specified pointer is invalid. It points the address of non-allocated
        # and/or non-executable region.
        MH_ERROR_NOT_EXECUTABLE

        # The specified target function cannot be hooked.
        MH_ERROR_UNSUPPORTED_FUNCTION

        # Failed to allocate memory.
        MH_ERROR_MEMORY_ALLOC

        # Failed to change the memory protection.
        MH_ERROR_MEMORY_PROTECT

        # The specified module is not loaded.
        MH_ERROR_MODULE_NOT_FOUND

        # The specified function is not found.
        MH_ERROR_FUNCTION_NOT_FOUND

    enum:
        MH_ALL_HOOKS

    MH_STATUS MH_Initialize()

    MH_STATUS MH_Uninitialize()

    MH_STATUS MH_CreateHook(LPVOID pTarget, LPVOID pDetour, LPVOID *ppOriginal)

    MH_STATUS MH_CreateHookApi(
        LPCWSTR pszModule, LPCSTR pszProcName, LPVOID pDetour, LPVOID *ppOriginal)

    MH_STATUS MH_CreateHookApiEx(
        LPCWSTR pszModule, LPCSTR pszProcName, LPVOID pDetour, LPVOID *ppOriginal, LPVOID *ppTarget)

    MH_STATUS MH_RemoveHook(LPVOID pTarget)

    MH_STATUS MH_EnableHook(LPVOID pTarget)

    MH_STATUS MH_DisableHook(LPVOID pTarget)

    MH_STATUS MH_QueueEnableHook(LPVOID pTarget)

    MH_STATUS MH_QueueDisableHook(LPVOID pTarget)

    MH_STATUS MH_ApplyQueued(VOID)

    const char * MH_StatusToString(MH_STATUS status)
