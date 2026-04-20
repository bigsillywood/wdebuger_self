#include"WdbgDll.hpp"

BOOL WDebugerObject::AntiDetection_InjectHookFunctions()
{
    CHAR debugbuf[256] = { 0 };
    SIZE_T writesize = 0;
    BYTE dummy = 0x90;

    auto CleanupRemote = [&](LPVOID addr)
    {
        if (addr) VirtualFreeEx(this->ProcessHandle, addr, 0, MEM_RELEASE);
    };

    // =========================================================
    // 1) NtQueryInformationProcess hook
    // layout:
    //   [PROC...]
    // entry = base + NTQUERY_HOOK_ENTRY_OFFSET
    // =========================================================
    DWORD NtQueryFuncLen =
        (DWORD)((ULONG_PTR)&NtQueryInformationProcessDebugHook_end -
            (ULONG_PTR)&NtQueryInformationProcessDebugHook_begin);

    LPVOID NtQueryHookRemote = VirtualAllocEx(
        this->ProcessHandle,
        NULL,
        NtQueryFuncLen,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    if (!NtQueryHookRemote)
    {
        sprintf_s(debugbuf, sizeof(debugbuf),
            "[InjectHook] VirtualAllocEx NtQueryInformationProcess failed, code=%lu\n",
            GetLastError());
        OutputDebugStringA(debugbuf);
        return FALSE;
    }

    WriteProcessMemory(this->ProcessHandle, NtQueryHookRemote, &dummy, 1, &writesize);

    UCHAR* NtQueryBuf = (UCHAR*)malloc(NtQueryFuncLen);
    if (!NtQueryBuf)
    {
        CleanupRemote(NtQueryHookRemote);
        return FALSE;
    }

    memcpy(NtQueryBuf, &NtQueryInformationProcessDebugHook_begin, NtQueryFuncLen);
    this->WritePhysicalMem(NtQueryBuf, NtQueryFuncLen, (DWORD64)NtQueryHookRemote);
    FlushInstructionCache(this->ProcessHandle, NtQueryHookRemote, NtQueryFuncLen);
    free(NtQueryBuf);

    this->HookInformations.NtQueryInformationHookAddress =
        (DWORD64)NtQueryHookRemote + NTQUERY_HOOK_ENTRY_OFFSET;
    this->HookInformations.NtQueryInformationOriginalAddress = 0;

    sprintf_s(debugbuf, sizeof(debugbuf),
        "[InjectHook] NtQueryInformationProcess hook injected at %p\n",
        NtQueryHookRemote);
    OutputDebugStringA(debugbuf);

    // =========================================================
    // 2) OutputDebugString hook
    // layout:
    //   [PROC ret]
    // entry = base + OUTPUTDEBUGSTRING_HOOK_ENTRY_OFFSET
    // =========================================================
    DWORD OutDbgFuncLen =
        (DWORD)((ULONG_PTR)&OutputDebugStringhook_end -
            (ULONG_PTR)&OutputDebugStringHook_begin);

    LPVOID OutDbgHookRemote = VirtualAllocEx(
        this->ProcessHandle,
        NULL,
        OutDbgFuncLen,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    if (!OutDbgHookRemote)
    {
        sprintf_s(debugbuf, sizeof(debugbuf),
            "[InjectHook] VirtualAllocEx OutputDebugString hook failed, code=%lu\n",
            GetLastError());
        OutputDebugStringA(debugbuf);

        CleanupRemote(NtQueryHookRemote);
        ZeroMemory(&this->HookInformations, sizeof(this->HookInformations));
        return FALSE;
    }

    WriteProcessMemory(this->ProcessHandle, OutDbgHookRemote, &dummy, 1, &writesize);

    UCHAR* OutDbgBuf = (UCHAR*)malloc(OutDbgFuncLen);
    if (!OutDbgBuf)
    {
        CleanupRemote(OutDbgHookRemote);
        CleanupRemote(NtQueryHookRemote);
        ZeroMemory(&this->HookInformations, sizeof(this->HookInformations));
        return FALSE;
    }

    memcpy(OutDbgBuf, &OutputDebugStringHook_begin, OutDbgFuncLen);
    this->WritePhysicalMem(OutDbgBuf, OutDbgFuncLen, (DWORD64)OutDbgHookRemote);
    FlushInstructionCache(this->ProcessHandle, OutDbgHookRemote, OutDbgFuncLen);
    free(OutDbgBuf);

    this->HookInformations.OutputDebugStringHookAddress =
        (DWORD64)OutDbgHookRemote + OUTPUTDEBUGSTRING_HOOK_ENTRY_OFFSET;
    this->HookInformations.OutputDebugStringAOrignalAddress = 0;
    this->HookInformations.OutputDebugStringWOrignalAddress = 0;

    sprintf_s(debugbuf, sizeof(debugbuf),
        "[InjectHook] OutputDebugString hook injected at %p\n",
        OutDbgHookRemote);
    OutputDebugStringA(debugbuf);

    // =========================================================
    // 3) NtSetInformationThread hook
    // layout:
    //   +NTSETINFO_HOOK_ORIGINAL_OFFSET dq NtSetInformationThread_original
    //   +NTSETINFO_HOOK_ENTRY_OFFSET    PROC ...
    // =========================================================
    DWORD NtSetInfoThreadFuncLen =
        (DWORD)((ULONG_PTR)&NtSetInformationThreadHook_end -
            (ULONG_PTR)&NtSetInformationThreadHook_begin);

    LPVOID NtSetInfoThreadRemote = VirtualAllocEx(
        this->ProcessHandle,
        NULL,
        NtSetInfoThreadFuncLen,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    if (!NtSetInfoThreadRemote)
    {
        sprintf_s(debugbuf, sizeof(debugbuf),
            "[InjectHook] VirtualAllocEx NtSetInformationThread hook failed, code=%lu\n",
            GetLastError());
        OutputDebugStringA(debugbuf);

        CleanupRemote(OutDbgHookRemote);
        CleanupRemote(NtQueryHookRemote);
        ZeroMemory(&this->HookInformations, sizeof(this->HookInformations));
        return FALSE;
    }

    WriteProcessMemory(this->ProcessHandle, NtSetInfoThreadRemote, &dummy, 1, &writesize);

    UCHAR* NtSetInfoThreadBuf = (UCHAR*)malloc(NtSetInfoThreadFuncLen);
    if (!NtSetInfoThreadBuf)
    {
        CleanupRemote(NtSetInfoThreadRemote);
        CleanupRemote(OutDbgHookRemote);
        CleanupRemote(NtQueryHookRemote);
        ZeroMemory(&this->HookInformations, sizeof(this->HookInformations));
        return FALSE;
    }

    memcpy(NtSetInfoThreadBuf, &NtSetInformationThreadHook_begin, NtSetInfoThreadFuncLen);

    {
        DWORD64 NullAddr = 0;
        memcpy(NtSetInfoThreadBuf + NTSETINFO_HOOK_ORIGINAL_OFFSET, &NullAddr, sizeof(DWORD64));
    }

    this->WritePhysicalMem(NtSetInfoThreadBuf, NtSetInfoThreadFuncLen, (DWORD64)NtSetInfoThreadRemote);
    FlushInstructionCache(this->ProcessHandle, NtSetInfoThreadRemote, NtSetInfoThreadFuncLen);
    free(NtSetInfoThreadBuf);

    this->HookInformations.NtSetInformationThreadHookAddress =
        (DWORD64)NtSetInfoThreadRemote + NTSETINFO_HOOK_ENTRY_OFFSET;
    this->HookInformations.NtSetInformationThreadOriginalAddress = 0;

    sprintf_s(debugbuf, sizeof(debugbuf),
        "[InjectHook] NtSetInformationThread hook injected at %p (entry=+0x%llX)\n",
        NtSetInfoThreadRemote,
        (unsigned long long)NTSETINFO_HOOK_ENTRY_OFFSET);
    OutputDebugStringA(debugbuf);

    // =========================================================
    // 4) GetProcAddress hook
    // layout:
    //   +GETPROC_HOOK_NTQUERY_RET_OFFSET     NtQueryInformationProcess hook address
    //   +GETPROC_HOOK_NTSETINFO_RET_OFFSET   NtSetInformationThread hook address
    //   +GETPROC_HOOK_OUTPUTDEBUG_RET_OFFSET OutputDebugString hook address
    //   +GETPROC_HOOK_ORIGINAL_OFFSET        original GetProcAddress
    //   +GETPROC_HOOK_ENTRY_OFFSET           PROC ...
    // =========================================================
    DWORD GetProcFuncLen =
        (DWORD)((ULONG_PTR)&GetProcAddressHook_end -
            (ULONG_PTR)&GetProcAddressHook_begin);

    LPVOID GetProcHookRemote = VirtualAllocEx(
        this->ProcessHandle,
        NULL,
        GetProcFuncLen,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    if (!GetProcHookRemote)
    {
        sprintf_s(debugbuf, sizeof(debugbuf),
            "[InjectHook] VirtualAllocEx GetProcAddress hook failed, code=%lu\n",
            GetLastError());
        OutputDebugStringA(debugbuf);

        CleanupRemote(NtSetInfoThreadRemote);
        CleanupRemote(OutDbgHookRemote);
        CleanupRemote(NtQueryHookRemote);
        ZeroMemory(&this->HookInformations, sizeof(this->HookInformations));
        return FALSE;
    }

    WriteProcessMemory(this->ProcessHandle, GetProcHookRemote, &dummy, 1, &writesize);

    UCHAR* GetProcBuf = (UCHAR*)malloc(GetProcFuncLen);
    if (!GetProcBuf)
    {
        CleanupRemote(GetProcHookRemote);
        CleanupRemote(NtSetInfoThreadRemote);
        CleanupRemote(OutDbgHookRemote);
        CleanupRemote(NtQueryHookRemote);
        ZeroMemory(&this->HookInformations, sizeof(this->HookInformations));
        return FALSE;
    }

    memcpy(GetProcBuf, &GetProcAddressHook_begin, GetProcFuncLen);

    {
        DWORD64 NtQueryHookEntry = this->HookInformations.NtQueryInformationHookAddress;
        DWORD64 NtSetInfoThreadEntry = this->HookInformations.NtSetInformationThreadHookAddress;
        DWORD64 OutputDebugStringEntry = this->HookInformations.OutputDebugStringHookAddress;
        DWORD64 GetProcOriginal = 0;

        memcpy(GetProcBuf + GETPROC_HOOK_NTQUERY_RET_OFFSET, &NtQueryHookEntry, sizeof(DWORD64));
        memcpy(GetProcBuf + GETPROC_HOOK_NTSETINFO_RET_OFFSET, &NtSetInfoThreadEntry, sizeof(DWORD64));
        memcpy(GetProcBuf + GETPROC_HOOK_OUTPUTDEBUG_RET_OFFSET, &OutputDebugStringEntry, sizeof(DWORD64));
        memcpy(GetProcBuf + GETPROC_HOOK_ORIGINAL_OFFSET, &GetProcOriginal, sizeof(DWORD64));
    }

    this->WritePhysicalMem(GetProcBuf, GetProcFuncLen, (DWORD64)GetProcHookRemote);
    FlushInstructionCache(this->ProcessHandle, GetProcHookRemote, GetProcFuncLen);
    free(GetProcBuf);

    this->HookInformations.GetProcAddressHookAddress =
        (DWORD64)GetProcHookRemote + GETPROC_HOOK_ENTRY_OFFSET;
    this->HookInformations.GetProcAddressOriginalAddress = 0;

    sprintf_s(debugbuf, sizeof(debugbuf),
        "[InjectHook] GetProcAddress hook injected at %p (entry=+0x%llX)\n",
        GetProcHookRemote,
        (unsigned long long)GETPROC_HOOK_ENTRY_OFFSET);
    OutputDebugStringA(debugbuf);

    return TRUE;
}


VOID WDebugerObject::AntiDetection_PatchIAT_ByNode(PDLLRecordNode node, DWORD64 GetProcBufBase)
{
    const std::string Ntdllstr = "ntdll.dll";
    const std::string Kernel32str = "kernel32.dll";

    const std::string NtQueryAPIstr = "NtQueryInformationProcess";
    const std::string NtSetInfoAPI = "NtSetInformationThread";
    const std::string GetProcAPIstr = "GetProcAddress";
    const std::string OutDbgAAPI = "OutputDebugStringA";
    const std::string OutDbgWAPI = "OutputDebugStringW";

    DWORD64 NtQueryIATValue = this->HookInformations.NtQueryInformationHookAddress;
    DWORD64 NtSetInfoIATValue = this->HookInformations.NtSetInformationThreadHookAddress;
    DWORD64 GetProcIATValue = this->HookInformations.GetProcAddressHookAddress;
    DWORD64 OutDbgIATValue = this->HookInformations.OutputDebugStringHookAddress;

    auto NtdllIt = node->ImportDLLtable.find(Ntdllstr);
    if (NtdllIt != node->ImportDLLtable.end())
    {
        auto& apiTable = NtdllIt->second.ImportAPITable;

        auto NtQueryIt = apiTable.find(NtQueryAPIstr);
        if (NtQueryIt != apiTable.end())
        {
            auto& ainfor = NtQueryIt->second;
            if (this->HookInformations.NtQueryInformationOriginalAddress == 0)
                this->HookInformations.NtQueryInformationOriginalAddress = ainfor.ImportAPIAddress;

            this->WritePhysicalMem(
                (UCHAR*)&NtQueryIATValue,
                sizeof(DWORD64),
                ainfor.ImportAPITableEntryPtr);
        }

        auto NtSetInfoIt = apiTable.find(NtSetInfoAPI);
        if (NtSetInfoIt != apiTable.end())
        {
            auto& ainfor = NtSetInfoIt->second;
            if (this->HookInformations.NtSetInformationThreadOriginalAddress == 0)
            {
                this->HookInformations.NtSetInformationThreadOriginalAddress = ainfor.ImportAPIAddress;

                DWORD64 OrigAddr = ainfor.ImportAPIAddress;
                this->WritePhysicalMem(
                    (UCHAR*)&OrigAddr,
                    sizeof(DWORD64),
                    this->HookInformations.NtSetInformationThreadHookAddress - NTSETINFO_HOOK_ENTRY_OFFSET + NTSETINFO_HOOK_ORIGINAL_OFFSET);
            }

            this->WritePhysicalMem(
                (UCHAR*)&NtSetInfoIATValue,
                sizeof(DWORD64),
                ainfor.ImportAPITableEntryPtr);
        }
    }

    auto K32It = node->ImportDLLtable.find(Kernel32str);
    if (K32It != node->ImportDLLtable.end())
    {
        auto& apiTable = K32It->second.ImportAPITable;

        auto GetProcIt = apiTable.find(GetProcAPIstr);
        if (GetProcIt != apiTable.end())
        {
            auto& ainfor = GetProcIt->second;
            if (this->HookInformations.GetProcAddressOriginalAddress == 0)
            {
                this->HookInformations.GetProcAddressOriginalAddress = ainfor.ImportAPIAddress;

                DWORD64 OrigAddr = ainfor.ImportAPIAddress;
                this->WritePhysicalMem(
                    (UCHAR*)&OrigAddr,
                    sizeof(DWORD64),
                    GetProcBufBase + GETPROC_HOOK_ORIGINAL_OFFSET);
            }

            this->WritePhysicalMem(
                (UCHAR*)&GetProcIATValue,
                sizeof(DWORD64),
                ainfor.ImportAPITableEntryPtr);
        }

        auto OutDbgAIt = apiTable.find(OutDbgAAPI);
        if (OutDbgAIt != apiTable.end())
        {
            auto& ainfor = OutDbgAIt->second;
            if (this->HookInformations.OutputDebugStringAOrignalAddress == 0)
                this->HookInformations.OutputDebugStringAOrignalAddress = ainfor.ImportAPIAddress;

            this->WritePhysicalMem(
                (UCHAR*)&OutDbgIATValue,
                sizeof(DWORD64),
                ainfor.ImportAPITableEntryPtr);
        }

        auto OutDbgWIt = apiTable.find(OutDbgWAPI);
        if (OutDbgWIt != apiTable.end())
        {
            auto& ainfor = OutDbgWIt->second;
            if (this->HookInformations.OutputDebugStringWOrignalAddress == 0)
                this->HookInformations.OutputDebugStringWOrignalAddress = ainfor.ImportAPIAddress;

            this->WritePhysicalMem(
                (UCHAR*)&OutDbgIATValue,
                sizeof(DWORD64),
                ainfor.ImportAPITableEntryPtr);
        }
    }
}


VOID WDebugerObject::AntiDetection_PatchIAT_ByMainModule(DWORD64 GetProcBufBase)
{
    const std::string Ntdllstr = "ntdll.dll";
    const std::string Kernel32str = "kernel32.dll";

    const std::string NtQueryAPIstr = "NtQueryInformationProcess";
    const std::string NtSetInfoAPI = "NtSetInformationThread";
    const std::string GetProcAPIstr = "GetProcAddress";
    const std::string OutDbgAAPI = "OutputDebugStringA";
    const std::string OutDbgWAPI = "OutputDebugStringW";

    DWORD64 NtQueryIATValue = this->HookInformations.NtQueryInformationHookAddress;
    DWORD64 NtSetInfoIATValue = this->HookInformations.NtSetInformationThreadHookAddress;
    DWORD64 GetProcIATValue = this->HookInformations.GetProcAddressHookAddress;
    DWORD64 OutDbgIATValue = this->HookInformations.OutputDebugStringHookAddress;

    auto MainNtDllIt = this->MainModuleImportDLLtable.find(Ntdllstr);
    if (MainNtDllIt != this->MainModuleImportDLLtable.end())
    {
        auto& apiTable = MainNtDllIt->second.ImportAPITable;

        auto NtQueryIt = apiTable.find(NtQueryAPIstr);
        if (NtQueryIt != apiTable.end())
        {
            auto& ainfor = NtQueryIt->second;
            if (this->HookInformations.NtQueryInformationOriginalAddress == 0)
                this->HookInformations.NtQueryInformationOriginalAddress = ainfor.ImportAPIAddress;

            this->WritePhysicalMem(
                (UCHAR*)&NtQueryIATValue,
                sizeof(DWORD64),
                ainfor.ImportAPITableEntryPtr);
        }

        auto NtSetInfoIt = apiTable.find(NtSetInfoAPI);
        if (NtSetInfoIt != apiTable.end())
        {
            auto& ainfor = NtSetInfoIt->second;
            if (this->HookInformations.NtSetInformationThreadOriginalAddress == 0)
            {
                this->HookInformations.NtSetInformationThreadOriginalAddress = ainfor.ImportAPIAddress;

                DWORD64 OrigAddr = ainfor.ImportAPIAddress;
                this->WritePhysicalMem(
                    (UCHAR*)&OrigAddr,
                    sizeof(DWORD64),
                    this->HookInformations.NtSetInformationThreadHookAddress - NTSETINFO_HOOK_ENTRY_OFFSET + NTSETINFO_HOOK_ORIGINAL_OFFSET);
            }

            this->WritePhysicalMem(
                (UCHAR*)&NtSetInfoIATValue,
                sizeof(DWORD64),
                ainfor.ImportAPITableEntryPtr);
        }
    }

    auto MainK32It = this->MainModuleImportDLLtable.find(Kernel32str);
    if (MainK32It != this->MainModuleImportDLLtable.end())
    {
        auto& apiTable = MainK32It->second.ImportAPITable;

        auto GetProcIt = apiTable.find(GetProcAPIstr);
        if (GetProcIt != apiTable.end())
        {
            auto& ainfor = GetProcIt->second;
            if (this->HookInformations.GetProcAddressOriginalAddress == 0)
            {
                this->HookInformations.GetProcAddressOriginalAddress = ainfor.ImportAPIAddress;

                DWORD64 OrigAddr = ainfor.ImportAPIAddress;
                this->WritePhysicalMem(
                    (UCHAR*)&OrigAddr,
                    sizeof(DWORD64),
                    GetProcBufBase + GETPROC_HOOK_ORIGINAL_OFFSET);
            }

            this->WritePhysicalMem(
                (UCHAR*)&GetProcIATValue,
                sizeof(DWORD64),
                ainfor.ImportAPITableEntryPtr);
        }

        auto OutDbgAIt = apiTable.find(OutDbgAAPI);
        if (OutDbgAIt != apiTable.end())
        {
            auto& ainfor = OutDbgAIt->second;
            if (this->HookInformations.OutputDebugStringAOrignalAddress == 0)
                this->HookInformations.OutputDebugStringAOrignalAddress = ainfor.ImportAPIAddress;

            this->WritePhysicalMem(
                (UCHAR*)&OutDbgIATValue,
                sizeof(DWORD64),
                ainfor.ImportAPITableEntryPtr);
        }

        auto OutDbgWIt = apiTable.find(OutDbgWAPI);
        if (OutDbgWIt != apiTable.end())
        {
            auto& ainfor = OutDbgWIt->second;
            if (this->HookInformations.OutputDebugStringWOrignalAddress == 0)
                this->HookInformations.OutputDebugStringWOrignalAddress = ainfor.ImportAPIAddress;

            this->WritePhysicalMem(
                (UCHAR*)&OutDbgIATValue,
                sizeof(DWORD64),
                ainfor.ImportAPITableEntryPtr);
        }
    }
}


VOID WDebugerObject::AntiDetection_PatchIAT()
{
    DWORD64 GetProcBufBase =
        this->HookInformations.GetProcAddressHookAddress - GETPROC_HOOK_ENTRY_OFFSET;

    PDLLRecordNode tempnode = this->dllhead;
    while (tempnode != NULL)
    {
        this->AntiDetection_PatchIAT_ByNode(tempnode, GetProcBufBase);
        tempnode = tempnode->next;
    }

    this->AntiDetection_PatchIAT_ByMainModule(GetProcBufBase);

    OutputDebugStringA("[PatchIAT] All IAT entries patched, AntiDetectionBits = TRUE\n");
}
VOID WDebugerObject::AntiDetection()
{
    
    EnterCriticalSection(&this->WdbgLock);
    if (this->AntiDetectionBits==FALSE)
    {
        UserAntiDetection(this->TargetPid, this->hDevice);
        if (this->AntiDetection_InjectHookFunctions())
        {
            this->AntiDetection_PatchIAT();
            this->AntiDetectionBits = TRUE;
        }
    }
    LeaveCriticalSection(&this->WdbgLock);
}

VOID WDebugerObject::AntiDetection_Force()
{
    EnterCriticalSection(&this->WdbgLock);

        UserAntiDetection(this->TargetPid, this->hDevice);
        if (this->AntiDetection_InjectHookFunctions())
        {
            this->AntiDetection_PatchIAT();
            this->AntiDetectionBits = TRUE;
        }

    LeaveCriticalSection(&this->WdbgLock);
}
