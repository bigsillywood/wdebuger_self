#include"WdbgDll.hpp"





BOOL WDebugerObject::AntiDetection_InjectHookFunctions()
{
    CHAR debugbuf[256];

    // ── NtQueryInformationProcess Hook ──
    DWORD NtQueryFuncLen = (DWORD)((&NtQueryInformationProcessDebugHook_end)
        - (&NtQueryInformationProcessDebugHook_begin));

    LPVOID NtQueryHookAddress = VirtualAllocEx(this->ProcessHandle, NULL,
        NtQueryFuncLen,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);
    if (NtQueryHookAddress == NULL)
    {
        sprintf_s(debugbuf, sizeof(debugbuf),
            "[InjectHook] VirtualAllocEx NtQuery failed, code=%d\n", GetLastError());
        OutputDebugStringA(debugbuf);
        return FALSE;
    }

    SIZE_T writesize = 0;
    BYTE dummy = 0x90;
    WriteProcessMemory(this->ProcessHandle, NtQueryHookAddress, &dummy, 1, &writesize);

    UCHAR* NtQueryBuf = (UCHAR*)malloc(NtQueryFuncLen);
    if (!NtQueryBuf)
    {
        VirtualFreeEx(this->ProcessHandle, NtQueryHookAddress, 0, MEM_RELEASE);
        return FALSE;
    }
    memcpy(NtQueryBuf, &NtQueryInformationProcessDebugHook_begin, NtQueryFuncLen);
    this->WritePhysicalMem(NtQueryBuf, NtQueryFuncLen, (DWORD64)NtQueryHookAddress);
    FlushInstructionCache(this->ProcessHandle, NtQueryHookAddress, NtQueryFuncLen);
    free(NtQueryBuf);

    this->HookInformations.NtQueryInformationHookAddress = (DWORD64)NtQueryHookAddress;
    this->HookInformations.NtQueryInformationOriginalAddress = 0; // 第二步动态填

    sprintf_s(debugbuf, sizeof(debugbuf),
        "[InjectHook] NtQuery hook injected at %p\n", NtQueryHookAddress);
    OutputDebugStringA(debugbuf);

    // ── GetProcAddress Hook ──
    DWORD GetProcFuncLen = (DWORD)((&GetProcAddressHook_end)
        - (&GetProcAddressHook_begin));

    LPVOID GetProcHookAddress = VirtualAllocEx(this->ProcessHandle, NULL,
        GetProcFuncLen,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);
    if (GetProcHookAddress == NULL)
    {
        sprintf_s(debugbuf, sizeof(debugbuf),
            "[InjectHook] VirtualAllocEx GetProcAddress failed, code=%d\n", GetLastError());
        OutputDebugStringA(debugbuf);
        VirtualFreeEx(this->ProcessHandle, NtQueryHookAddress, 0, MEM_RELEASE);
        this->HookInformations.NtQueryInformationHookAddress = 0;
        return FALSE;
    }

    WriteProcessMemory(this->ProcessHandle, GetProcHookAddress, &dummy, 1, &writesize);

    UCHAR* GetProcBuf = (UCHAR*)malloc(GetProcFuncLen);
    if (!GetProcBuf)
    {
        VirtualFreeEx(this->ProcessHandle, NtQueryHookAddress, 0, MEM_RELEASE);
        VirtualFreeEx(this->ProcessHandle, GetProcHookAddress, 0, MEM_RELEASE);
        this->HookInformations.NtQueryInformationHookAddress = 0;
        return FALSE;
    }
    memcpy(GetProcBuf, &GetProcAddressHook_begin, GetProcFuncLen);

    // +0x00 : NtQueryInformationProcess Hook 起始地址
    // +0x08 : 原始 GetProcAddress 地址，暂填 0，第二步动态回填
    DWORD64 NtQueryHookAddr64 = (DWORD64)NtQueryHookAddress;
    DWORD64 NullAddr = 0;
    memcpy(GetProcBuf + 0x00, &NtQueryHookAddr64, sizeof(DWORD64));
    memcpy(GetProcBuf + 0x08, &NullAddr, sizeof(DWORD64));

    this->WritePhysicalMem(GetProcBuf, GetProcFuncLen, (DWORD64)GetProcHookAddress);
    FlushInstructionCache(this->ProcessHandle, GetProcHookAddress, GetProcFuncLen);
    free(GetProcBuf);

    // +0x10 才是函数体起始，IAT 写这个地址
    this->HookInformations.GetProcAddressHookAddress = (DWORD64)GetProcHookAddress + 0x10;
    this->HookInformations.GetProcAddressOriginalAddress = 0; // 第二步动态填

    sprintf_s(debugbuf, sizeof(debugbuf),
        "[InjectHook] GetProcAddress hook injected at %p (entry=+0x10)\n", GetProcHookAddress);
    OutputDebugStringA(debugbuf);

    return TRUE;
}


// ── 子方法1：对单个 DLLRecordNode 挂 hook ──
VOID WDebugerObject::AntiDetection_PatchIAT_ByNode(PDLLRecordNode node, DWORD64 GetProcBufBase)
{
    const std::string Ntdllstr = "ntdll.dll";
    const std::string Kernel32str = "kernel32.dll";
    const std::string NtQueryAPIstr = "NtQueryInformationProcess";
    const std::string GetProcAPIstr = "GetProcAddress";

    DWORD64 NtQueryIATValue = this->HookInformations.NtQueryInformationHookAddress;
    DWORD64 GetProcIATValue = this->HookInformations.GetProcAddressHookAddress;

    // NtQueryInformationProcess
    auto DllIt = node->ImportDLLtable.find(Ntdllstr);
    if (DllIt != node->ImportDLLtable.end())
    {
        auto APIIt = DllIt->second.ImportAPITable.find(NtQueryAPIstr);
        if (APIIt != DllIt->second.ImportAPITable.end())
        {
            auto& ainfor = APIIt->second;
            if (this->HookInformations.NtQueryInformationOriginalAddress == 0)
                this->HookInformations.NtQueryInformationOriginalAddress = ainfor.ImportAPIAddress;
            this->WritePhysicalMem((UCHAR*)&NtQueryIATValue, sizeof(DWORD64),
                ainfor.ImportAPITableEntryPtr);
        }
    }

    // GetProcAddress
    auto DllIt2 = node->ImportDLLtable.find(Kernel32str);
    if (DllIt2 != node->ImportDLLtable.end())
    {
        auto APIIt2 = DllIt2->second.ImportAPITable.find(GetProcAPIstr);
        if (APIIt2 != DllIt2->second.ImportAPITable.end())
        {
            auto& ainfor2 = APIIt2->second;
            if (this->HookInformations.GetProcAddressOriginalAddress == 0)
            {
                this->HookInformations.GetProcAddressOriginalAddress = ainfor2.ImportAPIAddress;
                DWORD64 OrigAddr = ainfor2.ImportAPIAddress;
                this->WritePhysicalMem((UCHAR*)&OrigAddr, sizeof(DWORD64),
                    GetProcBufBase + 0x08);
            }
            this->WritePhysicalMem((UCHAR*)&GetProcIATValue, sizeof(DWORD64),
                ainfor2.ImportAPITableEntryPtr);
        }
    }
}


// ── 子方法2：对主模块 ImportDLLtable 挂 hook ──
VOID WDebugerObject::AntiDetection_PatchIAT_ByMainModule(DWORD64 GetProcBufBase)
{
    const std::string Ntdllstr = "ntdll.dll";
    const std::string Kernel32str = "kernel32.dll";
    const std::string NtQueryAPIstr = "NtQueryInformationProcess";
    const std::string GetProcAPIstr = "GetProcAddress";

    DWORD64 NtQueryIATValue = this->HookInformations.NtQueryInformationHookAddress;
    DWORD64 GetProcIATValue = this->HookInformations.GetProcAddressHookAddress;

    // NtQueryInformationProcess
    auto MainNtDllIt = this->MainModuleImportDLLtable.find(Ntdllstr);
    if (MainNtDllIt != this->MainModuleImportDLLtable.end())
    {
        auto APIIt = MainNtDllIt->second.ImportAPITable.find(NtQueryAPIstr);
        if (APIIt != MainNtDllIt->second.ImportAPITable.end())
        {
            auto& ainfor = APIIt->second;
            if (this->HookInformations.NtQueryInformationOriginalAddress == 0)
                this->HookInformations.NtQueryInformationOriginalAddress = ainfor.ImportAPIAddress;
            this->WritePhysicalMem((UCHAR*)&NtQueryIATValue, sizeof(DWORD64),
                ainfor.ImportAPITableEntryPtr);
        }
    }

    // GetProcAddress
    auto MainK32It = this->MainModuleImportDLLtable.find(Kernel32str);
    if (MainK32It != this->MainModuleImportDLLtable.end())
    {
        auto APIIt2 = MainK32It->second.ImportAPITable.find(GetProcAPIstr);
        if (APIIt2 != MainK32It->second.ImportAPITable.end())
        {
            auto& ainfor2 = APIIt2->second;
            if (this->HookInformations.GetProcAddressOriginalAddress == 0)
            {
                this->HookInformations.GetProcAddressOriginalAddress = ainfor2.ImportAPIAddress;
                DWORD64 OrigAddr = ainfor2.ImportAPIAddress;
                this->WritePhysicalMem((UCHAR*)&OrigAddr, sizeof(DWORD64),
                    GetProcBufBase + 0x08);
            }
            this->WritePhysicalMem((UCHAR*)&GetProcIATValue, sizeof(DWORD64),
                APIIt2->second.ImportAPITableEntryPtr);
        }
    }
}


// ── 子方法3：遍历所有模块+主模块一次性全部挂 hook ──
VOID WDebugerObject::AntiDetection_PatchIAT()
{
    DWORD64 GetProcBufBase = this->HookInformations.GetProcAddressHookAddress - 0x10;

   

    // 遍历 dllhead 链表
    PDLLRecordNode tempnode = this->dllhead;
    while (tempnode != NULL)
    {
        this->AntiDetection_PatchIAT_ByNode(tempnode, GetProcBufBase);
        tempnode = tempnode->next;
    }

    // 主模块
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

/*
VOID WDebugerObject::AntiDetection()
{
    CHAR debugbuf[256];
    UserAntiDetection(this->TargetPid, this->hDevice);

    const std::string Ntdllstr = "ntdll.dll";
    const std::string Kernel32str = "kernel32.dll";
    const std::string NtQueryAPIstr = "NtQueryInformationProcess";
    const std::string GetProcAPIstr = "GetProcAddress";

    // ================================================================
    // 1. 分配并注入 NtQueryInformationProcess Hook
    // ================================================================
    DWORD NtQueryFuncLen = (DWORD)((&NtQueryInformationProcessDebugHook_end)
        - (&NtQueryInformationProcessDebugHook_begin));

    LPVOID NtQueryHookAddress = VirtualAllocEx(this->ProcessHandle, NULL,
        NtQueryFuncLen,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);
    if (NtQueryHookAddress == NULL)
    {
        sprintf_s(debugbuf, sizeof(debugbuf),
            "[AntiDetection] VirtualAllocEx NtQuery failed, code=%d\n", GetLastError());
        OutputDebugStringA(debugbuf);
        return;
    }

    SIZE_T writesize = 0;
    BYTE dummy = 0x90;
    WriteProcessMemory(this->ProcessHandle, NtQueryHookAddress, &dummy, 1, &writesize);

    UCHAR* NtQueryBuf = (UCHAR*)malloc(NtQueryFuncLen);
    if (!NtQueryBuf) { VirtualFreeEx(this->ProcessHandle, NtQueryHookAddress, 0, MEM_RELEASE); return; }
    memcpy(NtQueryBuf, &NtQueryInformationProcessDebugHook_begin, NtQueryFuncLen);
    this->WritePhysicalMem(NtQueryBuf, NtQueryFuncLen, (DWORD64)NtQueryHookAddress);
    FlushInstructionCache(this->ProcessHandle, NtQueryHookAddress, NtQueryFuncLen);
    free(NtQueryBuf);

    this->HookInformations.NtQueryInformationHookAddress = (DWORD64)NtQueryHookAddress;

    // ================================================================
    // 2. 先遍历 IAT 收集 GetProcAddress 原始地址
    // ================================================================
    DWORD64 OriginalGetProcAddr = 0;

    // 从 dllhead 链表中找
    PDLLRecordNode tempnode = this->dllhead;
    while (tempnode != NULL && OriginalGetProcAddr == 0)
    {
        auto DllIt = tempnode->ImportDLLtable.find(Kernel32str);
        if (DllIt != tempnode->ImportDLLtable.end())
        {
            auto APIIt = DllIt->second.ImportAPITable.find(GetProcAPIstr);
            if (APIIt != DllIt->second.ImportAPITable.end())
                OriginalGetProcAddr = APIIt->second.ImportAPIAddress;
        }
        tempnode = tempnode->next;
    }

    // 从主模块 IAT 兜底
    if (OriginalGetProcAddr == 0)
    {
        auto MainDllIt = this->MainModuleImportDLLtable.find(Kernel32str);
        if (MainDllIt != this->MainModuleImportDLLtable.end())
        {
            auto APIIt = MainDllIt->second.ImportAPITable.find(GetProcAPIstr);
            if (APIIt != MainDllIt->second.ImportAPITable.end())
                OriginalGetProcAddr = APIIt->second.ImportAPIAddress;
        }
    }

    if (OriginalGetProcAddr == 0)
    {
        OutputDebugStringA("[AntiDetection] Cannot find GetProcAddress in IAT, abort\n");
        VirtualFreeEx(this->ProcessHandle, NtQueryHookAddress, 0, MEM_RELEASE);
        this->HookInformations.NtQueryInformationHookAddress = 0;
        return;
    }

    // ================================================================
    // 3. 分配并注入 GetProcAddress Hook
    // ================================================================
    DWORD GetProcFuncLen = (DWORD)((&GetProcAddressHook_end)
        - (&GetProcAddressHook_begin));

    LPVOID GetProcHookAddress = VirtualAllocEx(this->ProcessHandle, NULL,
        GetProcFuncLen,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);
    if (GetProcHookAddress == NULL)
    {
        sprintf_s(debugbuf, sizeof(debugbuf),
            "[AntiDetection] VirtualAllocEx GetProcAddress failed, code=%d\n", GetLastError());
        OutputDebugStringA(debugbuf);
        VirtualFreeEx(this->ProcessHandle, NtQueryHookAddress, 0, MEM_RELEASE);
        this->HookInformations.NtQueryInformationHookAddress = 0;
        return;
    }

    WriteProcessMemory(this->ProcessHandle, GetProcHookAddress, &dummy, 1, &writesize);

    UCHAR* GetProcBuf = (UCHAR*)malloc(GetProcFuncLen);
    if (!GetProcBuf)
    {
        VirtualFreeEx(this->ProcessHandle, NtQueryHookAddress, 0, MEM_RELEASE);
        VirtualFreeEx(this->ProcessHandle, GetProcHookAddress, 0, MEM_RELEASE);
        this->HookInformations.NtQueryInformationHookAddress = 0;
        return;
    }
    memcpy(GetProcBuf, &GetProcAddressHook_begin, GetProcFuncLen);

    // +0 : NtQueryInformationProcess Hook 地址（mov rax 返回值）
    DWORD64 NtQueryHookAddr64 = (DWORD64)NtQueryHookAddress;
    memcpy(GetProcBuf + 0x0, &NtQueryHookAddr64, sizeof(DWORD64));

    // +8 : 原始 GetProcAddress 地址（从目标进程 IAT 取到的）
    memcpy(GetProcBuf + 0x8, &OriginalGetProcAddr, sizeof(DWORD64));

    this->WritePhysicalMem(GetProcBuf, GetProcFuncLen, (DWORD64)GetProcHookAddress);
    FlushInstructionCache(this->ProcessHandle, GetProcHookAddress, GetProcFuncLen);
    free(GetProcBuf);

    this->HookInformations.GetProcAddressHookAddress = (DWORD64)GetProcHookAddress + 0x10; // 跳过数据区
    this->HookInformations.GetProcAddressOriginalAddress = OriginalGetProcAddr;

    // ================================================================
    // 4. 修改 IAT 指针
    // ================================================================
    EnterCriticalSection(&this->WdbgLock);

    // IAT 中 GetProcAddress 条目写入的地址是函数体起始，即 +16
    DWORD64 GetProcIATValue = (DWORD64)GetProcHookAddress + 0x10;
    DWORD64 NtQueryIATValue = (DWORD64)NtQueryHookAddress;

    tempnode = this->dllhead;
    while (tempnode != NULL)
    {
        // NtQueryInformationProcess hook
        auto DllIt = tempnode->ImportDLLtable.find(Ntdllstr);
        if (DllIt != tempnode->ImportDLLtable.end())
        {
            auto APIIt = DllIt->second.ImportAPITable.find(NtQueryAPIstr);
            if (APIIt != DllIt->second.ImportAPITable.end())
            {
                auto& ainfor = APIIt->second;
                if (this->HookInformations.NtQueryInformationOriginalAddress == 0)
                    this->HookInformations.NtQueryInformationOriginalAddress = ainfor.ImportAPIAddress;
                this->WritePhysicalMem((UCHAR*)&NtQueryIATValue, sizeof(DWORD64),
                    ainfor.ImportAPITableEntryPtr);
            }
        }

        // GetProcAddress hook
        auto DllIt2 = tempnode->ImportDLLtable.find(Kernel32str);
        if (DllIt2 != tempnode->ImportDLLtable.end())
        {
            auto APIIt2 = DllIt2->second.ImportAPITable.find(GetProcAPIstr);
            if (APIIt2 != DllIt2->second.ImportAPITable.end())
            {
                auto& ainfor2 = APIIt2->second;
                this->WritePhysicalMem((UCHAR*)&GetProcIATValue, sizeof(DWORD64),
                    ainfor2.ImportAPITableEntryPtr);
            }
        }

        tempnode = tempnode->next;
    }

    // 主模块 IAT
    auto MainNtDllIt = this->MainModuleImportDLLtable.find(Ntdllstr);
    if (MainNtDllIt != this->MainModuleImportDLLtable.end())
    {
        auto APIIt = MainNtDllIt->second.ImportAPITable.find(NtQueryAPIstr);
        if (APIIt != MainNtDllIt->second.ImportAPITable.end())
        {
            auto& ainfor = APIIt->second;
            if (this->HookInformations.NtQueryInformationOriginalAddress == 0)
                this->HookInformations.NtQueryInformationOriginalAddress = ainfor.ImportAPIAddress;
            this->WritePhysicalMem((UCHAR*)&NtQueryIATValue, sizeof(DWORD64),
                ainfor.ImportAPITableEntryPtr);
        }
    }

    auto MainK32It = this->MainModuleImportDLLtable.find(Kernel32str);
    if (MainK32It != this->MainModuleImportDLLtable.end())
    {
        auto APIIt2 = MainK32It->second.ImportAPITable.find(GetProcAPIstr);
        if (APIIt2 != MainK32It->second.ImportAPITable.end())
        {
            this->WritePhysicalMem((UCHAR*)&GetProcIATValue, sizeof(DWORD64),
                APIIt2->second.ImportAPITableEntryPtr);
        }
    }

    // 两个 Hook 全部完成
    this->AntiDetectionBits = TRUE;
    LeaveCriticalSection(&this->WdbgLock);

    OutputDebugStringA("[AntiDetection] All hooks applied, AntiDetectionBits = TRUE\n");
}

*/
