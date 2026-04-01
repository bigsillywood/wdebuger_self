#include "WdbgDll.hpp"
#define DEVICENAME L"\\\\.\\wdbgDevice" 


BOOL CombineThreadC(HANDLE DebugHandle) {
    _TEB* teb_ptr = NtCurrentTeb();
    LONG offset = GetDbgReserveOffsetSecond();
    if (offset == 0) {
        return FALSE;
    }
    UCHAR* dbgreserve_ptr = ((UCHAR*)teb_ptr+offset);
    *((HANDLE*)dbgreserve_ptr) = DebugHandle;
    return 1;
}

HANDLE CreateWdbgDevice()
{
    return CreateFileW(DEVICENAME,
        GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, NULL);
}
void CloseWdbgDevice(HANDLE hDevice)
{
    if (hDevice != INVALID_HANDLE_VALUE) {
        CloseHandle(hDevice);
    }
}
HANDLE krnlDebugActive(__in HANDLE TargetPid,__in HANDLE hDevice)
{
    struct CREATE_DEBUG_OBJ_ARG args;
    args.DebugerPid = (HANDLE)GetCurrentProcessId();
    args.TargetPid = TargetPid;
    ULONG readlen = 0;
    HANDLE dbghandle = INVALID_HANDLE_VALUE;
    BOOL ok = DeviceIoControl(hDevice,
        IOCTL_CREATE_DEBUG_OBJ,
        (UCHAR*)&args,
        sizeof(struct CREATE_DEBUG_OBJ_ARG),
        (UCHAR*)&dbghandle,
        sizeof(HANDLE),
        &readlen,
        NULL);
    return dbghandle;
}

HANDLE UserOpenProcess(__in HANDLE TargetPid,__in HANDLE hDevice) {
    struct OPEN_PROCESS_ARG args;
    args.TargetPid = TargetPid;
    HANDLE out_handle = INVALID_HANDLE_VALUE;
    ULONG readlen = 0;
    BOOL ok = DeviceIoControl(hDevice,
        IOCTL_OPEN_TARGET_PROCESS,
        (UCHAR*)&args,
        sizeof(struct OPEN_PROCESS_ARG),
        (UCHAR*)&out_handle,
        sizeof(HANDLE),
        &readlen,
        NULL);
    return out_handle;
}

HANDLE UserOpenThread(__in HANDLE TargetPid,__in HANDLE TargetTid,__in HANDLE hDevice)
{

    struct OPEN_THREAD_ARG args;
    args.Pid = TargetPid;
    args.Tid = TargetTid;
    HANDLE out_handle = NULL;
    ULONG readlen = 0;
    BOOL ok = DeviceIoControl(hDevice,
        IOCTL_OPEN_TARGET_THREAD,
        (UCHAR*)&args,
        sizeof(struct OPEN_THREAD_ARG),
        (UCHAR*)&out_handle,
        sizeof(HANDLE),
        &readlen,
        NULL);

    return out_handle;
}


WDBGDLL_API BOOL RemoveHandles(PVOID dbgreserve_0, int threadid, int processid)
{
    PDBGSS_EVENT_ENTRY* ppEntry = (PDBGSS_EVENT_ENTRY*)dbgreserve_0;
    PDBGSS_EVENT_ENTRY current = *ppEntry;
    HANDLE heapHandle = GetProcessHeap();
    while (current)
    {
        if (current->EventCode != 0 &&
            (current->ProcessId == (ULONG)processid ||
                current->ThreadId == (ULONG)threadid))
        {
            if (current->ProcessHandle) CloseHandle(current->ProcessHandle);
            if (current->ThreadHandle) CloseHandle(current->ThreadHandle);

            *ppEntry = current->Next;
            HeapFree(heapHandle, 0, current);

            current = *ppEntry;
            continue;
        }

        ppEntry = &current->Next;
        current = current->Next;
    }

    return TRUE;
}

BOOL ContinueThreadC(HANDLE dbghandle,HANDLE ProcessId, HANDLE ThreadId)
{
    CLIENT_ID cid = { 0 };
    cid.UniqueProcess = ProcessId;
    cid.UniqueThread = ThreadId;
    NTSTATUS status = NtDebugContinue(dbghandle, &cid, DBG_CONTINUE);
    if (status<0)
    {
        return FALSE;
    }
    else {
        return TRUE;
    }
}









BOOL UserPhysicalRead(__in HANDLE TargetPid,__in HANDLE hDevice,__in ULONG64 VirtualAddr,__in size_t ReadLen,__out UCHAR* readbuffer)
{

    struct READ_PHY_ARG arg;
    arg.TargetPid = (HANDLE)(ULONG_PTR)TargetPid;
    arg.TargetVirtualAddr = (PVOID)(ULONG_PTR)VirtualAddr;
    arg.ReadBufferPtr = readbuffer;
    arg.read_size = ReadLen;
    size_t bytesRet = 0;
    DWORD readlen = 0;
    BOOL dioOk = DeviceIoControl(hDevice,
        IOCTL_READ_PHYSICAL_MEM,
        &arg,
        sizeof(arg),
        (UCHAR*)&bytesRet,
        sizeof(size_t),
        &readlen,
        NULL);
    return dioOk;
}


BOOL UserPhysicalWrite(__in HANDLE TargetPID,__in HANDLE hDevice,__in ULONG64 VirtualAddr,__in size_t WriteLen,__in UCHAR* writebuffer)
{
    struct WRITE_PHY_ARG arg;
    arg.TargetPid = (HANDLE)(ULONG_PTR)TargetPID;
    arg.TargetVirtualAddr = (PVOID)(ULONG_PTR)VirtualAddr;
    arg.WriteBufferPtr = writebuffer;
    arg.write_size = WriteLen;

    size_t bytesReturned = 0;
    DWORD write_len = 0;
    BOOL ok = DeviceIoControl(hDevice,
        IOCTL_WRITE_PHYSICAL_MEM,
        &arg, sizeof(arg),
        &bytesReturned, sizeof(size_t),
        &write_len, NULL);
    return ok;
}

