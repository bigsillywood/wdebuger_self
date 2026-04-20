#pragma once
#include<Windows.h>
const DWORD LISTEN_YIELD_MS = 25;
const DWORD LISTEN_WAIT_TIMEOUT_MS = 10;

typedef struct _DBGUI_WAIT_STATE_CHANGE {
    UCHAR buffer[0x200];
}DBGUI_WAIT_STATE_CHANGE,* PDBGUI_WAIT_STATE_CHANGE;

typedef struct _DBGSS_EVENT_ENTRY {
    struct _DBGSS_EVENT_ENTRY* Next;    // Á´±í
    HANDLE ProcessHandle;               // ÊÂ¼þÖÐµÄ hProcess
    HANDLE ThreadHandle;                // ÊÂ¼þÖÐµÄ hThread
    ULONG  ProcessId;                   // PID
    ULONG  ThreadId;                    // TID
    ULONG  EventCode;                   // CREATE_THREAD / EXCEPTION µÈ
    PVOID  StateChangeBuffer;           // Raw DBGUI state-change pointer
} DBGSS_EVENT_ENTRY, * PDBGSS_EVENT_ENTRY;


typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
}CLIENT_ID, * PCLIENT_ID;

extern "C" NTSTATUS NtDebugContinue(
    HANDLE DebugObject,
    void* ClientId,
    LONG ContinueStatus
);
extern "C" NTSTATUS ZwRemoveProcessDebug(
    HANDLE ProcessHandle,
    HANDLE DBGHandle
);
extern "C" NTSTATUS NTAPI
DbgUiWaitStateChange(
    PDBGUI_WAIT_STATE_CHANGE WaitStateChange,   
    LARGE_INTEGER* Timeout
);

extern "C" NTSTATUS NTAPI
DbgUiConvertStateChangeStructure(
    PDBGUI_WAIT_STATE_CHANGE WaitStateChange,
    DEBUG_EVENT* DebugEvent
);
extern "C" NTSTATUS NTAPI
DbgUiConvertStateChangeStructureEx(
    PDBGUI_WAIT_STATE_CHANGE WaitStateChange,
    DEBUG_EVENT* DebugEvent
);

extern "C" UCHAR NtQueryInformationProcessDebugHook_begin;
extern "C" UCHAR NtQueryInformationProcessDebugHook_end;
extern "C" UCHAR GetProcAddressHook_begin;
extern "C" UCHAR GetProcAddressHook_end;
extern "C" UCHAR OutputDebugStringHook_begin;
extern "C" UCHAR OutputDebugStringhook_end;
extern "C" UCHAR NtSetInformationThreadHook_begin;
extern "C" UCHAR NtSetInformationThreadHook_end;

BOOL WaitForDebugEventSelf(DEBUG_EVENT* PDebugEvent, INT waitmiliseconds);
#define NTQUERY_HOOK_ENTRY_OFFSET                    0x00
#define OUTPUTDEBUGSTRING_HOOK_ENTRY_OFFSET          0x00

#define NTSETINFO_HOOK_ORIGINAL_OFFSET               0x00
#define NTSETINFO_HOOK_ENTRY_OFFSET                  0x08

#define GETPROC_HOOK_NTQUERY_RET_OFFSET              0x00
#define GETPROC_HOOK_NTSETINFO_RET_OFFSET            0x08
#define GETPROC_HOOK_OUTPUTDEBUG_RET_OFFSET          0x10
#define GETPROC_HOOK_ORIGINAL_OFFSET                 0x18
#define GETPROC_HOOK_ENTRY_OFFSET                    0x20