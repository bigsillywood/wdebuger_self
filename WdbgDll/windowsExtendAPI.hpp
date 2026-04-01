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
BOOL WaitForDebugEventSelf(DEBUG_EVENT* PDebugEvent, INT waitmiliseconds);
