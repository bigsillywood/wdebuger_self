#include<Windows.h>
#include<stdio.h>
#define DEVICENAME L"\\\\.\\wdbgDevice"

HWND hEditInput, hButton, hEditOutput;
HWND hEditInput2, hButton2, hEditOutput2;
HWND hStatic1, hStatic2, hStatic3;
HWND hLogWindow, hCmdInput, hCmdButton;   // 新增日志窗口和命令行
HANDLE hdevice;
HANDLE dbgthreadhandle;


HANDLE hsignlevent;

HANDLE hsignleventCreateProcessDebugEvent;
HANDLE hsignleventExitProcessDebugEvent;
HANDLE hsignleventLoadDllDebugEvent;
HANDLE hsignleventUnloadDllDebugEvent;
HANDLE hsignleventExceptionDebugEvent;
HANDLE hsignleventOutputDebugStringEvent;
HANDLE hsignleventRipEvent;

CRITICAL_SECTION csCreateProcessDebugEvent;
CRITICAL_SECTION csExitProcessDebugEvent;
CRITICAL_SECTION csLoadDllDebugEvent;
CRITICAL_SECTION csUnloadDllDebugEvent;
//CRITICAL_SECTION csExceptionDebugEvent;
CRITICAL_SECTION csOutputDebugStringEvent;
CRITICAL_SECTION csRipEvent;


BOOL ignoreCreateProcessDebugEvent;
BOOL ignoreExitProcessDebugEvent;
BOOL ignoreLoadDllDebugEvent;
BOOL ignoreUnloadDllDebugEvent;
//BOOL ignoreExceptionDebugEvent;
BOOL ignoreOutputDebugStringEvent;
BOOL ignoreRipEvent;

struct CREATE_DEBUG_OBJ_ARG {
	__in HANDLE DebugerPid;
	__in HANDLE TargetPid;
};
// ==== NtQueryObject 定义 ====
typedef enum _OBJECT_INFORMATION_CLASS {
    ObjectBasicInformation = 0,
    ObjectNameInformation = 1,
    ObjectTypeInformation = 2,
    // 这里只用到 ObjectTypeInformation
} OBJECT_INFORMATION_CLASS;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;

typedef struct _OBJECT_TYPE_INFORMATION {
    UNICODE_STRING TypeName;
    ULONG Reserved[22]; // 实际比这个长，但我们只关心 TypeName
} OBJECT_TYPE_INFORMATION;

typedef NTSTATUS (NTAPI *PFN_NtQueryObject)(
    HANDLE Handle,
    OBJECT_INFORMATION_CLASS ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
);
PFN_NtQueryObject NtQueryObjectFunc;
void QueryHandle(HWND hwnd);


ULONG GetDbgReserveOffset();
void DebugThread(HANDLE dbghandle);
void AppendLog(HWND hEdit, LPCWSTR text);



#define CREATE_DEBUG_OBJ 0X801
#define READ_PHYSICAL_MEM 0X802
#define WRTIE_PHYSICAL_MEM 0X803

#define IOCTL_CREATE_DEBUG_OBJ CTL_CODE(FILE_DEVICE_UNKNOWN,CREATE_DEBUG_OBJ,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_READ_PHYSICAL_MEM CTL_CODE(FILE_DEVICE_UNKNOWN,READ_PHYSICAL_MEM,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_WRTIE_PHYSICAL_MEM CTL_CODE(FILE_DEVICE_UNKNOWN,WRTIE_PHYSICAL_MEM,METHOD_BUFFERED,FILE_ANY_ACCESS)



typedef struct ThreadLinkListNode{
    ULONG ThreadPid;
    HANDLE Threadhandle;
    LPVOID lpThreadLocalBase;
    LPTHREAD_START_ROUTINE lpStartAddress;
    struct threadLinkListNode* Flink;
    struct ThreadLinkListNode* Blink;
}ThreadLinkListNode,*PThreadLinkListNode;

typedef struct ProcessLinkListNode{
    ULONG ProcessId;

}ProcessLinkListNode,*PProcessLinkListNode;

PThreadLinkListNode head;
PThreadLinkListNode tail;