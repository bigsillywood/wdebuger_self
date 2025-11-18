#pragma once
#include<ntifs.h>
#include<intrin.h>
#define PAGE_SIZE_BYTES 0x1000
#define PAGE_ALIGN_DOWN(addr) ((PUCHAR)((ULONG_PTR)(addr) & ~(PAGE_SIZE_BYTES - 1)))
#define COPY_TAG 'PgCp'
#define WDBG_TAG 'wdbg'
#define CREATE_DEBUG_OBJ 0X801
#define READ_PHYSICAL_MEM 0X802
#define WRITE_PHYSICAL_MEM 0X803
#define OPEN_TARGET_PROCESS 0x804
#define CREATE_TARGET_PROCESS 0X805
#define OPEN_TARGET_THREAD 0x806

#define IOCTL_CREATE_DEBUG_OBJ CTL_CODE(FILE_DEVICE_UNKNOWN,CREATE_DEBUG_OBJ,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_READ_PHYSICAL_MEM CTL_CODE(FILE_DEVICE_UNKNOWN,READ_PHYSICAL_MEM,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_WRITE_PHYSICAL_MEM CTL_CODE(FILE_DEVICE_UNKNOWN,WRITE_PHYSICAL_MEM,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_OPEN_TARGET_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN,OPEN_TARGET_PROCESS,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_CREATE_TARGET_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN,CREATE_TARGET_PROCESS,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_OPEN_TARGET_THREAD CTL_CODE(FILE_DEVICE_UNKNOWN,OPEN_TARGET_THREAD,METHOD_BUFFERED,FILE_ANY_ACCESS)


// 64-bit driver code
/*
	Comm.c struct
*/
struct CREATE_DEBUG_OBJ_ARG {
	__in HANDLE DebugerPid;
	__in HANDLE TargetPid;
};


struct READ_PHY_ARG {
	__in HANDLE TargetPid;
	__in PVOID TargetVirtualAddr;
	__out UCHAR* ReadBufferPtr;
	__in size_t read_size;
};
struct WRITE_PHY_ARG {
	__in HANDLE TargetPid;
	__in PVOID TargetVirtualAddr;
	__in UCHAR* WriteBufferPtr;
	__in size_t write_size;
};
struct OPEN_PROCESS_ARG {
	__in HANDLE TargetPid;
};
struct OPEN_THREAD_ARG {
	__in HANDLE Pid;
	__in HANDLE Tid;
};
struct QUERY_THREADLIST_ARG {
	__in HANDLE TargetProcessHandle;
	__out UCHAR *buffer;
	__in size_t buffer_size;
};

struct CREATE_PROCESS_ARG {
	PHANDLE ProcessHandlePtr;
	PHANDLE ThreadHandlePtr;
};


typedef struct _KSERVICE_DESCRIPTOR_TABLE {
    PVOID ServiceTable;         // 
    PULONG_PTR CounterTable;        // 
    ULONG_PTR  TableSize;           // 
    ULONG_PTR  ParamTableBase;      // 
} KSERVICE_DESCRIPTOR_TABLE, * PKSERVICE_DESCRIPTOR_TABLE;

typedef struct SSDT_SET
{
    PKSERVICE_DESCRIPTOR_TABLE SSDT;
    PKSERVICE_DESCRIPTOR_TABLE SSDTshadow;
    PKSERVICE_DESCRIPTOR_TABLE SSDTfilter;
}SSDT_SET, * PSSDT_SET;

enum ssdttype
{
    normal = 0, shadow, filter

};


typedef NTSTATUS(NTAPI* PFN_ZwCreateDebugObject)(
	PHANDLE DebugObjectHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	ULONG Flags // DEBUG_KILL_ON_CLOSE = 0x1 可选
	);


typedef NTSTATUS(*PFN_NtCreateDebugObject)(
    PHANDLE DebugObjectHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG Flags
    );
typedef NTSTATUS(*PFN_NtDebugActiveProcess) (
	HANDLE TargetProcessHandle,
	HANDLE DebugObjectHandle
	);

//HANDLE dbg_handle;
__forceinline
BOOLEAN SafeReadU64(PUCHAR addr, ULONG64* out)
{
	__try {
		*out = *(ULONG64*)addr;
		return TRUE;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;
	}
}
__forceinline
BOOLEAN SafeReadU8(PUCHAR addr, UCHAR* out)
{
	__try {
		*out = *addr;
		return TRUE;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;
	}
}

__forceinline
BOOLEAN SafeReadI32(PUCHAR addr, INT32* out)
{
	__try {
		*out = *(INT32*)addr;
		return TRUE;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;
	}
}
/*
memory_operation.c
*/
NTSYSCALLAPI
PVOID
NTAPI
PsGetProcessSectionBaseAddress(PEPROCESS eprocess);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtOpenThread(PHANDLE ThreadHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID         ClientId);
NTSYSCALLAPI
NTSTATUS
NTAPI
ZwGetNextThread(
	HANDLE ProcessHandle,       // 进程句柄（必须有 PROCESS_QUERY_INFORMATION 权限）
	HANDLE ThreadHandle,        // 上一个线程句柄（第一次传 NULL）
	ACCESS_MASK DesiredAccess,  // 需要的线程访问权限（如 THREAD_QUERY_INFORMATION）
	ULONG HandleAttributes,     // 句柄属性（通常为 0）
	ULONG Flags,                // 保留，必须为 0
	PHANDLE NewThreadHandle     // 输出：下一个线程句柄
);

NTSTATUS ReadTargetPhysicalMemory(__in HANDLE TargetPid, __in PVOID VirtualAddress, __in SIZE_T readlen, __out UCHAR* outputbuffer, size_t* actual_size);
NTSTATUS WriteTargetPhysicalMemory(__in HANDLE TargetPid, __in PVOID VirtualAddress, __in SIZE_T writelen, __in UCHAR* inputbuffer);
/*
scan.c
*/
NTSTATUS GETSSDT(PSSDT_SET ssdt_set);
NTSTATUS  GETSERVICEFUNCTIONADDR(__in ULONG eaxt, __out PVOID* addr, __in int ssdttype);
NTSTATUS FindFunctionAddrByName(__in WCHAR* name, __out PVOID* addr);
NTSTATUS ChangePreviousMode(KPROCESSOR_MODE mode);
NTSTATUS GetCr3Offset(__out ULONG64* offset);
/*
kdbg.c
*/
NTSTATUS  CreateDebugObjectToProcess(__in HANDLE DebugerPID, __in HANDLE TargetProcessPid, __out HANDLE* dbg_out_handle);

/*
comm.c
*/
NTSTATUS UserCreateDebugObject(PDEVICE_OBJECT device_ptr, PIRP irp_ptr, PIO_STACK_LOCATION stack);
NTSTATUS UserReadMemory(PDEVICE_OBJECT device_ptr, PIRP irp_ptr, PIO_STACK_LOCATION stack);
NTSTATUS UserWriteMemory(PDEVICE_OBJECT device_ptr, PIRP irp_ptr, PIO_STACK_LOCATION stack);
NTSTATUS UserOpenProcess(PDEVICE_OBJECT device_ptr,PIRP irp_ptr,PIO_STACK_LOCATION stack);
NTSTATUS UserOpenThread(PDEVICE_OBJECT device_ptr, PIRP irp_ptr, PIO_STACK_LOCATION stack);
/*
callback.c
*/
NTSTATUS  IOCTL_FUNC(PDEVICE_OBJECT device_ptr, PIRP irp_ptr);
NTSTATUS  MJ_DEVICECREATION(PDEVICE_OBJECT device_ptr, PIRP irp_ptr);
NTSTATUS  MJ_DEVICECLOSE(PDEVICE_OBJECT device_ptr, PIRP irp_ptr);
NTSTATUS MJ_DEVICECLEAN(PDEVICE_OBJECT device_ptr, PIRP irp_ptr);

/*
krnInt.c
*/
NTSTATUS KrnlOpenProcess(__in HANDLE TargetProcessId, __out HANDLE* handle_out);
NTSTATUS KrnlOpenThread(__in PCLIENT_ID pcid,__out HANDLE *handle_out);


/*
processmonitor.c
*/
NTSTATUS EnumProcessThreadId(HANDLE TargetProcessHandle, UCHAR* ThreadIdBuffer, size_t buffersize);