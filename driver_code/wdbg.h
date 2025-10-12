#pragma once
#include<ntifs.h>
#define PAGE_SIZE_BYTES 0x1000
#define PAGE_ALIGN_DOWN(addr) ((PUCHAR)((ULONG_PTR)(addr) & ~(PAGE_SIZE_BYTES - 1)))
#define COPY_TAG 'PgCp'

#define CREATE_DEBUG_OBJ 0X801
#define OPEN_TARGET_PROCESS 0x804
#define OPEN_TARGET_THREAD 0x805
#define READ_PHYSICAL_MEM 0X802
#define WRTIE_PHYSICAL_MEM 0X803


#define IOCTL_CREATE_DEBUG_OBJ CTL_CODE(FILE_DEVICE_UNKNOWN,CREATE_DEBUG_OBJ,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_READ_PHYSICAL_MEM CTL_CODE(FILE_DEVICE_UNKNOWN,READ_PHYSICAL_MEM,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_WRTIE_PHYSICAL_MEM CTL_CODE(FILE_DEVICE_UNKNOWN,WRTIE_PHYSICAL_MEM,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_CREATE_TARGET_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN,OPEN_TARGET_PROCESS,METHOD_BUFFERED,FILE_ANY_ACCESS);
#define IOCTL_CREATE_TARGET_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN,OPEN_TARGET_THREAD,METHOD_BUFFERED,FILE_ANY_ACCESS);


// 64-bit driver code
struct CREATE_DEBUG_OBJ_ARG {
	__in HANDLE DebugerPid;
	__in HANDLE TargetPid;
};


typedef NTSTATUS(NTAPI* PFN_ZwCreateDebugObject)(
	PHANDLE DebugObjectHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	ULONG Flags // DEBUG_KILL_ON_CLOSE = 0x1 可选
	);
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

HANDLE dbg_handle;
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


/*
SSDTfinder.c
*/
NTSTATUS GETSSDT(PSSDT_SET ssdt_set);
NTSTATUS  GETSERVICEFUNCTIONADDR(__in ULONG eaxt, __out PVOID* addr, __in int ssdttype);
NTSTATUS FindFunctionAddrByName(__in WCHAR* name, __out PVOID* addr);
NTSTATUS ChangePreviousMode(KPROCESSOR_MODE mode);
/*
kdbg.c
*/
NTSTATUS  CreateDebugObjectToProcess(__in HANDLE DebugerPID, __in HANDLE TargetProcessPid, __out HANDLE* dbg_out_handle);

/*
comm.c
*/
NTSTATUS  IOCTL_FUNC(PDEVICE_OBJECT device_ptr, PIRP irp_ptr);
NTSTATUS  MJ_DEVICECREATION(PDEVICE_OBJECT device_ptr, PIRP irp_ptr);
NTSTATUS  MJ_DEVICECLOSE(PDEVICE_OBJECT device_ptr, PIRP irp_ptr);
NTSTATUS MJ_DEVICECLEAN(PDEVICE_OBJECT device_ptr, PIRP irp_ptr);