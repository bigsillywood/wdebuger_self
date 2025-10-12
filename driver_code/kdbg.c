#include"wdbg.h"


NTSTATUS KrnOpenProcess(__in HANDLE TargetProcessId,__out HANDLE* handle_out) {
	OBJECT_ATTRIBUTES OA;
	RtlZeroMemory(&OA,sizeof(OA));
	OA.Length = sizeof(OA);
	CLIENT_ID cid = {0};
	cid.UniqueProcess = TargetProcessId;
	NTSTATUS status = ZwOpenProcess(handle_out,PROCESS_ALL_ACCESS,&OA,&cid);
	return status;
}
/*
NTSTATUS KrnOpenThread(__in HANDLE TargetProcessId,__in HANDLE TargetThreadId, __out HANDLE* handle_out) {
	OBJECT_ATTRIBUTES OA;
	RtlZeroMemory(&OA, sizeof(OA));
	OA.Length = sizeof(OA);
	CLIENT_ID cid = { 0 };
	cid.UniqueProcess = TargetProcessId;
	cid.UniqueThread = TargetThreadId;
	int eaxt=0x139;

	return status;
}
*/
NTSTATUS AttachDebugObjectToProcess(__in HANDLE TargetProcessPid) {
	CLIENT_ID cid = { 0 };
	cid.UniqueProcess = TargetProcessPid;
	OBJECT_ATTRIBUTES oa = { 0 };
	oa.Length = sizeof(oa);
	HANDLE TargetProcessHandle;
	NTSTATUS status = ZwOpenProcess(&TargetProcessHandle, PROCESS_ALL_ACCESS, &oa, &cid);
	if (!NT_SUCCESS(status)) {
		return status;
	}
	ULONG eaxt = 0xD6;
	PVOID func_addr;
	status = GETSERVICEFUNCTIONADDR(eaxt, &func_addr, normal);
	if (!NT_SUCCESS(status)) {
		ZwClose(TargetProcessHandle);
		return status;
	}
	PFN_NtDebugActiveProcess NtDebugActiveProcess = (PFN_NtDebugActiveProcess)func_addr;
	status = NtDebugActiveProcess(TargetProcessHandle, dbg_handle);
	ZwClose(TargetProcessHandle);
	return status;
}
NTSTATUS CreateDebugObjectToProcess(__in HANDLE DebugerPID, __in HANDLE TargetProcessPid, __out HANDLE* dbg_out_handle) {
	/*
	PEPROCESS Process_Eprocess = NULL;
	NTSTATUS status = PsLookupProcessByProcessId(PID,&Process_Eprocess);
	*/
	NTSTATUS status;
	ACCESS_MASK access = 0x1F000F; // DEBUG_OBJECT_ALL_ACCESS
	OBJECT_ATTRIBUTES oa;
	RtlZeroMemory(&oa, sizeof(oa));
	oa.Length = sizeof(oa);
	ULONG flag = 1;

	ULONG eaxt = 0xAB;
	PVOID func_addr1 = NULL;
	status = GETSERVICEFUNCTIONADDR(eaxt, &func_addr1, normal);

	if (NT_SUCCESS(status)) {
		DbgPrint("ntcreatedebugobject addr=%p", func_addr1);
	}
	else
	{
		DbgPrint("faild");
	}
	
	/*
	UNICODE_STRING zs = RTL_CONSTANT_STRING(L"ZwCreateDebugObject");
	PFN_ZwCreateDebugObject ZwCreateDebugObject_ =
		(PFN_ZwCreateDebugObject)MmGetSystemRoutineAddress(&zs);
	if (!ZwCreateDebugObject_) {
		return STATUS_PROCEDURE_NOT_FOUND;
	}

	status = ZwCreateDebugObject_(&dbg_handle, access, &oa, flag);
	if (!NT_SUCCESS(status)) {
		// 处理失败
		return status;
	}
	*/
	
	InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
	PFN_NtCreateDebugObject NtcreateDebugObject = (PFN_NtCreateDebugObject)func_addr1;
	
	status = NtcreateDebugObject(&dbg_handle, access, &oa, flag);
	if (!NT_SUCCESS(status)) {
		DbgPrint("failed");
		return status;
	}
	
	


	CLIENT_ID cid = { 0 };
	cid.UniqueProcess = DebugerPID;
	cid.UniqueThread = NULL;
	OBJECT_ATTRIBUTES oa2;
	RtlZeroMemory(&oa2, sizeof(oa2));
	oa2.Length = sizeof(oa2);
	HANDLE process_handle;
	status = ZwOpenProcess(&process_handle, PROCESS_DUP_HANDLE, &oa2, &cid);
	if (!NT_SUCCESS(status)) {
		DbgPrint("failed");
		ZwClose(dbg_handle);
		return status;
	}
	status = ZwDuplicateObject(NtCurrentProcess(), dbg_handle, process_handle, dbg_out_handle, 0, 0, DUPLICATE_SAME_ACCESS);
	if (!NT_SUCCESS(status)) {
		goto closelabel;
	}
	status = AttachDebugObjectToProcess(TargetProcessPid);
	if (!NT_SUCCESS(status)) {
	closelabel:
		DbgPrint("failed");
		ZwClose(process_handle);
		ZwClose(dbg_handle);
		dbg_handle = NULL;
		return status;
	}
	ZwClose(process_handle);
	return status;
}







