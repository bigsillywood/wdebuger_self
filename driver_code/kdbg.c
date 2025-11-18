#include"wdbg.h"



NTSTATUS AttachDebugObjectToProcess(__in HANDLE TargetProcessPid, HANDLE dbg_handle) {
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

NTSTATUS CreateDebugObjectToProcess(
	__in HANDLE DebuggerPid,
	__in HANDLE TargetProcessPid,
	__out HANDLE* DebugObjectHandleOut
) {
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	HANDLE dbgObject = NULL, hDebugger = NULL;
	PVOID pNtCreateDebugObject = NULL;

	// 1. 获取 NtCreateDebugObject 地址
	status = GETSERVICEFUNCTIONADDR(0xAB, &pNtCreateDebugObject, normal);
	if (!NT_SUCCESS(status) || !pNtCreateDebugObject) {
		DbgPrint("[-] Failed to get NtCreateDebugObject");
		return status;
	}
	DbgPrint("[+] NtCreateDebugObject = %p", pNtCreateDebugObject);

	PFN_NtCreateDebugObject NtCreateDebugObjectFn = (PFN_NtCreateDebugObject)pNtCreateDebugObject;

	// 2. 创建 DebugObject
	OBJECT_ATTRIBUTES oa;
	InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

	status = NtCreateDebugObjectFn(&dbgObject, 0x1F000F, &oa, 1);
	if (!NT_SUCCESS(status)) {
		DbgPrint("[-] NtCreateDebugObject failed: 0x%X", status);
		return status;
	}

	// 3. 打开调试器进程
	CLIENT_ID cid = { DebuggerPid, NULL };
	InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

	status = ZwOpenProcess(&hDebugger, PROCESS_DUP_HANDLE, &oa, &cid);
	if (!NT_SUCCESS(status)) {
		DbgPrint("[-] ZwOpenProcess(Debugger) failed: 0x%X", status);
		goto cleanup;
	}

	// 4. Duplicate DebugObject 句柄到调试器进程
	status = ZwDuplicateObject(
		NtCurrentProcess(),
		dbgObject,
		hDebugger,
		DebugObjectHandleOut,
		0,
		0,
		DUPLICATE_SAME_ACCESS
	);
	if (!NT_SUCCESS(status)) {
		DbgPrint("[-] ZwDuplicateObject failed: 0x%X", status);
		goto cleanup;
	}

	// 5. Attach DebugObject 到目标进程
	status = AttachDebugObjectToProcess(TargetProcessPid, dbgObject);
	if (!NT_SUCCESS(status)) {
		DbgPrint("[-] AttachDebugObjectToProcess failed: 0x%X", status);
		goto cleanup;
	}

cleanup:
	if (hDebugger) ZwClose(hDebugger);
	if (dbgObject) ZwClose(dbgObject);

	return status;
}





