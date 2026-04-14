#include"wdbg.h"

NTSTATUS AntiDebugerDetection(HANDLE TargetPid) {
	//DbgBreakPoint();
	PEPROCESS TargetEprocessPtr=NULL;
	HANDLE TargetProcessHandle;
	CLIENT_ID CID;
	CID.UniqueProcess = TargetPid;
	CID.UniqueThread = NULL;
	OBJECT_ATTRIBUTES OA;
	RtlZeroMemory(&OA, sizeof(OA));
	OA.Length = sizeof(OA);
	NTSTATUS result=ZwOpenProcess(&TargetProcessHandle,PROCESS_ALL_ACCESS,&OA,&CID);
	if (!NT_SUCCESS(result))
	{
		return result;
	}
	result = ObReferenceObjectByHandleWithTag(TargetProcessHandle,
		GENERIC_ALL,
		*PsProcessType,
		KernelMode,
		WDBG_TAG, 
		&TargetEprocessPtr,
		NULL);
	ZwClose(TargetProcessHandle);
	if (!NT_SUCCESS(result))
	{
		return result;
	}
	PVOID TargetPeb = PsGetProcessPeb(TargetEprocessPtr);
	if (TargetPeb==NULL)
	{
		ObDereferenceObjectWithTag(TargetEprocessPtr, WDBG_TAG);
		return STATUS_UNSUCCESSFUL;
	}
	DWORD64 IsDebugerPresentBitOffset = (DWORD64)TargetPeb + 2;
	UCHAR buffer[2] = { 0x00,0x00 };
	result = WriteTargetPhysicalMemory(TargetPid, IsDebugerPresentBitOffset, 1, buffer);
	if (!NT_SUCCESS(result))
	{
		ObDereferenceObjectWithTag(TargetEprocessPtr, WDBG_TAG);
		return result;
	}
	ObDereferenceObjectWithTag(TargetEprocessPtr, WDBG_TAG);
	return result;
}
