#include"wdbg.h"

NTSTATUS KrnlOpenProcess(__in HANDLE TargetProcessId, __out HANDLE* handle_out) {
	OBJECT_ATTRIBUTES OA;
	RtlZeroMemory(&OA, sizeof(OA));
	OA.Length = sizeof(OA);
	CLIENT_ID cid = { 0 };
	cid.UniqueProcess = TargetProcessId;
	NTSTATUS status = ZwOpenProcess(handle_out, PROCESS_ALL_ACCESS, &OA, &cid);
	return status;
}

NTSTATUS KrnlOpenThread(__in PCLIENT_ID pcid,__out HANDLE* handle_out) {
	NTSTATUS status = STATUS_SUCCESS;
	OBJECT_ATTRIBUTES OA;
	RtlZeroMemory(&OA, sizeof(OA));
	OA.Length = sizeof(OA);
	status = NtOpenThread(handle_out,THREAD_ALL_ACCESS,&OA,pcid);
	return status;
}
//give up this, because of the privilige leak maybe dangerous
/*
NTSTATUS krnlCreateUserProcess() {

}
*/
