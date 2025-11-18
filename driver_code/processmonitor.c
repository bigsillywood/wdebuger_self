#include"wdbg.h"

NTSTATUS GetTidFromThreadHandle(HANDLE ThreadHandle,HANDLE *Tidout) {
	PETHREAD ethreadptr;
	NTSTATUS status = ObReferenceObjectByHandleWithTag(ThreadHandle,
														THREAD_ALL_ACCESS,
														PsThreadType,
														KernelMode,
														WDBG_TAG,
														&ethreadptr,
														NULL);
	if (!NT_SUCCESS(status)) {
		return status;
	}
	*Tidout = PsGetThreadId(ethreadptr);
	ObDereferenceObjectWithTag(ethreadptr,WDBG_TAG);
	return status;
}	

NTSTATUS EnumProcessThreadId(HANDLE TargetProcessHandle,UCHAR* ThreadIdBuffer,size_t buffersize) {
	HANDLE CurThreadHandle = NULL;
	NTSTATUS status=STATUS_SUCCESS;
	ULONG index = 0;
	size_t max_index = buffersize / (sizeof(HANDLE)) - 1;
	HANDLE NewThreadHandle=NULL;
	HANDLE* ThreadIdArrary = (HANDLE*)ThreadIdBuffer;
	HANDLE Tid = NULL;
	while(1){
		if (index>max_index) {
			return STATUS_BUFFER_TOO_SMALL;
		}
		status = ZwGetNextThread(TargetProcessHandle,CurThreadHandle,THREAD_ALL_ACCESS,NULL,NULL,&NewThreadHandle);
		if (!NT_SUCCESS(status)) {
			goto exit;
		}
		status = GetTidFromThreadHandle(NewThreadHandle,&Tid);
		if (!NT_SUCCESS(status)) {
			goto exit;
		}
		ThreadIdArrary[index] = Tid;
		if (CurThreadHandle!=NULL) {
			ZwClose(CurThreadHandle);
		}
		CurThreadHandle = NewThreadHandle;
		index++;
	}
exit:
	if (CurThreadHandle != NULL) {
		ZwClose(CurThreadHandle);
	}
	return status;
}