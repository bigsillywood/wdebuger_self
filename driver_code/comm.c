#include"wdbg.h"

NTSTATUS UserCreateDebugObject(PDEVICE_OBJECT device_ptr, PIRP irp_ptr, PIO_STACK_LOCATION stack)
{
	//DbgBreakPoint();
	NTSTATUS status = STATUS_SUCCESS;
	if ((stack->Parameters.DeviceIoControl.InputBufferLength != sizeof(struct CREATE_DEBUG_OBJ_ARG))
		|| (stack->Parameters.DeviceIoControl.OutputBufferLength != sizeof(HANDLE)))
	{
		return STATUS_INVALID_PARAMETER;
	}
	struct CREATE_DEBUG_OBJ_ARG* bufferarg = (struct CREATE_DEBUG_OBJ_ARG*)irp_ptr->AssociatedIrp.SystemBuffer;
	HANDLE DbgOutHandle;
	status = CreateDebugObjectToProcess(bufferarg->DebugerPid, bufferarg->TargetPid, &DbgOutHandle);
	irp_ptr->IoStatus.Information = sizeof(HANDLE);
	RtlZeroMemory(irp_ptr->AssociatedIrp.SystemBuffer, sizeof(struct CREATE_DEBUG_OBJ_ARG));
	if (NT_SUCCESS(status)) {
		RtlCopyMemory(irp_ptr->AssociatedIrp.SystemBuffer, (UCHAR*)&DbgOutHandle, sizeof(HANDLE));
	}
	else
	{
		(HANDLE)(irp_ptr->AssociatedIrp.SystemBuffer) = -1;
	}
	return status;
}
NTSTATUS UserReadMemory(PDEVICE_OBJECT device_ptr,PIRP irp_ptr,PIO_STACK_LOCATION stack) {
	NTSTATUS status = STATUS_SUCCESS;
	if (stack->Parameters.DeviceIoControl.InputBufferLength!=sizeof(struct READ_PHY_ARG)
		||stack->Parameters.DeviceIoControl.OutputBufferLength!=sizeof(size_t)) {
		return STATUS_INVALID_PARAMETER;
	}
	struct READ_PHY_ARG* bufferarg = (struct READ_PHY_ARG*)irp_ptr->AssociatedIrp.SystemBuffer;
	PMDL mdl_ptr = IoAllocateMdl(bufferarg->ReadBufferPtr,bufferarg->read_size,FALSE,FALSE,NULL);
	if (mdl_ptr==NULL) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	__try {
		MmProbeAndLockPages(mdl_ptr,UserMode,IoWriteAccess);
	}
	__except(EXCEPTION_EXECUTE_HANDLER){
		IoFreeMdl(mdl_ptr);
		return STATUS_INVALID_USER_BUFFER;
	}
	UCHAR* systemBuffer = MmGetSystemAddressForMdlSafe(mdl_ptr,NormalPagePriority|MdlMappingNoExecute);
	if (systemBuffer==NULL)
	{
		MmUnlockPages(mdl_ptr);
		IoFreeMdl(mdl_ptr);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	size_t actual_size=0;
	status = ReadTargetPhysicalMemory(bufferarg->TargetPid,bufferarg->TargetVirtualAddr,bufferarg->read_size,systemBuffer,&actual_size);
	irp_ptr->IoStatus.Information = sizeof(size_t);
	if (NT_SUCCESS(status)) {
		RtlCopyMemory(irp_ptr->AssociatedIrp.SystemBuffer, (UCHAR*)&actual_size, sizeof(size_t));
	}
	MmUnlockPages(mdl_ptr);
	IoFreeMdl(mdl_ptr);
	return status;
}
NTSTATUS UserWriteMemory(PDEVICE_OBJECT device_ptr,PIRP irp_ptr,PIO_STACK_LOCATION stack) {
	//DbgBreakPoint();
	NTSTATUS status = STATUS_SUCCESS;
	if (stack->Parameters.DeviceIoControl.InputBufferLength!=sizeof(struct WRITE_PHY_ARG)
		||stack->Parameters.DeviceIoControl.OutputBufferLength!=sizeof(size_t)) {
		status = STATUS_INVALID_PARAMETER;
		return status;
	}
	struct WRITE_PHY_ARG* bufferarg = (struct WRITE_PHY_ARG*)irp_ptr->AssociatedIrp.SystemBuffer;
	PMDL mdl_ptr = IoAllocateMdl(bufferarg->WriteBufferPtr,bufferarg->write_size,FALSE,FALSE,NULL);
	if (mdl_ptr==NULL) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	__try {
		MmProbeAndLockPages(mdl_ptr,UserMode,IoWriteAccess);
	}__except(EXCEPTION_EXECUTE_HANDLER) {
		IoFreeMdl(mdl_ptr);
		return STATUS_INVALID_USER_BUFFER;
	}
	UCHAR* systembuffer = MmGetSystemAddressForMdlSafe(mdl_ptr, NormalPagePriority | MdlMappingNoExecute);
	if (systembuffer==NULL) {
		MmUnlockPages(mdl_ptr);
		IoFreeMdl(mdl_ptr);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	status = WriteTargetPhysicalMemory(bufferarg->TargetPid,bufferarg->TargetVirtualAddr,bufferarg->write_size,systembuffer);
	if (NT_SUCCESS(status) ){
		RtlCopyMemory(irp_ptr->AssociatedIrp.SystemBuffer, (UCHAR*)&(bufferarg->write_size), sizeof(size_t));
	}
	MmUnlockPages(mdl_ptr);
	IoFreeMdl(mdl_ptr);
	return status;
}

NTSTATUS UserOpenProcess(PDEVICE_OBJECT device_ptr, PIRP irp_ptr, PIO_STACK_LOCATION stack)
{
	NTSTATUS status = STATUS_SUCCESS;
	if (stack->Parameters.DeviceIoControl.InputBufferLength!=sizeof(struct OPEN_PROCESS_ARG)||
		stack->Parameters.DeviceIoControl.OutputBufferLength!=sizeof(HANDLE)) {
		return STATUS_INVALID_PARAMETER;
	}
	HANDLE outhandle = NULL;
	struct OPEN_PROCESS_ARG* bufferarg = (struct OPEN_PROCESS_ARG*)irp_ptr->AssociatedIrp.SystemBuffer;
	status = KrnlOpenProcess(bufferarg->TargetPid,&outhandle);
	irp_ptr->IoStatus.Information = sizeof(HANDLE);
	if (NT_SUCCESS(status)) {
		RtlCopyMemory(irp_ptr->AssociatedIrp.SystemBuffer,(UCHAR*)&outhandle,sizeof(HANDLE));
	}
	else
	{
		(HANDLE)(irp_ptr->AssociatedIrp.SystemBuffer) = -1;
	}
	return status;
}

NTSTATUS UserOpenThread(PDEVICE_OBJECT device_ptr, PIRP irp_ptr, PIO_STACK_LOCATION stack)
{
	NTSTATUS status = STATUS_SUCCESS;
	if (stack->Parameters.DeviceIoControl.InputBufferLength != sizeof(struct OPEN_THREAD_ARG) ||
		stack->Parameters.DeviceIoControl.OutputBufferLength != sizeof(HANDLE)) {
		return STATUS_INVALID_PARAMETER;
	}
	HANDLE outhandle = NULL;
	struct OPEN_THREAD_ARG* bufferarg = (struct OPEN_THREAD_ARG*)irp_ptr->AssociatedIrp.SystemBuffer;
	CLIENT_ID cid;
	cid.UniqueProcess = bufferarg->Tid;
	cid.UniqueThread = bufferarg->Tid;
	status = KrnlOpenThread(&cid,&outhandle);
	irp_ptr->IoStatus.Information = sizeof(HANDLE);
	if (NT_SUCCESS(status)) {
		RtlCopyMemory(irp_ptr->AssociatedIrp.SystemBuffer, (UCHAR*)&outhandle, sizeof(HANDLE));
	}
	else
	{
		(HANDLE)(irp_ptr->AssociatedIrp.SystemBuffer) = -1;
	}
	return status;
}

NTSTATUS UserQueryThreadList(PDEVICE_OBJECT device_ptr,PIRP irp_ptr,PIO_STACK_LOCATION stack)
{
	NTSTATUS status = STATUS_SUCCESS;
	if (stack->Parameters.DeviceIoControl.InputBufferLength!=sizeof(struct QUERY_THREADLIST_ARG)) {
		return STATUS_INVALID_PARAMETER;
	}
	struct QUERY_THREADLIST_ARG* args = (struct QUERY_THREADLIST_ARG*)irp_ptr->AssociatedIrp.SystemBuffer;
	PMDL mdl_ptr = IoAllocateMdl(args->buffer,args->buffer_size,FALSE,FALSE,NULL);
	__try
	{
		MmProbeAndLockPages(mdl_ptr,UserMode, IoWriteAccess);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		IoFreeMdl(mdl_ptr);
		return STATUS_INVALID_USER_BUFFER;
	}
	UCHAR* systembuffer = MmGetSystemAddressForMdlSafe(mdl_ptr, NormalPagePriority | MdlMappingNoExecute);
	if (systembuffer == NULL) {
		MmUnlockPages(mdl_ptr);
		IoFreeMdl(mdl_ptr);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	status = EnumProcessThreadId(args->TargetProcessHandle,systembuffer,args->buffer_size);
	if (status==STATUS_NO_MORE_ENTRIES) {
		return STATUS_SUCCESS;
	}
	else
	{
		return status;
	}
}