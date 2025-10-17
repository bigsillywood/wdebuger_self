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
	return status;
}
NTSTATUS IOCTL_FUNC(PDEVICE_OBJECT device_ptr, PIRP irp_ptr) {
	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp_ptr);
	ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
	KPROCESSOR_MODE oldmode = ExGetPreviousMode();
	status = ChangePreviousMode(0);
	switch (code) {
	case IOCTL_CREATE_DEBUG_OBJ: {
		
		status = UserCreateDebugObject(device_ptr, irp_ptr, stack);
		
		break;
	}
	case IOCTL_READ_PHYSICAL_MEM:
	{
		DbgBreakPoint();
		status = UserReadMemory(device_ptr,irp_ptr,stack);
		break;
	}	
	case IOCTL_WRITE_PHYSICAL_MEM: 
	{

	}
	default: 
	{
		break;
	}
	}
	status = ChangePreviousMode(oldmode);
	irp_ptr->IoStatus.Status = status;
	IoCompleteRequest(irp_ptr, IO_NO_INCREMENT);
	return status;
}
NTSTATUS MJ_DEVICECREATION(PDEVICE_OBJECT device_ptr, PIRP irp_ptr) {
	irp_ptr->IoStatus.Status = STATUS_SUCCESS;
	irp_ptr->IoStatus.Information = 0;
	IoCompleteRequest(irp_ptr,IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
NTSTATUS MJ_DEVICECLOSE(PDEVICE_OBJECT device_ptr,PIRP irp_ptr) {
	irp_ptr->IoStatus.Status = STATUS_SUCCESS;
	irp_ptr->IoStatus.Information = 0;
	IoCompleteRequest(irp_ptr,IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
NTSTATUS MJ_DEVICECLEAN(PDEVICE_OBJECT device_ptr, PIRP irp_ptr) {
	irp_ptr->IoStatus.Status = STATUS_SUCCESS;
	irp_ptr->IoStatus.Information = 0;
	IoCompleteRequest(irp_ptr, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}