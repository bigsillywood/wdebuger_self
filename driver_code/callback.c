#include "wdbg.h"
NTSTATUS MJ_DEVICECREATION(PDEVICE_OBJECT device_ptr, PIRP irp_ptr) {
	irp_ptr->IoStatus.Status = STATUS_SUCCESS;
	irp_ptr->IoStatus.Information = 0;
	IoCompleteRequest(irp_ptr, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
NTSTATUS MJ_DEVICECLOSE(PDEVICE_OBJECT device_ptr, PIRP irp_ptr) {
	irp_ptr->IoStatus.Status = STATUS_SUCCESS;
	irp_ptr->IoStatus.Information = 0;
	IoCompleteRequest(irp_ptr, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
NTSTATUS MJ_DEVICECLEAN(PDEVICE_OBJECT device_ptr, PIRP irp_ptr) {
	irp_ptr->IoStatus.Status = STATUS_SUCCESS;
	irp_ptr->IoStatus.Information = 0;
	IoCompleteRequest(irp_ptr, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
NTSTATUS IOCTL_FUNC(PDEVICE_OBJECT device_ptr, PIRP irp_ptr) {
	DbgBreakPoint();
	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp_ptr);
	ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
	KPROCESSOR_MODE oldmode = ExGetPreviousMode();
	status = ChangePreviousMode(0);
	switch (code) {
	case IOCTL_OPEN_TARGET_PROCESS: {
		status = UserOpenProcess(device_ptr,irp_ptr,stack);
		break;
	}
	case IOCTL_CREATE_DEBUG_OBJ: {

		status = UserCreateDebugObject(device_ptr, irp_ptr, stack);

		break;
	}
	case IOCTL_READ_PHYSICAL_MEM:
	{
		status = UserReadMemory(device_ptr, irp_ptr, stack);
		break;
	}
	case IOCTL_WRITE_PHYSICAL_MEM:
	{
		status = UserWriteMemory(device_ptr, irp_ptr, stack);
		break;
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