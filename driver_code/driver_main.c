#include"wdbg.h"
#define DEVICE_NAME L"\\Device\\wdbgDevice" 
#define	SYMBOLICLINK_NAME L"\\??\\wdbgDevice"
#define DRIVER_MEM 1024
void unload(PDRIVER_OBJECT selfptr) {
	DbgPrint("driver unload\n");
	if (selfptr->DeviceObject) {
		IoDeleteDevice(selfptr->DeviceObject);
		UNICODE_STRING sym_name = { 0 };
		RtlInitUnicodeString(&sym_name, SYMBOLICLINK_NAME);
		IoDeleteSymbolicLink(&sym_name);
	}
}



NTSTATUS GsDriverEntry(PDRIVER_OBJECT selfptr, PUNICODE_STRING reg_path) {
	UNREFERENCED_PARAMETER(reg_path);
	DbgBreakPoint();
	//dbg_handle = NULL;
	selfptr->DriverUnload = unload;
	NTSTATUS status = STATUS_SUCCESS;;

	UNICODE_STRING device_name;
	PDEVICE_OBJECT device_ptr;
	RtlInitUnicodeString(&device_name, DEVICE_NAME);

	status = IoCreateDevice(selfptr, DRIVER_MEM, &device_name, FILE_DEVICE_UNKNOWN, 0, FALSE, &device_ptr);
	if (!NT_SUCCESS(status)) {
		DbgPrint("create new device failed");
		return status;
	}

	RtlZeroMemory(device_ptr->DeviceExtension, DRIVER_MEM);
	device_ptr->Flags |= DO_BUFFERED_IO;
	device_ptr->Flags &= ~DO_DEVICE_INITIALIZING;
	UNICODE_STRING symboliclinkname;
	RtlInitUnicodeString(&symboliclinkname, SYMBOLICLINK_NAME);
	status = IoCreateSymbolicLink(&symboliclinkname, &device_name);

	if (!NT_SUCCESS(status)) {
		DbgPrint("link symbolic failed");
		IoDeleteDevice(device_ptr);
		return status;
	}

	selfptr->MajorFunction[IRP_MJ_CREATE] = MJ_DEVICECREATION;
	selfptr->MajorFunction[IRP_MJ_CLOSE] = MJ_DEVICECLOSE;
	selfptr->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IOCTL_FUNC;
	selfptr->MajorFunction[IRP_MJ_CLEANUP] = MJ_DEVICECLEAN;
	return status;
}