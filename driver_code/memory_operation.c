#include"wdbg.h"



NTSTATUS Read_Physical_memory(ULONG64 ptr, UCHAR* outputbuffer, size_t readlen, size_t* copiedsize) {


	MM_COPY_ADDRESS targetaddr;
	targetaddr.PhysicalAddress.QuadPart = ptr;
	return MmCopyMemory(outputbuffer, targetaddr, readlen, MM_COPY_MEMORY_PHYSICAL, copiedsize);
	
}
NTSTATUS  Write_Physical_memory(ULONG64 ptr,UCHAR* inputbuffer,size_t writelen) {
	PHYSICAL_ADDRESS targetaddr;
	targetaddr.QuadPart = ptr;
	UCHAR* virtualaddr = NULL;
	virtualaddr=MmMapIoSpaceEx(targetaddr, writelen, PAGE_READWRITE | PAGE_NOCACHE);
	if (virtualaddr==NULL)
	{
		return STATUS_UNSUCCESSFUL;
	}
	return STATUS_SUCCESS;
}
NTSTATUS GetPml4(PEPROCESS EprocessPtr) {
	
}
