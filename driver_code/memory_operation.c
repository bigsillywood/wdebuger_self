#include"wdbg.h"




NTSTATUS ReadPhysicalMemory(ULONG64 Physical_ptr, UCHAR* outputbuffer, size_t readlen, size_t* copiedsize) {  
	MM_COPY_ADDRESS targetaddr;
	targetaddr.PhysicalAddress.QuadPart = Physical_ptr;
	return MmCopyMemory(outputbuffer, targetaddr, readlen, MM_COPY_MEMORY_PHYSICAL,copiedsize);
}
NTSTATUS  WritePhysicalMemory(ULONG64 ptr,UCHAR* inputbuffer,size_t writelen) {
	PHYSICAL_ADDRESS targetaddr;
	targetaddr.QuadPart = ptr;
	UCHAR* virtualaddr = NULL;
	virtualaddr=MmMapIoSpaceEx(targetaddr, writelen, PAGE_READWRITE | PAGE_NOCACHE);
	if (virtualaddr==NULL)
	{
		return STATUS_UNSUCCESSFUL;
	}
	RtlCopyMemory(virtualaddr,inputbuffer,writelen);
	return STATUS_SUCCESS;
}
NTSTATUS GetTargetPhysicalMemory(__in ULONG64 cr3,__in ULONG64 VirtualAddress,__out PULONG64 PhysicalAddress) {
	ULONG64 PML4 = (cr3) & (~0xfff);
	ULONG64 pdpt_index = (VirtualAddress >> 39) & 0x1ff;
	ULONG64 Physical_addr_pdpt = pdpt_index * 8 + PML4;
	ULONG64 PDPT = NULL;
	size_t copied_size;
	NTSTATUS status= ReadPhysicalMemory(Physical_addr_pdpt,(UCHAR*) & PDPT,8,&copied_size);
	if (!NT_SUCCESS(status)) {
		return status;
	}
	PDPT = PDPT & 0x000FFFFFFFFFF000;

	ULONG64 pd_index = (VirtualAddress >> 30) & 0x1ff;
	ULONG64 Physical_addr_pd = pd_index * 8 + PDPT;
	ULONG64 PD = NULL;
	status = ReadPhysicalMemory(Physical_addr_pd, (UCHAR*)&PD, 8, &copied_size);
	if (!NT_SUCCESS(status)) {
		return status;
	}
	PD =PD & 0x000FFFFFFFFFF000;

	ULONG64 pt_index= (VirtualAddress >> 21) & 0x1ff;
	ULONG64 Physical_addr_pt = pt_index * 8 + PD;
	ULONG64 PT = NULL;
	status = ReadPhysicalMemory(Physical_addr_pt, (UCHAR*)&PT, 8, &copied_size);
	if (!NT_SUCCESS(status)) {
		return status;
	}
	PT = PT & 0x000FFFFFFFFFF000;

	ULONG64 pte_index= (VirtualAddress >> 12) & 0x1ff;
	ULONG64 Physical_addr_pte = pte_index * 8 + PT;
	ULONG64 PTE = NULL;
	status = ReadPhysicalMemory(Physical_addr_pte,(UCHAR*)&PTE,8,&copied_size);
	if (!NT_SUCCESS(status)) {
		return status;
	}
	PTE = PTE & 0x000FFFFFFFFFF000;

	ULONG64 offset = VirtualAddress & 0xfff;
	(*PhysicalAddress) = PTE + offset;
	return status;
}



NTSTATUS ReadTargetPhysicalMemory(__in HANDLE TargetPid,__in PVOID VirtualAddress,__in SIZE_T readlen,__out UCHAR* outputbuffer,size_t *actual_size) {
	PEPROCESS PTargetEprocess=NULL;
	
	NTSTATUS status = PsLookupProcessByProcessId(TargetPid,&PTargetEprocess);
	if (!NT_SUCCESS(status)) {
		return status;
	}
	ULONG64 cr3offset=0x00;
	status=GetCr3Offset(&cr3offset);
	if (!NT_SUCCESS(status)) {
		ObDereferenceObject(PTargetEprocess);
		return status;
	}
	PVOID TargetCr3 = *((PVOID*)(cr3offset+(ULONG64)PTargetEprocess));	
	
	ULONG64 PhysicalAddress = NULL;
	status = GetTargetPhysicalMemory(TargetCr3,VirtualAddress,&PhysicalAddress);
	if (!NT_SUCCESS(status)) {
		ObDereferenceObject(PTargetEprocess);
		return status;
	}
	status = ReadPhysicalMemory(PhysicalAddress,outputbuffer,readlen,actual_size);
	ObDereferenceObject(PTargetEprocess);
	return status;
}


NTSTATUS WriteTargetPhysicalMemory(__in HANDLE TargetPid, __in PVOID VirtualAddress, __in SIZE_T writelen, __in UCHAR* inputbuffer){

	PEPROCESS PTargetEprocess = NULL;
	NTSTATUS status = PsLookupProcessByProcessId(TargetPid,&PTargetEprocess);
	if (!NT_SUCCESS(status)) {
		return status;
	}
	ULONG64 cr3offset = 0x00;
	status = GetCr3Offset(&cr3offset);
	if (!NT_SUCCESS(status)) {
		ObDereferenceObject(PTargetEprocess);
		return status;
	}
	PVOID TargetCr3 = *((PVOID*)(cr3offset + (ULONG64)PTargetEprocess));
	ULONG64 PhysicalAddress = NULL;
	ULONG64 VirtualAddrPageStart = (ULONG64)VirtualAddress & (~0xfff);
	size_t CycleWritelen = 0;
	ULONG64 PageOffset = (ULONG64)VirtualAddress & 0xfff;
	size_t remain = 0;
	while ((LONG64)writelen>0) {
		remain = PAGE_SIZE - PageOffset;
		CycleWritelen = ((writelen+PageOffset)>PAGE_SIZE)?remain:writelen;
		status = GetTargetPhysicalMemory(TargetCr3, VirtualAddrPageStart, &PhysicalAddress);     
		if (!NT_SUCCESS(status)) {
			ObDereferenceObject(PTargetEprocess);
			return status;
		}
		status = WritePhysicalMemory(PhysicalAddress+PageOffset, inputbuffer, CycleWritelen);
		if (!NT_SUCCESS(status)) {
			ObDereferenceObject(PTargetEprocess);
			return status;
		}
		inputbuffer += CycleWritelen;
		writelen -= CycleWritelen;
		PageOffset = 0;
		VirtualAddrPageStart += PAGE_SIZE;
	}
	ObDereferenceObject(PTargetEprocess);
	return status;
}

