#include"wdbg.h"




NTSTATUS FindFunctionAddrByName(__in WCHAR* name, __out PVOID* addr) {

	UNICODE_STRING funcname;
	RtlInitUnicodeString(&funcname, name);
	*addr = MmGetSystemRoutineAddress(&funcname);
	if (*addr == NULL) {
		return STATUS_PROCEDURE_NOT_FOUND;
	}
	return STATUS_SUCCESS;
}

NTSTATUS ChangePreviousMode(KPROCESSOR_MODE mode) {
	PVOID func_addr;
	NTSTATUS st = FindFunctionAddrByName(L"ExGetPreviousMode",&func_addr);
	if (!NT_SUCCESS(st)) {
		return st;
	}
	PUCHAR mcode = (PUCHAR)func_addr;
	UCHAR b1,b2;
	ULONG offset = 0;
	while (SafeReadU8(mcode,&b1)&&b1!=0xC3) {
		if (b1==0x8A) {
			if (SafeReadU8(mcode+1,&b2)&&b2==0x80) {
				SafeReadI32(mcode+2,&offset);
			}
		}
		mcode++;
	}
	if (offset!=0) {
		PETHREAD currentthread = PsGetCurrentThread();
		*((UCHAR*)((UCHAR*)currentthread + offset)) = mode;
		return STATUS_SUCCESS;
	}
	return STATUS_UNSUCCESSFUL;
}


/*

NTSTATUS GETSERVICEFUNCTIONADDR(__in ULONG eaxt, __out PVOID* addr, __in int ssdttype) {
	ULONG edit = eaxt >> 7;
	edit = edit & 0x20;//ÕâÀï±£Ö¤£¬ÒªÃ´È¡0x20ÒªÃ´È¡0
	SSDT_SET set;
	PSSDT_SET pset = &set;
	NTSTATUS st = GETSSDT(pset);
	if (!NT_SUCCESS(st)) {
		return st;
	}
	PCHAR temp_ptr1 = (PCHAR)((PKSERVICE_DESCRIPTOR_TABLE)pset + ssdttype);//r10
	temp_ptr1 = (PCHAR)(*((LONG64*)temp_ptr1)) + edit;
	temp_ptr1 = *(ULONG64*)temp_ptr1;
	int temp_value = *((int*)(temp_ptr1 + eaxt * 4));
	LONG64 offset = (LONG64)temp_value;//rax
	PCHAR temp_ptr3 = offset >> 4;//sar r11,4 ËãÊýÓÒÒÆ4
	temp_ptr1 = (ULONG64)temp_ptr3 + (ULONG64)temp_ptr1;
	(*addr) = temp_ptr1;
	return st;
}
*/
NTSTATUS GETSERVICEFUNCTIONADDR(__in ULONG eaxt, __out PVOID* addr, __in int ssdttype)
{
	ULONG edit = (eaxt >> 7) & 0x20; // ±£Ö¤ÒªÃ´ 0 ÒªÃ´ 0x20

	SSDT_SET set;
	PSSDT_SET pset = &set;
	NTSTATUS st = GETSSDT(pset);
	if (!NT_SUCCESS(st)) {
		return st;
	}

	// ÄÃµ½Ö¸¶¨µÄ SSDT
	PUCHAR temp_ptr1 = (PUCHAR)((PKSERVICE_DESCRIPTOR_TABLE)pset + ssdttype);

	ULONG64 tableAddr;
	if (!SafeReadU64(temp_ptr1, &tableAddr)) {
		return STATUS_ACCESS_VIOLATION;
	}
	temp_ptr1 = (PUCHAR)(tableAddr + edit);

	// ÔÙ½âÒ»´Î
	ULONG64 tableBase;
	if (!SafeReadU64(temp_ptr1, &tableBase)) {
		return STATUS_ACCESS_VIOLATION;
	}
	temp_ptr1 = (PUCHAR)tableBase;

	// ¸ù¾Ý eax Ë÷Òý¶Áº¯ÊýµØÖ·
	INT32 temp_value;
	if (!SafeReadI32(temp_ptr1 + eaxt * 4, &temp_value)) {
		return STATUS_ACCESS_VIOLATION;
	}

	LONG64 offset = (LONG64)temp_value;
	PUCHAR temp_ptr3 = (PUCHAR)(offset >> 4);  // sar r11,4

	temp_ptr1 = (PUCHAR)((ULONG64)temp_ptr3 + (ULONG64)temp_ptr1);
	*addr = temp_ptr1;
	return STATUS_SUCCESS;
}
NTSTATUS GETSSDT(PSSDT_SET ssdt_set) {
	PUCHAR mcodestart = NULL;
	PUCHAR mcode2start = NULL;
	PUCHAR mcode3start = NULL;
	INT32 tempoffset1 = 0;
	INT32 tempoffset2 = 0;
	//INT32 tempoffset3 = 0;
	NTSTATUS st = FindFunctionAddrByName(L"ZwOpenProcess", &mcodestart);

	if (!NT_SUCCESS(st)) {
		return st;
	}



	/*
	while ((*mcodestart) != 0xc3) {

		if ((*mcodestart) == 0xE9)
		{
			tempoffset1 = (*(INT32*)(mcodestart + 1));
			mcode2start = mcodestart + 0x5 + tempoffset1;
			break;
		}
		mcodestart++;

	}*/
	UCHAR b;
	while (SafeReadU8(mcodestart, &b) && b != 0xC3)
	{
		if (b == 0xE9)
		{
			INT32 rel;
			if (!SafeReadI32(mcodestart + 1, &rel))
			{
				return STATUS_ACCESS_VIOLATION;  // ¶ÁÈ¡Ê§°Ü£¬Ö±½Ó·µ»Ø
			}

			tempoffset1 = rel;
			mcode2start = mcodestart + 5 + tempoffset1;
			break;
		}
		mcodestart++;
	}

	if (mcode2start == NULL)
	{
		st = STATUS_PROCEDURE_NOT_FOUND;
		return st;
	}

	/*
	while ((*mcode2start) != 0xc3) {
		if ((*mcode2start) == 0x4C && (*(mcode2start + 1)) == 0x8D && (*(mcode2start + 2)) == 0x1D) {
			tempoffset2 = (*(INT32*)(mcode2start + 3));
			mcode3start = mcode2start + 0x7 + tempoffset2;
			break;
		}
		mcode2start++;
	}
	*/

	UCHAR b00, b01, b02;
	while (SafeReadU8(mcode2start, &b00) && b00 != 0xC3)
	{
		if (SafeReadU8(mcode2start + 1, &b01) &&
			SafeReadU8(mcode2start + 2, &b02) &&
			b00 == 0x4C && b01 == 0x8D && b02 == 0x1D)
		{
			INT32 rel;
			if (!SafeReadI32(mcode2start + 3, &rel))
			{
				return STATUS_ACCESS_VIOLATION; // ¶ÁÈ¡Ê§°Ü¾ÍÖ±½Ó·µ»Ø
			}

			tempoffset2 = rel;
			mcode3start = mcode2start + 0x7 + tempoffset2;
			break;
		}
		mcode2start++;
	}


	if (mcode3start == NULL)
	{
		st = STATUS_PROCEDURE_NOT_FOUND;
		return st;
	}




	/*
	while ((*mcode3start) != 0xc3)
	{
		if ((*mcode3start) == 0x4C && (*(mcode3start + 1)) == 0x8D && (*(mcode3start + 2)) == 0x15) {

			ssdt_set->SSDT = (PKSERVICE_DESCRIPTOR_TABLE)(mcode3start + 0x7 + (*(INT32*)(mcode3start + 3)));
			DbgPrint("ssdt:%p", ssdt_set->SSDT);
			count++;
		}
		if ((*mcode3start) == 0x4C && (*(mcode3start + 1)) == 0x8D && (*(mcode3start + 2)) == 0x1D && count == 1) {
			ssdt_set->SSDTshadow = (PKSERVICE_DESCRIPTOR_TABLE)(mcode3start + 0x7 + (*(INT32*)(mcode3start + 3)));
			DbgPrint("ssdtshadow:%p", ssdt_set->SSDTshadow);
			count++;
		}
		if ((*mcode3start) == 0x4C && (*(mcode3start + 1)) == 0x8D && (*(mcode3start + 2)) == 0x1D && count == 2) {
			ssdt_set->SSDTfilter = (PKSERVICE_DESCRIPTOR_TABLE)(mcode3start + 0x7 + (*(INT32*)(mcode3start + 3)));
			DbgPrint("ssdtfilter:%p", ssdt_set->SSDTfilter);
			count++;
		}
		if (count == 3)
		{
			st = STATUS_SUCCESS;
			return st;
		}
		mcode3start++;

	}
	*/
	ULONG count = 0;
	UCHAR b0, b1, b2;

	while (SafeReadU8(mcode3start, &b0) && b0 != 0xC3)
	{
		if (SafeReadU8(mcode3start + 1, &b1) &&
			SafeReadU8(mcode3start + 2, &b2))
		{
			if (b0 == 0x4C && b1 == 0x8D && b2 == 0x15)
			{
				INT32 rel;
				if (!SafeReadI32(mcode3start + 3, &rel))
					return STATUS_ACCESS_VIOLATION;

				ssdt_set->SSDT = (PKSERVICE_DESCRIPTOR_TABLE)(mcode3start + 0x7 + rel);
				DbgPrint("ssdt:%p", ssdt_set->SSDT);
				count++;
			}
			else if (b0 == 0x4C && b1 == 0x8D && b2 == 0x1D && count == 1)
			{
				INT32 rel;
				if (!SafeReadI32(mcode3start + 3, &rel))
					return STATUS_ACCESS_VIOLATION;

				ssdt_set->SSDTshadow = (PKSERVICE_DESCRIPTOR_TABLE)(mcode3start + 0x7 + rel);
				DbgPrint("ssdtshadow:%p", ssdt_set->SSDTshadow);
				count++;
			}
			else if (b0 == 0x4C && b1 == 0x8D && b2 == 0x1D && count == 2)
			{
				INT32 rel;
				if (!SafeReadI32(mcode3start + 3, &rel))
					return STATUS_ACCESS_VIOLATION;

				ssdt_set->SSDTfilter = (PKSERVICE_DESCRIPTOR_TABLE)(mcode3start + 0x7 + rel);
				DbgPrint("ssdtfilter:%p", ssdt_set->SSDTfilter);
				count++;
			}
		}

		if (count == 3)
		{
			st = STATUS_SUCCESS;
			return st;
		}

		mcode3start++;
	}


	st = STATUS_INSUFFICIENT_RESOURCES;
	return st;
}

