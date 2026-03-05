#include "WdbgDll.hpp"



CapStonePageHandle::CapStonePageHandle()
{
	cs_open(CS_ARCH_X86, CS_MODE_64, &caphandle);
	cs_option(caphandle, CS_OPT_DETAIL, CS_OPT_ON);
}

CapStonePageHandle::~CapStonePageHandle()
{
	cs_close(&caphandle);
}

BOOL CapStonePageHandle::TranslationBuffer(__in UCHAR* buffer,
											__in size_t bufferlen, 
											__in DWORD64 VirtualAddr,
											__out cs_insn **PageCodeBuffer,
											__out SIZE_T* CodeCount)
{
	*(CodeCount) = cs_disasm(this->caphandle, buffer, bufferlen, VirtualAddr,0,PageCodeBuffer);
	return 1;
}

