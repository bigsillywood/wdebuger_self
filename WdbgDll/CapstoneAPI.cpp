#include "WdbgDll.hpp"


CapStonePageHandle::CapStonePageHandle()
{
	this->caphandle = 0;

	if (cs_open(CS_ARCH_X86,CS_MODE_64,&this->caphandle) != CS_ERR_OK)
	{
		this->caphandle = 0;
		return;
	}

	cs_option(this->caphandle,CS_OPT_DETAIL,CS_OPT_ON);

	cs_opt_skipdata skipdata = {};
	skipdata.mnemonic = const_cast<char*>("db");

	cs_option(this->caphandle,CS_OPT_SKIPDATA_SETUP,(size_t)&skipdata);
	cs_option(this->caphandle,CS_OPT_SKIPDATA,CS_OPT_ON);
}

CapStonePageHandle::~CapStonePageHandle()
{
	if (this->caphandle != 0)
	{
		cs_close(&this->caphandle);
		this->caphandle = 0;
	}
}

BOOL CapStonePageHandle::TranslationBuffer(__in UCHAR*		buffer,
											__in size_t		bufferlen,
											__in DWORD64	VirtualAddr,
											__out cs_insn**	CodeBuffer,
											__out SIZE_T*	CodeCount)
{
	*(CodeCount) = cs_disasm(this->caphandle,buffer,bufferlen,VirtualAddr,0,CodeBuffer);
	return 1;
}

BOOL CapStonePageHandle::TranslateOneInstruction(__in  UCHAR*				buffer,
												 __in  size_t				bufferlen,
												 __in  DWORD64				VirtualAddr,
												 __out POneInstructionRecord OutRecord)
{
	if (buffer == NULL || bufferlen == 0 || OutRecord == NULL)
	{
		return FALSE;
	}

	cs_insn* insn = NULL;
	SIZE_T count = cs_disasm(this->caphandle,buffer,bufferlen,VirtualAddr,1,&insn);

	if (count == 0 || insn == NULL)
	{
	
		ZeroMemory(OutRecord,sizeof(OneInstructionRecord));
		OutRecord->id				= 0;
		OutRecord->InnerPageIndex	= 0;
		OutRecord->InstructionAddr	= VirtualAddr;
		OutRecord->InstructionLen	= 1;
		OutRecord->InstructionBuffer[0] = buffer[0];
		_snprintf_s(
			(char*)OutRecord->InstructionString,
			192,
			_TRUNCATE,
			"db 0x%02X",
			buffer[0]
		);
		return TRUE;
	}

	ZeroMemory(OutRecord,sizeof(OneInstructionRecord));
	OutRecord->id				= insn[0].id;
	OutRecord->InnerPageIndex	= 0;
	OutRecord->InstructionAddr	= insn[0].address;
	OutRecord->InstructionLen	= (uint8_t)insn[0].size;
	memcpy(OutRecord->InstructionBuffer,insn[0].bytes,insn[0].size);
	_snprintf_s(
		(char*)OutRecord->InstructionString,
		192,
		_TRUNCATE,
		"%s %s",
		insn[0].mnemonic,
		insn[0].op_str
	);

	cs_free(insn,count);
	return TRUE;
}
