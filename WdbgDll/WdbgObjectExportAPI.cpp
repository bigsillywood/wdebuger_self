
#include "WdbgDll.hpp"

UCHAR BreakPointerBuffer[24] = { 0xcc,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90 };
WDebugerObject::WDebugerObject(HANDLE TargetPid)
{
	this->MainThreadid = NULL;
	this->ProcessHandle = NULL;
	this->dllhead = NULL;
	this->islisten = FALSE;
	this->TargetPid = TargetPid;
	this->hDevice = NULL;
	this->DebugHandle = NULL;
	//this->CodeStruct.CodeLockOk = FALSE;
	this->isLockOk = FALSE;
	this->CodeStruct.CurrentLookingPageStartAddress = NULL;
	RtlZeroMemory(&(this->ProcessInfo),sizeof(CREATE_PROCESS_DEBUG_INFO));
}

WDebugerObject::~WDebugerObject()
{
	this->islisten=FALSE;
	
	OneInstructionRecord* TempInsPtr;
	for (auto  it = this->CodeStruct.Blist.begin(); it!=this->CodeStruct.Blist.end(); it++)
	{
		TempInsPtr = it->second;
		if (TempInsPtr->enable==TRUE) {
			this->WritePhysicalMem(TempInsPtr->InstructionBuffer,TempInsPtr->InstructionLen,TempInsPtr->InstructionAddr);
		}
		free(TempInsPtr);
	}

	for (auto IterPage = this->CodeStruct.Pagelist.begin(); IterPage != this->CodeStruct.Pagelist.end();IterPage++) {
		if (IterPage->second!=NULL) {
			cs_free(IterPage->second->PageCodes,IterPage->second->CodeCounts);
			free(IterPage->second);
		}
	}


	ZwRemoveProcessDebug(this->ProcessHandle,this->DebugHandle);
	if (this->DebugHandle!=NULL && this->DebugHandle!=INVALID_HANDLE_VALUE) {
		CloseHandle(this->DebugHandle);
	}


	if (this->listen_thread.joinable()) {
		this->listen_thread.join();
	}


	if (this->hDevice!=NULL && this->hDevice!=INVALID_HANDLE_VALUE) {
		CloseHandle(this->hDevice);
	}
	for (auto it = ThreadInfoMaps.begin(); it != ThreadInfoMaps.end();it++) {
		
		if (it->second->ThreadHandle!=NULL && it->second->ThreadHandle !=INVALID_HANDLE_VALUE) {
			CloseHandle(it->second->ThreadHandle);
		}
		if (it->second != NULL) {
			free(it->second);
		}
	}
	if (this->ProcessHandle!=NULL && this->ProcessHandle!=INVALID_HANDLE_VALUE)
	{
		CloseHandle(this->ProcessHandle);
	}
	this->CLEANALLDLL();
	if (this->isLockOk) {
		DeleteCriticalSection(&(this->WdbgLock));
	}
	this->isLockOk = FALSE;
	/*
		if (this->CodeStruct.CodeLockOk) {
		DeleteCriticalSection(&(this->CodeStruct.CodeLock));
	}
	
	*/

	//this->CodeStruct.CodeLockOk = FALSE;
}


std::unique_ptr<WDebugerObject> WDebugerObject::Create(HANDLE TargetPid)
{
	std::unique_ptr<WDebugerObject> ptr(new WDebugerObject(TargetPid));
	if (!(ptr->init())) {
		return nullptr;
	}
	return ptr;
}
BOOL WDebugerObject::GetThreadList(HANDLE* Tidbuffer, DWORD buffersize)
{
	RtlZeroMemory(Tidbuffer,buffersize*sizeof(HANDLE));
	DWORD MaxIndex = buffersize - 1;
	DWORD index = 0;
	BOOL result = TRUE;
	EnterCriticalSection(&(this->WdbgLock));
	for (auto it = this->ThreadInfoMaps.begin(); it != this->ThreadInfoMaps.end();it++) {
		if (index>MaxIndex)
		{
			SetLastError(ERROR_DS_USER_BUFFER_TO_SMALL);
			result = FALSE;
		}
		Tidbuffer[index] = it->first;
		index++;
	}
	LeaveCriticalSection(&(this->WdbgLock));
	return result;
}


BOOL WDebugerObject::ContinueThread(HANDLE Tid)
{
	
	EnterCriticalSection(&this->WdbgLock);
	auto iter = this->ThreadInfoMaps.find(Tid);
	if (iter==this->ThreadInfoMaps.end())
	{
		LeaveCriticalSection(&this->WdbgLock);
		return FALSE;
	}
	if (iter->second->devent.dwDebugEventCode == 0) {
		LeaveCriticalSection(&this->WdbgLock);
		return FALSE;
	}
	iter->second->stepflag = StepReasonNone;
	POneInstructionRecord bptr;
	for (auto it = this->CodeStruct.Blist.begin(); it != this->CodeStruct.Blist.end();)
	{
		bptr = it->second;
		if (bptr->OnlyOver == TRUE&&bptr->InstructionAddr!=iter->second->ThreadContext.Rip)
		{
			WritePhysicalMem(bptr->InstructionBuffer, bptr->InstructionLen, bptr->InstructionAddr);
			FlushInstructionCache(this->ProcessHandle, (LPCVOID)bptr->InstructionAddr, bptr->InstructionLen);
			it = this->CodeStruct.Blist.erase(it);
			DWORD64 StartAddr = bptr->InstructionAddr & (~0XFFF);
			this->CodeStruct.Pagelist.find(StartAddr)->second->CodeCounts--;
			free(bptr);
		}
		else
		{
			if (bptr->enable == TRUE && bptr->dirty == TRUE)
			{
				WritePhysicalMem(BreakPointerBuffer, bptr->InstructionLen, bptr->InstructionAddr);
				FlushInstructionCache(this->ProcessHandle, (LPCVOID)bptr->InstructionAddr, bptr->InstructionLen);
				bptr->dirty = FALSE;
			}
			++it;
		}
	}
	BOOL ok = this->ContinueThreadLocked(Tid);
	LeaveCriticalSection(&this->WdbgLock);
	return ok;
}
BOOL WDebugerObject::SetCodeStructCurrentLookingInstructions(DWORD64 VirtualAddress)
{
	PageInfor* SavedCurrentPagePtr = NULL;
	EnterCriticalSection(&this->WdbgLock);
	auto itSaved = this->CodeStruct.Pagelist.find(
		this->CodeStruct.CurrentLookingPageStartAddress
	);
	if (itSaved != this->CodeStruct.Pagelist.end()) {
		SavedCurrentPagePtr = itSaved->second;
		if (SavedCurrentPagePtr==NULL)
		{
			LeaveCriticalSection(&(this->WdbgLock));
			OutputDebugStringW(L"illegal second,ouccr in SetCodeStructCurrentLookingInstructions");
			return FALSE;
		}
		if (SavedCurrentPagePtr->CurrentVirtualAddress==VirtualAddress) {
			LeaveCriticalSection(&(this->WdbgLock));
			return TRUE;
		}
	
	}
	DWORD64 PageStartAddress = VirtualAddress & (~0xFFF);

	auto it = this->CodeStruct.Pagelist.find(PageStartAddress);
	if (it == this->CodeStruct.Pagelist.end() || it->second == NULL) {
		if(!this->CahchePage(PageStartAddress)) {
			LeaveCriticalSection(&this->WdbgLock);
			return FALSE;
		}
		auto temp = this->CodeStruct.Pagelist.find(PageStartAddress);
		if (temp==this->CodeStruct.Pagelist.end()) {
			LeaveCriticalSection(&this->WdbgLock);
			return FALSE;
		}

		PageInfor* NewPageInfor = temp->second;
		if (NewPageInfor==NULL) {
			LeaveCriticalSection(&(this->WdbgLock));
			OutputDebugStringW(L"illegal second,ouccr in SetCodeStructCurrentLookingInstructions");
			return FALSE;
		}
		for (size_t i = 0; i < NewPageInfor->CodeCounts;i++) {
			if(NewPageInfor->PageCodes[i].address==VirtualAddress) {
				OutputDebugStringW(L"find vaddr ,set up looking");
				NewPageInfor->CurrentLookingCodeIndexInPage = i;
				NewPageInfor->CurrentVirtualAddress = VirtualAddress;
				this->CodeStruct.CurrentLookingPageStartAddress = PageStartAddress;
				goto SUCCESS;
			}
		}
		this->CodeStruct.Pagelist.erase(NewPageInfor->StartVirtualAddr);
		this->FreePage(NewPageInfor);	
		LeaveCriticalSection(&this->WdbgLock);
		return FALSE;
	}
	else
	{
		PageInfor* TemPageInfor = it->second;
		for (SIZE_T i = 0; i <TemPageInfor->CodeCounts; i++)
		{
			if (TemPageInfor->PageCodes[i].address==VirtualAddress) {
				TemPageInfor->CurrentVirtualAddress = VirtualAddress;
				TemPageInfor->CurrentLookingCodeIndexInPage = i;
				this->CodeStruct.CurrentLookingPageStartAddress = PageStartAddress;
				goto SUCCESS;
			}
		}
		LeaveCriticalSection(&this->WdbgLock);
		return FALSE;
	}

SUCCESS:
	if ((SavedCurrentPagePtr!=NULL)&&(SavedCurrentPagePtr->StartVirtualAddr!=PageStartAddress)) {
		if (SavedCurrentPagePtr->BreakPointCounts==0) {
			this->CodeStruct.Pagelist.erase(SavedCurrentPagePtr->StartVirtualAddr);
			this->FreePage(SavedCurrentPagePtr);
		}
	}
	LeaveCriticalSection(&this->WdbgLock);
	return TRUE;
}







DWORD64 WDebugerObject::GetTargetCode(POneInstructionRecord InstructionRecordBufferPtr, SIZE_T MaxInstructions)
{
	OutputDebugStringW(L"get target code start");
	SIZE_T index = 0;
	
	OutputDebugStringW(L"get tempageptr map");
	EnterCriticalSection(&this->WdbgLock);
	auto it = this->CodeStruct.Pagelist.find(this->CodeStruct.CurrentLookingPageStartAddress);
	if (it==this->CodeStruct.Pagelist.end())
	{
		
		LeaveCriticalSection(&this->WdbgLock);
		return 0;
	}
	if (it->second==NULL) {
		OutputDebugStringW(L"illegal second,ouccr in GetTargetCode");
		LeaveCriticalSection(&this->WdbgLock);
		return 0;
	}
	PageInfor* TemPagePtr =it->second;
	OutputDebugStringW(L"start copy");
	while (index<MaxInstructions&&(index+(TemPagePtr->CurrentLookingCodeIndexInPage))<(TemPagePtr->CodeCounts)) {
		OutputDebugStringW(L"start copy index");
		InstructionRecordBufferPtr[index].InnerPageIndex = TemPagePtr->CurrentLookingCodeIndexInPage + index;
		OutputDebugStringW(L"start copy instructionAddr");
		InstructionRecordBufferPtr[index].InstructionAddr = TemPagePtr->PageCodes[index + TemPagePtr->CurrentLookingCodeIndexInPage].address;
		InstructionRecordBufferPtr[index].InstructionLen = TemPagePtr->PageCodes[index + TemPagePtr->CurrentLookingCodeIndexInPage].size;
		memcpy(InstructionRecordBufferPtr[index].InstructionBuffer,
			TemPagePtr->PageCodes[index + TemPagePtr->CurrentLookingCodeIndexInPage].bytes,
			InstructionRecordBufferPtr[index].InstructionLen);
		char* out = (char*)InstructionRecordBufferPtr[index].InstructionString;

		_snprintf_s(
			out,
			192,
			_TRUNCATE,
			"%s %s",
			TemPagePtr->PageCodes[index + TemPagePtr->CurrentLookingCodeIndexInPage].mnemonic,
			TemPagePtr->PageCodes[index + TemPagePtr->CurrentLookingCodeIndexInPage].op_str
		);

		InstructionRecordBufferPtr[index].enable = FALSE;
		auto finder = this->CodeStruct.Blist.find(InstructionRecordBufferPtr[index].InstructionAddr);
		if (finder!=this->CodeStruct.Blist.end()&&finder->second!=NULL) {
			InstructionRecordBufferPtr[index].enable = finder->second->enable;
		}
		index++;
	}
	LeaveCriticalSection(&this->WdbgLock);
	return index;
}

BOOL WDebugerObject::SetBreakPointUp(DWORD64 InstructionAddr)
{
	PageInfor* TargetPage = NULL;
	DWORD64 StartAddress = InstructionAddr & (~0xfff);
	EnterCriticalSection(&this->WdbgLock);
	auto Saved = this->CodeStruct.Pagelist.find(StartAddress);
	if (Saved==this->CodeStruct.Pagelist.end()||Saved->second==NULL)
	{
		if (!this->CahchePage(StartAddress)) {
			LeaveCriticalSection(&this->WdbgLock);
			return FALSE;
		}
	}
	auto finder = this->CodeStruct.Blist.find(InstructionAddr);
	if (finder!=this->CodeStruct.Blist.end())
	{
		POneInstructionRecord InsPtr;
		InsPtr = finder->second;
		if (InsPtr!=NULL)
		{
			if (InsPtr->enable==FALSE){
				if (this->WritePhysicalMem(BreakPointerBuffer, InsPtr->InstructionLen, InstructionAddr)) {
					FlushInstructionCache(this->ProcessHandle, (LPCVOID)InsPtr->InstructionAddr, InsPtr->InstructionLen);
					InsPtr->enable = TRUE;
					InsPtr->dirty = FALSE;
					InsPtr->OnlyOver = FALSE;
					LeaveCriticalSection(&this->WdbgLock);
					return TRUE;
				}
				else
				{
					LeaveCriticalSection(&this->WdbgLock);
					return FALSE;
				}
			}
			else {
				LeaveCriticalSection(&this->WdbgLock);
				return TRUE;
			}
		}
		else
		{
			this->CodeStruct.Blist.erase(InstructionAddr);
		}
	}

	cs_insn* tempPtr;
	for (SIZE_T i = 0; i < this->CodeStruct.Pagelist[StartAddress]->CodeCounts; i++)
	{
		tempPtr = &(this->CodeStruct.Pagelist[StartAddress]->PageCodes[i]);
		if (InstructionAddr==tempPtr->address) {
			//start copy
			POneInstructionRecord InstructionPtr = (POneInstructionRecord)malloc(sizeof(OneInstructionRecord));
			
			if (InstructionPtr==NULL)
			{
				LeaveCriticalSection(&this->WdbgLock);
				return FALSE;
			}
			ZeroMemory(InstructionPtr, sizeof(OneInstructionRecord));
			InstructionPtr->InnerPageIndex = i;
			InstructionPtr->InstructionAddr = InstructionAddr;
			InstructionPtr->InstructionLen = tempPtr->size;
			InstructionPtr->id = tempPtr->id;
			memcpy(InstructionPtr->InstructionBuffer,tempPtr->bytes,InstructionPtr->InstructionLen);
			_snprintf_s(
				(char*)InstructionPtr->InstructionString,
				192,
				_TRUNCATE,
				"%s %s",
				tempPtr->mnemonic,
				tempPtr->op_str
			);
			if(this->WritePhysicalMem(BreakPointerBuffer,InstructionPtr->InstructionLen,InstructionAddr)){
				FlushInstructionCache(this->ProcessHandle,(LPCVOID)InstructionPtr->InstructionAddr,InstructionPtr->InstructionLen);
				InstructionPtr->enable = TRUE;
				InstructionPtr->dirty = FALSE;
				InstructionPtr->OnlyOver = FALSE;
				this->CodeStruct.Blist[InstructionAddr] = InstructionPtr;
				this->CodeStruct.Pagelist[StartAddress]->BreakPointCounts++;

				LeaveCriticalSection(&this->WdbgLock);
				return TRUE;
			}
			else
			{
				free(InstructionPtr);
				LeaveCriticalSection(&this->WdbgLock);
				return FALSE;
			}

		}
	}
	LeaveCriticalSection(&this->WdbgLock);
}

BOOL WDebugerObject::SetBreakPointDown(DWORD64 InstructionAddr)
{
	//EnterCriticalSection(&this->ThreadMapLock);
	EnterCriticalSection(&this->WdbgLock);
	auto it = this->CodeStruct.Blist.find(InstructionAddr);
	if (it==this->CodeStruct.Blist.end()) {
		//LeaveCriticalSection(&this->CodeStruct.CodeLock);
		LeaveCriticalSection(&this->WdbgLock);
		return FALSE;
	}
	else
	{
		
		POneInstructionRecord ptr = it->second;
		if (ptr==NULL) {
			this->CodeStruct.Blist.erase(InstructionAddr);
			//LeaveCriticalSection(&this->CodeStruct.CodeLock);
			LeaveCriticalSection(&this->WdbgLock);
			return TRUE;
		}

		
		for (auto iter2 = this->ThreadInfoMaps.begin(); iter2 != this->ThreadInfoMaps.end(); iter2++)
		{
			if (iter2->second->devent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT
				&& iter2->second->devent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT
				&& (DWORD64)iter2->second->devent.u.Exception.ExceptionRecord.ExceptionAddress == InstructionAddr
				&& it->second->enable == TRUE) {
				DWORD oflag = iter2->second->ThreadContext.ContextFlags;
				iter2->second->ThreadContext.ContextFlags = CONTEXT_CONTROL;
				/*
				GetThreadContext(iter2->second->ThreadHandle, &iter2->second->ThreadContext);
				iter2->second->ThreadContext.Rip = iter2->second->ThreadContext.Rip - 1;
				*/
				
				SetThreadContext(iter2->second->ThreadHandle, &iter2->second->ThreadContext);
				iter2->second->ThreadContext.ContextFlags = oflag;
			}
		}
		
		

		if (this->WritePhysicalMem(ptr->InstructionBuffer,ptr->InstructionLen,ptr->InstructionAddr)) {
			FlushInstructionCache(this->ProcessHandle,(LPCVOID)ptr->InstructionAddr,ptr->InstructionLen);
			ptr->enable = FALSE;
			ptr->dirty = FALSE;
			//LeaveCriticalSection(&this->CodeStruct.CodeLock);
			LeaveCriticalSection(&this->WdbgLock);
			return TRUE;
		}
		else
		{
			//LeaveCriticalSection(&this->CodeStruct.CodeLock);
			LeaveCriticalSection(&this->WdbgLock);
			return FALSE;
		}

	}
	//LeaveCriticalSection(&this->CodeStruct.CodeLock);
	LeaveCriticalSection(&this->WdbgLock);
	return 0;
}

BOOL WDebugerObject::DeleteBreakPoint(DWORD64 InstructionAddr)
{
	DWORD64 StartAddr=InstructionAddr&(~0xfff);
	//EnterCriticalSection(&this->ThreadMapLock);
	EnterCriticalSection(&this->WdbgLock);
	auto it=this->CodeStruct.Blist.find(InstructionAddr);
	if (it==this->CodeStruct.Blist.end()) {
		LeaveCriticalSection(&this->WdbgLock);
		//LeaveCriticalSection(&this->ThreadMapLock);
		return TRUE;
	}
	else
	{
		POneInstructionRecord Ptr = it->second;
		if(Ptr==NULL){
			this->CodeStruct.Blist.erase(InstructionAddr);
			//LeaveCriticalSection(&this->CodeStruct.CodeLock);
			LeaveCriticalSection(&this->WdbgLock);
			return TRUE;
		}

		for (auto iter2 = this->ThreadInfoMaps.begin(); iter2 != this->ThreadInfoMaps.end(); iter2++)
		{
			if (iter2->second->devent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT
				&& iter2->second->devent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT
				&& (DWORD64)iter2->second->devent.u.Exception.ExceptionRecord.ExceptionAddress == InstructionAddr
				&& it->second->enable == TRUE) {
				DWORD oflag = iter2->second->ThreadContext.ContextFlags;
				iter2->second->ThreadContext.ContextFlags = CONTEXT_CONTROL;
				SetThreadContext(iter2->second->ThreadHandle, &iter2->second->ThreadContext);
				iter2->second->ThreadContext.ContextFlags = oflag;
			}
		}
		

		BOOL flag=FALSE;
		if (Ptr->enable==TRUE) {
			flag=WritePhysicalMem(Ptr->InstructionBuffer,Ptr->InstructionLen,Ptr->InstructionAddr);
			FlushInstructionCache(this->ProcessHandle, (LPCVOID)Ptr->InstructionAddr, Ptr->InstructionLen);
		}
		else
		{
			free(Ptr);
			this->CodeStruct.Blist.erase(InstructionAddr);
			if (this->CodeStruct.Pagelist[StartAddr] != NULL) {
				this->CodeStruct.Pagelist[StartAddr]->BreakPointCounts--;
			}
			//LeaveCriticalSection(&this->CodeStruct.CodeLock);
			LeaveCriticalSection(&this->WdbgLock);
			
			return TRUE;
		}
		if (flag) {
			free(Ptr);
			this->CodeStruct.Blist.erase(InstructionAddr);
			if (this->CodeStruct.Pagelist[StartAddr] != NULL) {
				this->CodeStruct.Pagelist[StartAddr]->BreakPointCounts--;
			}
			//LeaveCriticalSection(&this->CodeStruct.CodeLock);
			LeaveCriticalSection(&this->WdbgLock);
			return TRUE;
		}
		//LeaveCriticalSection(&this->CodeStruct.CodeLock);
		LeaveCriticalSection(&this->WdbgLock);
		return FALSE;
	}
}



//pls reserve a threadinfo space before call
BOOL WDebugerObject::GetThreadInfo(HANDLE Tid,__out ThreadInfo* outinfo)
{
	if (outinfo==NULL) {
		return FALSE;
	}
	BOOL result=FALSE;
	EnterCriticalSection(&(this->WdbgLock));

	if (ThreadInfoMaps.find(Tid)!=ThreadInfoMaps.end())
	{
		memcpy((UCHAR*)outinfo,(UCHAR*)(ThreadInfoMaps[Tid]),sizeof(ThreadInfo));
		result = TRUE;
	}
	LeaveCriticalSection(&(this->WdbgLock));
	return result;
}
BOOL WDebugerObject::EnumDllInfo(PDLLRecordNode* head)
{
	if (!head) return FALSE;
	*head = NULL;
	EnterCriticalSection(&this->WdbgLock);
	PDLLRecordNode cur = this->dllhead;
	PDLLRecordNode* insertPos = head;
	while (cur != NULL)
	{
		PDLLRecordNode newNode = (PDLLRecordNode)malloc(sizeof(DLLRecordNode));
		if (!newNode)
		{
			LeaveCriticalSection(&this->WdbgLock);
			return FALSE;
		}
		memcpy(newNode, cur, sizeof(DLLRecordNode));
		newNode->next = NULL;
		*insertPos = newNode;
		insertPos = &newNode->next;
		cur = cur->next;
	}
	LeaveCriticalSection(&this->WdbgLock);
	return TRUE;
}

BOOL WDebugerObject::SuspendTargetThread(HANDLE Tid)
{
	BOOL result = FALSE;
	HANDLE threadhandle = NULL;
	EnterCriticalSection(&(this->WdbgLock));
	if(ThreadInfoMaps.find(Tid)!=ThreadInfoMaps.end()){
		threadhandle = ThreadInfoMaps[Tid]->ThreadHandle;
		result = SuspendThread(threadhandle)>=0?TRUE:FALSE;
	}
	LeaveCriticalSection(&(this->WdbgLock));
	return result;
}

BOOL WDebugerObject::ResumeTargetThread(HANDLE Tid)
{
	BOOL result = FALSE;
	HANDLE threadhandle = NULL;
	EnterCriticalSection(&(this->WdbgLock));
	if (ThreadInfoMaps.find(Tid) != ThreadInfoMaps.end()) {
		threadhandle = ThreadInfoMaps[Tid]->ThreadHandle;
		result = ResumeThread(threadhandle)>=0?TRUE:FALSE;
	}
	LeaveCriticalSection(&(this->WdbgLock));
	return result;
}



VOID WDebugerObject::GetProcessInfo(CREATE_PROCESS_DEBUG_INFO* outinfo)
{

	EnterCriticalSection(&(this->WdbgLock));
	memcpy(outinfo,&(this->ProcessInfo),sizeof(CREATE_PROCESS_DEBUG_INFO));
	LeaveCriticalSection(&(this->WdbgLock));
}

BOOL WDebugerObject::ChangeContext(HANDLE Tid, CONTEXT* tcontext)
{
	
	EnterCriticalSection(&(this->WdbgLock));
	BOOL result=FALSE;
	if (ThreadInfoMaps.find(Tid) != ThreadInfoMaps.end())
	{
		DWORD oFlags = ThreadInfoMaps[Tid]->ThreadContext.ContextFlags;
		ThreadInfoMaps[Tid]->ThreadContext.ContextFlags = CONTEXT_ALL;
		HANDLE temphandle = ThreadInfoMaps[Tid]->ThreadHandle;
		if (SetThreadContext(temphandle,tcontext)) {
			memcpy((UCHAR*)&(ThreadInfoMaps[Tid]->ThreadContext),(UCHAR*)tcontext,sizeof(CONTEXT));
			result = TRUE;
		}
		ThreadInfoMaps[Tid]->ThreadContext.ContextFlags = oFlags;
	}
	LeaveCriticalSection(&(this->WdbgLock));
	return result;
}

BOOL WDebugerObject::CreateListenThread()
{
	EnterCriticalSection(&(this->WdbgLock));
	if (this->islisten == FALSE) {
		this->islisten = TRUE;
		this->listen_thread = std::thread(&WDebugerObject::ListenThread,this);
	}
	else
	{
		LeaveCriticalSection(&(this->WdbgLock));
		return FALSE;
	}
	LeaveCriticalSection(&(this->WdbgLock));
	return TRUE;
}

BOOL WDebugerObject::init()
{
	
	this->isLockOk=InitializeCriticalSectionAndSpinCount(&(this->WdbgLock), 4000);
	if (this->isLockOk==FALSE)
	{
		return FALSE;
	}

	/*
	this->CodeStruct.CodeLockOk = InitializeCriticalSectionAndSpinCount(&(this->WdbgLock), 4000);
	if (this->CodeStruct.CodeLockOk==FALSE) {
		return FALSE;
	}
	*/
	
	this->hDevice= CreateWdbgDevice();
	if(this->hDevice==INVALID_HANDLE_VALUE) {

		return FALSE;
		
	}
	this->DebugHandle = krnlDebugActive(this->TargetPid,this->hDevice);
	if (this->DebugHandle==INVALID_HANDLE_VALUE || this->DebugHandle == NULL) {
		CloseHandle(this->hDevice);
		return FALSE;
	}
}

HANDLE WDebugerObject::GetDebugProcessHandle()
{
	return this->ProcessInfo.hProcess;
}

BOOL WDebugerObject::ReadPhysicalMem(UCHAR* readbuffer, size_t readsize,ULONG64 VirtualAddr)
{
	if (VirtualAddr == 0) {
		//printf("[PhysMem] ReadPhysicalMem: rejected NULL address\n");
		return FALSE;
	}
	if (VirtualAddr < 0x10000ULL) {
		//printf("[PhysMem] ReadPhysicalMem: rejected low address 0x%llX (NULL region)\n", VirtualAddr);
		return FALSE;
	}
	if (VirtualAddr > 0x7FFFFFFFFFFFULL) {
		//printf("[PhysMem] ReadPhysicalMem: rejected kernel address 0x%llX\n", VirtualAddr);
		return FALSE;
	}
	if (readbuffer == nullptr) {
		//printf("[PhysMem] ReadPhysicalMem: rejected NULL buffer\n");
		return FALSE;
	}
	if (readsize == 0 || readsize > 0x10000000ULL) { // 最大单次读256MB，防越界
		//printf("[PhysMem] ReadPhysicalMem: rejected invalid size %zu\n", readsize);
		return FALSE;
	}
	return UserPhysicalRead(this->TargetPid,this->hDevice,VirtualAddr,readsize,readbuffer);
}

BOOL WDebugerObject::WritePhysicalMem(UCHAR* writebuffer, size_t writesize, ULONG64 VirtualAddr)
{
	if (VirtualAddr == 0) {
		//printf("[PhysMem] WritePhysicalMem: rejected NULL address\n");
		return FALSE;
	}
	if (VirtualAddr < 0x10000ULL) {
		//printf("[PhysMem] WritePhysicalMem: rejected low address 0x%llX\n", VirtualAddr);
		return FALSE;
	}
	if (VirtualAddr > 0x7FFFFFFFFFFFULL) {
		//printf("[PhysMem] WritePhysicalMem: rejected kernel address 0x%llX\n", VirtualAddr);
		return FALSE;
	}
	if (writebuffer == nullptr) {
		//printf("[PhysMem] WritePhysicalMem: rejected NULL buffer\n");
		return FALSE;
	}
	if (writesize == 0 || writesize > 0x1000000ULL) { // 写操作限制更严，最大16MB
		//printf("[PhysMem] WritePhysicalMem: rejected invalid size %zu\n", writesize);
		return FALSE;
	}
	return UserPhysicalWrite(this->TargetPid,this->hDevice,VirtualAddr,writesize,writebuffer);
}


BOOL WDebugerObject::StepOverOneStep(HANDLE Tid)
{
	EnterCriticalSection(&this->WdbgLock);
	auto iter = this->ThreadInfoMaps.find(Tid);
	if (iter == this->ThreadInfoMaps.end())
	{
		LeaveCriticalSection(&this->WdbgLock);
		return FALSE;
	}
	if (iter->second->devent.dwDebugEventCode==0) {
		LeaveCriticalSection(&this->WdbgLock);
		return FALSE;
	}
	POneInstructionRecord bptr;
	for (auto it = this->CodeStruct.Blist.begin(); it != this->CodeStruct.Blist.end();)
	{
		bptr = it->second;
		if (bptr->OnlyOver==TRUE)
		{
			WritePhysicalMem(bptr->InstructionBuffer, bptr->InstructionLen, bptr->InstructionAddr);
			FlushInstructionCache(this->ProcessHandle, (LPCVOID)bptr->InstructionAddr, bptr->InstructionLen);
			DWORD64 StartAddr = bptr->InstructionAddr&(~0XFFF);
			this->CodeStruct.Pagelist.find(StartAddr)->second->CodeCounts--;
			free(bptr);
			it = this->CodeStruct.Blist.erase(it);
		}
		else
		{
			if (bptr->enable == TRUE && bptr->dirty == FALSE && bptr->InstructionAddr == iter->second->ThreadContext.Rip)
			{
				WritePhysicalMem(bptr->InstructionBuffer, bptr->InstructionLen, bptr->InstructionAddr);
				FlushInstructionCache(this->ProcessHandle, (LPCVOID)bptr->InstructionAddr, bptr->InstructionLen);
				bptr->dirty = TRUE;
			}
			else if (bptr->enable==TRUE &&bptr->dirty==TRUE &&bptr->InstructionAddr!=iter->second->ThreadContext.Rip )
			{
				WritePhysicalMem(BreakPointerBuffer, bptr->InstructionLen, bptr->InstructionAddr);
				FlushInstructionCache(this->ProcessHandle, (LPCVOID)bptr->InstructionAddr, bptr->InstructionLen);
				bptr->dirty = FALSE;
			}
			++it;
		}
		
	}
	iter->second->stepflag = StepReasonUserOverStep;
	this->ContinueThreadLocked(Tid);

	LeaveCriticalSection(&this->WdbgLock);
	return TRUE;
}

BOOL WDebugerObject::StepIntoOneStep(HANDLE Tid) {
	EnterCriticalSection(&this->WdbgLock);
	auto iter = this->ThreadInfoMaps.find(Tid);
	if (iter == this->ThreadInfoMaps.end())
	{
		LeaveCriticalSection(&this->WdbgLock);
		return FALSE;
	}
	if (iter->second->devent.dwDebugEventCode == 0) {
		LeaveCriticalSection(&this->WdbgLock);
		return FALSE;
	}
	iter->second->stepflag = StepReasonUserSingleStep;
	POneInstructionRecord bptr;

	for (auto it = this->CodeStruct.Blist.begin(); it != this->CodeStruct.Blist.end();)
	{

		bptr = it->second;
		if (bptr->OnlyOver == TRUE)
		{
			WritePhysicalMem(bptr->InstructionBuffer, bptr->InstructionLen, bptr->InstructionAddr);
			FlushInstructionCache(this->ProcessHandle, (LPCVOID)bptr->InstructionAddr, bptr->InstructionLen);
			DWORD64 StartAddr = bptr->InstructionAddr & (~0XFFF);
			this->CodeStruct.Pagelist.find(StartAddr)->second->CodeCounts--;
			free(bptr);
			it = this->CodeStruct.Blist.erase(it);
		}
		else
		{
			if (bptr->enable == TRUE && bptr->dirty == FALSE &&bptr->InstructionAddr==iter->second->ThreadContext.Rip)
			{
				WritePhysicalMem(bptr->InstructionBuffer, bptr->InstructionLen, bptr->InstructionAddr);
				FlushInstructionCache(this->ProcessHandle, (LPCVOID)bptr->InstructionAddr, bptr->InstructionLen);
				bptr->dirty = TRUE;
			}
			++it;
		}
	}
	BOOL ok = this->ContinueThreadLocked(Tid);
	LeaveCriticalSection(&this->WdbgLock);
	return ok;

}