
#include "WdbgDll.hpp"


WDebugerObject::WDebugerObject(HANDLE TargetPid)
{
	this->MainThreadid = NULL;
	this->ProcessHandle = NULL;
	this->dllhead = NULL;
	this->islisten = FALSE;
	this->TargetPid = TargetPid;
	this->hDevice = NULL;
	this->DebugHandle = NULL;
	this->CodeStruct.CodeLockOk = FALSE;
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
		DeleteCriticalSection(&(this->ThreadMapLock));
	}
	this->isLockOk = FALSE;
	if (this->CodeStruct.CodeLockOk) {
		DeleteCriticalSection(&(this->CodeStruct.CodeLock));
	}
	this->CodeStruct.CodeLockOk = FALSE;
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
	EnterCriticalSection(&(this->ThreadMapLock));
	for (auto it = this->ThreadInfoMaps.begin(); it != this->ThreadInfoMaps.end();it++) {
		if (index>MaxIndex)
		{
			SetLastError(ERROR_DS_USER_BUFFER_TO_SMALL);
			result = FALSE;
		}
		Tidbuffer[index] = it->first;
		index++;
	}
	LeaveCriticalSection(&(this->ThreadMapLock));
	return result;
}

BOOL WDebugerObject::ContinueThread(HANDLE Tid)
{
	
	BOOL result;
	EnterCriticalSection(&(this->ThreadMapLock));
	auto it = this->ThreadInfoMaps.find(Tid);
	if (it==this->ThreadInfoMaps.end() ||it->second->devent.dwDebugEventCode==0) {
		LeaveCriticalSection(&(this->ThreadMapLock));
		return FALSE;
	}
	result = ContinueThreadC(this->DebugHandle,this->TargetPid,Tid);
	if(result){	
		RtlZeroMemory(&(ThreadInfoMaps[Tid]->devent),sizeof(DEBUG_EVENT));
	}
	LeaveCriticalSection(&(this->ThreadMapLock));
	return result;
}

BOOL WDebugerObject::SetCodeStructCurrentLookingInstructions(DWORD64 VirtualAddress)
{
	PageInfor* SavedCurrentPagePtr = NULL;
	EnterCriticalSection(&this->CodeStruct.CodeLock);
	auto itSaved = this->CodeStruct.Pagelist.find(
		this->CodeStruct.CurrentLookingPageStartAddress
	);
	if (itSaved != this->CodeStruct.Pagelist.end()) {
		SavedCurrentPagePtr = itSaved->second;
		if (SavedCurrentPagePtr==NULL)
		{
			LeaveCriticalSection(&(this->CodeStruct.CodeLock));
			OutputDebugStringW(L"illegal second,ouccr in SetCodeStructCurrentLookingInstructions");
			return FALSE;
		}
		if (SavedCurrentPagePtr->CurrentVirtualAddress==VirtualAddress) {
			LeaveCriticalSection(&(this->CodeStruct.CodeLock));
			return TRUE;
		}
	
	}
	DWORD64 PageStartAddress = VirtualAddress & (~0xFFF);

	auto it = this->CodeStruct.Pagelist.find(PageStartAddress);
	if (it == this->CodeStruct.Pagelist.end() || it->second == NULL) {
		if(!this->CahchePage(PageStartAddress)) {
			LeaveCriticalSection(&this->CodeStruct.CodeLock);
			return FALSE;
		}
		auto temp = this->CodeStruct.Pagelist.find(PageStartAddress);
		if (temp==this->CodeStruct.Pagelist.end()) {
			LeaveCriticalSection(&this->CodeStruct.CodeLock);
			return FALSE;
		}

		PageInfor* NewPageInfor = temp->second;
		if (NewPageInfor==NULL) {
			LeaveCriticalSection(&(this->CodeStruct.CodeLock));
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
		LeaveCriticalSection(&this->CodeStruct.CodeLock);
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
		LeaveCriticalSection(&this->CodeStruct.CodeLock);
		return FALSE;
	}

SUCCESS:
	if ((SavedCurrentPagePtr!=NULL)&&(SavedCurrentPagePtr->StartVirtualAddr!=PageStartAddress)) {
		if (SavedCurrentPagePtr->BreakPointCounts==0) {
			this->CodeStruct.Pagelist.erase(SavedCurrentPagePtr->StartVirtualAddr);
			this->FreePage(SavedCurrentPagePtr);
		}
	}
	LeaveCriticalSection(&this->CodeStruct.CodeLock);
	return TRUE;
}







DWORD64 WDebugerObject::GetTargetCode(POneInstructionRecord InstructionRecordBufferPtr, SIZE_T MaxInstructions)
{
	OutputDebugStringW(L"get target code start");
	SIZE_T index = 0;
	
	OutputDebugStringW(L"get tempageptr map");
	EnterCriticalSection(&this->CodeStruct.CodeLock);
	auto it = this->CodeStruct.Pagelist.find(this->CodeStruct.CurrentLookingPageStartAddress);
	if (it==this->CodeStruct.Pagelist.end())
	{
		
		LeaveCriticalSection(&this->CodeStruct.CodeLock);
		return 0;
	}
	if (it->second==NULL) {
		OutputDebugStringW(L"illegal second,ouccr in GetTargetCode");
		LeaveCriticalSection(&this->CodeStruct.CodeLock);
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
	LeaveCriticalSection(&this->CodeStruct.CodeLock);
	return index;
}

BOOL WDebugerObject::SetBreakPointUp(DWORD64 InstructionAddr)
{
	PageInfor* TargetPage = NULL;
	DWORD64 StartAddress = InstructionAddr & (~0xfff);
	EnterCriticalSection(&this->CodeStruct.CodeLock);
	auto Saved = this->CodeStruct.Pagelist.find(StartAddress);
	if (Saved==this->CodeStruct.Pagelist.end()||Saved->second==NULL)
	{
		if (!this->CahchePage(StartAddress)) {
			LeaveCriticalSection(&this->CodeStruct.CodeLock);
			return FALSE;
		}
	}
	UCHAR WriteBuffer[24];
	memset(WriteBuffer,0x90,24);
	WriteBuffer[0] = 0xCC;
	auto finder = this->CodeStruct.Blist.find(InstructionAddr);
	if (finder!=this->CodeStruct.Blist.end())
	{
		POneInstructionRecord InsPtr;
		InsPtr = finder->second;
		if (InsPtr!=NULL)
		{
			if (InsPtr->enable==FALSE){
				if (this->WritePhysicalMem(WriteBuffer, InsPtr->InstructionLen, InstructionAddr)) {
					InsPtr->enable = TRUE;
					LeaveCriticalSection(&this->CodeStruct.CodeLock);
					return TRUE;
				}
				else
				{
					LeaveCriticalSection(&this->CodeStruct.CodeLock);
					return FALSE;
				}
			}
			else {
				LeaveCriticalSection(&this->CodeStruct.CodeLock);
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
				LeaveCriticalSection(&this->CodeStruct.CodeLock);
				return FALSE;
			}
			ZeroMemory(InstructionPtr, sizeof(OneInstructionRecord));
			InstructionPtr->InnerPageIndex = i;
			InstructionPtr->InstructionAddr = InstructionAddr;
			InstructionPtr->InstructionLen = tempPtr->size;
			memcpy(InstructionPtr->InstructionBuffer,tempPtr->bytes,InstructionPtr->InstructionLen);
			_snprintf_s(
				(char*)InstructionPtr->InstructionString,
				192,
				_TRUNCATE,
				"%s %s",
				tempPtr->mnemonic,
				tempPtr->op_str
			);
			if(this->WritePhysicalMem(WriteBuffer,InstructionPtr->InstructionLen,InstructionAddr)){
				InstructionPtr->enable = TRUE;
				this->CodeStruct.Blist[InstructionAddr] = InstructionPtr;
				this->CodeStruct.Pagelist[StartAddress]->BreakPointCounts++;
				LeaveCriticalSection(&this->CodeStruct.CodeLock);
				return TRUE;
			}
			else
			{
				free(InstructionPtr);
				LeaveCriticalSection(&this->CodeStruct.CodeLock);
				return FALSE;
			}

		}
	}
	LeaveCriticalSection(&this->CodeStruct.CodeLock);
}

BOOL WDebugerObject::SetBreakPointDown(DWORD64 InstructionAddr)
{
	EnterCriticalSection(&this->CodeStruct.CodeLock);
	auto it = this->CodeStruct.Blist.find(InstructionAddr);
	if (it==this->CodeStruct.Blist.end()) {
		LeaveCriticalSection(&this->CodeStruct.CodeLock);
		return TRUE;
	}
	else
	{
		POneInstructionRecord ptr = it->second;
		if (ptr==NULL) {
			this->CodeStruct.Blist.erase(InstructionAddr);
			LeaveCriticalSection(&this->CodeStruct.CodeLock);
			return TRUE;
		}
		if (this->WritePhysicalMem(ptr->InstructionBuffer,ptr->InstructionLen,ptr->InstructionAddr)) {
			ptr->enable = FALSE;
			LeaveCriticalSection(&this->CodeStruct.CodeLock);
			return TRUE;
		}
		else
		{
			LeaveCriticalSection(&this->CodeStruct.CodeLock);
			return FALSE;
		}

	}
	LeaveCriticalSection(&this->CodeStruct.CodeLock);
	return 0;
}

BOOL WDebugerObject::DeleteBreakPoint(DWORD64 InstructionAddr)
{
	DWORD64 StartAddr=InstructionAddr&(~0xfff);
	EnterCriticalSection(&this->CodeStruct.CodeLock);
	auto it=this->CodeStruct.Blist.find(InstructionAddr);
	if (it==this->CodeStruct.Blist.end()) {
		LeaveCriticalSection(&this->CodeStruct.CodeLock);
		return TRUE;
	}
	else
	{
		POneInstructionRecord Ptr = it->second;
		if(Ptr==NULL){
			this->CodeStruct.Blist.erase(InstructionAddr);
			LeaveCriticalSection(&this->CodeStruct.CodeLock);
			return TRUE;
		}
		BOOL flag=FALSE;
		if (Ptr->enable==TRUE) {
			flag=WritePhysicalMem(Ptr->InstructionBuffer,Ptr->InstructionLen,Ptr->InstructionAddr);
		}
		if (flag) {
			free(Ptr);
			this->CodeStruct.Blist.erase(InstructionAddr);
			if (this->CodeStruct.Pagelist[StartAddr] != NULL) {
				this->CodeStruct.Pagelist[StartAddr]->BreakPointCounts--;
			}
			LeaveCriticalSection(&this->CodeStruct.CodeLock);
			return TRUE;
		}
		LeaveCriticalSection(&this->CodeStruct.CodeLock);
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
	EnterCriticalSection(&(this->ThreadMapLock));

	if (ThreadInfoMaps.find(Tid)!=ThreadInfoMaps.end())
	{
		memcpy((UCHAR*)outinfo,(UCHAR*)(ThreadInfoMaps[Tid]),sizeof(ThreadInfo));
		result = TRUE;
	}
	LeaveCriticalSection(&(this->ThreadMapLock));
	return result;
}
BOOL WDebugerObject::EnumDllInfo(PDLLRecordNode* head)
{
	if (!head) return FALSE;
	*head = NULL;
	EnterCriticalSection(&this->ThreadMapLock);
	PDLLRecordNode cur = this->dllhead;
	PDLLRecordNode* insertPos = head;
	while (cur != NULL)
	{
		PDLLRecordNode newNode = (PDLLRecordNode)malloc(sizeof(DLLRecordNode));
		if (!newNode)
		{
			LeaveCriticalSection(&this->ThreadMapLock);
			return FALSE;
		}
		memcpy(newNode, cur, sizeof(DLLRecordNode));
		newNode->next = NULL;
		*insertPos = newNode;
		insertPos = &newNode->next;
		cur = cur->next;
	}
	LeaveCriticalSection(&this->ThreadMapLock);
	return TRUE;
}

BOOL WDebugerObject::SuspendTargetThread(HANDLE Tid)
{
	BOOL result = FALSE;
	HANDLE threadhandle = NULL;
	EnterCriticalSection(&(this->ThreadMapLock));
	if(ThreadInfoMaps.find(Tid)!=ThreadInfoMaps.end()){
		threadhandle = ThreadInfoMaps[Tid]->ThreadHandle;
		result = SuspendThread(threadhandle)>=0?TRUE:FALSE;
	}
	LeaveCriticalSection(&(this->ThreadMapLock));
	return result;
}

BOOL WDebugerObject::ResumeTargetThread(HANDLE Tid)
{
	BOOL result = FALSE;
	HANDLE threadhandle = NULL;
	EnterCriticalSection(&(this->ThreadMapLock));
	if (ThreadInfoMaps.find(Tid) != ThreadInfoMaps.end()) {
		threadhandle = ThreadInfoMaps[Tid]->ThreadHandle;
		result = ResumeThread(threadhandle)>=0?TRUE:FALSE;
	}
	LeaveCriticalSection(&(this->ThreadMapLock));
	return result;
}



VOID WDebugerObject::GetProcessInfo(CREATE_PROCESS_DEBUG_INFO* outinfo)
{

	EnterCriticalSection(&(this->ThreadMapLock));
	memcpy(outinfo,&(this->ProcessInfo),sizeof(CREATE_PROCESS_DEBUG_INFO));
	LeaveCriticalSection(&(this->ThreadMapLock));
}

BOOL WDebugerObject::ChangeContext(HANDLE Tid, CONTEXT* tcontext)
{
	EnterCriticalSection(&(this->ThreadMapLock));
	BOOL result=FALSE;
	if (ThreadInfoMaps.find(Tid) != ThreadInfoMaps.end())
	{
		HANDLE temphandle = ThreadInfoMaps[Tid]->ThreadHandle;
		if (SetThreadContext(temphandle,tcontext)) {
			memcpy((UCHAR*)&(ThreadInfoMaps[Tid]->ThreadContext),(UCHAR*)tcontext,sizeof(CONTEXT));
			result = TRUE;
		}
	}
	LeaveCriticalSection(&(this->ThreadMapLock));
	return result;
}

BOOL WDebugerObject::CreateListenThread()
{
	EnterCriticalSection(&(this->ThreadMapLock));
	if (this->islisten == FALSE) {
		this->islisten = TRUE;
		this->listen_thread = std::thread(&WDebugerObject::ListenThread,this);
	}
	else
	{
		LeaveCriticalSection(&(this->ThreadMapLock));
		return FALSE;
	}
	LeaveCriticalSection(&(this->ThreadMapLock));
	return TRUE;
}

BOOL WDebugerObject::init()
{
	
	this->isLockOk=InitializeCriticalSectionAndSpinCount(&(this->ThreadMapLock), 4000);
	if (this->isLockOk==FALSE)
	{
		return FALSE;
	}
	this->CodeStruct.CodeLockOk = InitializeCriticalSectionAndSpinCount(&(this->CodeStruct.CodeLock), 4000);
	if (this->CodeStruct.CodeLockOk==FALSE) {
		return FALSE;
	}
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
