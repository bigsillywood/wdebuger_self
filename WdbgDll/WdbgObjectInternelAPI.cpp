#include"WdbgDll.hpp"

UCHAR BreakPointerBuffer1[24] = { 0xcc,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90 };
BOOL FindInsInPageLocked(PageInfor *page,POneInstructionRecord InsPtr,DWORD64 InsAddr) {
	cs_insn* StartIns = page->PageCodes;
	SIZE_T Index=0;
	while (Index<page->CodeCounts)
	{
		if (StartIns[Index].address==InsAddr) {
			InsPtr->id = StartIns[Index].id;
			InsPtr->InnerPageIndex = Index;
			InsPtr->InstructionAddr = InsAddr;
			InsPtr->InstructionLen = StartIns[Index].size;
			memcpy(InsPtr->InstructionBuffer,StartIns[Index].bytes, InsPtr->InstructionLen);
			_snprintf_s(
				(char*)InsPtr->InstructionString,
				192,
				_TRUNCATE,
				"%s %s",
				StartIns[Index].mnemonic,
				StartIns[Index].op_str
			);
			return TRUE;
		}
		Index++;
	}
	return FALSE;
}
BOOL WDebugerObject::CombineThread()
{

	return CombineThreadC(this->DebugHandle);
}



VOID WDebugerObject::ADDTHREAD(DEBUG_EVENT* CreateThreadEvent)
{
	ThreadInfo* NewInfo = (ThreadInfo*)malloc(sizeof(ThreadInfo));
	RtlCopyMemory((UCHAR*)(&(NewInfo->devent)), (UCHAR*)CreateThreadEvent, sizeof(DEBUG_EVENT));



	NewInfo->lpStartAddress = NewInfo->devent.u.CreateThread.lpStartAddress;
	NewInfo->lpThreadLocalBase = NewInfo->devent.u.CreateThread.lpThreadLocalBase;
	NewInfo->Tid = (HANDLE)NewInfo->devent.dwThreadId;

	NewInfo->ThreadHandle = UserOpenThread(this->TargetPid, NewInfo->Tid, this->hDevice);
	NewInfo->stepflag = StepReasonNone;
	NewInfo->ThreadContext.ContextFlags = CONTEXT_CONTROL;
	if (GetThreadContext(NewInfo->ThreadHandle, &(NewInfo->ThreadContext))) {
		NewInfo->CurLookingRSP=NewInfo->ThreadContext.Rsp;
		NewInfo->CurLookingRip = NewInfo->ThreadContext.Rip;
	}
	else
	{
		OutputErrorCode(GetLastError());
		RtlZeroMemory(&(NewInfo->ThreadContext), sizeof(CONTEXT));
		NewInfo->CurLookingRSP = (DWORD64)NewInfo->lpThreadLocalBase;
		NewInfo->CurLookingRip = (DWORD64)NewInfo->lpStartAddress;
	}
	//NewInfo->CurLookingRip = (DWORD64)NewInfo->lpStartAddress;
	

	CloseHandle(NewInfo->devent.u.CreateThread.hThread);
	//EnterCriticalSection(&(this->ThreadMapLock));
	this->ThreadInfoMaps[NewInfo->Tid] = NewInfo;
	//LeaveCriticalSection(&(this->ThreadMapLock));
}

VOID WDebugerObject::ADDPROCESS(DEBUG_EVENT* CreateProcessEvent)
{
	ThreadInfo* NewInfo = (ThreadInfo*)malloc(sizeof(ThreadInfo));
	RtlCopyMemory((UCHAR*)(&(NewInfo->devent)), (UCHAR*)CreateProcessEvent, sizeof(DEBUG_EVENT));




	NewInfo->lpStartAddress = (LPTHREAD_START_ROUTINE)DumpEntryAddress((DWORD64)(CreateProcessEvent->u.CreateProcessInfo.lpBaseOfImage));
	NewInfo->lpThreadLocalBase = NewInfo->devent.u.CreateProcessInfo.lpThreadLocalBase;

	NewInfo->Tid = (HANDLE)NewInfo->devent.dwThreadId;

	NewInfo->ThreadHandle = UserOpenThread(this->TargetPid, NewInfo->Tid, this->hDevice);
	NewInfo->stepflag = StepReasonNone;
	NewInfo->ThreadContext.ContextFlags = CONTEXT_CONTROL;
	CloseHandle(NewInfo->devent.u.CreateProcessInfo.hProcess);
	CloseHandle(NewInfo->devent.u.CreateProcessInfo.hThread);


	if (GetThreadContext(NewInfo->ThreadHandle, &(NewInfo->ThreadContext))) {
		NewInfo->CurLookingRip = NewInfo->ThreadContext.Rip;
		NewInfo->CurLookingRSP = NewInfo->ThreadContext.Rsp;
	}
	else
	{
		NewInfo->CurLookingRip = (DWORD64)NewInfo->lpStartAddress;
		NewInfo->CurLookingRSP = (DWORD64)NewInfo->lpThreadLocalBase;
	}

	
	//EnterCriticalSection(&(this->ThreadMapLock));
	this->MainThreadid = (HANDLE)(CreateProcessEvent->dwThreadId);
	this->ProcessInfo = NewInfo->devent.u.CreateProcessInfo;
	this->ProcessInfo.lpStartAddress = NewInfo->lpStartAddress;
	this->ProcessInfo.hProcess = UserOpenProcess(this->TargetPid, this->hDevice);
	this->ThreadInfoMaps[NewInfo->Tid] = NewInfo;
	//LeaveCriticalSection(&(this->ThreadMapLock));

}



VOID WDebugerObject::DELETETHREAD(HANDLE Tid)
{
	//EnterCriticalSection(&(this->ThreadMapLock));
	ThreadInfo* temp = this->ThreadInfoMaps[Tid];
	CloseHandle(temp->ThreadHandle);
	free(temp);
	ThreadInfoMaps.erase(Tid);
	ContinueThreadC(this->DebugHandle, this->TargetPid, Tid);
	//LeaveCriticalSection(&(this->ThreadMapLock));
}

VOID WDebugerObject::DELETEPROCESS(HANDLE MainTid)
{
	//EnterCriticalSection(&(this->ThreadMapLock));
	ThreadInfo* temp;
	for (auto it = this->ThreadInfoMaps.begin(); it != this->ThreadInfoMaps.end(); it++)
	{
		CloseHandle(it->second->ThreadHandle);
		temp = it->second;
		free(temp);
	}
	this->ThreadInfoMaps.erase(this->ThreadInfoMaps.begin(), this->ThreadInfoMaps.end());
	CloseHandle(this->ProcessInfo.hFile);
	CloseHandle(this->ProcessHandle);
	ContinueThreadC(this->DebugHandle, this->TargetPid, MainTid);
	//ZeroMemory(&(this->ProcessInfo),sizeof(CREATE_PROCESS_DEBUG_INFO));
	//LeaveCriticalSection(&(this->ThreadMapLock));
}



VOID WDebugerObject::LOADDLL(DEBUG_EVENT* LoadDllEvent)
{
	PDLLRecordNode NewNode = (PDLLRecordNode)malloc(sizeof(DLLRecordNode));
	if (NewNode==nullptr)
	{
		return;
	}
	NewNode->dllinfo = LoadDllEvent->u.LoadDll;
	NewNode->LoadingThread = (HANDLE)(LoadDllEvent->dwThreadId);

	//EnterCriticalSection(&(this->ThreadMapLock));
	PThreadInfo threadinfo = this->ThreadInfoMaps[(HANDLE)LoadDllEvent->dwThreadId];
	threadinfo->devent = *LoadDllEvent;

	if (GetThreadContext(threadinfo->ThreadHandle, &(threadinfo->ThreadContext))) {

	}
	else
	{
		OutputErrorCode(GetLastError());
		RtlZeroMemory(&(threadinfo->ThreadContext), sizeof(CONTEXT));
	}

	threadinfo->CurLookingRip = threadinfo->ThreadContext.Rip;
	threadinfo->CurLookingRSP = threadinfo->ThreadContext.Rsp;

	if (this->dllhead == NULL) {
		NewNode->next = NULL;
		this->dllhead = NewNode;
	}
	else
	{
		NewNode->next = this->dllhead;
		this->dllhead = NewNode;
	}
	WCHAR buffer[256] = { 0 };
	DWORD PathLen=GetFinalPathNameByHandleW(NewNode->dllinfo.hFile,buffer,256, FILE_NAME_NORMALIZED| VOLUME_NAME_DOS);
	if (PathLen<256)
	{
		//SUCCEED
		DWORD LeftIndex = PathLen-1;
		while (buffer[LeftIndex]!=L'\\'&&LeftIndex>=0)
		{
			LeftIndex--;
		}
		LeftIndex = LeftIndex + 1;

		NewNode->NameLen = PathLen - LeftIndex;
		NewNode->NameBufferPtr = (WCHAR*)malloc(sizeof(WCHAR)*(NewNode->NameLen+1));
		if (NewNode->NameBufferPtr == NULL)
		{

			NewNode->NameLen = 0;
		}
		else {
			memcpy(NewNode->NameBufferPtr, buffer+LeftIndex, sizeof(WCHAR) * (NewNode->NameLen + 1));
			NewNode->NameBufferPtr[NewNode->NameLen] = 0x00;
		}
	}
	else
	{
		NewNode->NameLen = 0;
	}
	//LeaveCriticalSection(&(this->ThreadMapLock));
}


VOID WDebugerObject::UNLOADDLL(DEBUG_EVENT* UnloadDllEvent)
{
	LPVOID hbase = UnloadDllEvent->u.UnloadDll.lpBaseOfDll;
	PDLLRecordNode cur = this->dllhead;
	PDLLRecordNode pre = NULL;
	//EnterCriticalSection(&(this->ThreadMapLock));
	while (cur != NULL) {
		if (hbase == cur->dllinfo.lpBaseOfDll) {
			if (pre == NULL)
			{
				this->dllhead = this->dllhead->next;
			}
			else
			{
				pre->next = cur->next;
			}
			CloseHandle(cur->dllinfo.hFile);
			free(cur);
			break;
		}
		else
		{
			pre = cur;
			cur = cur->next;
		}
	}
	//LeaveCriticalSection(&(this->ThreadMapLock));
}



VOID WDebugerObject::EXCEPTIONRECORD(DEBUG_EVENT* ExceptionEvent)
{
	//EnterCriticalSection(&(this->ThreadMapLock));
	PThreadInfo infoptr = this->ThreadInfoMaps[(HANDLE)ExceptionEvent->dwThreadId];
	infoptr->devent = (*ExceptionEvent);
	infoptr->CurLookingRip = (DWORD64)(infoptr->devent.u.Exception.ExceptionRecord.ExceptionAddress);
	//char buf[256];
	
	if (ExceptionEvent->u.Exception.ExceptionRecord.ExceptionCode==EXCEPTION_SINGLE_STEP&&infoptr->stepflag==StepReasonBreakpointRecovery) {
		infoptr->ThreadContext.ContextFlags = CONTEXT_CONTROL;
	}
	else
	{
		infoptr->ThreadContext.ContextFlags = CONTEXT_ALL;
	}
	if (!GetThreadContext(infoptr->ThreadHandle, &(infoptr)->ThreadContext)) {
	}
	else
	{
	}



	if (ExceptionEvent->u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT)
	{
		infoptr->ThreadContext.Rip -= 1;
	}
	
	infoptr->CurLookingRSP = infoptr->ThreadContext.Rsp;
	//LeaveCriticalSection(&(this->ThreadMapLock));
}


VOID WDebugerObject::ListenThread()
{

	this->CombineThread();
	DEBUG_EVENT _devent;
	char buf[256];
	while (this->islisten) {
		Sleep(LISTEN_YIELD_MS);
		EnterCriticalSection(&this->WdbgLock);
		BOOL ok = WaitForDebugEventSelf(&_devent, LISTEN_WAIT_TIMEOUT_MS);
		if (!ok) {
			LeaveCriticalSection(&this->WdbgLock);
			continue;
		}
		HANDLE threadid = (HANDLE)_devent.dwThreadId;
		
		switch (_devent.dwDebugEventCode)
		{
		case CREATE_PROCESS_DEBUG_EVENT:
		{

			sprintf_s(buf, sizeof(buf),
				"Detect process creation: processId=%u, mainThreadId=%u\n",
				_devent.dwProcessId,
				_devent.dwThreadId);

			OutputDebugStringA(buf);
			ADDPROCESS(&_devent);
			this->ContinueThreadLocked(threadid);
			break;
		}
		case CREATE_THREAD_DEBUG_EVENT:
		{
			sprintf_s(buf, sizeof(buf),
				"detect a thread creation,threadid:%d", _devent.dwThreadId);

			OutputDebugStringA(buf);
			ADDTHREAD(&_devent);
			this->ContinueThreadLocked(threadid);
			break;
		}
		case EXIT_PROCESS_DEBUG_EVENT:
		{
			sprintf_s(buf, sizeof(buf),
				"Detect process exit: processId=%u, mainThreadId=%u\n",
				_devent.dwProcessId,
				_devent.dwThreadId);
			OutputDebugStringA(buf);
			DELETEPROCESS((HANDLE)_devent.dwThreadId);
			this->CLEANALLDLL();
			this->ContinueThreadLocked(threadid);
			this->islisten = FALSE;
			break;
		}
		case EXIT_THREAD_DEBUG_EVENT:
		{
			sprintf_s(buf, sizeof(buf),
				"detect a thread exit,threadid:%d", _devent.dwThreadId);
			OutputDebugStringA(buf);
			DELETETHREAD((HANDLE)(_devent.dwThreadId));
			this->ContinueThreadLocked(threadid);
			break;
		}
		case EXCEPTION_DEBUG_EVENT:
		{
			sprintf_s(buf, sizeof(buf),
				"detect a exception,threadid:%d,sub code0x%X", _devent.dwThreadId,_devent.u.Exception.ExceptionRecord.ExceptionCode);
			OutputDebugStringA(buf);
			EXCEPTIONRECORD(&_devent);
			break;
		}
		case LOAD_DLL_DEBUG_EVENT:
		{
			sprintf_s(buf, sizeof(buf),
				"detect a DLL loading,threadid:%d", _devent.dwThreadId);
			OutputDebugStringA(buf);
			LOADDLL(&_devent);
			this->ContinueThreadLocked(threadid);
			break;
		}
		case UNLOAD_DLL_DEBUG_EVENT:
		{
			UNLOADDLL(&_devent);
			this->ContinueThreadLocked(threadid);
			break;
		}
		case RIP_EVENT:
		{
			this->ContinueThreadLocked(threadid);
			break;
		}
		default:
			break;
		}
		LeaveCriticalSection(&this->WdbgLock);
	}
}

BOOL WDebugerObject::CahchePage(DWORD64 PageStartAddress)
{

	UCHAR ReadingBuffer[4096];
	if (!this->ReadPhysicalMem(ReadingBuffer, 4096, PageStartAddress)) {
		return FALSE;
	}
	PageInfor* NewPageInfor = (PageInfor*)malloc(sizeof(PageInfor));
	if (NewPageInfor == NULL)
	{
		return FALSE;
	}
	ZeroMemory(NewPageInfor, sizeof(PageInfor));

	NewPageInfor->StartVirtualAddr = PageStartAddress;
	BOOL isok=this->CodeStruct.CapstoneAPIhandle.TranslationBuffer(ReadingBuffer,
		4096,
		PageStartAddress,
		&(NewPageInfor->PageCodes),
		&NewPageInfor->CodeCounts);
	if (!isok) {
		free(NewPageInfor);
		return FALSE;
	}
	this->CodeStruct.Pagelist[PageStartAddress] = NewPageInfor;
	return TRUE;
}

VOID WDebugerObject::FreePage(PageInfor* Page)
{
	cs_free(Page->PageCodes,Page->CodeCounts);
	free(Page);
}

BOOL WDebugerObject::ContinueThreadLocked(HANDLE Tid)
{
	
	DEBUG_EVENT _devent;
	char buf[256];
	auto iter = this->ThreadInfoMaps.find(Tid);
	if (iter==ThreadInfoMaps.end()||iter->second->devent.dwDebugEventCode==0) {
		return FALSE;
	}
	PThreadInfo TempThreadInfo = iter->second;
	DWORD oContextflag = TempThreadInfo->ThreadContext.ContextFlags;
	THREAD_STEP_REASON oreason = TempThreadInfo->stepflag;
	BOOL result = FALSE;
	//breakpoint recovery
	if (TempThreadInfo->devent.dwDebugEventCode==EXCEPTION_DEBUG_EVENT
		&& TempThreadInfo->devent.u.Exception.ExceptionRecord.ExceptionCode==EXCEPTION_BREAKPOINT
		&&TempThreadInfo->stepflag==StepReasonNone)
	{
		auto iter2 = this->CodeStruct.Blist.find((DWORD64)TempThreadInfo->devent.u.Exception.ExceptionRecord.ExceptionAddress);
		if (iter2!=this->CodeStruct.Blist.end()&&(iter2->second->enable==TRUE||iter2->second->OnlyOver==TRUE))
		{
			BOOL cflag=CombineThreadC(this->DebugHandle);
			POneInstructionRecord BreakPointPtr = iter2->second;
			DWORD64 BreakPointAddr = BreakPointPtr->InstructionAddr;
			UINT8 BreakPointInstuctionLen = BreakPointPtr->InstructionLen;
			UCHAR BreakPointInstruction[24] = { 0x90 };
			memcpy(BreakPointInstruction, BreakPointPtr->InstructionBuffer, BreakPointPtr->InstructionLen);


			TempThreadInfo->ThreadContext.ContextFlags = CONTEXT_CONTROL;
			//TempThreadInfo->ThreadContext.Rip = TempThreadInfo->ThreadContext.Rip - 1;
			TempThreadInfo->ThreadContext.EFlags = TempThreadInfo->ThreadContext.EFlags |= 0x100;

			if (!SetThreadContext(TempThreadInfo->ThreadHandle, &TempThreadInfo->ThreadContext)) {
				goto exit;
			}
			if (!this->WritePhysicalMem(BreakPointInstruction, BreakPointInstuctionLen, BreakPointAddr)) {
				goto exit;
			}
			if (!FlushInstructionCache(this->ProcessHandle, (LPCVOID)BreakPointAddr, BreakPointInstuctionLen)) {
				goto exit;
			}
			result = ContinueThreadC(this->DebugHandle, this->TargetPid, Tid);
			if (result) {
				RtlZeroMemory(&(ThreadInfoMaps[Tid]->devent), sizeof(DEBUG_EVENT));
			}
			TempThreadInfo->stepflag = StepReasonBreakpointRecovery;
			sprintf_s(buf, sizeof(buf),
				"start wait single ");
			
			OutputDebugStringA(buf);

			while (TRUE)
			{
				BOOL ok = WaitForDebugEventSelf(&_devent,LISTEN_WAIT_TIMEOUT_MS);
				if (!ok) {
					continue;
				}
				sprintf_s(buf, sizeof(buf),
					"get an event ");
				OutputDebugStringA(buf);
				HANDLE threadid = (HANDLE)_devent.dwThreadId;
				switch (_devent.dwDebugEventCode)
				{
				case CREATE_PROCESS_DEBUG_EVENT:
				{

					sprintf_s(buf, sizeof(buf),
						"Detect process creation: processId=%u, mainThreadId=%u\n",
						_devent.dwProcessId,
						_devent.dwThreadId);

					OutputDebugStringA(buf);
					ADDPROCESS(&_devent);
					this->ContinueThreadLocked(threadid);
					break;
				}
				case CREATE_THREAD_DEBUG_EVENT:
				{
					sprintf_s(buf, sizeof(buf),
						"detect a thread creation,threadid:%d", _devent.dwThreadId);

					OutputDebugStringA(buf);
					ADDTHREAD(&_devent);
					this->ContinueThreadLocked(threadid);

					break;
				}
				case EXIT_PROCESS_DEBUG_EVENT:
				{
					sprintf_s(buf, sizeof(buf),
						"Detect process exit: processId=%u, mainThreadId=%u\n",
						_devent.dwProcessId,
						_devent.dwThreadId);
					OutputDebugStringA(buf);
					DELETEPROCESS((HANDLE)_devent.dwThreadId);
					this->CLEANALLDLL();
					this->ContinueThreadLocked(threadid);
					this->islisten = FALSE;
					return TRUE;
					break;
				}
				case EXIT_THREAD_DEBUG_EVENT:
				{
					sprintf_s(buf, sizeof(buf),
						"detect a thread exit,threadid:%d", _devent.dwThreadId);
					OutputDebugStringA(buf);
					DELETETHREAD((HANDLE)(_devent.dwThreadId));
					this->ContinueThreadLocked(threadid);
					if ((HANDLE)_devent.dwThreadId==Tid)
					{
						return TRUE;
					}
					break;
				}
				case EXCEPTION_DEBUG_EVENT:
				{
					sprintf_s(buf, sizeof(buf),
						"detect a exception,threadid:%d,sub code0x%X", _devent.dwThreadId, _devent.u.Exception.ExceptionRecord.ExceptionCode);
					OutputDebugStringA(buf);
					if ((HANDLE)_devent.dwThreadId==Tid)
					{
						if (_devent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP)
						{
							TempThreadInfo->ThreadContext.ContextFlags = CONTEXT_CONTROL;
							GetThreadContext(TempThreadInfo->ThreadHandle, &TempThreadInfo->ThreadContext);
							TempThreadInfo->ThreadContext.EFlags &= (~0x100);
							BOOL flag = SetThreadContext(TempThreadInfo->ThreadHandle,&TempThreadInfo->ThreadContext);
							if (flag) {
								this->WritePhysicalMem(BreakPointerBuffer1, BreakPointInstuctionLen, BreakPointAddr);
								FlushInstructionCache(this->ProcessHandle, (LPCVOID)BreakPointAddr, BreakPointInstuctionLen);
							}
							goto exit;
						}else {
							TempThreadInfo->stepflag = oreason;
							TempThreadInfo->ThreadContext.ContextFlags = oContextflag;
							EXCEPTIONRECORD(&_devent);
							TempThreadInfo->ThreadContext.ContextFlags = CONTEXT_CONTROL;
							GetThreadContext(TempThreadInfo->ThreadHandle, &TempThreadInfo->ThreadContext);
							TempThreadInfo->ThreadContext.EFlags &= (~0x100);
							BOOL flag = SetThreadContext(TempThreadInfo->ThreadHandle, &TempThreadInfo->ThreadContext);
							if (flag) {
								this->WritePhysicalMem(BreakPointerBuffer1, BreakPointInstuctionLen, BreakPointAddr);
								FlushInstructionCache(this->ProcessHandle, (LPCVOID)BreakPointAddr, BreakPointInstuctionLen);
							}
							return TRUE;
						}
					}
					else {
						EXCEPTIONRECORD(&_devent);
					}
					break;
				}
				case LOAD_DLL_DEBUG_EVENT:
				{
					/*
					sprintf_s(buf, sizeof(buf),
						"detect a DLL loading,threadid:%d", _devent.dwThreadId);
					OutputDebugStringA(buf);
					*/
					
					LOADDLL(&_devent);
					this->ContinueThreadLocked(threadid);
					break;
				}
				case UNLOAD_DLL_DEBUG_EVENT:
				{
					UNLOADDLL(&_devent);
					this->ContinueThreadLocked(threadid);
					break;
				}
				case RIP_EVENT:
				{
					this->ContinueThreadLocked(threadid);
					break;
				}
				default:
					break;
				}
			}

		}else {
			TempThreadInfo->ThreadContext.Rip += 1;
		}
	}
	//user single step recovery
	if (TempThreadInfo->stepflag==StepReasonUserSingleStep&&TempThreadInfo->devent.dwDebugEventCode==EXCEPTION_DEBUG_EVENT)
	{
		TempThreadInfo->ThreadContext.ContextFlags = CONTEXT_CONTROL;
		TempThreadInfo->ThreadContext.EFlags |= 0x100;
		SetThreadContext(TempThreadInfo->ThreadHandle,&TempThreadInfo->ThreadContext);
		goto exit;
	}
	//user stepover 
	if (TempThreadInfo->stepflag==StepReasonUserOverStep&&TempThreadInfo->devent.dwDebugEventCode==EXCEPTION_DEBUG_EVENT)
	{
		POneInstructionRecord CurIns;
		POneInstructionRecord NextIns;
		PPageInfor PagePtr;
		DWORD64 NextInsAddr;
		DWORD64 StartAddr;
		auto iter2 = this->CodeStruct.Blist.find(TempThreadInfo->ThreadContext.Rip);
		if (iter2!=this->CodeStruct.Blist.end()) {
			CurIns = iter2->second;
			if (CurIns->id==X86_INS_CALL)
			{

				NextInsAddr = CurIns->InstructionAddr + CurIns->InstructionLen;
				if (this->CodeStruct.Blist.find(NextInsAddr)!=this->CodeStruct.Blist.end())
				{
					NextIns = this->CodeStruct.Blist.find(NextInsAddr)->second;
					goto SkipCacheNext;
				}
				StartAddr = NextInsAddr & (~0XFFF);
				auto PageIter = this->CodeStruct.Pagelist.find(StartAddr);
				if (PageIter==this->CodeStruct.Pagelist.end())
				{
					this->CahchePage(StartAddr);
				}
				PageIter = this->CodeStruct.Pagelist.find(StartAddr);
				if (PageIter==this->CodeStruct.Pagelist.end())
				{
					goto exit;
				}
				PagePtr = PageIter->second;
				NextIns = (POneInstructionRecord)malloc(sizeof(OneInstructionRecord));
				if (NextIns==NULL)
				{
					goto exit;
				}
				if (!FindInsInPageLocked(PagePtr,NextIns,NextInsAddr))
				{
					goto exit;
				}
			}
			else
			{
				TempThreadInfo->ThreadContext.ContextFlags = CONTEXT_CONTROL;
				TempThreadInfo->ThreadContext.EFlags |= 0x100;
				SetThreadContext(TempThreadInfo->ThreadHandle, &TempThreadInfo->ThreadContext);
				goto exit;
			}
		}
		else
		{
			StartAddr = TempThreadInfo->ThreadContext.Rip&(~0xFFF);
			auto pageiter = this->CodeStruct.Pagelist.find(StartAddr);
			if (pageiter==this->CodeStruct.Pagelist.end())
			{
				this->CahchePage(StartAddr);
			}
			pageiter = this->CodeStruct.Pagelist.find(StartAddr);
			if (pageiter==this->CodeStruct.Pagelist.end())
			{
				goto exit;
			}
			PagePtr = this->CodeStruct.Pagelist.find(StartAddr)->second;
			CurIns = (POneInstructionRecord)malloc(sizeof(OneInstructionRecord));
			
			if (!FindInsInPageLocked(PagePtr,CurIns,TempThreadInfo->ThreadContext.Rip))
			{
				goto exit;
			}
			if (CurIns == NULL)
			{
				goto exit;
			}
			if (CurIns->id==X86_INS_CALL)
			{
				NextInsAddr = CurIns->InstructionAddr + CurIns->InstructionLen;
				if (this->CodeStruct.Blist.find(NextInsAddr) != this->CodeStruct.Blist.end())
				{
					free(CurIns);
					NextIns = this->CodeStruct.Blist.find(NextInsAddr)->second;
					goto SkipCacheNext;
				}
				StartAddr = NextInsAddr & (~0xFFF);
				pageiter = this->CodeStruct.Pagelist.find(StartAddr);
				if (pageiter == this->CodeStruct.Pagelist.end())
				{
					this->CahchePage(StartAddr);
				}
				pageiter = this->CodeStruct.Pagelist.find(StartAddr);
				if (pageiter == this->CodeStruct.Pagelist.end())
				{
					free(CurIns);
					goto exit;
				}
				NextIns = (POneInstructionRecord)malloc(sizeof(OneInstructionRecord));
				if (!FindInsInPageLocked(PagePtr, NextIns, NextInsAddr))
				{
					free(CurIns);
					goto exit;
				}
			}
			else {
				free(CurIns);
				TempThreadInfo->ThreadContext.ContextFlags = CONTEXT_CONTROL;
				TempThreadInfo->ThreadContext.EFlags |= 0x100;
				SetThreadContext(TempThreadInfo->ThreadHandle, &TempThreadInfo->ThreadContext);
				goto exit;
			}
		}
		if (NextIns==NULL)
		{
			goto exit;
		}
		NextIns->enable = FALSE;
		NextIns->dirty = FALSE;
		NextIns->OnlyOver = TRUE;
		this->CodeStruct.Blist[NextInsAddr] = NextIns;
	SkipCacheNext:
		WritePhysicalMem(BreakPointerBuffer1,NextIns->InstructionLen,NextIns->InstructionAddr);
		FlushInstructionCache(this->ProcessHandle, (LPCVOID)NextIns->InstructionAddr, NextIns->InstructionLen);
		if (NextIns->enable==TRUE)
		{
			NextIns->dirty = FALSE;
		}
		TempThreadInfo->ThreadContext.ContextFlags = CONTEXT_CONTROL;
		TempThreadInfo->ThreadContext.EFlags &= (~0x100);	
		SetThreadContext(TempThreadInfo->ThreadHandle, &TempThreadInfo->ThreadContext);
		goto exit;
	}
exit:
	TempThreadInfo->stepflag = oreason;
	TempThreadInfo->ThreadContext.ContextFlags = oContextflag;
	result = ContinueThreadC(this->DebugHandle, this->TargetPid, Tid);
	
	if (result) {
		RtlZeroMemory(&(ThreadInfoMaps[Tid]->devent), sizeof(DEBUG_EVENT));
	}
	return result;


}



VOID WDebugerObject::CLEANALLDLL()
{
	//EnterCriticalSection(&(this->ThreadMapLock));
	PDLLRecordNode cur = this->dllhead;
	PDLLRecordNode temp = NULL;
	while (cur != NULL) {
		temp = cur;
		cur = cur->next;
		free(temp->NameBufferPtr);
		CloseHandle(temp->dllinfo.hFile);
		free(temp);
	}
	this->dllhead = NULL;
	//LeaveCriticalSection(&(this->ThreadMapLock));
}





DWORD64 WDebugerObject::DumpEntryAddress(DWORD64 ImageBase)
{
	IMAGE_DOS_HEADER DosHeaderBuffer;
	BOOL result = ReadPhysicalMem((UCHAR*)&DosHeaderBuffer, sizeof(IMAGE_DOS_HEADER), ImageBase);
	if (result == FALSE) {
		return -1;
	}
	LONG NTheaderoffset = DosHeaderBuffer.e_lfanew;
	DWORD64 NtHeaderAddress = ImageBase + NTheaderoffset;
	IMAGE_NT_HEADERS NtHeaderBuffer;
	result = ReadPhysicalMem((UCHAR*)&NtHeaderBuffer, sizeof(IMAGE_NT_HEADERS), NtHeaderAddress);
	if (result == FALSE) {
		return -1;
	}
	return (NtHeaderBuffer.OptionalHeader.AddressOfEntryPoint + ImageBase);

}



