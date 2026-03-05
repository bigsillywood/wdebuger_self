#include"WdbgDll.hpp"
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

	if (GetThreadContext(NewInfo->ThreadHandle, &(NewInfo->ThreadContext))) {

	}
	else
	{
		OutputErrorCode(GetLastError());
		RtlZeroMemory(&(NewInfo->ThreadContext), sizeof(CONTEXT));
	}
	NewInfo->CurLookingRip = (DWORD64)NewInfo->lpStartAddress;
	NewInfo->CurLookingRSP = (DWORD64)NewInfo->lpThreadLocalBase;

	CloseHandle(NewInfo->devent.u.CreateThread.hThread);
	EnterCriticalSection(&(this->ThreadMapLock));
	this->ThreadInfoMaps[NewInfo->Tid] = NewInfo;
	LeaveCriticalSection(&(this->ThreadMapLock));
}

VOID WDebugerObject::ADDPROCESS(DEBUG_EVENT* CreateProcessEvent)
{
	ThreadInfo* NewInfo = (ThreadInfo*)malloc(sizeof(ThreadInfo));
	RtlCopyMemory((UCHAR*)(&(NewInfo->devent)), (UCHAR*)CreateProcessEvent, sizeof(DEBUG_EVENT));




	NewInfo->lpStartAddress = (LPTHREAD_START_ROUTINE)DumpEntryAddress((DWORD64)(CreateProcessEvent->u.CreateProcessInfo.lpBaseOfImage));
	NewInfo->lpThreadLocalBase = NewInfo->devent.u.CreateProcessInfo.lpThreadLocalBase;

	NewInfo->Tid = (HANDLE)NewInfo->devent.dwThreadId;

	NewInfo->ThreadHandle = UserOpenThread(this->TargetPid, NewInfo->Tid, this->hDevice);
	CloseHandle(NewInfo->devent.u.CreateProcessInfo.hProcess);
	CloseHandle(NewInfo->devent.u.CreateProcessInfo.hThread);


	if (GetThreadContext(NewInfo->ThreadHandle, &(NewInfo->ThreadContext))) {

	}
	else
	{
		OutputErrorCode(GetLastError());
		RtlZeroMemory(&(NewInfo->ThreadContext), sizeof(CONTEXT));
	}

	NewInfo->CurLookingRip = (DWORD64)NewInfo->lpStartAddress;
	NewInfo->CurLookingRSP = (DWORD64)NewInfo->lpThreadLocalBase;
	EnterCriticalSection(&(this->ThreadMapLock));
	this->MainThreadid = (HANDLE)(CreateProcessEvent->dwThreadId);
	this->ProcessInfo = NewInfo->devent.u.CreateProcessInfo;
	this->ProcessInfo.lpStartAddress = NewInfo->lpStartAddress;
	this->ProcessInfo.hProcess = UserOpenProcess(this->TargetPid, this->hDevice);
	this->ThreadInfoMaps[NewInfo->Tid] = NewInfo;
	LeaveCriticalSection(&(this->ThreadMapLock));

}



VOID WDebugerObject::DELETETHREAD(HANDLE Tid)
{
	EnterCriticalSection(&(this->ThreadMapLock));
	ThreadInfo* temp = this->ThreadInfoMaps[Tid];
	CloseHandle(temp->ThreadHandle);
	free(temp);
	ThreadInfoMaps.erase(Tid);
	ContinueThreadC(this->DebugHandle, this->TargetPid, Tid);
	LeaveCriticalSection(&(this->ThreadMapLock));
}

VOID WDebugerObject::DELETEPROCESS(HANDLE MainTid)
{
	EnterCriticalSection(&(this->ThreadMapLock));
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
	LeaveCriticalSection(&(this->ThreadMapLock));
}



VOID WDebugerObject::LOADDLL(DEBUG_EVENT* LoadDllEvent)
{
	PDLLRecordNode NewNode = (PDLLRecordNode)malloc(sizeof(DLLRecordNode));
	NewNode->dllinfo = LoadDllEvent->u.LoadDll;
	NewNode->LoadingThread = (HANDLE)(LoadDllEvent->dwThreadId);

	EnterCriticalSection(&(this->ThreadMapLock));
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

	LeaveCriticalSection(&(this->ThreadMapLock));
}


VOID WDebugerObject::UNLOADDLL(DEBUG_EVENT* UnloadDllEvent)
{
	LPVOID hbase = UnloadDllEvent->u.UnloadDll.lpBaseOfDll;
	PDLLRecordNode cur = this->dllhead;
	PDLLRecordNode pre = NULL;
	EnterCriticalSection(&(this->ThreadMapLock));
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
	LeaveCriticalSection(&(this->ThreadMapLock));
}



VOID WDebugerObject::EXCEPTIONRECORD(DEBUG_EVENT* ExceptionEvent)
{
	EnterCriticalSection(&(this->ThreadMapLock));
	PThreadInfo infoptr = this->ThreadInfoMaps[(HANDLE)ExceptionEvent->dwThreadId];
	infoptr->devent = (*ExceptionEvent);
	infoptr->CurLookingRip = (DWORD64)(infoptr->devent.u.Exception.ExceptionRecord.ExceptionAddress);
	CONTEXT context = { 0 };
	GetThreadContext(infoptr->ThreadHandle, &(infoptr)->ThreadContext);
	infoptr->ThreadContext = context;
	infoptr->CurLookingRSP = context.Rsp;
	LeaveCriticalSection(&(this->ThreadMapLock));
}


VOID WDebugerObject::ListenThread()
{

	this->CombineThread();
	DEBUG_EVENT _devent;
	char buf[256];
	while (this->islisten) {
		BOOL ok = WaitForDebugEventSelf(&_devent, 100);
		if (!ok) {
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
			this->ContinueThread(threadid);
			break;
		}
		case CREATE_THREAD_DEBUG_EVENT:
		{
			sprintf_s(buf, sizeof(buf),
				"detect a thread creation,threadid:%d", _devent.dwThreadId);

			OutputDebugStringA(buf);
			ADDTHREAD(&_devent);
			this->ContinueThread(threadid);
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
			this->ContinueThread(threadid);
			this->islisten = FALSE;
			break;
		}
		case EXIT_THREAD_DEBUG_EVENT:
		{
			sprintf_s(buf, sizeof(buf),
				"detect a thread exit,threadid:%d", _devent.dwThreadId);
			OutputDebugStringA(buf);
			DELETETHREAD((HANDLE)(_devent.dwThreadId));
			this->ContinueThread(threadid);
			break;
		}
		case EXCEPTION_DEBUG_EVENT:
		{
			sprintf_s(buf, sizeof(buf),
				"detect a exception,threadid:%d", _devent.dwThreadId);
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
			this->ContinueThread(threadid);
			break;
		}
		case UNLOAD_DLL_DEBUG_EVENT:
		{
			UNLOADDLL(&_devent);
			this->ContinueThread(threadid);
			break;
		}
		case RIP_EVENT:
		{
			this->ContinueThread(threadid);
			break;
		}
		default:
			break;
		}

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



VOID WDebugerObject::CLEANALLDLL()
{
	EnterCriticalSection(&(this->ThreadMapLock));
	PDLLRecordNode cur = this->dllhead;
	PDLLRecordNode temp = NULL;
	while (cur != NULL) {
		temp = cur;
		cur = cur->next;
		CloseHandle(temp->dllinfo.hFile);
		free(temp);
	}
	this->dllhead = NULL;
	LeaveCriticalSection(&(this->ThreadMapLock));
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



