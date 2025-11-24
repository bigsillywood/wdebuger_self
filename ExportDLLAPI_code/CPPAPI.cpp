
#include "WdbgDll.hpp"

WDebugerObject::WDebugerObject(HANDLE TargetPid)
{
	
	this->islisten = FALSE;
	this->TargetPid = TargetPid;
	this->hDevice = NULL;
	this->DebugHandle = NULL;
	InitializeCriticalSectionAndSpinCount(&(this->ThreadMapLock), 4000);
	RtlZeroMemory(&(this->ProcessInfo),sizeof(CREATE_PROCESS_DEBUG_INFO));
}

WDebugerObject::~WDebugerObject()
{
	this->islisten=FALSE;
	//
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
	DeleteCriticalSection(&this->ThreadMapLock);
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
//pls reserve a threadinfo space before call
BOOL WDebugerObject::GetThreadInfo(HANDLE Tid,__out ThreadInfo* outinfo)
{
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

BOOL WDebugerObject::CombineThread()
{

	return CombineThreadC(this->DebugHandle);
}

VOID WDebugerObject::ADDTHREAD(DEBUG_EVENT* CreateThreadEvent)
{
	ThreadInfo* NewInfo = (ThreadInfo*)malloc(sizeof(ThreadInfo));
	RtlCopyMemory((UCHAR*)(&(NewInfo->devent)),(UCHAR*)CreateThreadEvent,sizeof(DEBUG_EVENT));
	


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
	NewInfo->CurLookingRip = NewInfo->ThreadContext.Rip;
	NewInfo->CurLookingRSP = NewInfo->ThreadContext.Rsp;

	CloseHandle(NewInfo->devent.u.CreateThread.hThread);
	EnterCriticalSection(&(this->ThreadMapLock));
	this->ThreadInfoMaps[NewInfo->Tid] = NewInfo;
	LeaveCriticalSection(&(this->ThreadMapLock));
}

VOID WDebugerObject::ADDPROCESS(DEBUG_EVENT* CreateProcessEvent)
{
	ThreadInfo* NewInfo = (ThreadInfo*)malloc(sizeof(ThreadInfo));
	RtlCopyMemory((UCHAR*)(&(NewInfo->devent)), (UCHAR*)CreateProcessEvent, sizeof(DEBUG_EVENT));
	



	NewInfo->lpStartAddress = NewInfo->devent.u.CreateProcessInfo.lpStartAddress;
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

	NewInfo->CurLookingRip = NewInfo->ThreadContext.Rip;
	NewInfo->CurLookingRSP = NewInfo->ThreadContext.Rsp;
	EnterCriticalSection(&(this->ThreadMapLock));
	this->MainThreadid = (HANDLE)(CreateProcessEvent->dwThreadId);
	this->ProcessInfo = NewInfo->devent.u.CreateProcessInfo;
	this->ProcessInfo.hProcess = UserOpenProcess(this->TargetPid,this->hDevice);
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
	ContinueThreadC(this->DebugHandle,this->TargetPid,Tid);
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
	ContinueThreadC(this->DebugHandle, this->TargetPid,MainTid);
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

	if (this->dllhead==NULL) {
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
	while (cur!=NULL) {
		if (hbase==cur->dllinfo.lpBaseOfDll) {
			if (pre==NULL)
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
	GetThreadContext(infoptr->ThreadHandle,&(infoptr)->ThreadContext);
	infoptr->ThreadContext = context;
	infoptr->CurLookingRSP = context.Rsp;
	LeaveCriticalSection(&(this->ThreadMapLock));
}

VOID WDebugerObject::CLEANALLDLL()
{
	EnterCriticalSection(&(this->ThreadMapLock));
	PDLLRecordNode cur=this->dllhead;
	PDLLRecordNode temp=NULL;
	while (cur!=NULL) {
		temp = cur;
		cur = cur->next;
		CloseHandle(temp->dllinfo.hFile);
		free(temp);
	}
	this->dllhead = NULL;
	LeaveCriticalSection(&(this->ThreadMapLock));
}


VOID WDebugerObject::ListenThread()
{

	this->CombineThread();
	DEBUG_EVENT _devent;
	char buf[256];
	while (this->islisten) {
		BOOL ok=WaitForDebugEventSelf(&_devent, 100);
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

HANDLE WDebugerObject::GetDebugProcessHandle()
{
	return this->ProcessInfo.hProcess;
}


BOOL WDebugerObject::ReadPhysicalMem(UCHAR* readbuffer, size_t readsize,ULONG64 VirtualAddr)
{
	
	return UserPhysicalRead(this->TargetPid,this->hDevice,VirtualAddr,readsize,readbuffer);
}

BOOL WDebugerObject::WritePhysicalMem(UCHAR* writebuffer, size_t writesize, ULONG64 VirtualAddr)
{
	return UserPhysicalWrite(this->TargetPid,this->hDevice,VirtualAddr,writesize,writebuffer);
}

