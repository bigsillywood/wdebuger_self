
#include "WdbgDll.hpp"
WDebugerObject::WDebugerObject(HANDLE TargetPid)
{
	this->islisten = FALSE;
	this->TargetPid = TargetPid;
	this->hDevice = NULL;
	this->DebugHandle = NULL;
	this->ThreadMapLock = {0};
	RtlZeroMemory(&(this->ProcessInfo),sizeof(CREATE_PROCESS_DEBUG_INFO));
}

WDebugerObject::~WDebugerObject()
{
	
	if (this->DebugHandle!=NULL) {
		CloseHandle(this->DebugHandle);
	}
	if (this->hDevice!=NULL) {
		CloseHandle(this->hDevice);
	}
	for (auto it = ThreadInfoMaps.begin(); it != ThreadInfoMaps.end();it++) {
		
		if (it->second->ThreadHandle!=NULL) {
			CloseHandle(it->second->ThreadHandle);
		}
		/*
		if (it->second->LockInit == TRUE) {
			DeleteCriticalSection(&(it->second->ThreadInfoLock));
		}
		
		*/
		if (it->second != NULL) {
			free(it->second);
		}
	}
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
	CLIENT_ID cid = { 0 };
	cid.UniqueProcess = this->TargetPid;
	cid.UniqueThread = Tid;
	BOOL result;
	EnterCriticalSection(&(this->ThreadMapLock));
	auto it = this->ThreadInfoMaps.find(Tid);
	if (it==this->ThreadInfoMaps.end() ||it->second->devent.dwDebugEventCode==0) {
		LeaveCriticalSection(&(this->ThreadMapLock));
		return FALSE;
	}
	NTSTATUS status = NtDebugContinue(this->DebugHandle,&cid, DBG_CONTINUE);
	if (status<0)
	{
		result = FALSE;
	}
	else
	{	
		RtlZeroMemory(&(ThreadInfoMaps[Tid]->devent),sizeof(DEBUG_EVENT));
		result = TRUE;
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

BOOL WDebugerObject::GetProcessInfo(CREATE_PROCESS_DEBUG_INFO* outinfo)
{

	EnterCriticalSection(&(this->ThreadMapLock));
	memcpy(outinfo,&(this->ProcessInfo),sizeof(CREATE_PROCESS_DEBUG_INFO));
	LeaveCriticalSection(&(this->ThreadMapLock));
	return 1;
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
	
	BOOL ok=InitializeCriticalSectionAndSpinCount(&(this->ThreadMapLock), 4000);
	if (!ok) {
		return FALSE;
	}
	this->hDevice= CreateWdbgDevice();
	if(this->hDevice==INVALID_HANDLE_VALUE) {
		DeleteCriticalSection(&(this->ThreadMapLock));
		return FALSE;
		
	}
	this->DebugHandle = krnlDebugActive(this->TargetPid,this->hDevice);
	if (this->DebugHandle==INVALID_HANDLE_VALUE || this->DebugHandle == NULL) {
		CloseHandle(this->hDevice);
		DeleteCriticalSection(&(this->ThreadMapLock));
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
	NewInfo->ThreadHandle = UserOpenThread(this->TargetPid,NewInfo->Tid,this->hDevice);
	GetThreadContext(NewInfo->ThreadHandle, &(NewInfo->ThreadContext));
	NewInfo->CurLookingRip = NewInfo->ThreadContext.Rip;
	NewInfo->CurLookingRSP = NewInfo->ThreadContext.Rsp;
	NewInfo->lpStartAddress = NewInfo->devent.u.CreateThread.lpStartAddress;
	NewInfo->lpThreadLocalBase = NewInfo->devent.u.CreateThread.lpThreadLocalBase;
	NewInfo->Tid = (HANDLE)NewInfo->devent.dwThreadId;
	CloseHandle(NewInfo->devent.u.CreateThread.hThread);


	EnterCriticalSection(&(this->ThreadMapLock));
	this->ThreadInfoMaps[NewInfo->Tid] = NewInfo;
	LeaveCriticalSection(&(this->ThreadMapLock));
}

VOID WDebugerObject::ADDPROCESS(DEBUG_EVENT* CreateProcessEvent)
{
	ThreadInfo* NewInfo = (ThreadInfo*)malloc(sizeof(ThreadInfo));
	RtlCopyMemory((UCHAR*)(&(NewInfo->devent)), (UCHAR*)CreateProcessEvent, sizeof(DEBUG_EVENT));
	NewInfo->ThreadHandle = UserOpenThread(this->TargetPid, NewInfo->Tid, this->hDevice);
	GetThreadContext(NewInfo->ThreadHandle, &(NewInfo->ThreadContext));
	NewInfo->CurLookingRip = NewInfo->ThreadContext.Rip;
	NewInfo->CurLookingRSP = NewInfo->ThreadContext.Rsp;
	NewInfo->lpStartAddress = NewInfo->devent.u.CreateProcessInfo.lpStartAddress;
	NewInfo->lpThreadLocalBase = NewInfo->devent.u.CreateProcessInfo.lpThreadLocalBase;
	NewInfo->Tid = (HANDLE)NewInfo->devent.dwThreadId;
	CloseHandle(NewInfo->devent.u.CreateProcessInfo.hProcess);
	CloseHandle(NewInfo->devent.u.CreateProcessInfo.hThread);

	EnterCriticalSection(&(this->ThreadMapLock));
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
	LeaveCriticalSection(&(this->ThreadMapLock));
}

VOID WDebugerObject::DELETEPROCESS()
{
	EnterCriticalSection(&(this->ThreadMapLock));
	ThreadInfo* temp;
	for (auto it = this->ThreadInfoMaps.begin(); it != this->ThreadInfoMaps.end(); it++)
	{
		CloseHandle(it->second->ThreadHandle);
		temp = it->second;
		free(temp);
	}
	CloseHandle(this->ProcessHandle);
	//ZeroMemory(&(this->ProcessInfo),sizeof(CREATE_PROCESS_DEBUG_INFO));
	LeaveCriticalSection(&(this->ThreadMapLock));
}


VOID WDebugerObject::ListenThread()
{

	this->CombineThread();
	DEBUG_EVENT _devent;
	while (1) {
		WaitForDebugEventSelf(&_devent, INFINITE);
		switch (_devent.dwDebugEventCode)
		{
		case CREATE_PROCESS_DEBUG_EVENT:
		{
			char buf[256];
			sprintf_s(buf, sizeof(buf),
				"Detect process creation: processId=%u, mainThreadId=%u\n",
				_devent.dwProcessId,
				_devent.dwThreadId);

			OutputDebugStringA(buf);
			ADDPROCESS(&_devent);
			break;
		}
		case CREATE_THREAD_DEBUG_EVENT:
		{
			char buf[256];
			sprintf_s(buf, sizeof(buf),
				"detect a thread creation,threadid:%d", _devent.dwThreadId);

			OutputDebugStringA(buf);
			ADDTHREAD(&_devent);
			break;
		}
		case EXIT_PROCESS_DEBUG_EVENT: 
		{
			DELETEPROCESS();
			break;
		}
		case EXIT_THREAD_DEBUG_EVENT:
		{
			DELETETHREAD((HANDLE)(_devent.dwThreadId));
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

