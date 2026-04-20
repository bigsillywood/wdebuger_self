#include "WdbgDll.hpp"

UCHAR BreakPointerBuffer[24] = { 0xcc,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90 };

WDebugerObject::WDebugerObject(HANDLE TargetPid)
{
	this->MainThreadid	= NULL;
	this->ProcessHandle = NULL;
	this->dllhead		= NULL;
	this->islisten		= FALSE;
	this->TargetPid		= TargetPid;
	this->hDevice		= NULL;
	this->DebugHandle	= NULL;
	this->isLockOk		= FALSE;
	this->CodeStruct.CurrentLookingAddr = 0;
	RtlZeroMemory(&(this->ProcessInfo),sizeof(CREATE_PROCESS_DEBUG_INFO));
	RtlZeroMemory(&(this->HookInformations),sizeof(AntiDetectHookFuncInformation));
}

WDebugerObject::~WDebugerObject()
{
	this->islisten = FALSE;
	free(this->ProcessName);


	OneInstructionRecord* TempInsPtr;
	for (auto it = this->CodeStruct.Blist.begin(); it != this->CodeStruct.Blist.end(); it++)
	{
		TempInsPtr = it->second;
		if (TempInsPtr->enable == TRUE)
		{
			this->WritePhysicalMem(TempInsPtr->InstructionBuffer,TempInsPtr->InstructionLen,TempInsPtr->InstructionAddr);
		}
		free(TempInsPtr);
	}

	ZwRemoveProcessDebug(this->ProcessHandle,this->DebugHandle);
	if (this->DebugHandle != NULL && this->DebugHandle != INVALID_HANDLE_VALUE)
	{
		CloseHandle(this->DebugHandle);
	}

	if (this->listen_thread.joinable())
	{
		this->listen_thread.join();
	}

	if (this->hDevice != NULL && this->hDevice != INVALID_HANDLE_VALUE)
	{
		CloseHandle(this->hDevice);
	}

	for (auto it = ThreadInfoMaps.begin(); it != ThreadInfoMaps.end(); it++)
	{
		if (it->second->ThreadHandle != NULL && it->second->ThreadHandle != INVALID_HANDLE_VALUE)
		{
			CloseHandle(it->second->ThreadHandle);
		}
		if (it->second != NULL)
		{
			free(it->second);
		}
	}

	if (this->ProcessHandle != NULL && this->ProcessHandle != INVALID_HANDLE_VALUE)
	{
		CloseHandle(this->ProcessHandle);
	}

	this->CLEANALLDLL();

	if (this->isLockOk)
	{
		DeleteCriticalSection(&(this->WdbgLock));
	}
	this->isLockOk = FALSE;
}


std::unique_ptr<WDebugerObject> WDebugerObject::Create(HANDLE TargetPid,BOOL isAntiDetect)
{
	std::unique_ptr<WDebugerObject> ptr(new WDebugerObject(TargetPid));
	if (!(ptr->init()))
	{
		return nullptr;
	}
	ptr->ProcessHandle = UserOpenProcess(ptr->TargetPid,ptr->hDevice);
	if (isAntiDetect)
	{
		UserAntiDetection(ptr->TargetPid,ptr->hDevice);
		if (ptr->AntiDetection_InjectHookFunctions())
		{
			ptr->AntiDetectionBits = TRUE;
		}
	}
	return ptr;
}

BOOL WDebugerObject::GetThreadList(HANDLE* Tidbuffer,DWORD buffersize)
{
	RtlZeroMemory(Tidbuffer,buffersize * sizeof(HANDLE));
	DWORD MaxIndex = buffersize - 1;
	DWORD index = 0;
	BOOL result = TRUE;
	EnterCriticalSection(&(this->WdbgLock));
	for (auto it = this->ThreadInfoMaps.begin(); it != this->ThreadInfoMaps.end(); it++)
	{
		if (index > MaxIndex)
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


// ---------------------------------------------------------------------------
// ReadAndTranslateOne
// ---------------------------------------------------------------------------
BOOL WDebugerObject::ReadAndTranslateOne(__in  DWORD64				VirtualAddr,
										 __out POneInstructionRecord OutRecord)
{
	UCHAR ReadBuf[ONDEMAND_READ_SIZE] = { 0 };

	if (!this->ReadPhysicalMem(ReadBuf,ONDEMAND_READ_SIZE,VirtualAddr))
	{
		return FALSE;
	}

	auto iter = this->CodeStruct.Blist.find(VirtualAddr);
	if (iter != this->CodeStruct.Blist.end() && iter->second != NULL)
	{
		POneInstructionRecord BpPtr = iter->second;
		if (BpPtr->enable == TRUE || BpPtr->dirty == FALSE)
		{
			memcpy(ReadBuf,BpPtr->InstructionBuffer,BpPtr->InstructionLen);
		}
	}

	return this->CodeStruct.CapstoneAPIhandle.TranslateOneInstruction(
		ReadBuf,
		ONDEMAND_READ_SIZE,
		VirtualAddr,
		OutRecord
	);
}


// ---------------------------------------------------------------------------
// CheckBreakPointStale
// ---------------------------------------------------------------------------
BOOL WDebugerObject::CheckBreakPointStale(__in  DWORD64 VirtualAddr,
										  __out BOOL*   IsStale)
{
	if (IsStale == NULL)
	{
		return FALSE;
	}
	*IsStale = FALSE;

	auto iter = this->CodeStruct.Blist.find(VirtualAddr);
	if (iter == this->CodeStruct.Blist.end() || iter->second == NULL)
	{
		return TRUE;
	}

	POneInstructionRecord BpPtr = iter->second;

	if (BpPtr->OnlyOver == TRUE || BpPtr->enable == FALSE)
	{
		return TRUE;
	}

	UCHAR RawBuf[ONDEMAND_READ_SIZE] = { 0 };
	if (!this->ReadPhysicalMem(RawBuf,ONDEMAND_READ_SIZE,VirtualAddr))
	{
		return FALSE;
	}

	if (RawBuf[0] != 0xCC)
	{
		*IsStale = TRUE;
		return TRUE;
	}

	if (BpPtr->InstructionLen <= 1)
	{
		return TRUE;
	}

	if (memcmp(RawBuf + 1, BpPtr->InstructionBuffer + 1, BpPtr->InstructionLen - 1) != 0)
	{
		*IsStale = TRUE;
	}

	return TRUE;
}


// ---------------------------------------------------------------------------
// SetCodeStructCurrentLookingInstructions
// ---------------------------------------------------------------------------
BOOL WDebugerObject::SetCodeStructCurrentLookingInstructions(DWORD64 VirtualAddress)
{
	EnterCriticalSection(&(this->WdbgLock));
	this->CodeStruct.CurrentLookingAddr = VirtualAddress;
	LeaveCriticalSection(&(this->WdbgLock));
	return TRUE;
}


// ---------------------------------------------------------------------------
// GetTargetCode
// ---------------------------------------------------------------------------
DWORD64 WDebugerObject::GetTargetCode(POneInstructionRecord InstructionRecordBufferPtr,SIZE_T MaxInstructions)
{
	OutputDebugStringW(L"GetTargetCode start");

	EnterCriticalSection(&(this->WdbgLock));

	if (this->CodeStruct.CurrentLookingAddr == 0)
	{
		LeaveCriticalSection(&(this->WdbgLock));
		return 0;
	}

	DWORD64 CurAddr = this->CodeStruct.CurrentLookingAddr;
	SIZE_T index = 0;

	while (index < MaxInstructions)
	{
		OneInstructionRecord TempRecord = { 0 };

		if (!this->ReadAndTranslateOne(CurAddr,&TempRecord))
		{
			break;
		}

		if (TempRecord.InstructionLen == 0)
		{
			break;
		}

		InstructionRecordBufferPtr[index] = TempRecord;
		InstructionRecordBufferPtr[index].enable = FALSE;
		InstructionRecordBufferPtr[index].stale  = FALSE;

		auto finder = this->CodeStruct.Blist.find(CurAddr);
		if (finder != this->CodeStruct.Blist.end() && finder->second != NULL)
		{
			InstructionRecordBufferPtr[index].enable = finder->second->enable;

			if (finder->second->enable == TRUE && finder->second->OnlyOver == FALSE)
			{
				BOOL IsStale = FALSE;
				if (this->CheckBreakPointStale(CurAddr,&IsStale))
				{
					InstructionRecordBufferPtr[index].stale = IsStale;
					finder->second->stale = IsStale;
				}
			}
		}

		CurAddr += TempRecord.InstructionLen;
		index++;
	}

	LeaveCriticalSection(&(this->WdbgLock));
	OutputDebugStringW(L"GetTargetCode end");
	return index;
}


// ---------------------------------------------------------------------------
// SetBreakPointUp
// ---------------------------------------------------------------------------
BOOL WDebugerObject::SetBreakPointUp(DWORD64 InstructionAddr)
{
	EnterCriticalSection(&(this->WdbgLock));

	auto finder = this->CodeStruct.Blist.find(InstructionAddr);
	if (finder != this->CodeStruct.Blist.end())
	{
		POneInstructionRecord InsPtr = finder->second;
		if (InsPtr != NULL)
		{
			if (InsPtr->enable == FALSE)
			{
				if (this->WritePhysicalMem(BreakPointerBuffer,InsPtr->InstructionLen,InstructionAddr))
				{
					FlushInstructionCache(this->ProcessHandle,(LPCVOID)InsPtr->InstructionAddr,InsPtr->InstructionLen);
					InsPtr->enable	= TRUE;
					InsPtr->dirty	= FALSE;
					InsPtr->OnlyOver= FALSE;
					LeaveCriticalSection(&(this->WdbgLock));
					return TRUE;
				}
				else
				{
					LeaveCriticalSection(&(this->WdbgLock));
					return FALSE;
				}
			}
			else
			{
				LeaveCriticalSection(&(this->WdbgLock));
				return TRUE;
			}
		}
		else
		{
			this->CodeStruct.Blist.erase(InstructionAddr);
		}
	}

	POneInstructionRecord InstructionPtr = (POneInstructionRecord)malloc(sizeof(OneInstructionRecord));
	if (InstructionPtr == NULL)
	{
		LeaveCriticalSection(&(this->WdbgLock));
		return FALSE;
	}
	ZeroMemory(InstructionPtr,sizeof(OneInstructionRecord));

	if (!this->ReadAndTranslateOne(InstructionAddr,InstructionPtr))
	{
		free(InstructionPtr);
		LeaveCriticalSection(&(this->WdbgLock));
		return FALSE;
	}

	if (this->WritePhysicalMem(BreakPointerBuffer,InstructionPtr->InstructionLen,InstructionAddr))
	{
		FlushInstructionCache(this->ProcessHandle,(LPCVOID)InstructionPtr->InstructionAddr,InstructionPtr->InstructionLen);
		InstructionPtr->enable	= TRUE;
		InstructionPtr->dirty	= FALSE;
		InstructionPtr->OnlyOver= FALSE;
		this->CodeStruct.Blist[InstructionAddr] = InstructionPtr;
		LeaveCriticalSection(&(this->WdbgLock));
		return TRUE;
	}
	else
	{
		free(InstructionPtr);
		LeaveCriticalSection(&(this->WdbgLock));
		return FALSE;
	}
}

BOOL WDebugerObject::SetBreakPointDown(DWORD64 InstructionAddr)
{
	EnterCriticalSection(&(this->WdbgLock));
	auto it = this->CodeStruct.Blist.find(InstructionAddr);
	if (it == this->CodeStruct.Blist.end())
	{
		LeaveCriticalSection(&(this->WdbgLock));
		return FALSE;
	}

	POneInstructionRecord ptr = it->second;
	if (ptr == NULL)
	{
		this->CodeStruct.Blist.erase(InstructionAddr);
		LeaveCriticalSection(&(this->WdbgLock));
		return TRUE;
	}

	for (auto iter2 = this->ThreadInfoMaps.begin(); iter2 != this->ThreadInfoMaps.end(); iter2++)
	{
		if (iter2->second->devent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT
			&& iter2->second->devent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT
			&& (DWORD64)iter2->second->devent.u.Exception.ExceptionRecord.ExceptionAddress == InstructionAddr
			&& it->second->enable == TRUE)
		{
			DWORD oflag = iter2->second->ThreadContext.ContextFlags;
			iter2->second->ThreadContext.ContextFlags = CONTEXT_CONTROL;
			SetThreadContext(iter2->second->ThreadHandle,&iter2->second->ThreadContext);
			iter2->second->ThreadContext.ContextFlags = oflag;
		}
	}

	if (this->WritePhysicalMem(ptr->InstructionBuffer,ptr->InstructionLen,ptr->InstructionAddr))
	{
		FlushInstructionCache(this->ProcessHandle,(LPCVOID)ptr->InstructionAddr,ptr->InstructionLen);
		ptr->enable = FALSE;
		ptr->dirty	= FALSE;
		LeaveCriticalSection(&(this->WdbgLock));
		return TRUE;
	}
	else
	{
		LeaveCriticalSection(&(this->WdbgLock));
		return FALSE;
	}
}

BOOL WDebugerObject::DeleteBreakPoint(DWORD64 InstructionAddr)
{
	EnterCriticalSection(&(this->WdbgLock));
	auto it = this->CodeStruct.Blist.find(InstructionAddr);
	if (it == this->CodeStruct.Blist.end())
	{
		LeaveCriticalSection(&(this->WdbgLock));
		return TRUE;
	}

	POneInstructionRecord Ptr = it->second;
	if (Ptr == NULL)
	{
		this->CodeStruct.Blist.erase(InstructionAddr);
		LeaveCriticalSection(&(this->WdbgLock));
		return TRUE;
	}

	for (auto iter2 = this->ThreadInfoMaps.begin(); iter2 != this->ThreadInfoMaps.end(); iter2++)
	{
		if (iter2->second->devent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT
			&& iter2->second->devent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT
			&& (DWORD64)iter2->second->devent.u.Exception.ExceptionRecord.ExceptionAddress == InstructionAddr
			&& it->second->enable == TRUE)
		{
			DWORD oflag = iter2->second->ThreadContext.ContextFlags;
			iter2->second->ThreadContext.ContextFlags = CONTEXT_CONTROL;
			SetThreadContext(iter2->second->ThreadHandle,&iter2->second->ThreadContext);
			iter2->second->ThreadContext.ContextFlags = oflag;
		}
	}

	if (Ptr->enable == FALSE)
	{
		free(Ptr);
		this->CodeStruct.Blist.erase(InstructionAddr);
		LeaveCriticalSection(&(this->WdbgLock));
		return TRUE;
	}

	BOOL flag = WritePhysicalMem(Ptr->InstructionBuffer,Ptr->InstructionLen,Ptr->InstructionAddr);
	FlushInstructionCache(this->ProcessHandle,(LPCVOID)Ptr->InstructionAddr,Ptr->InstructionLen);
	if (flag)
	{
		free(Ptr);
		this->CodeStruct.Blist.erase(InstructionAddr);
		LeaveCriticalSection(&(this->WdbgLock));
		return TRUE;
	}
	LeaveCriticalSection(&(this->WdbgLock));
	return FALSE;
}

BOOL WDebugerObject::GetThreadBriefList(__out PThreadBriefInfo OutBuffer,
	__in  DWORD            BufferCount,
	__out DWORD* OutCount)
{
	if (OutBuffer == NULL || OutCount == NULL || BufferCount == 0)
	{
		return FALSE;
	}
	*OutCount = 0;

	EnterCriticalSection(&(this->WdbgLock));

	for (auto it = this->ThreadInfoMaps.begin();
		it != this->ThreadInfoMaps.end() && *OutCount < BufferCount;
		++it)
	{
		PThreadInfo pInfo = it->second;
		if (pInfo == NULL) continue;

		PThreadBriefInfo slot = &OutBuffer[*OutCount];
		slot->Tid = (HANDLE)pInfo->Tid;
		slot->CurLookingRip = pInfo->CurLookingRip;
		slot->DeventCode = pInfo->devent.dwDebugEventCode;

		// 只有异常事件才有 ExceptionCode，其余为 0
		if (pInfo->devent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
		{
			slot->SubExceptionCode =
				pInfo->devent.u.Exception.ExceptionRecord.ExceptionCode;
		}
		else
		{
			slot->SubExceptionCode = 0;
		}

		(*OutCount)++;
	}

	LeaveCriticalSection(&(this->WdbgLock));
	return TRUE;
}


BOOL WDebugerObject::GetThreadInfo(HANDLE Tid,__out ThreadInfo* outinfo)
{
	if (outinfo == NULL)
	{
		return FALSE;
	}
	BOOL result = FALSE;
	EnterCriticalSection(&(this->WdbgLock));
	if (ThreadInfoMaps.find(Tid) != ThreadInfoMaps.end())
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
	EnterCriticalSection(&(this->WdbgLock));
	PDLLRecordNode cur = this->dllhead;
	PDLLRecordNode* insertPos = head;
	while (cur != NULL)
	{
		PDLLRecordNode newNode = (PDLLRecordNode)malloc(sizeof(DLLRecordNode));
		if (!newNode)
		{
			LeaveCriticalSection(&(this->WdbgLock));
			return FALSE;
		}
		memcpy(newNode,cur,sizeof(DLLRecordNode));
		newNode->next = NULL;
		*insertPos = newNode;
		insertPos = &newNode->next;
		cur = cur->next;
	}
	LeaveCriticalSection(&(this->WdbgLock));
	return TRUE;
}


BOOL WDebugerObject::EnumModules(__out PModuleInfo OutBuffer,
								 __in  DWORD       BufferCount,
								 __out DWORD*      OutCount)
{
	if (OutBuffer == NULL || OutCount == NULL || BufferCount == 0)
	{
		return FALSE;
	}

	*OutCount = 0;
	EnterCriticalSection(&(this->WdbgLock));

	// ── 先写主模块 ───────────────────────────────────────────
	if (*OutCount < BufferCount)
	{
		PModuleInfo slot = &OutBuffer[*OutCount];
		ZeroMemory(slot, sizeof(ModuleInfo));
		slot->BaseAddress  = reinterpret_cast<DWORD64>(this->ProcessInfo.lpBaseOfImage);
		slot->IsMainModule = TRUE;


		if (this->ProcessName != NULL && this->ProcessNameLen > 0)
		{
		
			DWORD copyLen = this->ProcessNameLen < (MODULE_NAME_MAX - 8)
				? this->ProcessNameLen
				: (MODULE_NAME_MAX - 8);    
			memcpy(slot->Name, this->ProcessName, copyLen * sizeof(WCHAR));
			slot->Name[copyLen] = L'\0';
	
			wcscat_s(slot->Name, MODULE_NAME_MAX, L" [Main]");
		}
		else
		{
			wcscpy_s(slot->Name, MODULE_NAME_MAX, L"[Main]");
		}
		(*OutCount)++;
	}


	PDLLRecordNode cur = this->dllhead;
	while (cur != NULL && *OutCount < BufferCount)
	{
		PModuleInfo slot = &OutBuffer[*OutCount];
		ZeroMemory(slot, sizeof(ModuleInfo));
		slot->BaseAddress  = reinterpret_cast<DWORD64>(cur->dllinfo.lpBaseOfDll);
		slot->IsMainModule = FALSE;

		if (cur->NameBufferPtr != NULL && cur->NameLen > 0)
		{
			DWORD copyLen = cur->NameLen < (MODULE_NAME_MAX - 1)
				? cur->NameLen
				: (MODULE_NAME_MAX - 1);
			memcpy(slot->Name, cur->NameBufferPtr, copyLen * sizeof(WCHAR));
			slot->Name[copyLen] = L'\0';
		}
		else
		{
			wcscpy_s(slot->Name, MODULE_NAME_MAX, L"(unknown)");
		}

		(*OutCount)++;
		cur = cur->next;
	}

	LeaveCriticalSection(&(this->WdbgLock));
	return TRUE;
}


BOOL WDebugerObject::SuspendTargetThread(HANDLE Tid)
{
	BOOL result = FALSE;
	HANDLE threadhandle = NULL;
	EnterCriticalSection(&(this->WdbgLock));
	if (ThreadInfoMaps.find(Tid) != ThreadInfoMaps.end())
	{
		threadhandle = ThreadInfoMaps[Tid]->ThreadHandle;
		result = SuspendThread(threadhandle) >= 0 ? TRUE : FALSE;
	}
	LeaveCriticalSection(&(this->WdbgLock));
	return result;
}

BOOL WDebugerObject::ResumeTargetThread(HANDLE Tid)
{
	BOOL result = FALSE;
	HANDLE threadhandle = NULL;
	EnterCriticalSection(&(this->WdbgLock));
	if (ThreadInfoMaps.find(Tid) != ThreadInfoMaps.end())
	{
		threadhandle = ThreadInfoMaps[Tid]->ThreadHandle;
		result = ResumeThread(threadhandle) >= 0 ? TRUE : FALSE;
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

BOOL WDebugerObject::ChangeContext(HANDLE Tid,CONTEXT* tcontext)
{
	EnterCriticalSection(&(this->WdbgLock));
	BOOL result = FALSE;
	if (ThreadInfoMaps.find(Tid) != ThreadInfoMaps.end())
	{
		DWORD oFlags = ThreadInfoMaps[Tid]->ThreadContext.ContextFlags;
		ThreadInfoMaps[Tid]->ThreadContext.ContextFlags = CONTEXT_ALL;
		HANDLE temphandle = ThreadInfoMaps[Tid]->ThreadHandle;
		if (SetThreadContext(temphandle,tcontext))
		{
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
	if (this->islisten == FALSE)
	{
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
	this->isLockOk = InitializeCriticalSectionAndSpinCount(&(this->WdbgLock),4000);
	if (this->isLockOk == FALSE)
	{
		return FALSE;
	}

	this->hDevice = CreateWdbgDevice();
	if (this->hDevice == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	this->DebugHandle = krnlDebugActive(this->TargetPid,this->hDevice);
	if (this->DebugHandle == INVALID_HANDLE_VALUE || this->DebugHandle == NULL)
	{
		CloseHandle(this->hDevice);
		return FALSE;
	}
	return TRUE;
}

HANDLE WDebugerObject::GetDebugProcessHandle()
{
	return this->ProcessInfo.hProcess;
}

BOOL WDebugerObject::ReadPhysicalMem(UCHAR* readbuffer,size_t readsize,ULONG64 VirtualAddr)
{
	return UserPhysicalRead(this->TargetPid,this->hDevice,VirtualAddr,readsize,readbuffer);
}

BOOL WDebugerObject::WritePhysicalMem(UCHAR* writebuffer,size_t writesize,ULONG64 VirtualAddr)
{
	return UserPhysicalWrite(this->TargetPid,this->hDevice,VirtualAddr,writesize,writebuffer);
}


// ---------------------------------------------------------------------------
// ContinueThread
// ---------------------------------------------------------------------------
BOOL WDebugerObject::ContinueThread(HANDLE Tid)
{
	EnterCriticalSection(&(this->WdbgLock));
	auto iter = this->ThreadInfoMaps.find(Tid);
	if (iter == this->ThreadInfoMaps.end())
	{
		LeaveCriticalSection(&(this->WdbgLock));
		return FALSE;
	}
	if (iter->second->devent.dwDebugEventCode == 0)
	{
		LeaveCriticalSection(&(this->WdbgLock));
		return FALSE;
	}

	iter->second->stepflag = StepReasonNone;

	POneInstructionRecord bptr;
	for (auto it = this->CodeStruct.Blist.begin(); it != this->CodeStruct.Blist.end();)
	{
		bptr = it->second;
		if (bptr->OnlyOver == TRUE)
		{
		
			WritePhysicalMem(bptr->InstructionBuffer,bptr->InstructionLen,bptr->InstructionAddr);
			FlushInstructionCache(this->ProcessHandle,(LPCVOID)bptr->InstructionAddr,bptr->InstructionLen);
			free(bptr);
			it = this->CodeStruct.Blist.erase(it);
		}
		else
		{
			if (bptr->enable == TRUE && bptr->dirty == TRUE)
			{
				WritePhysicalMem(BreakPointerBuffer,bptr->InstructionLen,bptr->InstructionAddr);
				FlushInstructionCache(this->ProcessHandle,(LPCVOID)bptr->InstructionAddr,bptr->InstructionLen);
				bptr->dirty = FALSE;
			}
			++it;
		}
	}

	BOOL ok = this->ContinueThreadLocked(Tid);
	LeaveCriticalSection(&(this->WdbgLock));
	return ok;
}


// ---------------------------------------------------------------------------
// StepIntoOneStep
// ---------------------------------------------------------------------------
BOOL WDebugerObject::StepIntoOneStep(HANDLE Tid)
{
	EnterCriticalSection(&(this->WdbgLock));
	auto iter = this->ThreadInfoMaps.find(Tid);
	if (iter == this->ThreadInfoMaps.end())
	{
		LeaveCriticalSection(&(this->WdbgLock));
		return FALSE;
	}
	if (iter->second->devent.dwDebugEventCode == 0)
	{
		LeaveCriticalSection(&(this->WdbgLock));
		return FALSE;
	}

	iter->second->stepflag = StepReasonUserSingleStep;

	POneInstructionRecord bptr;
	for (auto it = this->CodeStruct.Blist.begin(); it != this->CodeStruct.Blist.end();)
	{
		bptr = it->second;
		if (bptr->OnlyOver == TRUE)
		{
			WritePhysicalMem(bptr->InstructionBuffer,bptr->InstructionLen,bptr->InstructionAddr);
			FlushInstructionCache(this->ProcessHandle,(LPCVOID)bptr->InstructionAddr,bptr->InstructionLen);
			free(bptr);
			it = this->CodeStruct.Blist.erase(it);
		}
		else
		{
			if (bptr->enable == TRUE && bptr->dirty == FALSE && bptr->InstructionAddr == iter->second->ThreadContext.Rip)
			{
				WritePhysicalMem(bptr->InstructionBuffer,bptr->InstructionLen,bptr->InstructionAddr);
				FlushInstructionCache(this->ProcessHandle,(LPCVOID)bptr->InstructionAddr,bptr->InstructionLen);
				bptr->dirty = TRUE;
			}
			++it;
		}
	}

	BOOL ok = this->ContinueThreadLocked(Tid);
	LeaveCriticalSection(&(this->WdbgLock));
	return ok;
}


// ---------------------------------------------------------------------------
// StepOverOneStep
// ---------------------------------------------------------------------------
BOOL WDebugerObject::StepOverOneStep(HANDLE Tid)
{
	EnterCriticalSection(&(this->WdbgLock));
	auto iter = this->ThreadInfoMaps.find(Tid);
	if (iter == this->ThreadInfoMaps.end())
	{
		LeaveCriticalSection(&(this->WdbgLock));
		return FALSE;
	}
	if (iter->second->devent.dwDebugEventCode == 0)
	{
		LeaveCriticalSection(&(this->WdbgLock));
		return FALSE;
	}

	POneInstructionRecord bptr;
	for (auto it = this->CodeStruct.Blist.begin(); it != this->CodeStruct.Blist.end();)
	{
		bptr = it->second;
		if (bptr->OnlyOver == TRUE)
		{
			WritePhysicalMem(bptr->InstructionBuffer,bptr->InstructionLen,bptr->InstructionAddr);
			FlushInstructionCache(this->ProcessHandle,(LPCVOID)bptr->InstructionAddr,bptr->InstructionLen);
			free(bptr);
			it = this->CodeStruct.Blist.erase(it);
		}
		else
		{
			if (bptr->enable == TRUE && bptr->dirty == FALSE && bptr->InstructionAddr == iter->second->ThreadContext.Rip)
			{
				WritePhysicalMem(bptr->InstructionBuffer,bptr->InstructionLen,bptr->InstructionAddr);
				FlushInstructionCache(this->ProcessHandle,(LPCVOID)bptr->InstructionAddr,bptr->InstructionLen);
				bptr->dirty = TRUE;
			}
			++it;
		}
	}

	OneInstructionRecord CurIns = { 0 };
	if (!this->ReadAndTranslateOne(iter->second->ThreadContext.Rip,&CurIns))
	{
		iter->second->stepflag = StepReasonUserSingleStep;
		BOOL ok = this->ContinueThreadLocked(Tid);
		LeaveCriticalSection(&(this->WdbgLock));
		return ok;
	}

	if (CurIns.id != X86_INS_CALL)
	{
		iter->second->stepflag = StepReasonUserSingleStep;
		BOOL ok = this->ContinueThreadLocked(Tid);
		LeaveCriticalSection(&(this->WdbgLock));
		return ok;
	}

	DWORD64 NextInsAddr = CurIns.InstructionAddr + CurIns.InstructionLen;

	auto nextFinder = this->CodeStruct.Blist.find(NextInsAddr);
	if (nextFinder != this->CodeStruct.Blist.end() && nextFinder->second != NULL)
	{
		nextFinder->second->OnlyOver = TRUE;
		WritePhysicalMem(BreakPointerBuffer,nextFinder->second->InstructionLen,NextInsAddr);
		FlushInstructionCache(this->ProcessHandle,(LPCVOID)NextInsAddr,nextFinder->second->InstructionLen);
		iter->second->stepflag = StepReasonUserOverStep;
		iter->second->ThreadContext.EFlags &= (~0x100);
		iter->second->ThreadContext.ContextFlags = CONTEXT_CONTROL;
		SetThreadContext(iter->second->ThreadHandle,&iter->second->ThreadContext);
		BOOL ok = this->ContinueThreadLocked(Tid);
		LeaveCriticalSection(&(this->WdbgLock));
		return ok;
	}

	POneInstructionRecord NextIns = (POneInstructionRecord)malloc(sizeof(OneInstructionRecord));
	if (NextIns == NULL)
	{
		iter->second->stepflag = StepReasonUserSingleStep;
		BOOL ok = this->ContinueThreadLocked(Tid);
		LeaveCriticalSection(&(this->WdbgLock));
		return ok;
	}
	ZeroMemory(NextIns,sizeof(OneInstructionRecord));

	if (!this->ReadAndTranslateOne(NextInsAddr,NextIns))
	{
		free(NextIns);
		iter->second->stepflag = StepReasonUserSingleStep;
		BOOL ok = this->ContinueThreadLocked(Tid);
		LeaveCriticalSection(&(this->WdbgLock));
		return ok;
	}

	NextIns->enable		= FALSE;
	NextIns->dirty		= FALSE;
	NextIns->OnlyOver	= TRUE;
	this->CodeStruct.Blist[NextInsAddr] = NextIns;

	WritePhysicalMem(BreakPointerBuffer,NextIns->InstructionLen,NextInsAddr);
	FlushInstructionCache(this->ProcessHandle,(LPCVOID)NextInsAddr,NextIns->InstructionLen);

	iter->second->stepflag = StepReasonUserOverStep;
	iter->second->ThreadContext.EFlags &= (~0x100);
	iter->second->ThreadContext.ContextFlags = CONTEXT_CONTROL;
	SetThreadContext(iter->second->ThreadHandle,&iter->second->ThreadContext);

	BOOL ok = this->ContinueThreadLocked(Tid);
	LeaveCriticalSection(&(this->WdbgLock));
	return ok;
}

HANDLE WDebugerObject::GetCurLookTid()
{
	HANDLE tid = NULL;
	EnterCriticalSection(&(this->WdbgLock));
	tid = this->CurLookTid;
	LeaveCriticalSection(&(this->WdbgLock));
	return tid;
}
