#include"WdbgDll.hpp"

UCHAR BreakPointerBuffer1[24] = { 0xcc,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90 };

BOOL WDebugerObject::CombineThread()
{
	return CombineThreadC(this->DebugHandle);
}



VOID WDebugerObject::ADDTHREAD(DEBUG_EVENT* CreateThreadEvent)
{
	ThreadInfo* NewInfo = (ThreadInfo*)malloc(sizeof(ThreadInfo));
	RtlCopyMemory((UCHAR*)(&(NewInfo->devent)),(UCHAR*)CreateThreadEvent,sizeof(DEBUG_EVENT));

	NewInfo->lpStartAddress		= NewInfo->devent.u.CreateThread.lpStartAddress;
	NewInfo->lpThreadLocalBase	= NewInfo->devent.u.CreateThread.lpThreadLocalBase;
	NewInfo->Tid				= (HANDLE)NewInfo->devent.dwThreadId;

	NewInfo->ThreadHandle = UserOpenThread(this->TargetPid,NewInfo->Tid,this->hDevice);
	NewInfo->stepflag = StepReasonNone;
	NewInfo->ThreadContext.ContextFlags = CONTEXT_CONTROL;
	if (GetThreadContext(NewInfo->ThreadHandle,&(NewInfo->ThreadContext)))
	{
		NewInfo->CurLookingRSP = NewInfo->ThreadContext.Rsp;
		NewInfo->CurLookingRip = NewInfo->ThreadContext.Rip;
	}
	else
	{
		OutputErrorCode(GetLastError());
		RtlZeroMemory(&(NewInfo->ThreadContext),sizeof(CONTEXT));
		NewInfo->CurLookingRSP = (DWORD64)NewInfo->lpThreadLocalBase;
		NewInfo->CurLookingRip = (DWORD64)NewInfo->lpStartAddress;
	}

	CloseHandle(NewInfo->devent.u.CreateThread.hThread);
	this->ThreadInfoMaps[NewInfo->Tid] = NewInfo;
}

VOID WDebugerObject::ADDPROCESS(DEBUG_EVENT* CreateProcessEvent)
{
	ThreadInfo* NewInfo = (ThreadInfo*)malloc(sizeof(ThreadInfo));
	RtlCopyMemory((UCHAR*)(&(NewInfo->devent)),(UCHAR*)CreateProcessEvent,sizeof(DEBUG_EVENT));
	NewInfo->lpStartAddress		= (LPTHREAD_START_ROUTINE)DumpEntryAddress((DWORD64)(CreateProcessEvent->u.CreateProcessInfo.lpBaseOfImage));
	NewInfo->lpThreadLocalBase	= NewInfo->devent.u.CreateProcessInfo.lpThreadLocalBase;
	NewInfo->Tid				= (HANDLE)NewInfo->devent.dwThreadId;

	NewInfo->ThreadHandle = UserOpenThread(this->TargetPid,NewInfo->Tid,this->hDevice);
	NewInfo->stepflag = StepReasonNone;
	NewInfo->ThreadContext.ContextFlags = CONTEXT_CONTROL;
	CloseHandle(NewInfo->devent.u.CreateProcessInfo.hProcess);
	CloseHandle(NewInfo->devent.u.CreateProcessInfo.hThread);

	if (GetThreadContext(NewInfo->ThreadHandle,&(NewInfo->ThreadContext)))
	{
		NewInfo->CurLookingRip = NewInfo->ThreadContext.Rip;
		NewInfo->CurLookingRSP = NewInfo->ThreadContext.Rsp;
	}
	else
	{
		NewInfo->CurLookingRip = (DWORD64)NewInfo->lpStartAddress;
		NewInfo->CurLookingRSP = (DWORD64)NewInfo->lpThreadLocalBase;
	}

	this->MainThreadid = (HANDLE)(CreateProcessEvent->dwThreadId);
	this->ProcessInfo = NewInfo->devent.u.CreateProcessInfo;
	this->ProcessInfo.lpStartAddress = NewInfo->lpStartAddress;
	this->ProcessInfo.hProcess = this->ProcessHandle;
	this->ThreadInfoMaps[NewInfo->Tid] = NewInfo;

	WCHAR buffer[256] = { 0 };
	DWORD PathLen = GetFinalPathNameByHandleW(this->ProcessInfo.hFile,buffer,256,FILE_NAME_NORMALIZED|VOLUME_NAME_DOS);
	if (PathLen < 256)
	{
		DWORD LeftIndex = PathLen - 1;
		while (buffer[LeftIndex] != L'\\' && LeftIndex >= 0)
		{
			LeftIndex--;
		}
		LeftIndex = LeftIndex + 1;

		this->ProcessNameLen = PathLen - LeftIndex;
		this->ProcessName = (WCHAR*)malloc(sizeof(WCHAR) * (this->ProcessNameLen + 1));
		if (this->ProcessName == NULL)
		{
			this->ProcessNameLen = 0;
		}
		else
		{
			memcpy(this->ProcessName,buffer + LeftIndex,sizeof(WCHAR) * (this->ProcessNameLen + 1));
			this->ProcessName[this->ProcessNameLen] = 0x00;
		}
	}
	else
	{
		this->ProcessNameLen = 0;
	}

	this->ImportDLLcounts = this->GetImportDllInformation((DWORD64)this->ProcessInfo.lpBaseOfImage,&this->MainModuleImportDLLtable);
	if (this->AntiDetectionBits == TRUE)
	{
		this->AntiDetection_PatchIAT_ByMainModule(this->HookInformations.GetProcAddressHookAddress - GETPROC_HOOK_ENTRY_OFFSET);
	}
}



VOID WDebugerObject::DELETETHREAD(HANDLE Tid)
{
	ThreadInfo* temp = this->ThreadInfoMaps[Tid];
	CloseHandle(temp->ThreadHandle);
	free(temp);
	ThreadInfoMaps.erase(Tid);
	ContinueThreadC(this->DebugHandle,this->TargetPid,Tid);
}

VOID WDebugerObject::DELETEPROCESS(HANDLE MainTid)
{
	ThreadInfo* temp;
	for (auto it = this->ThreadInfoMaps.begin(); it != this->ThreadInfoMaps.end(); it++)
	{
		CloseHandle(it->second->ThreadHandle);
		temp = it->second;
		free(temp);
	}
	this->ThreadInfoMaps.erase(this->ThreadInfoMaps.begin(),this->ThreadInfoMaps.end());
	CloseHandle(this->ProcessInfo.hFile);
	CloseHandle(this->ProcessHandle);
	ContinueThreadC(this->DebugHandle,this->TargetPid,MainTid);
}



VOID WDebugerObject::LOADDLL(DEBUG_EVENT* LoadDllEvent)
{
	PDLLRecordNode NewNode = new DLLRecordNode();
	if (NewNode == nullptr)
	{
		return;
	}
	NewNode->dllinfo		= LoadDllEvent->u.LoadDll;
	NewNode->LoadingThread	= (HANDLE)(LoadDllEvent->dwThreadId);

	PThreadInfo threadinfo = this->ThreadInfoMaps[(HANDLE)LoadDllEvent->dwThreadId];
	threadinfo->devent = *LoadDllEvent;

	if (GetThreadContext(threadinfo->ThreadHandle,&(threadinfo->ThreadContext)))
	{
	}
	else
	{
		OutputErrorCode(GetLastError());
		RtlZeroMemory(&(threadinfo->ThreadContext),sizeof(CONTEXT));
	}

	if (this->dllhead == NULL)
	{
		NewNode->next = NULL;
		this->dllhead = NewNode;
	}
	else
	{
		NewNode->next = this->dllhead;
		this->dllhead = NewNode;
	}

	WCHAR buffer[256] = { 0 };
	DWORD PathLen = GetFinalPathNameByHandleW(NewNode->dllinfo.hFile,buffer,256,FILE_NAME_NORMALIZED|VOLUME_NAME_DOS);
	if (PathLen < 256)
	{
		DWORD LeftIndex = PathLen - 1;
		while (buffer[LeftIndex] != L'\\' && LeftIndex >= 0)
		{
			LeftIndex--;
		}
		LeftIndex = LeftIndex + 1;

		NewNode->NameLen = PathLen - LeftIndex;
		NewNode->NameBufferPtr = (WCHAR*)malloc(sizeof(WCHAR) * (NewNode->NameLen + 1));
		if (NewNode->NameBufferPtr == NULL)
		{
			NewNode->NameLen = 0;
		}
		else
		{
			memcpy(NewNode->NameBufferPtr,buffer + LeftIndex,sizeof(WCHAR) * (NewNode->NameLen + 1));
			NewNode->NameBufferPtr[NewNode->NameLen] = 0x00;
		}
	}
	else
	{
		NewNode->NameLen = 0;
	}

	NewNode->ImportDLLcounts = this->GetImportDllInformation((DWORD64)NewNode->dllinfo.lpBaseOfDll,&NewNode->ImportDLLtable);
	if (this->AntiDetectionBits == TRUE)
	{
		this->AntiDetection_PatchIAT_ByNode(NewNode,this->HookInformations.GetProcAddressHookAddress - GETPROC_HOOK_ENTRY_OFFSET);
	}
}

VOID WDebugerObject::UNLOADDLL(DEBUG_EVENT* UnloadDllEvent)
{
	LPVOID hbase = UnloadDllEvent->u.UnloadDll.lpBaseOfDll;
	PDLLRecordNode cur = this->dllhead;
	PDLLRecordNode pre = NULL;

	while (cur != NULL)
	{
		if (hbase == cur->dllinfo.lpBaseOfDll)
		{
			if (pre == NULL)
			{
				this->dllhead = this->dllhead->next;
			}
			else
			{
				pre->next = cur->next;
			}

			if (cur->dllinfo.hFile != NULL)
			{
				CloseHandle(cur->dllinfo.hFile);
				cur->dllinfo.hFile = NULL;
			}

			if (cur->NameBufferPtr != NULL)
			{
				free(cur->NameBufferPtr);
				cur->NameBufferPtr = NULL;
			}

			delete cur;
			break;
		}
		else
		{
			pre = cur;
			cur = cur->next;
		}
	}
}

VOID WDebugerObject::EXCEPTIONRECORD(DEBUG_EVENT* ExceptionEvent)
{
	PThreadInfo infoptr = this->ThreadInfoMaps[(HANDLE)ExceptionEvent->dwThreadId];
	infoptr->devent = (*ExceptionEvent);
	CurLookTid = (HANDLE)ExceptionEvent->dwThreadId;

	if (ExceptionEvent->u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP && infoptr->stepflag == StepReasonBreakpointRecovery)
	{
		infoptr->ThreadContext.ContextFlags = CONTEXT_CONTROL;
	}
	else
	{
		infoptr->ThreadContext.ContextFlags = CONTEXT_ALL;
	}
	GetThreadContext(infoptr->ThreadHandle,&(infoptr)->ThreadContext);

	if (ExceptionEvent->u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT)
	{
		infoptr->ThreadContext.Rip -= 1;
	}
	infoptr->CurLookingRip = (DWORD64)(infoptr->ThreadContext.Rip);
	infoptr->CurLookingRSP = infoptr->ThreadContext.Rsp;
}


VOID WDebugerObject::ListenThread()
{
	this->CombineThread();
	DEBUG_EVENT _devent;
	char buf[256];
	while (this->islisten)
	{
		Sleep(LISTEN_YIELD_MS);
		EnterCriticalSection(&this->WdbgLock);
		BOOL ok = WaitForDebugEventSelf(&_devent,LISTEN_WAIT_TIMEOUT_MS);
		if (!ok)
		{
			LeaveCriticalSection(&this->WdbgLock);
			continue;
		}
		HANDLE threadid = (HANDLE)_devent.dwThreadId;

		switch (_devent.dwDebugEventCode)
		{
		case CREATE_PROCESS_DEBUG_EVENT:
		{
			sprintf_s(buf,sizeof(buf),
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
			sprintf_s(buf,sizeof(buf),
				"detect a thread creation,threadid:%d",_devent.dwThreadId);
			OutputDebugStringA(buf);
			ADDTHREAD(&_devent);
			this->ContinueThreadLocked(threadid);
			break;
		}
		case EXIT_PROCESS_DEBUG_EVENT:
		{
			sprintf_s(buf,sizeof(buf),
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
			sprintf_s(buf,sizeof(buf),
				"detect a thread exit,threadid:%d",_devent.dwThreadId);
			OutputDebugStringA(buf);
			DELETETHREAD((HANDLE)(_devent.dwThreadId));
			this->ContinueThreadLocked(threadid);
			break;
		}
		case EXCEPTION_DEBUG_EVENT:
		{
			sprintf_s(buf,sizeof(buf),
				"detect a exception,threadid:%d,sub code0x%X",_devent.dwThreadId,_devent.u.Exception.ExceptionRecord.ExceptionCode);
			OutputDebugStringA(buf);
			EXCEPTIONRECORD(&_devent);
			break;
		}
		case LOAD_DLL_DEBUG_EVENT:
		{
			sprintf_s(buf,sizeof(buf),
				"detect a DLL loading,threadid:%d",_devent.dwThreadId);
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


BOOL WDebugerObject::ContinueThreadLocked(HANDLE Tid)
{
	DEBUG_EVENT _devent;
	char buf[256];

	auto iter = this->ThreadInfoMaps.find(Tid);
	if (iter == ThreadInfoMaps.end() || iter->second->devent.dwDebugEventCode == 0)
	{
		return FALSE;
	}

	PThreadInfo TempThreadInfo = iter->second;
	DWORD oContextflag				= TempThreadInfo->ThreadContext.ContextFlags;
	THREAD_STEP_REASON oreason		= TempThreadInfo->stepflag;
	BOOL result						= FALSE;


	if (TempThreadInfo->devent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT
		&& TempThreadInfo->devent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT
		&& TempThreadInfo->stepflag == StepReasonNone)
	{
		auto iter2 = this->CodeStruct.Blist.find((DWORD64)TempThreadInfo->devent.u.Exception.ExceptionRecord.ExceptionAddress);
		if (iter2 != this->CodeStruct.Blist.end()
			&& (iter2->second->enable == TRUE || iter2->second->OnlyOver == TRUE))
		{
			BOOL cflag = CombineThreadC(this->DebugHandle);
			POneInstructionRecord BreakPointPtr		= iter2->second;
			DWORD64 BreakPointAddr					= BreakPointPtr->InstructionAddr;
			UINT8	BreakPointInstuctionLen			= BreakPointPtr->InstructionLen;
			UCHAR	BreakPointInstruction[24]		= { 0x90 };
			memcpy(BreakPointInstruction,BreakPointPtr->InstructionBuffer,BreakPointPtr->InstructionLen);

			// 设 TF，恢复原始字节，放行一条
			TempThreadInfo->ThreadContext.ContextFlags = CONTEXT_CONTROL;
			TempThreadInfo->ThreadContext.EFlags |= 0x100;
			if (!SetThreadContext(TempThreadInfo->ThreadHandle,&TempThreadInfo->ThreadContext))
			{
				goto exit;
			}
			if (!this->WritePhysicalMem(BreakPointInstruction,BreakPointInstuctionLen,BreakPointAddr))
			{
				goto exit;
			}
			if (!FlushInstructionCache(this->ProcessHandle,(LPCVOID)BreakPointAddr,BreakPointInstuctionLen))
			{
				goto exit;
			}

			result = ContinueThreadC(this->DebugHandle,this->TargetPid,Tid);
			if (result)
			{
				RtlZeroMemory(&(ThreadInfoMaps[Tid]->devent),sizeof(DEBUG_EVENT));
			}
			TempThreadInfo->stepflag = StepReasonBreakpointRecovery;

			sprintf_s(buf,sizeof(buf),"start wait single ");
			OutputDebugStringA(buf);

		
			while (TRUE)
			{
				BOOL ok = WaitForDebugEventSelf(&_devent,LISTEN_WAIT_TIMEOUT_MS);
				if (!ok)
				{
					continue;
				}
				sprintf_s(buf,sizeof(buf),"get an event ");
				OutputDebugStringA(buf);

				HANDLE threadid = (HANDLE)_devent.dwThreadId;
				switch (_devent.dwDebugEventCode)
				{
				case CREATE_PROCESS_DEBUG_EVENT:
				{
					sprintf_s(buf,sizeof(buf),
						"Detect process creation: processId=%u, mainThreadId=%u\n",
						_devent.dwProcessId,_devent.dwThreadId);
					OutputDebugStringA(buf);
					ADDPROCESS(&_devent);
					this->ContinueThreadLocked(threadid);
					break;
				}
				case CREATE_THREAD_DEBUG_EVENT:
				{
					sprintf_s(buf,sizeof(buf),
						"detect a thread creation,threadid:%d",_devent.dwThreadId);
					OutputDebugStringA(buf);
					ADDTHREAD(&_devent);
					this->ContinueThreadLocked(threadid);
					break;
				}
				case EXIT_PROCESS_DEBUG_EVENT:
				{
					sprintf_s(buf,sizeof(buf),
						"Detect process exit: processId=%u, mainThreadId=%u\n",
						_devent.dwProcessId,_devent.dwThreadId);
					OutputDebugStringA(buf);
					DELETEPROCESS((HANDLE)_devent.dwThreadId);
					this->CLEANALLDLL();
					this->ContinueThreadLocked(threadid);
					this->islisten = FALSE;
					return TRUE;
				}
				case EXIT_THREAD_DEBUG_EVENT:
				{
					sprintf_s(buf,sizeof(buf),
						"detect a thread exit,threadid:%d",_devent.dwThreadId);
					OutputDebugStringA(buf);
					DELETETHREAD((HANDLE)(_devent.dwThreadId));
					this->ContinueThreadLocked(threadid);
					if ((HANDLE)_devent.dwThreadId == Tid)
					{
						return TRUE;
					}
					break;
				}
				case EXCEPTION_DEBUG_EVENT:
				{
					sprintf_s(buf,sizeof(buf),
						"detect a exception,threadid:%d,sub code0x%X",
						_devent.dwThreadId,_devent.u.Exception.ExceptionRecord.ExceptionCode);
					OutputDebugStringA(buf);

					if ((HANDLE)_devent.dwThreadId == Tid)
					{
						if (_devent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP)
						{
							
							EXCEPTIONRECORD(&_devent);
							TempThreadInfo->stepflag = StepReasonBreakpointRecovery;
							TempThreadInfo->ThreadContext.ContextFlags = CONTEXT_CONTROL;
							GetThreadContext(TempThreadInfo->ThreadHandle,&TempThreadInfo->ThreadContext);
							TempThreadInfo->ThreadContext.EFlags &= (~0x100);
							BOOL flag = SetThreadContext(TempThreadInfo->ThreadHandle,&TempThreadInfo->ThreadContext);
							if (flag)
							{
								this->WritePhysicalMem(BreakPointerBuffer1,BreakPointInstuctionLen,BreakPointAddr);
								FlushInstructionCache(this->ProcessHandle,(LPCVOID)BreakPointAddr,BreakPointInstuctionLen);
							}
							goto exit;
						}
						else
						{
							TempThreadInfo->stepflag = oreason;
							TempThreadInfo->ThreadContext.ContextFlags = oContextflag;
							EXCEPTIONRECORD(&_devent);
							TempThreadInfo->ThreadContext.ContextFlags = CONTEXT_CONTROL;
							GetThreadContext(TempThreadInfo->ThreadHandle,&TempThreadInfo->ThreadContext);
							TempThreadInfo->ThreadContext.EFlags &= (~0x100);
							BOOL flag = SetThreadContext(TempThreadInfo->ThreadHandle,&TempThreadInfo->ThreadContext);
							if (flag)
							{
								this->WritePhysicalMem(BreakPointerBuffer1,BreakPointInstuctionLen,BreakPointAddr);
								FlushInstructionCache(this->ProcessHandle,(LPCVOID)BreakPointAddr,BreakPointInstuctionLen);
							}
							return TRUE;
						}
					}
					else
					{
						EXCEPTIONRECORD(&_devent);
					}
					break;
				}
				case LOAD_DLL_DEBUG_EVENT:
				{
					sprintf_s(buf,sizeof(buf),
						"detect a DLL loading,threadid:%d",_devent.dwThreadId);
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
			}
		}
		else
		{
			TempThreadInfo->ThreadContext.Rip += 1;
		}
	}


	if (TempThreadInfo->stepflag == StepReasonUserSingleStep
		&& TempThreadInfo->devent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
	{
		TempThreadInfo->ThreadContext.ContextFlags = CONTEXT_CONTROL;
		TempThreadInfo->ThreadContext.EFlags |= 0x100;
		SetThreadContext(TempThreadInfo->ThreadHandle,&TempThreadInfo->ThreadContext);
		goto exit;
	}


	if (TempThreadInfo->stepflag == StepReasonUserOverStep
		&& TempThreadInfo->devent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
	{
		
		OneInstructionRecord CurIns = { 0 };
		if (!this->ReadAndTranslateOne(TempThreadInfo->ThreadContext.Rip,&CurIns))
		{
			
			goto exit;
		}

		if (CurIns.id != X86_INS_CALL)
		{
			
			TempThreadInfo->ThreadContext.ContextFlags = CONTEXT_CONTROL;
			TempThreadInfo->ThreadContext.EFlags |= 0x100;
			SetThreadContext(TempThreadInfo->ThreadHandle,&TempThreadInfo->ThreadContext);
			goto exit;
		}

		
		DWORD64 NextInsAddr = CurIns.InstructionAddr + CurIns.InstructionLen;

		
		auto nextFinder = this->CodeStruct.Blist.find(NextInsAddr);
		if (nextFinder != this->CodeStruct.Blist.end() && nextFinder->second != NULL)
		{
			
			nextFinder->second->OnlyOver = TRUE;
			WritePhysicalMem(BreakPointerBuffer1,nextFinder->second->InstructionLen,NextInsAddr);
			FlushInstructionCache(this->ProcessHandle,(LPCVOID)NextInsAddr,nextFinder->second->InstructionLen);
			if (nextFinder->second->enable == TRUE)
			{
				nextFinder->second->dirty = FALSE;
			}
			goto OverSetupDone;
		}

		
		{
			POneInstructionRecord NextIns = (POneInstructionRecord)malloc(sizeof(OneInstructionRecord));
			if (NextIns == NULL)
			{
				goto exit;
			}
			ZeroMemory(NextIns,sizeof(OneInstructionRecord));

			if (!this->ReadAndTranslateOne(NextInsAddr,NextIns))
			{
				free(NextIns);
				goto exit;
			}

			NextIns->enable		= FALSE;
			NextIns->dirty		= FALSE;
			NextIns->OnlyOver	= TRUE;
			this->CodeStruct.Blist[NextInsAddr] = NextIns;

			WritePhysicalMem(BreakPointerBuffer1,NextIns->InstructionLen,NextInsAddr);
			FlushInstructionCache(this->ProcessHandle,(LPCVOID)NextInsAddr,NextIns->InstructionLen);
		}

	OverSetupDone:
		// 关掉 TF，让目标跑到临时断点
		TempThreadInfo->ThreadContext.ContextFlags = CONTEXT_CONTROL;
		TempThreadInfo->ThreadContext.EFlags &= (~0x100);
		SetThreadContext(TempThreadInfo->ThreadHandle,&TempThreadInfo->ThreadContext);
		goto exit;
	}

exit:
	TempThreadInfo->stepflag = oreason;
	TempThreadInfo->ThreadContext.ContextFlags = oContextflag;
	result = ContinueThreadC(this->DebugHandle,this->TargetPid,Tid);
	if (result)
	{
		RtlZeroMemory(&(ThreadInfoMaps[Tid]->devent),sizeof(DEBUG_EVENT));
	}
	return result;
}



VOID WDebugerObject::CLEANALLDLL()
{
	PDLLRecordNode cur = this->dllhead;
	PDLLRecordNode temp = NULL;
	while (cur != NULL)
	{
		temp = cur;
		cur = cur->next;
		free(temp->NameBufferPtr);
		CloseHandle(temp->dllinfo.hFile);
		delete temp;
	}
	this->dllhead = NULL;
}



DWORD64 WDebugerObject::DumpEntryAddress(DWORD64 ImageBase)
{
	IMAGE_DOS_HEADER DosHeaderBuffer;
	BOOL result = ReadPhysicalMem((UCHAR*)&DosHeaderBuffer,sizeof(IMAGE_DOS_HEADER),ImageBase);
	if (result == FALSE)
	{
		return -1;
	}
	LONG NTheaderoffset = DosHeaderBuffer.e_lfanew;
	DWORD64 NtHeaderAddress = ImageBase + NTheaderoffset;
	IMAGE_NT_HEADERS NtHeaderBuffer;
	result = ReadPhysicalMem((UCHAR*)&NtHeaderBuffer,sizeof(IMAGE_NT_HEADERS),NtHeaderAddress);
	if (result == FALSE)
	{
		return -1;
	}
	return (NtHeaderBuffer.OptionalHeader.AddressOfEntryPoint + ImageBase);
}
