#include"user.h"


void CreateProcessDebugEvenHandleThread(DEBUG_EVENT* debug_event){
    WaitForSingleObject(hsignleventCreateProcessDebugEvent,INFINITE);
    
    return;
}








//dbg线程
void DebugThread(HANDLE dbghandle){
    WaitForSingleObject(hsignlevent,INFINITE);
    ULONG offset=GetDbgReserveOffset();
     if(offset!=0){
        struct _TEB* CurrentTEB=NtCurrentTeb();
        UCHAR* dbgreserve_ptr=(UCHAR*)CurrentTEB+offset;
        //wchar_t buffer2[64];
		//swprintf(buffer2,64,L"reserve_offset=%d",offset);
		//MessageBoxW(NULL, buffer2, L"debug", MB_ICONINFORMATION);
         *((HANDLE*)dbgreserve_ptr)=dbghandle;
    }else{
        /*
         MessageBoxW(NULL, L"get dbg reserve offset failed", L"error", MB_ICONERROR);
        
        */
        return;
    }
    DEBUG_EVENT debug_event;
    while (1)
    {
        WaitForDebugEvent(&debug_event,INFINITE);
        switch (debug_event.dwDebugEventCode)
        {
            case CREATE_PROCESS_DEBUG_EVENT:
                AppendLog(hLogWindow, L"CREATE_PROCESS_DEBUG_EVENT");
                EnterCriticalSection(&csCreateProcessDebugEvent);
                if (ignoreCreateProcessDebugEvent)
                {
                    ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, DBG_CONTINUE);
                }else{
                    
                }
                LeaveCriticalSection(&csCreateProcessDebugEvent);
                break;
            case EXIT_PROCESS_DEBUG_EVENT:
                AppendLog(hLogWindow, L"EXIT_PROCESS_DEBUG_EVENT");
                EnterCriticalSection(&csExitProcessDebugEvent);
                if(ignoreExitProcessDebugEvent){
                    ContinueDebugEvent(debug_event.dwProcessId,debug_event.dwThreadId,DBG_CONTINUE);
                }else{

                }
                LeaveCriticalSection(&csExitProcessDebugEvent);
                break;
            case LOAD_DLL_DEBUG_EVENT:
                AppendLog(hLogWindow, L"LOAD_DLL_DEBUG_EVENT");

            break;
            case UNLOAD_DLL_DEBUG_EVENT:
                AppendLog(hLogWindow, L"UNLOAD_DLL_DEBUG_EVENT");
            break;
            case EXCEPTION_DEBUG_EVENT:
                AppendLog(hLogWindow, L"EXCEPTION_DEBUG_EVENT");
            break;
            case OUTPUT_DEBUG_STRING_EVENT:
                AppendLog(hLogWindow, L"OUTPUT_DEBUG_STRING_EVENT");
            break;
            case RIP_EVENT:
                AppendLog(hLogWindow, L"RIP_EVENT");
            break;
            default:
                AppendLog(hLogWindow, L"unknown debug event");
        }
    }
    return;
}