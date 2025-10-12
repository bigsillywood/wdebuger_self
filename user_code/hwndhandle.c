#include"user.h"

void AppendLog(HWND hEdit, LPCWSTR text)
{
    // 临时关闭只读
    SendMessageW(hEdit, EM_SETREADONLY, FALSE, 0);

    // 获取当前文本长度
    int len = GetWindowTextLengthW(hEdit);

    // 将光标移动到末尾
    SendMessageW(hEdit, EM_SETSEL, len, len);

    // 插入新内容
    SendMessageW(hEdit, EM_REPLACESEL, FALSE, (LPARAM)(LPWSTR)text);

    // 插入换行
    SendMessageW(hEdit, EM_REPLACESEL, FALSE, (LPARAM)(LPWSTR)L"\r\n");

    // 恢复只读
    SendMessageW(hEdit, EM_SETREADONLY, TRUE, 0);

    // 自动滚动到底部
    SendMessageW(hEdit, EM_SCROLLCARET, 0, 0);
}



// ==== 查询函数 ====


void QueryHandle(HWND hwnd) {
    wchar_t input[64];
    GetWindowTextW(hEditInput, input, 64);

    HANDLE h = (HANDLE)_wcstoui64(input, NULL, 0);

    BYTE buffer[0x1000];
    ULONG retLen = 0;

    NTSTATUS status = NtQueryObjectFunc(
        h,
        ObjectTypeInformation,
        buffer,
        sizeof(buffer),
        &retLen
    );

    if (status != 0) {
        wchar_t msg[128];
        swprintf(msg, 128, L"NtQueryObject failed: 0x%08X", status);
        SetWindowTextW(hEditOutput, msg);
        return;
    }

    OBJECT_TYPE_INFORMATION *info = (OBJECT_TYPE_INFORMATION*)buffer;
    wchar_t result[256];
    swprintf(result, 256, L"Handle 0x%p → Type: %.*s",
             h,
             info->TypeName.Length / sizeof(WCHAR),
             info->TypeName.Buffer);

    SetWindowTextW(hEditOutput, result);
}
void PidHandle(HWND hwnd){
    
    wchar_t pidbuffer[64];
    GetWindowTextW(hEditInput2,pidbuffer,64);
    HANDLE targetpid=(HANDLE)_wcstoi64(pidbuffer,NULL,0);
    HANDLE currentpid=GetCurrentProcessId();
    if(hdevice==INVALID_HANDLE_VALUE){
        wchar_t buffer[64];
		swprintf(buffer,64,L"open device failed!errorcode=%d,pls reopen it",GetLastError());
		MessageBoxW(NULL, buffer, L"error", MB_ICONERROR);
		return 1;
    }
    struct CREATE_DEBUG_OBJ_ARG args;
    args.DebugerPid=currentpid;
    args.TargetPid=targetpid;
    ULONG readlen=0;
    HANDLE dbghandle=NULL;
    BOOL ok=DeviceIoControl(hdevice,
                            IOCTL_CREATE_DEBUG_OBJ,
                            (UCHAR*)&args,
                            sizeof(struct CREATE_DEBUG_OBJ_ARG),
                            (UCHAR*)&dbghandle,
                            sizeof(HANDLE),
                            &readlen,
                            NULL);
    if (!ok)
    {
        MessageBoxW(NULL, L"create failed", L"error", MB_ICONERROR);
        return 1;
    }
    if(dbghandle==NULL){
        MessageBoxW(NULL, L"dbghandle is NULL", L"error", MB_ICONERROR);
        return 1;
    }
    InitializeCriticalSection(&csCreateProcessDebugEvent);
    InitializeCriticalSection(&csExitProcessDebugEvent);
    InitializeCriticalSection(&csLoadDllDebugEvent);
    InitializeCriticalSection(&csUnloadDllDebugEvent);
    //InitializeCriticalSection(&csExceptionDebugEvent);
    InitializeCriticalSection(&csOutputDebugStringEvent);
    InitializeCriticalSection(&csRipEvent);

    hsignlevent=CreateEventW(NULL,FALSE,FALSE,NULL);
    hsignleventCreateProcessDebugEvent=CreateEventW(NULL,FALSE,FALSE,NULL);
    hsignleventExitProcessDebugEvent=CreateEventW(NULL,FALSE,FALSE,NULL);
    hsignleventLoadDllDebugEvent=CreateEventW(NULL,FALSE,FALSE,NULL);
    hsignleventUnloadDllDebugEvent=CreateEventW(NULL,FALSE,FALSE,NULL);
    hsignleventExceptionDebugEvent=CreateEventW(NULL,FALSE,FALSE,NULL);
    hsignleventOutputDebugStringEvent=CreateEventW(NULL,FALSE,FALSE,NULL);
    hsignleventRipEvent=CreateEventW(NULL,FALSE,FALSE,NULL);

    dbgthreadhandle= CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)DebugThread,dbghandle,0,NULL);
    //pushThreadLinkList(dbgthreadhandle);
    
    wchar_t buffer2[64];
    /*
    
    */
    swprintf(buffer2,64,L"handle value=0x%p",dbghandle);
    SetWindowTextW(hEditOutput2, buffer2);

    SetEvent(hsignlevent);
    
    SendMessage(hEditInput2, EM_SETREADONLY, TRUE, 0);
    EnableWindow(hButton2, FALSE); 
    

    return 0;
}