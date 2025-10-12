#include <windows.h>
#include "user.h"

#define window_width 1200
#define window_height 800
#define window_x 10
#define window_y 10

HFONT hFont = NULL;

typedef NTSTATUS (NTAPI *PFN_NtQueryObject)(
    HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG);
PFN_NtQueryObject NtQueryObjectFunc;

// ==== 更新字体 ====
void UpdateFont(HWND hwnd, int w, int h) {
    if (hFont) { DeleteObject(hFont); hFont = NULL; }

    int fontHeight = h / 40;  // 整体调小
    if (fontHeight < 12) fontHeight = 12;

    hFont = CreateFontW(
        -fontHeight, 0, 0, 0,
        FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
        CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
        DEFAULT_PITCH | FF_DONTCARE,
        L"Consolas"   // 日志窗口用等宽字体更清晰
    );

    HWND child = GetWindow(hwnd, GW_CHILD);
    while (child) {
        SendMessageW(child, WM_SETFONT, (WPARAM)hFont, TRUE);
        child = GetWindow(child, GW_HWNDNEXT);
    }
}


// ==== 控件布局 ====
void ResizeControls(HWND hwnd, int w, int h) {
    int topH = h / 5;      // 上面输入区占 1/5
    int logH = h * 3 / 5;  // 日志区占 3/5
    int cmdH = h / 10;     // 命令行输入占 1/10

    // === 上半部分 ===
    MoveWindow(hStatic1, 10, 10, 150, 20, TRUE);
    MoveWindow(hEditInput, 170, 10, 200, 25, TRUE);
    MoveWindow(hButton, 380, 10, 80, 25, TRUE);

    MoveWindow(hEditOutput, 10, 40, 460, 25, TRUE);

    MoveWindow(hStatic2, 10, 70, 150, 20, TRUE);
    MoveWindow(hEditInput2, 170, 70, 200, 25, TRUE);
    MoveWindow(hButton2, 380, 70, 80, 25, TRUE);

    MoveWindow(hStatic3, 10, 100, 100, 20, TRUE);
    MoveWindow(hEditOutput2, 10, 130, 460, 25, TRUE);

    // === 计算日志窗口位置 ===
    RECT rc;
    GetWindowRect(hEditOutput2, &rc);
    ScreenToClient(hwnd, (LPPOINT)&rc.left);
    ScreenToClient(hwnd, (LPPOINT)&rc.right);

    int logY = rc.bottom + 80;   // 在 handle 输出框下方留 80px 间隔
    int logHeight = h - logY - cmdH - 40; // 底部留给命令行

    MoveWindow(hLogWindow, 10, logY, w - 20, logHeight, TRUE);

    // === 底部命令行输入 ===
    MoveWindow(hCmdInput, 10, logY + logHeight + 10, w - 120, cmdH, TRUE);
    MoveWindow(hCmdButton, w - 100, logY + logHeight + 10, 90, cmdH, TRUE);

    UpdateFont(hwnd, w, h);
}

// ==== 窗口回调 ====
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE:
        hStatic1 = CreateWindowW(L"STATIC", L"checking handle:",
            WS_VISIBLE | WS_CHILD, 10, 10, 120, 20, hwnd, NULL, NULL, NULL);

        hEditInput = CreateWindowW(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER,
            170, 10, 200, 25, hwnd, NULL, NULL, NULL);

        hButton = CreateWindowW(L"BUTTON", L"check", WS_VISIBLE | WS_CHILD,
            380, 10, 80, 25, hwnd, (HMENU)1, NULL, NULL);

        hEditOutput = CreateWindowW(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_READONLY,
            10, 40, 460, 25, hwnd, NULL, NULL, NULL);

        hStatic2 = CreateWindowW(L"STATIC", L"sending targetpid:",
            WS_VISIBLE | WS_CHILD, 10, 70, 150, 20, hwnd, NULL, NULL, NULL);

        hEditInput2 = CreateWindowW(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER,
            170, 70, 200, 25, hwnd, NULL, NULL, NULL);

        hButton2 = CreateWindowW(L"BUTTON", L"send", WS_VISIBLE | WS_CHILD,
            380, 70, 80, 25, hwnd, (HMENU)2, NULL, NULL);

        hStatic3 = CreateWindowW(L"STATIC", L"handle=",
            WS_VISIBLE | WS_CHILD, 10, 100, 100, 20, hwnd, NULL, NULL, NULL);

        hEditOutput2 = CreateWindowW(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_READONLY,
            10, 130, 460, 25, hwnd, NULL, NULL, NULL);

        // === 日志窗口 ===
        hLogWindow = CreateWindowW(L"EDIT", L"",
    		WS_VISIBLE | WS_CHILD | WS_BORDER | ES_MULTILINE | ES_READONLY | WS_VSCROLL,
    		10, 260, 1180, 350, hwnd, NULL, NULL, NULL);
        // === 命令行输入框和按钮 ===
        hCmdInput = CreateWindowW(L"EDIT", L"",
            WS_VISIBLE | WS_CHILD | WS_BORDER,
            10, 620, 1050, 25, hwnd, NULL, NULL, NULL);

        hCmdButton = CreateWindowW(L"BUTTON", L"Exec",
            WS_VISIBLE | WS_CHILD,
            1070, 620, 100, 25, hwnd, (HMENU)3, NULL, NULL);

        UpdateFont(hwnd, window_width, window_height);
        break;

    case WM_COMMAND:
        if (LOWORD(wParam) == 1) {
            QueryHandle(hwnd);
        }
        else if (LOWORD(wParam) == 2) {
            PidHandle(hwnd);
        }
        else if (LOWORD(wParam) == 3) {
            // 这里是命令行输入按钮
            // 你可以自己写处理逻辑
        }
        break;

    case WM_SIZE:
        ResizeControls(hwnd, LOWORD(lParam), HIWORD(lParam));
        break;

    case WM_ERASEBKGND: {
        HDC hdc = (HDC)wParam;
        RECT rc; GetClientRect(hwnd, &rc);
        FillRect(hdc, &rc, (HBRUSH)(COLOR_WINDOW+1));
        return 1;
    }

    case WM_DESTROY:
		if (dbgthreadhandle)
		{
			TerminateThread(dbgthreadhandle, 0);
			CloseHandle(dbgthreadhandle);
			dbgthreadhandle = NULL;
		}
		
        if (hdevice != INVALID_HANDLE_VALUE) CloseHandle(hdevice);
        if (hFont) DeleteObject(hFont);
        PostQuitMessage(0);
        break;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

// ==== WinMain ====
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
    LPSTR lpCmdLine, int nCmdShow)
{
    ignoreCreateProcessDebugEvent=TRUE;
    hdevice = CreateFileW(DEVICENAME,
        GENERIC_READ|GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, NULL);
    if (hdevice == INVALID_HANDLE_VALUE) {
        wchar_t buffer[128];
        swprintf(buffer,128,L"open device failed! errorcode=%d",GetLastError());
        MessageBoxW(NULL, buffer, L"error", MB_ICONERROR);
        return 1;
    }

    HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
    NtQueryObjectFunc = (PFN_NtQueryObject)GetProcAddress(hNtDll, "NtQueryObject");
    if (!NtQueryObjectFunc) {
        MessageBoxW(NULL, L"NtQueryObject not found!", L"error", MB_ICONERROR);
        return 1;
    }

    WNDCLASSW wc = { 0 };
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = L"HandleChecker";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW+1);
    RegisterClassW(&wc);

    HWND hwnd = CreateWindowExW(
        WS_EX_COMPOSITED,
        L"HandleChecker", L"testing driver",
        WS_OVERLAPPEDWINDOW | WS_VISIBLE,
        window_x, window_y, window_width, window_height,
        NULL, NULL, hInstance, NULL);
	
    
	
	MSG msg = { 0 };
    
	while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    return 0;
}
