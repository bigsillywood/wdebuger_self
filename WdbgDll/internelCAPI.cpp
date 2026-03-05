#include"WdbgDll.hpp"

LONG DbgSsReservedOffsetFirst = NULL;
LONG DbgSsReservedOffsetSecond = NULL;
LONG GetDbgReserveOffsetFirst() {
    if (DbgSsReservedOffsetFirst == NULL) {
        HMODULE h = GetModuleHandleA("ntdll.dll");
        if (!h) h = LoadLibraryA("ntdll.dll");
        FARPROC p = GetProcAddress(h, "DbgUiConnectToDbg");
        UCHAR* mcode = (UCHAR*)p;
        ULONG offset = 0;
        while ((*mcode) != 0xC3)
        {
            if (((*mcode) == 0x48) && ((*(mcode + 1)) == 0x39) && ((*(mcode + 2)) == 0x88)) {
                LONG* offset_ptr = (LONG*)(mcode + 3);
                offset = *offset_ptr;
            }
            mcode++;
        }

        DbgSsReservedOffsetFirst = offset - 8;
        return DbgSsReservedOffsetFirst;
    }
    else
    {
        return DbgSsReservedOffsetFirst;
    }
}
LONG GetDbgReserveOffsetSecond() {
    if (DbgSsReservedOffsetSecond == NULL) {
        HMODULE h = GetModuleHandleA("ntdll.dll");
        if (!h) h = LoadLibraryA("ntdll.dll");
        FARPROC p = GetProcAddress(h, "DbgUiConnectToDbg");
        UCHAR* mcode = (UCHAR*)p;
        ULONG offset = 0;
        while ((*mcode) != 0xC3)
        {
            if (((*mcode) == 0x48) && ((*(mcode + 1)) == 0x39) && ((*(mcode + 2)) == 0x88)) {
                LONG* offset_ptr = (LONG*)(mcode + 3);
                offset = *offset_ptr;
            }
            mcode++;
        }

        DbgSsReservedOffsetSecond = offset;
        return DbgSsReservedOffsetSecond;
    }
    else
    {
        return DbgSsReservedOffsetSecond;
    }
}


void OutputErrorCode(DWORD errcode)
{
    char buf[100];
    sprintf_s(buf, sizeof(buf),
        "lasterror code:%d\n", errcode);
    OutputDebugStringA(buf);
}