#include"user.h"

ULONG GetDbgReserveOffset(){
    HMODULE h = GetModuleHandleA("ntdll.dll");
    if (!h) h = LoadLibraryA("ntdll.dll");
    FARPROC p = GetProcAddress(h, "DbgUiConnectToDbg");
    UCHAR *mcode=(UCHAR*)p;
    ULONG offset=0;
    while ((*mcode)!=0xC3)
    {
        if(((*mcode)==0x48)&&((*(mcode+1))==0x39)&&((*(mcode+2))==0x88)){
            ULONG *offset_ptr=(ULONG*)(mcode+3);
            offset=*offset_ptr;
        }
        mcode++;
    }
    return offset;
}