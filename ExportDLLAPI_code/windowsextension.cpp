#include"WdbgDll.hpp"
//this will not set up the TEB reserve , make user can track it by them self
BOOL WaitForDebugEventWorkerSelf(DEBUG_EVENT* PDebugEvent, INT waitmiliseconds, BOOL extendflag);
BOOL WaitForDebugEventSelf(DEBUG_EVENT* PDebugEvent, INT waitmiliseconds) {
	return WaitForDebugEventWorkerSelf(PDebugEvent,waitmiliseconds,0);
}
BOOL WaitForDebugEventWorkerSelf(DEBUG_EVENT* PDebugEvent,INT waitmiliseconds,BOOL extendflag) {
	LARGE_INTEGER timeout;
	LARGE_INTEGER* p_timeout = &timeout;
	DBGUI_WAIT_STATE_CHANGE waitstatechange;
	memset(&waitstatechange,0,sizeof(DBGUI_WAIT_STATE_CHANGE));
	if (waitmiliseconds==-1)
	{
		p_timeout = NULL;
	}
	else
	{
		timeout.QuadPart = -10000 * waitmiliseconds;
	}
	NTSTATUS result = 0;
	
	do
	{
		result =DbgUiWaitStateChange(&waitstatechange,p_timeout);
	} while (result==0x101||result==0x0c0);

	if (result<0) {
		SetLastError(result);
		return 0;
	}
	if (result==0x102)
	{
		SetLastError(0x79);
		return 0;
	}
	result = extendflag ? DbgUiConvertStateChangeStructureEx(&waitstatechange,PDebugEvent) :
		DbgUiConvertStateChangeStructure(&waitstatechange, PDebugEvent) ;
	if (result < 0) {
		SetLastError(result);
		return 0;
	}
	return 1;
}