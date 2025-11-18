
#include"windowsExtendAPI.hpp"
#include<iostream>
#include <map>
#include<thread>
#ifndef WDBGDLL_EXPORTS
#define WDBGDLL_EXPORTS
#endif 


#ifdef WDBGDLL_EXPORTS
#define WDBGDLL_API __declspec(dllexport)
#else
#define WDBGDLL_API __declspec(dllimport)
#endif

#define CREATE_DEBUG_OBJ 0X801
#define READ_PHYSICAL_MEM 0X802
#define WRITE_PHYSICAL_MEM 0X803
#define OPEN_TARGET_PROCESS 0x804
#define CREATE_TARGET_PROCESS 0X805
#define OPEN_TARGET_THREAD 0x806

#define IOCTL_CREATE_DEBUG_OBJ CTL_CODE(FILE_DEVICE_UNKNOWN,CREATE_DEBUG_OBJ,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_READ_PHYSICAL_MEM CTL_CODE(FILE_DEVICE_UNKNOWN,READ_PHYSICAL_MEM,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_WRITE_PHYSICAL_MEM CTL_CODE(FILE_DEVICE_UNKNOWN,WRITE_PHYSICAL_MEM,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_OPEN_TARGET_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN,OPEN_TARGET_PROCESS,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_CREATE_TARGET_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN,CREATE_TARGET_PROCESS,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_OPEN_TARGET_THREAD CTL_CODE(FILE_DEVICE_UNKNOWN,OPEN_TARGET_THREAD,METHOD_BUFFERED,FILE_ANY_ACCESS)


struct CREATE_DEBUG_OBJ_ARG {
	__in HANDLE DebugerPid;
	__in HANDLE TargetPid;
};
struct READ_PHY_ARG {
	__in HANDLE TargetPid;
	__in PVOID TargetVirtualAddr;
	__out UCHAR* ReadBufferPtr;
	__in size_t read_size;
};
struct WRITE_PHY_ARG {
	HANDLE TargetPid;
	PVOID TargetVirtualAddr;
	UCHAR* WriteBufferPtr;
	size_t write_size;
};
struct OPEN_PROCESS_ARG {
	__in HANDLE TargetPid;
};
struct OPEN_THREAD_ARG {
	__in HANDLE Pid;
	__in HANDLE Tid;
};	


typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
}CLIENT_ID, * PCLIENT_ID;

typedef struct _ThreadInfo {
	HANDLE Tid;

	HANDLE ThreadHandle;
	LPVOID lpThreadLocalBase;
	LPTHREAD_START_ROUTINE lpStartAddress;

	DWORD64 CurLookingRip;
	DWORD64 CurLookingRSP;

	DEBUG_EVENT devent;
	CONTEXT ThreadContext;
}ThreadInfo,*PThreadInfo;



class WDBGDLL_API WDebugerObject {
private:
	//PDBGSS_EVENT_ENTRY reserve;
	HANDLE hDevice;
	HANDLE DebugHandle;
	HANDLE TargetPid;
	HANDLE ProcessHandle;
	CREATE_PROCESS_DEBUG_INFO ProcessInfo;
	std::map <HANDLE , ThreadInfo*> ThreadInfoMaps;
	BOOL init();
	CRITICAL_SECTION ThreadMapLock;
	BOOL islisten;
	BOOL CombineThread();
	PDBGSS_EVENT_ENTRY ReservedHandleList;
	VOID ADDTHREAD(DEBUG_EVENT* CreateThreadEvent);
	VOID ADDPROCESS(DEBUG_EVENT* CreateProcessEvent);
	VOID DELETETHREAD(HANDLE Tid);
	VOID DELETEPROCESS();
	VOID ListenThread();
	std::thread listen_thread;
public:
	WDebugerObject(HANDLE TargetPid);  
	~WDebugerObject();
	static std::unique_ptr<WDebugerObject> Create(HANDLE TargetPid);
	BOOL GetThreadList(HANDLE *Tidbuffer,DWORD buffersize);
	BOOL ContinueThread(HANDLE Tid);
	BOOL GetThreadInfo(HANDLE Tid,ThreadInfo *outinfo);
	BOOL GetProcessInfo(CREATE_PROCESS_DEBUG_INFO *outinfo);
	BOOL ChangeContext(HANDLE Tid,CONTEXT* tcontext);
	BOOL CreateListenThread();
	HANDLE GetDebugProcessHandle();
	BOOL ReadPhysicalMem(UCHAR* readbuffer, size_t readsize, ULONG64 VirtualAddr);
	BOOL WritePhysicalMem(UCHAR* writebuffer, size_t writesize, ULONG64 VirtualAddr);
};

LONG GetDbgReserveOffsetFirst();
LONG GetDbgReserveOffsetSecond();
extern "C" WDBGDLL_API BOOL CombineThreadC(HANDLE DebugHandle);
extern "C" WDBGDLL_API HANDLE CreateWdbgDevice();
extern "C" WDBGDLL_API void CloseWdbgDevice(HANDLE hDevice);

extern "C" WDBGDLL_API HANDLE krnlDebugActive(__in HANDLE TargetPid,
											__in HANDLE hDevice);
extern "C" WDBGDLL_API BOOL UserPhysicalRead(__in HANDLE TargetPid,
											 __in HANDLE hDevice,
											 __in ULONG64 VirtualAddr,
											 __in size_t ReadLen,
											 __out UCHAR* readbuffer);
extern "C" WDBGDLL_API BOOL UserPhysicalWrite(__in HANDLE TargetPID,
											  __in HANDLE hDevice,
											  __in ULONG64 VirtualAddr,
											  __in size_t WriteLen,
											  __in UCHAR* writebuffer);
extern "C" WDBGDLL_API HANDLE UserOpenProcess(__in HANDLE TargetPid, __in HANDLE hDevice);
extern "C" WDBGDLL_API HANDLE UserOpenThread(__in HANDLE TargetPid,__in HANDLE TargetTid,__in HANDLE hDevice);
extern "C" WDBGDLL_API BOOL RemoveHandles(PVOID dbgreserve_0, int threadid, int processid);