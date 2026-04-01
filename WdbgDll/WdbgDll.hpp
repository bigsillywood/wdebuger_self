
#include"windowsExtendAPI.hpp"
#include<iostream>
#include <map>
#include<unordered_map>
#include<thread>
#include<vector>
#include<string.h>

#include"capstone/capstone.h"
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
	const UCHAR* WriteBufferPtr;
	size_t write_size;
};
struct OPEN_PROCESS_ARG {
	__in HANDLE TargetPid;
};
struct OPEN_THREAD_ARG {
	__in HANDLE Pid;
	__in HANDLE Tid;
};	

enum THREAD_STEP_REASON {
	StepReasonNone = 0,
	StepReasonBreakpointRecovery,
	StepReasonUserSingleStep,
	StepReasonUserOverStep,
	StepReasonOther
};
typedef struct _ThreadInfo {
	HANDLE Tid;

	HANDLE ThreadHandle;
	LPVOID lpThreadLocalBase;
	LPTHREAD_START_ROUTINE lpStartAddress;

	DWORD64 CurLookingRip;
	DWORD64 CurLookingRSP;

	DEBUG_EVENT devent;
	CONTEXT ThreadContext;
	THREAD_STEP_REASON stepflag;
}ThreadInfo,*PThreadInfo;

typedef struct _DLLRecordNode {
	_DLLRecordNode* next;
	HANDLE LoadingThread;
	LOAD_DLL_DEBUG_INFO dllinfo;
	WCHAR *NameBufferPtr;
	DWORD NameLen;
}DLLRecordNode,*PDLLRecordNode;



typedef struct _OneInstructionRecord {
	//instruction type
	unsigned int id;
	//point to the index of the instruction in capstone structure 
	DWORD64 InnerPageIndex;
	DWORD64 InstructionAddr;
	UCHAR InstructionBuffer[24];
	UCHAR InstructionString[192];
	uint8_t InstructionLen;
	BOOL enable;
	BOOL dirty;
	BOOL OnlyOver;
}OneInstructionRecord, * POneInstructionRecord;





class CapStonePageHandle {
private:
	csh caphandle;
public:
	CapStonePageHandle();
	~CapStonePageHandle();
	BOOL TranslationBuffer(__in UCHAR *buffer,
							__in size_t bufferlen,
							__in DWORD64 VirtualAddr,
							__out cs_insn **CodeBuffer,
							__out SIZE_T *CodeCount);
};


typedef struct _PageInfor {
	DWORD64 StartVirtualAddr;
	cs_insn *PageCodes;
	SIZE_T CodeCounts;
	SIZE_T CurrentLookingCodeIndexInPage;
	DWORD64 CurrentVirtualAddress;
	SIZE_T BreakPointCounts;
}PageInfor,*PPageInfor;

typedef struct _UnionCodeStruct {
	//CRITICAL_SECTION CodeLock;
	//BOOL CodeLockOk;
	CapStonePageHandle CapstoneAPIhandle;
	std::unordered_map<DWORD64, _PageInfor*>Pagelist;
	DWORD64 CurrentLookingPageStartAddress;
	std::unordered_map<DWORD64,OneInstructionRecord*> Blist;
}UnionCodeStruct,*PUnionCodeStruct;



class WDBGDLL_API WDebugerObject {
private:

	UnionCodeStruct CodeStruct;


	//PDBGSS_EVENT_ENTRY reserve;
	PDLLRecordNode dllhead;
	HANDLE hDevice;
	HANDLE DebugHandle;
	HANDLE TargetPid;
	HANDLE ProcessHandle;
	HANDLE MainThreadid;


	
	CREATE_PROCESS_DEBUG_INFO ProcessInfo;
	std::unordered_map <HANDLE , ThreadInfo*> ThreadInfoMaps;



	BOOL init();
	//CRITICAL_SECTION ThreadMapLock;
	CRITICAL_SECTION WdbgLock;

	BOOL isLockOk;

	BOOL islisten;
	std::thread listen_thread;
	BOOL CombineThread();
	//PDBGSS_EVENT_ENTRY ReservedHandleList;
	VOID ADDTHREAD(DEBUG_EVENT* CreateThreadEvent);

	VOID ADDPROCESS(DEBUG_EVENT* CreateProcessEvent);
	VOID DELETETHREAD(HANDLE Tid);
	VOID DELETEPROCESS(HANDLE MainTid);
	VOID LOADDLL(DEBUG_EVENT* LoadDllEvent);
	VOID UNLOADDLL(DEBUG_EVENT* UnloadDllEvent);
	VOID EXCEPTIONRECORD(DEBUG_EVENT* ExceptionEvent);
	VOID CLEANALLDLL();
	VOID ListenThread();
	BOOL CahchePage(DWORD64 PageStartAddress);
	VOID FreePage(PageInfor *Page);
	BOOL ContinueThreadLocked(HANDLE Tid);
	DWORD64 DumpEntryAddress(DWORD64 imagebase);

	
public:
	WDebugerObject(HANDLE TargetPid);  
	~WDebugerObject();
	static std::unique_ptr<WDebugerObject> Create(HANDLE TargetPid);
	BOOL GetThreadList(HANDLE *Tidbuffer,DWORD buffersize);
	BOOL ContinueThread(HANDLE Tid);


	BOOL SetCodeStructCurrentLookingInstructions(DWORD64 VirtualAddress);

	//return how many actual instructions it has
	DWORD64 GetTargetCode(POneInstructionRecord InstructionRecordBufferPtr,SIZE_T MaxInstructions);

	BOOL SetBreakPointUp(DWORD64 InstructionAddr);
	BOOL SetBreakPointDown(DWORD64 InstructionAddr);
	BOOL DeleteBreakPoint(DWORD64 InstructionAddr);

	BOOL GetThreadInfo(HANDLE Tid,ThreadInfo *outinfo);
	BOOL EnumDllInfo(PDLLRecordNode* head);
	BOOL SuspendTargetThread(HANDLE Tid);
	BOOL ResumeTargetThread(HANDLE Tid);
	//BOOL FlushTargetThreadContext(HANDLE Tid);

	VOID GetProcessInfo(CREATE_PROCESS_DEBUG_INFO *outinfo);
	BOOL ChangeContext(HANDLE Tid,CONTEXT* tcontext);
	BOOL CreateListenThread();
	HANDLE GetDebugProcessHandle();
	BOOL ReadPhysicalMem(UCHAR* readbuffer, size_t readsize, ULONG64 VirtualAddr);
	BOOL WritePhysicalMem(UCHAR* writebuffer, size_t writesize, ULONG64 VirtualAddr);
	BOOL StepIntoOneStep(HANDLE Tid);
	BOOL StepOverOneStep(HANDLE Tid);


	//this function will get the import Table Entry Address for hooking
	DWORD64 GetImportAPIAddressPtrByName(WCHAR *SpaceDllName,CHAR *ImportDllName,CHAR* APIName);

	//this function will get the export Tabel Enrtry Address for hooking
	DWORD64 GetExportAPIAddressPtrByName(WCHAR *DllName,CHAR* APIName);
};




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
extern "C" WDBGDLL_API BOOL ContinueThreadC(HANDLE dbghandle,HANDLE ProcessId,HANDLE ThreadId);




void OutputErrorCode(DWORD errcode);
LONG GetDbgReserveOffsetFirst();
LONG GetDbgReserveOffsetSecond();