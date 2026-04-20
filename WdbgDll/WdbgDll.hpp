
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
#define ANTI_DETECTION 0X807

#define IOCTL_CREATE_DEBUG_OBJ CTL_CODE(FILE_DEVICE_UNKNOWN,CREATE_DEBUG_OBJ,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_READ_PHYSICAL_MEM CTL_CODE(FILE_DEVICE_UNKNOWN,READ_PHYSICAL_MEM,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_WRITE_PHYSICAL_MEM CTL_CODE(FILE_DEVICE_UNKNOWN,WRITE_PHYSICAL_MEM,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_OPEN_TARGET_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN,OPEN_TARGET_PROCESS,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_CREATE_TARGET_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN,CREATE_TARGET_PROCESS,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_OPEN_TARGET_THREAD CTL_CODE(FILE_DEVICE_UNKNOWN,OPEN_TARGET_THREAD,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_ANTI_DETECTION CTL_CODE(FILE_DEVICE_UNKNOWN,ANTI_DETECTION,METHOD_BUFFERED,FILE_ANY_ACCESS)

// 按需翻译时向目标读取的字节数
// x86-64 最长指令 15 字节，多读一段让 Capstone 在跨页时也能拿到完整字节流
#define ONDEMAND_READ_SIZE 32


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
struct AntiDetection_ARG {
	__in HANDLE TargetPid;
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

typedef struct _ImportAPIinfo {
	DWORD64 ImportAPITableEntryPtr;
	DWORD64 ImportAPIAddress;
}ImportAPIinfo,PImportAPIinfo;
typedef struct _ImportModuleInfo {
	std::unordered_map<std::string,ImportAPIinfo> ImportAPITable;
	DWORD APIcounts;
}ImportModuleInfo,PImportModuleInfo;

typedef struct _DLLRecordNode {
	_DLLRecordNode* next;
	HANDLE LoadingThread;
	LOAD_DLL_DEBUG_INFO dllinfo;
	std::unordered_map<std::string,ImportModuleInfo> ImportDLLtable;
	DWORD ImportDLLcounts;
	WCHAR *NameBufferPtr;
	DWORD NameLen;
}DLLRecordNode,*PDLLRecordNode;

typedef struct _AntiDetectHookFuncInformation {
	DWORD64 NtQueryInformationHookAddress;
	DWORD64 NtQueryInformationOriginalAddress;
	DWORD64 GetProcAddressHookAddress;
	DWORD64 GetProcAddressOriginalAddress;
	DWORD64 OutputDebugStringAOrignalAddress;
	DWORD64 OutputDebugStringWOrignalAddress;
	DWORD64 OutputDebugStringHookAddress;
	DWORD64 NtSetInformationThreadOriginalAddress;
	DWORD64 NtSetInformationThreadHookAddress;
}AntiDetectHookFuncInformation,*PAntiDetectHookFuncInformation;

typedef struct _OneInstructionRecord {
	
	unsigned int id;

	DWORD64 InnerPageIndex;
	DWORD64 InstructionAddr;
	UCHAR InstructionBuffer[24];
	UCHAR InstructionString[192];
	uint8_t InstructionLen;
	BOOL enable;
	BOOL dirty;
	BOOL OnlyOver;

	BOOL stale;
}OneInstructionRecord,*POneInstructionRecord;



typedef struct _ThreadBriefInfo {
	HANDLE Tid;
	DWORD64 CurLookingRip;         
	DWORD  DeventCode;            
	DWORD  SubExceptionCode;     
	
}ThreadBriefInfo, * PThreadBriefInfo;

class CapStonePageHandle {
private:
	csh caphandle;
public:
	CapStonePageHandle();
	~CapStonePageHandle();
	BOOL TranslationBuffer(__in UCHAR*		buffer,
							__in size_t		bufferlen,
							__in DWORD64	VirtualAddr,
							__out cs_insn**	CodeBuffer,
							__out SIZE_T*	CodeCount);

	BOOL TranslateOneInstruction(__in  UCHAR*				buffer,
								 __in  size_t				bufferlen,
								 __in  DWORD64				VirtualAddr,
								 __out POneInstructionRecord OutRecord);
};



typedef struct _UnionCodeStruct {
	CapStonePageHandle CapstoneAPIhandle;
	
	std::unordered_map<DWORD64,OneInstructionRecord*> Blist;

	DWORD64 CurrentLookingAddr;
}UnionCodeStruct,*PUnionCodeStruct;

struct AntiDetectionFuncStruct {
	UCHAR* FuncName;
	UCHAR* StartAddress;
	DWORD FuncLen;
};

#define MODULE_NAME_MAX 128
typedef struct _ModuleInfo {
	DWORD64 BaseAddress;
	WCHAR   Name[MODULE_NAME_MAX];
	BOOL    IsMainModule;           // TRUE 表示主 EXE 模块
}ModuleInfo,*PModuleInfo;


#define IMPORT_NAME_MAX  256
#define IMPORT_DLL_MAX   128
typedef struct _ImportEntryFlat {
	CHAR    APIName[IMPORT_NAME_MAX];   // 函数名
	CHAR    FromDLL[IMPORT_DLL_MAX];    // 来自哪个 DLL（已做 ApiSet 解析）
	DWORD64 IATAddress;                 // IAT 表项虚拟地址（写 hook 用）
	DWORD64 FuncAddress;                // 当前函数实际地址
}ImportEntryFlat, * PImportEntryFlat;

class WDBGDLL_API WDebugerObject {
private:

	UnionCodeStruct CodeStruct;

	PDLLRecordNode dllhead;
	HANDLE hDevice;
	HANDLE DebugHandle;
	HANDLE TargetPid;
	HANDLE ProcessHandle;
	HANDLE MainThreadid;
	WCHAR* ProcessName;
	DWORD ProcessNameLen;
	HANDLE CurLookTid;
	BOOL AntiDetectionBits;
	std::unordered_map<std::string,ImportModuleInfo> MainModuleImportDLLtable;
	DWORD ImportDLLcounts;
	CREATE_PROCESS_DEBUG_INFO ProcessInfo;
	std::unordered_map<HANDLE,ThreadInfo*> ThreadInfoMaps;
	AntiDetectHookFuncInformation HookInformations;

	BOOL init();
	CRITICAL_SECTION WdbgLock;
	BOOL isLockOk;

	BOOL islisten;
	std::thread listen_thread;
	BOOL CombineThread();

	VOID ADDTHREAD(DEBUG_EVENT* CreateThreadEvent);
	VOID ADDPROCESS(DEBUG_EVENT* CreateProcessEvent);
	VOID DELETETHREAD(HANDLE Tid);
	VOID DELETEPROCESS(HANDLE MainTid);
	VOID LOADDLL(DEBUG_EVENT* LoadDllEvent);
	VOID UNLOADDLL(DEBUG_EVENT* UnloadDllEvent);
	VOID EXCEPTIONRECORD(DEBUG_EVENT* ExceptionEvent);
	VOID CLEANALLDLL();
	VOID ListenThread();
	BOOL ContinueThreadLocked(HANDLE Tid);
	DWORD64 DumpEntryAddress(DWORD64 imagebase);
	DWORD64 GetImportAPIInformation(PIMAGE_IMPORT_DESCRIPTOR ImportDllDescriptor,DWORD64 DllBase,std::unordered_map<std::string,ImportAPIinfo>* ImportAPITablePtr);
	DWORD64 GetImportDllInformation(DWORD64 DllBase,std::unordered_map<std::string,ImportModuleInfo>* ImportDLLtable);
	BOOL AntiDetection_InjectHookFunctions();
	VOID AntiDetection_PatchIAT_ByNode(PDLLRecordNode node,DWORD64 GetProcBufBase);
	VOID AntiDetection_PatchIAT_ByMainModule(DWORD64 GetProcBufBase);
	VOID AntiDetection_PatchIAT();

	BOOL ReadAndTranslateOne(__in  DWORD64				VirtualAddr,
							 __out POneInstructionRecord OutRecord);

	BOOL CheckBreakPointStale(__in  DWORD64 VirtualAddr,
							  __out BOOL*   IsStale);

public:
	WDebugerObject(HANDLE TargetPid);
	~WDebugerObject();
	static std::unique_ptr<WDebugerObject> Create(HANDLE TargetPid,BOOL isAntiDetect);
	BOOL GetThreadList(HANDLE* Tidbuffer,DWORD buffersize);
	BOOL GetThreadBriefList(__out PThreadBriefInfo OutBuffer,
		__in  DWORD            BufferCount,
		__out DWORD* OutCount);
	BOOL ContinueThread(HANDLE Tid);

	BOOL SetCodeStructCurrentLookingInstructions(DWORD64 VirtualAddress);

	DWORD64 GetTargetCode(POneInstructionRecord InstructionRecordBufferPtr,SIZE_T MaxInstructions);

	BOOL SetBreakPointUp(DWORD64 InstructionAddr);
	BOOL SetBreakPointDown(DWORD64 InstructionAddr);
	BOOL DeleteBreakPoint(DWORD64 InstructionAddr);

	BOOL GetThreadInfo(HANDLE Tid,ThreadInfo* outinfo);
	BOOL EnumDllInfo(PDLLRecordNode* head);
	BOOL EnumModules(__out PModuleInfo OutBuffer,
					 __in  DWORD       BufferCount,
					 __out DWORD*      OutCount);
	BOOL SuspendTargetThread(HANDLE Tid);
	BOOL ResumeTargetThread(HANDLE Tid);

	VOID GetProcessInfo(CREATE_PROCESS_DEBUG_INFO* outinfo);
	BOOL ChangeContext(HANDLE Tid,CONTEXT* tcontext);
	BOOL CreateListenThread();
	HANDLE GetDebugProcessHandle();
	BOOL ReadPhysicalMem(UCHAR* readbuffer,size_t readsize,ULONG64 VirtualAddr);
	BOOL WritePhysicalMem(UCHAR* writebuffer,size_t writesize,ULONG64 VirtualAddr);
	BOOL StepIntoOneStep(HANDLE Tid);
	BOOL StepOverOneStep(HANDLE Tid);

	HANDLE GetCurLookTid();
	DWORD64 GetImportAPIAddressPtrByName(WCHAR* SpaceDllName,CHAR* ImportDllName,CHAR* APIName);
	VOID AntiDetection();
	VOID AntiDetection_Force();
	DWORD64 GetExportAPIAddressPtrByName(WCHAR* DllName,CHAR* APIName);

	BOOL GetImportTable(__in  DWORD64          ModuleBase,
		__out PImportEntryFlat  OutBuffer,
		__in  DWORD             BufferCount,
		__out DWORD* OutCount);
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
extern "C" WDBGDLL_API HANDLE UserOpenProcess(__in HANDLE TargetPid,__in HANDLE hDevice);
extern "C" WDBGDLL_API HANDLE UserOpenThread(__in HANDLE TargetPid,__in HANDLE TargetTid,__in HANDLE hDevice);
extern "C" WDBGDLL_API BOOL RemoveHandles(PVOID dbgreserve_0,int threadid,int processid);
extern "C" WDBGDLL_API BOOL ContinueThreadC(HANDLE dbghandle,HANDLE ProcessId,HANDLE ThreadId);

extern "C" WDBGDLL_API BOOL UserAntiDetection(__in HANDLE TargetPid,
											  __in HANDLE hDevice);



void OutputErrorCode(DWORD errcode);
LONG GetDbgReserveOffsetFirst();
LONG GetDbgReserveOffsetSecond();
