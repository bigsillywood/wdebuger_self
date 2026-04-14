#include"WdbgDll.hpp"

static std::unordered_map<std::string, std::string> g_ApiSetFallbackMap = {
	{"api-ms-win-core-rtlsupport-l1-1-0.dll", "ntdll.dll"},
	{"api-ms-win-core-sysinfo-l1-1-0.dll", "kernel32.dll"},
	{"api-ms-win-core-synch-l1-1-0.dll", "kernel32.dll"},
	{"api-ms-win-core-heap-l1-1-0.dll", "kernel32.dll"},
	{"api-ms-win-core-libraryloader-l1-1-0.dll", "kernel32.dll"},
	{"api-ms-win-core-processthreads-l1-1-0.dll", "kernel32.dll"},
	{"api-ms-win-core-file-l1-1-0.dll", "kernel32.dll"},
	{"api-ms-win-core-handle-l1-1-0.dll", "kernel32.dll"},
	{"api-ms-win-core-memory-l1-1-0.dll", "kernel32.dll"},
	{"api-ms-win-core-string-l1-1-0.dll", "kernel32.dll"},
	{"api-ms-win-core-errorhandling-l1-1-0.dll", "kernel32.dll"},
	{"api-ms-win-core-debug-l1-1-0.dll", "kernel32.dll"},
	{"api-ms-win-core-console-l1-1-0.dll", "kernel32.dll"},
	{"api-ms-win-core-localization-l1-2-0.dll", "kernel32.dll"},
	{"api-ms-win-core-datetime-l1-1-0.dll", "kernel32.dll"},
	{"api-ms-win-core-util-l1-1-0.dll", "kernel32.dll"},
	{"api-ms-win-core-interlocked-l1-1-0.dll", "kernel32.dll"},
	{"api-ms-win-core-profile-l1-1-0.dll", "kernel32.dll"},
	{"api-ms-win-core-namedpipe-l1-1-0.dll", "kernel32.dll"},
	{"api-ms-win-core-io-l1-1-0.dll", "kernel32.dll"},
	{"api-ms-win-core-winrt-l1-1-0.dll", "combase.dll"},
	{"api-ms-win-core-com-l1-1-0.dll", "combase.dll"},
	{"api-ms-win-security-base-l1-1-0.dll", "advapi32.dll"},
	{"api-ms-win-security-lsalookup-l2-1-0.dll", "sechost.dll"},
	{"api-ms-win-security-sddl-l1-1-0.dll", "advapi32.dll"},
	{"api-ms-win-service-core-l1-1-0.dll", "sechost.dll"},
	{"api-ms-win-eventing-provider-l1-1-0.dll", "advapi32.dll"},
	{"api-ms-win-crt-runtime-l1-1-0.dll", "ucrtbase.dll"},
	{"api-ms-win-crt-string-l1-1-0.dll", "ucrtbase.dll"},
	{"api-ms-win-crt-heap-l1-1-0.dll", "ucrtbase.dll"},
	{"api-ms-win-crt-stdio-l1-1-0.dll", "ucrtbase.dll"},
	{"api-ms-win-crt-convert-l1-1-0.dll", "ucrtbase.dll"},
	{"api-ms-win-crt-math-l1-1-0.dll", "ucrtbase.dll"},
	{"api-ms-win-crt-time-l1-1-0.dll", "ucrtbase.dll"},
	{"api-ms-win-crt-filesystem-l1-1-0.dll", "ucrtbase.dll"},
	{"api-ms-win-crt-locale-l1-1-0.dll", "ucrtbase.dll"},
	{"api-ms-win-crt-environment-l1-1-0.dll", "ucrtbase.dll"}
};
__inline DWORD64 GetNTHeaderAddress(IMAGE_DOS_HEADER* DOSHeaderBuffer, DWORD64 DosStartAddress) {
	return DOSHeaderBuffer->e_lfanew + DosStartAddress;
}

static std::string ToLowerString(const std::string& s)
{
	std::string out = s;
	for (size_t i = 0; i < out.size(); i++)
	{
		if (out[i] >= 'A' && out[i] <= 'Z')
		{
			out[i] = out[i] - 'A' + 'a';
		}
	}
	return out;
}

static bool IsApiSetDllName(const std::string& s)
{
	if (s.size() >= 11 && s.compare(0, 11, "api-ms-win-") == 0)
	{
		return true;
	}
	if (s.size() >= 7 && s.compare(0, 7, "ext-ms-") == 0)
	{
		return true;
	}
	return false;
}

static std::string ResolveApiSetDllName(const std::string& DllName)
{
	std::string LowerName = ToLowerString(DllName);

	if (!IsApiSetDllName(LowerName))
	{
		return LowerName;
	}

	auto it = g_ApiSetFallbackMap.find(LowerName);
	if (it != g_ApiSetFallbackMap.end())
	{
		return it->second;
	}

	return LowerName;
}
DWORD64  WDebugerObject::GetImportAPIInformation(PIMAGE_IMPORT_DESCRIPTOR ImportDllDescriptor, DWORD64 DllBaseAddress, std::unordered_map<std::string, ImportAPIinfo>* ImportAPITablePtr) {
	DWORD TempIndex = 0;
	IMAGE_THUNK_DATA NameOrderThunk;
	IMAGE_THUNK_DATA ImportAddrThunk;
	PIMAGE_IMPORT_BY_NAME Ibn = NULL;
	UCHAR NameBufferWithHint[256];

	IMAGE_IMPORT_DESCRIPTOR TempImporTable = *ImportDllDescriptor;
	std::string APIname;
	ImportAPIinfo TempInfo;
	DWORD64 NameThunkRVA = TempImporTable.OriginalFirstThunk;

	if (NameThunkRVA == 0)
	{
		NameThunkRVA = TempImporTable.FirstThunk;
	}
	while (this->ReadPhysicalMem((UCHAR*)&NameOrderThunk, sizeof(IMAGE_THUNK_DATA), DllBaseAddress + NameThunkRVA + TempIndex * sizeof(IMAGE_THUNK_DATA))
		&& NameOrderThunk.u1.ForwarderString != NULL
		&& this->ReadPhysicalMem((UCHAR*)&ImportAddrThunk, sizeof(IMAGE_THUNK_DATA), DllBaseAddress + TempImporTable.FirstThunk + TempIndex * sizeof(IMAGE_THUNK_DATA)))
	{
		ZeroMemory(NameBufferWithHint, sizeof(NameBufferWithHint));
		if (!this->ReadPhysicalMem(NameBufferWithHint, sizeof(NameBufferWithHint), DllBaseAddress + NameOrderThunk.u1.AddressOfData))
		{
			break;
		}
		Ibn = (PIMAGE_IMPORT_BY_NAME)NameBufferWithHint;
		APIname = (char*)Ibn->Name;
		TempInfo.ImportAPITableEntryPtr = DllBaseAddress + TempImporTable.FirstThunk + TempIndex * sizeof(IMAGE_THUNK_DATA);
		TempInfo.ImportAPIAddress = ImportAddrThunk.u1.Function;

		

		(*ImportAPITablePtr)[APIname] = TempInfo;
		TempIndex++;
	}
	return TempIndex;
}
DWORD64 WDebugerObject::GetImportDllInformation(DWORD64 DllBaseAddress, std::unordered_map<std::string, ImportModuleInfo>* ImportDLLtable)
{
	IMAGE_DOS_HEADER DosHeaderBuffer;
	if (!this->ReadPhysicalMem((UCHAR*)&DosHeaderBuffer, sizeof(IMAGE_DOS_HEADER), DllBaseAddress)) {
		return NULL;
	}

	DWORD64 NtStartAddress = GetNTHeaderAddress(&DosHeaderBuffer, DllBaseAddress);
	IMAGE_NT_HEADERS NtHeaders;
	if (!this->ReadPhysicalMem((UCHAR*)&NtHeaders, sizeof(_IMAGE_NT_HEADERS), NtStartAddress)) {
		return NULL;
	}

	if (NtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0) {
		return 0;
	}

	DWORD64 ImportTableEntryAddress = DllBaseAddress + NtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	IMAGE_IMPORT_DESCRIPTOR TempImporTable;
	DWORD Dllindex = 0;
	CHAR DllNameBuffer[256];
	DWORD64 DllNamePtr = NULL;
	std::string TempDllName;
	//CHAR buf[256];

	while (this->ReadPhysicalMem((UCHAR*)&TempImporTable, sizeof(IMAGE_IMPORT_DESCRIPTOR), ImportTableEntryAddress + sizeof(IMAGE_IMPORT_DESCRIPTOR) * Dllindex)
		&& (TempImporTable.Name != 0
			|| TempImporTable.FirstThunk != 0
			|| TempImporTable.OriginalFirstThunk != 0))
	{
		DllNamePtr = TempImporTable.Name + DllBaseAddress;
		RtlZeroMemory(DllNameBuffer, 256);

		if (this->ReadPhysicalMem((UCHAR*)DllNameBuffer, 256, DllNamePtr))
		{
			TempDllName = DllNameBuffer;
			TempDllName = ResolveApiSetDllName(TempDllName);

			auto it = ImportDLLtable->find(TempDllName);
			if (it == ImportDLLtable->end())
			{
				ImportModuleInfo NewInfo;
				NewInfo.APIcounts = 0;
				NewInfo.APIcounts = (DWORD)this->GetImportAPIInformation(&TempImporTable, DllBaseAddress, &NewInfo.ImportAPITable);
				/*
				sprintf_s(buf, sizeof(buf),
					"Find importDLL NAME= %s,address=%llx,APIcounts=%lu\n",
					TempDllName.c_str(), DllBaseAddress, NewInfo.APIcounts);
				OutputDebugStringA(buf);

				
				*/
				(*ImportDLLtable)[TempDllName] = NewInfo;
			}
			else
			{
				DWORD APIcounts = (DWORD)this->GetImportAPIInformation(&TempImporTable, DllBaseAddress, &it->second.ImportAPITable);
				it->second.APIcounts = (DWORD)it->second.ImportAPITable.size();
				/*
								sprintf_s(buf, sizeof(buf),
					"Append importDLL NAME= %s,address=%llx,AddAPIcounts=%lu,TotalAPIcounts=%lu\n",
					TempDllName.c_str(), DllBaseAddress, APIcounts, it->second.APIcounts);
				OutputDebugStringA(buf);
				
				*/

			}
		}

		Dllindex++;
	}
	return Dllindex;
}
//return the Table Entry address for API
DWORD64 WDebugerObject::GetImportAPIAddressPtrByName(WCHAR* SpaceDllName, CHAR* ImportDllName, CHAR* APIName) {
	EnterCriticalSection(&this->WdbgLock);
	PDLLRecordNode DllNode = this->dllhead;
	std::unordered_map<std::string, ImportModuleInfo>* ImportDLLtable = NULL;
	DWORD ImportDLLcounts = 0;

	if (wcscmp(SpaceDllName, this->ProcessName) == 0)
	{
		ImportDLLtable = &this->MainModuleImportDLLtable;
		ImportDLLcounts = this->ImportDLLcounts;
	}
	else {
		while (DllNode != NULL) {
			if (DllNode->NameLen == 0)
			{
				DllNode = DllNode->next;
				continue;
			}
			if (wcscmp(SpaceDllName, DllNode->NameBufferPtr) == 0) {
				ImportDLLtable = &DllNode->ImportDLLtable;
				ImportDLLcounts = DllNode->ImportDLLcounts;
				break;
			}
			DllNode = DllNode->next;
		}
	}

	if (ImportDLLtable == NULL || ImportDLLcounts == 0)
	{
		LeaveCriticalSection(&this->WdbgLock);
		return NULL;
	}

	auto ImportDllIt = ImportDLLtable->find(std::string(ImportDllName));
	if (ImportDllIt == ImportDLLtable->end())
	{
		LeaveCriticalSection(&this->WdbgLock);
		return NULL;
	}

	auto ApiIt = ImportDllIt->second.ImportAPITable.find(std::string(APIName));
	if (ApiIt == ImportDllIt->second.ImportAPITable.end())
	{
		LeaveCriticalSection(&this->WdbgLock);
		return NULL;
	}

	DWORD64 RetPtr = ApiIt->second.ImportAPITableEntryPtr;
	LeaveCriticalSection(&this->WdbgLock);
	return RetPtr;
}


