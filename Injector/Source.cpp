#include <Windows.h>
#include <tchar.h>
#include <winternl.h>
#include "Remote.h"
#include <Psapi.h>

#define IF_FAIL_GO(err, func, hand)	\
			err = func; \
			if (0 != err) goto hand;


DWORD CreateProc(LPCTSTR appName, HANDLE & hProc, HANDLE & hThread) {

	STARTUPINFO si = {};
	PROCESS_INFORMATION pi = {};


	if (!CreateProcess(
		appName, nullptr, nullptr,
		nullptr, true, CREATE_SUSPENDED,
		nullptr, nullptr, &si, &pi)) 
	{
		DWORD err = GetLastError();
		_tprintf(_T("CreateProccess Failed with error: 0x%x\n"), err);

		return err;
	}

	Sleep(1000);

	hProc = pi.hProcess;
	hThread = pi.hThread;

	return ERROR_SUCCESS;
}

DWORD LoopEntry(HANDLE hProc, HANDLE hThread, ULONG_PTR& addressOfEntry, WORD& originalEntry) {
	PROCESS_BASIC_INFORMATION pbi = {};
	ULONG retLen = 0;
	PEB peb = {};
	IMAGE_DOS_HEADER dos = {};
	IMAGE_NT_HEADERS32 nt = {};

	WORD patchedEntry = 0xFEEB;

	NTSTATUS qStatus = NtQueryInformationProcess(
		hProc,
		ProcessBasicInformation,
		&pbi,
		sizeof(PROCESS_BASIC_INFORMATION),
		&retLen);

	if (qStatus)
	{
		_tprintf(_T("NtQueryInformationProcess Failed with error: 0x%x\n"), qStatus);

		return qStatus;
	}

	DWORD error = ReadRemote<PEB>(hProc, (ULONG_PTR)pbi.PebBaseAddress, peb);

	ULONG_PTR pRemoteBaseAddress = (ULONG_PTR)peb.Reserved3[1];

	ReadRemote<IMAGE_DOS_HEADER>(hProc, pRemoteBaseAddress, dos);
	ReadRemote<IMAGE_NT_HEADERS32>(hProc, (ULONG_PTR)(pRemoteBaseAddress + dos.e_lfanew), nt);

	addressOfEntry = pRemoteBaseAddress + nt.OptionalHeader.AddressOfEntryPoint;

	ReadRemote<WORD>(hProc, addressOfEntry, originalEntry);
	WriteRemote<WORD>(hProc, addressOfEntry, patchedEntry);

	ResumeThread(hThread);

	Sleep(1000);

	return 0;
}

extern "C" NTSYSCALLAPI NTSTATUS NTAPI NtSuspendProcess(HANDLE proc);
extern "C" NTSYSCALLAPI NTSTATUS NTAPI NtResumeProcess(HANDLE proc);


DWORD DeloopEntry(HANDLE hProc, HANDLE hThread, ULONG_PTR addressOfEntry, WORD originalEntry)
{
	NtSuspendProcess(hProc);

	WriteRemote<WORD>(hProc, addressOfEntry, originalEntry);

	NtResumeProcess(hProc);

	Sleep(1000);

	return 0;
}

DWORD FindLoadLibrary(HANDLE hProc, HANDLE hThread, ULONG_PTR& loadLibAddr)
{
	LPCSTR targetLib = "KERNEL32.dll";
	LPCSTR targetFunc = "LoadLibraryW";
	DWORD size, amount, needed = 0;

	HMODULE* hModules = nullptr;

	EnumProcessModules(hProc, nullptr, 0, &needed);

	size = needed;
	amount = size / sizeof(HMODULE);

	hModules = (HMODULE*)malloc(size);

	EnumProcessModules(hProc, hModules, size, &needed);

	for (DWORD i = 0; i < amount; i++)
	{
		ULONG_PTR moduleBase = (ULONG_PTR)hModules[i];
		IMAGE_DOS_HEADER dos = {};
		IMAGE_NT_HEADERS32 nt = {};

		ReadRemote<IMAGE_DOS_HEADER>(hProc, moduleBase, dos);
		ReadRemote<IMAGE_NT_HEADERS32>(hProc, (ULONG_PTR)(moduleBase + dos.e_lfanew), nt);

		IMAGE_DATA_DIRECTORY exportDir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

		if (0 == exportDir.Size) continue;

		IMAGE_EXPORT_DIRECTORY moduleExport = {};

		ReadRemote<IMAGE_EXPORT_DIRECTORY>(hProc, (ULONG_PTR)(moduleBase + exportDir.VirtualAddress), moduleExport);

		CHAR moduleName[MAX_PATH];
		DWORD moduleNameLen = 0;

		ReadRemote<CHAR>(hProc, (ULONG_PTR)(moduleBase + moduleExport.Name), moduleName, moduleNameLen);

		if (strcmp(moduleName, targetLib)) continue;

		DWORD numberOfFuncs = moduleExport.NumberOfFunctions;
		DWORD numberOfFuncs2 = moduleExport.NumberOfFunctions;


		ULONG_PTR* functionNamesRva = (ULONG_PTR*)malloc(sizeof(ULONG_PTR) * numberOfFuncs);
		ULONG_PTR* functionAddrsRva = (ULONG_PTR*)malloc(sizeof(ULONG_PTR) * numberOfFuncs);

		
		ReadRemote<ULONG_PTR>(hProc, (ULONG_PTR)(moduleBase + moduleExport.AddressOfNames), functionNamesRva, numberOfFuncs);
		ReadRemote<ULONG_PTR>(hProc, (ULONG_PTR)(moduleBase + moduleExport.AddressOfFunctions), functionAddrsRva, numberOfFuncs2);


		for (DWORD j = 0; j < numberOfFuncs; j++) {
			CHAR functionName[MAX_PATH];
			DWORD functionNameLen = 0;

			ReadRemote<CHAR>(hProc, (ULONG_PTR)(moduleBase + functionNamesRva[j]), functionName, functionNameLen);

			if (!strcmp(functionName, targetFunc)) {
				// may be mistake
				loadLibAddr = (ULONG_PTR) (moduleBase + functionAddrsRva[j]);
				break;
			}
		}

		free(functionNamesRva);
		free(functionAddrsRva);
		break;


	}

	return 0;
}

DWORD Inject(HANDLE hProc, HANDLE hThread, ULONG_PTR& loadLibAddr)
{
	UCHAR shellx86[]
	{
		/* 0x00 */ 0x90, 0x90, 0x90, 0x90, 0x90,
		/* 0x05 */ 0x6A, 0x00, 0x6A, 0x00,
		/* 0x09 */ 0x68, 0x00, 0x00, 0x00, 0x00,
		/* 0x0E */ 0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,
		/* 0x14 */ 0xF7, 0xD8,
		/* 0x16 */ 0x1B, 0xC0,
		/* 0x18 */ 0xF7, 0xD8,
		/* 0x1A */ 0x48,
		/* 0x1B */ 0xC3,
		/* 0x1C */ 0x90, 0x90, 0x90, 0x90,
		/* 0x20 */ 0x00, 0x00, 0x00, 0x00,
		/* 0x24 */ 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
		/* 0x30 */ 0x43, 0x00, 0x3a, 0x00, 0x5c, 0x00, 0x55, 0x00, 0x73,
				   0x00, 0x65, 0x00, 0x72, 0x00, 0x73, 0x00, 0x5c, 0x00,
				   0x61, 0x00, 0x72, 0x00, 0x74, 0x00, 0x65, 0x00, 0x6d,
			       0x00, 0x5c, 0x00, 0x73, 0x00, 0x6f, 0x00, 0x75, 0x00,
				   0x72, 0x00, 0x63, 0x00, 0x65, 0x00, 0x5c, 0x00, 0x72,
				   0x00, 0x65, 0x00, 0x70, 0x00, 0x6f, 0x00, 0x73, 0x00,
				   0x5c, 0x00, 0x49, 0x00, 0x6e, 0x00, 0x6a, 0x00, 0x65,
				   0x00, 0x63, 0x00, 0x74, 0x00, 0x6f, 0x00, 0x72, 0x00,
				   0x5c, 0x00, 0x52, 0x00, 0x65, 0x00, 0x6c, 0x00, 0x65,
				   0x00, 0x61, 0x00, 0x73, 0x00, 0x65, 0x00, 0x5c, 0x00,
				   0x44, 0x00, 0x4c, 0x00, 0x4c, 0x00, 0x2e, 0x00, 0x64,
				   0x00, 0x6c, 0x00, 0x6c, 0x00, 0x00, 0x00
		
	};

	PVOID pShellRemote = VirtualAllocEx(hProc, nullptr, sizeof(shellx86), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	ULONG_PTR shellBase = (ULONG_PTR)pShellRemote;
	ULONG_PTR stringOffset = shellBase + 0x30;
	ULONG_PTR funcOffset = shellBase + 0x20;

	memcpy(shellx86 + 0x20, &loadLibAddr, sizeof(ULONG_PTR));

	memcpy(shellx86 + 0x0A, &stringOffset, sizeof(ULONG_PTR));

	memcpy(shellx86 + 0x10, &funcOffset, sizeof(ULONG_PTR));

	SIZE_T written = 0;

	// move memory
	WriteProcessMemory(hProc, pShellRemote, shellx86, sizeof(shellx86), &written);

	// create thread entry
	DWORD tid;
	HANDLE hRemoteThread = CreateRemoteThread(hProc, nullptr, 0, LPTHREAD_START_ROUTINE(shellBase), nullptr, 0, &tid);

	WaitForSingleObject(hRemoteThread, INFINITE);

	DWORD exitCode = 0xf;
	GetExitCodeThread(hRemoteThread, &exitCode);

	CloseHandle(hRemoteThread);
	
	return 0;
}

int main() {

	LPCTSTR appName = _T("C:\\Windows\\SysWOW64\\notepad.exe");

	HANDLE hProc = INVALID_HANDLE_VALUE;
	HANDLE hThread = INVALID_HANDLE_VALUE;
	DWORD status = ERROR_SUCCESS;

	ULONG_PTR addressOfEntry = 0;
	WORD originalEntry = 0;
	ULONG_PTR loadDirAddr = 0;

	// create suspended process

	IF_FAIL_GO(status, CreateProc(appName, hProc, hThread), MAIN_ERROR_HANDLE);

	IF_FAIL_GO(status, LoopEntry(hProc, hThread, addressOfEntry, originalEntry), MAIN_ERROR_HANDLE);

	// find loadlibrary
	IF_FAIL_GO(status, FindLoadLibrary(hProc, hThread, loadDirAddr), MAIN_ERROR_HANDLE);

	// inject
	IF_FAIL_GO(status, Inject(hProc, hThread, loadDirAddr), MAIN_ERROR_HANDLE);
	// deloop

	IF_FAIL_GO(status, DeloopEntry(hProc, hThread, addressOfEntry, originalEntry), MAIN_ERROR_HANDLE);

MAIN_ERROR_HANDLE:
	_tprintf(_T("ERROR: 0x%x\n"), status);
	return status;
}