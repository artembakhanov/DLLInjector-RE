#pragma once

#include <Windows.h>

template<class T> 
DWORD ReadRemote(
	_In_ HANDLE hProc,
	_In_ ULONG_PTR offset,
	_Out_ T& value
)
{
	SIZE_T numBytesToRead = 0;
	if (!ReadProcessMemory(hProc, (LPVOID)offset, &value, sizeof(T), &numBytesToRead))
	{
		DWORD err = GetLastError();
		_tprintf(_T("ReadProcessMemory Failed with error: 0x%x\n"), err);

		return err;
	}

	return 0;
}

template<class T>
DWORD ReadRemote(
	_In_ HANDLE hProc,
	_In_ ULONG_PTR offset,
	_Out_ T* value,
	DWORD& amount
)
{
	ULONG_PTR p = offset;
	DWORD counter = 0;

	T zero = {};

	for (;;) {
		T current;
		ReadRemote<T>(hProc, p, current);
		value[counter] = current;

		counter++;

		if (0 != amount && counter == amount) break;

		p += sizeof(T);

		if (0 == amount && 0 == memcmp(&current, &zero, sizeof(T))) break;

	}

	counter--;
	amount = counter;
	return 0;
}

template<class T>
DWORD WriteRemote(
	_In_ HANDLE hProc,
	_In_ ULONG_PTR offset,
	_In_ const T& value
)
{
	SIZE_T numBytesToWrite = 0;
	if (!WriteProcessMemory(hProc, (LPVOID)offset, &value, sizeof(T), &numBytesToWrite))
	{
		DWORD err = GetLastError();
		_tprintf(_T("WriteProcessMemory Failed with error: 0x%x\n"), err);

		return err;
	}

	return 0;
}
