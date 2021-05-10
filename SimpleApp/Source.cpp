#include <Windows.h>

typedef HMODULE(__stdcall* pfnLoadLib)(LPCWSTR libname);	

pfnLoadLib gLoadLib = LoadLibraryW;
const wchar_t* gLibName = L"C:\\Users\\artem\\source\\repos\\Injector\\Release\\DLL.dll";

DWORD _declspec(noinline) Func()
{
	if (nullptr == gLoadLib(gLibName)) {
		return 0xffffffff;
	}

	return 0;
}

int main() {
	Func();
}