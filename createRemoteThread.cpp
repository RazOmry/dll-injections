#include <iostream>
#include <string>
#include <windows.h>
#include <tlhelp32.h>

HANDLE getProcessHandle(const std::string& name);
void injectDll(HANDLE process, const std::string& dllName, LPTHREAD_START_ROUTINE loadFunction);

int main()
{
	std::cout << "Enter process name: ";
	std::string processName;
	std::getline(std::cin, processName);

	HANDLE remoteProcess = getProcessHandle(processName);
	FARPROC loadLibrary = GetProcAddress(GetModuleHandle("Kernel32"), "LoadLibraryA");

	std::cout << "Enter DLL name: ";
	std::string dllName;
	std::getline(std::cin, dllName);

	injectDll(remoteProcess, dllName, (LPTHREAD_START_ROUTINE)loadLibrary);

	CloseHandle(remoteProcess);

	return 0;
}

HANDLE getProcessHandle(const std::string& name)
{
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (Process32First(snapshot, &entry))
	{
		while (Process32Next(snapshot, &entry))
		{
			if (name == entry.szExeFile)
			{
				HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, entry.th32ProcessID);
				CloseHandle(snapshot);
				return hProcess;
			}
		}
	}

	CloseHandle(snapshot);
	return nullptr;
}

void injectDll(HANDLE process, const std::string& dllName, LPTHREAD_START_ROUTINE loadFunction)
{
	// writing the dll name address into the remote address memory 
	LPVOID dllAddress = VirtualAllocEx(process, nullptr, dllName.size() + 1,
		MEM_COMMIT, PAGE_READWRITE);
	WriteProcessMemory(process, dllAddress, dllName.c_str(), dllName.size() + 1, nullptr);

	// loading the dll in new thread 
	HANDLE thread = CreateRemoteThread(process, nullptr, 0, loadFunction, dllAddress, 0, nullptr);
	if (thread == nullptr)
		std::cout << "Cannot open remote thread\n";

	WaitForSingleObject(thread, INFINITE);
	CloseHandle(thread);
	VirtualFreeEx(process, dllAddress, dllName.size() + 1, MEM_RELEASE);
}
